"""Task #42 regression -- record_user_signal must work on DuckDB.

Pre-fix bug: DuckDB rejected `INSERT ... ON CONFLICT DO UPDATE SET
trust_score = ...` because trust_score participated in an index. Even
after removing ON CONFLICT, plain UPDATE on the indexed column tripped
DuckDB's ART-index "Duplicate key id: 1" rule. Fix:
  1) Remove the trust_score index from the Table() definition; add it
     back conditionally for non-DuckDB dialects.
  2) Rewrite _duckdb_upsert_raw to SELECT-then-route (UPDATE-if-exists,
     INSERT-else), since duckdb-engine's cursor.rowcount is unreliable.

If either half regresses, these tests fail.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import init_storage, record_user_signal


TENANT = "11111111-2222-3333-4444-aaaaaaaa4242"


@pytest.fixture
def duckdb_session():
    eng = create_engine("duckdb:///:memory:")
    db = sessionmaker(bind=eng)()
    init_storage(db)
    yield db
    db.close()
    eng.dispose()


def test_record_user_signal_first_call_inserts(duckdb_session):
    """Pre-fix: this raised BinderException at the INSERT step."""
    score = record_user_signal(
        duckdb_session, tenant_id=TENANT, user_id="alice",
        signal_kind="clean_invocation")
    assert score == 51, f"expected 50+1=51, got {score}"


def test_record_user_signal_second_call_updates(duckdb_session):
    """Pre-fix: 2nd call raised ConstraintException 'Duplicate key id: 1'
    because DuckDB's UPDATE-on-indexed-column was disallowed."""
    record_user_signal(duckdb_session, tenant_id=TENANT,
                       user_id="alice", signal_kind="clean_invocation")
    # 2nd same-user call must UPDATE, not INSERT
    score = record_user_signal(
        duckdb_session, tenant_id=TENANT, user_id="alice",
        signal_kind="clean_invocation")
    assert score == 52, f"expected 51+1=52, got {score}"

    # Confirm one row, not two
    rows = duckdb_session.execute(text(
        "SELECT COUNT(*) FROM kya_user_trust WHERE user_id='alice'"
    )).scalar()
    assert rows == 1, f"expected 1 row, got {rows}"


def test_record_user_signal_negative_delta(duckdb_session):
    """Negative-signal path also exercises the UPDATE-on-indexed-column
    fix (trust_score decreases)."""
    record_user_signal(duckdb_session, tenant_id=TENANT,
                       user_id="bob", signal_kind="clean_invocation")
    score = record_user_signal(
        duckdb_session, tenant_id=TENANT, user_id="bob",
        signal_kind="rogue_pattern_high_severity")
    # 51 + (-1 for rogue_pattern_high_severity, conservative) = 50
    # Actual delta depends on SIGNAL_DELTAS; verify it's lower than start
    assert score < 51


def test_record_user_signal_multiple_users(duckdb_session):
    """INSERT path runs multiple times for different (tenant, user)
    pairs. Each INSERT must succeed without PK collisions on the
    DuckDB sequence."""
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        score = record_user_signal(
            duckdb_session, tenant_id=TENANT, user_id=user,
            signal_kind="clean_invocation")
        assert score == 51
    rows = duckdb_session.execute(text(
        "SELECT COUNT(*) FROM kya_user_trust"
    )).scalar()
    assert rows == 4


def test_record_user_signal_signal_counts_accumulate(duckdb_session):
    """After multiple signals, the JSON signal_counts column must
    aggregate correctly (regression for the read-modify-write path)."""
    for _ in range(3):
        record_user_signal(duckdb_session, tenant_id=TENANT,
                           user_id="alice",
                           signal_kind="clean_invocation")
    record_user_signal(duckdb_session, tenant_id=TENANT,
                       user_id="alice",
                       signal_kind="rogue_pattern_high_severity")

    row = duckdb_session.execute(text(
        "SELECT signal_counts FROM kya_user_trust WHERE user_id='alice'"
    )).first()
    counts = row[0]
    assert counts.get("clean_invocation") == 3
    assert counts.get("rogue_pattern_high_severity") == 1


# ── record_principal_signal regression (same root cause) ─────────


def test_record_principal_signal_first_insert(duckdb_session):
    """Pre-fix: principal_trust had the same indexed-column issue.
    Index((tenant_id, principal_kind, trust_score)) made the 2nd
    call raise 'Duplicate key' on update."""
    from kya import record_principal_signal
    score = record_principal_signal(
        duckdb_session, tenant_id=TENANT, principal_kind="user",
        principal_id="alice", signal_kind="clean_invocation")
    assert score == 51


def test_record_principal_signal_second_update(duckdb_session):
    """Same flow as the user-trust 2nd-update test, but for the
    principal table. Was the canary for the related bug."""
    from kya import record_principal_signal
    record_principal_signal(
        duckdb_session, tenant_id=TENANT, principal_kind="user",
        principal_id="alice", signal_kind="clean_invocation")
    score = record_principal_signal(
        duckdb_session, tenant_id=TENANT, principal_kind="user",
        principal_id="alice", signal_kind="clean_invocation")
    assert score == 52

    rows = duckdb_session.execute(text(
        "SELECT COUNT(*) FROM kya_principal_trust "
        "WHERE principal_id='alice'"
    )).scalar()
    assert rows == 1


def test_record_principal_signal_different_kinds_isolated(duckdb_session):
    """Same principal_id with different principal_kind should
    produce separate rows."""
    from kya import record_principal_signal
    record_principal_signal(
        duckdb_session, tenant_id=TENANT, principal_kind="user",
        principal_id="bob", signal_kind="clean_invocation")
    record_principal_signal(
        duckdb_session, tenant_id=TENANT, principal_kind="agent",
        principal_id="bob", signal_kind="clean_invocation")
    rows = duckdb_session.execute(text(
        "SELECT COUNT(*) FROM kya_principal_trust "
        "WHERE principal_id='bob'"
    )).scalar()
    assert rows == 2
