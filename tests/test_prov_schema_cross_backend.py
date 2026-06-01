"""Regression suite for the prov_schema raw-SQL portability fix.

Before this PR, several public-API primitives hardcoded
``prov_schema.kya_*`` in their raw text() SQL. That works on PG with
the prov_schema schema present but breaks on SQLite/DuckDB/MySQL
with ``no such table: prov_schema.kya_*``.

These tests exercise the previously-broken primitives against
SQLite to lock in the cross-backend contract. If anyone reverts
the qual_for_raw_sql() pattern, this file fails fast.

Functions covered:
  - kya.get_user_trust + list_user_trust       (users.py)
  - kya.summarize_request + list_recent_requests + request_score
                                                (requests.py)
  - kya.agent_divergence_score                  (fault_attribution.py)
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kya import (
    agent_divergence_score,
    get_user_trust,
    init_storage,
    list_recent_requests,
    list_user_trust,
    new_correlation_id,
    record_invocation,
    record_user_signal,
    request_score,
    summarize_request,
)

TENANT = "11111111-2222-3333-4444-portable42"


@pytest.fixture
def sqlite_db():
    eng = create_engine("sqlite:///:memory:")
    db = sessionmaker(bind=eng)()
    init_storage(db)
    yield db
    db.close()
    eng.dispose()


# ── kya.users (get_user_trust / list_user_trust) ──────────────────


def test_get_user_trust_works_on_sqlite(sqlite_db):
    """Regression: get_user_trust hardcoded prov_schema.kya_user_trust
    which broke on SQLite. Verify it now resolves via
    qual_for_raw_sql()."""
    record_user_signal(sqlite_db, tenant_id=TENANT, user_id="alice",
                       signal_kind="clean_invocation")
    t = get_user_trust(sqlite_db, TENANT, "alice")
    assert t.user_id == "alice"
    assert t.trust_score >= 50  # baseline + clean


def test_get_user_trust_returns_default_for_unknown_user(sqlite_db):
    """Unknown user => fresh-default UserTrust at STARTING_TRUST."""
    from kya.users import STARTING_TRUST
    t = get_user_trust(sqlite_db, TENANT, "never_seen")
    assert t.trust_score == STARTING_TRUST
    assert t.user_id == "never_seen"


def test_list_user_trust_works_on_sqlite(sqlite_db):
    """Regression: list_user_trust hardcoded prov_schema in SELECT.
    Verify it returns tenant-scoped rows sorted by lowest trust."""
    # Seed two users with different trust levels
    record_user_signal(sqlite_db, tenant_id=TENANT, user_id="happy",
                       signal_kind="clean_invocation")
    record_user_signal(sqlite_db, tenant_id=TENANT, user_id="rogue",
                       signal_kind="cross_tenant")  # -15
    rows = list_user_trust(sqlite_db, TENANT, limit=10)
    assert len(rows) == 2
    # Sorted ascending by trust_score (lowest first -- most risky)
    assert rows[0]["trust_score"] < rows[1]["trust_score"]
    assert rows[0]["user_id"] == "rogue"


def test_list_user_trust_tenant_isolation(sqlite_db):
    """Tenant scoping verified: other-tenant rows not returned."""
    TENANT_B = "22222222-3333-4444-5555-portable43"
    record_user_signal(sqlite_db, tenant_id=TENANT, user_id="alice",
                       signal_kind="clean_invocation")
    record_user_signal(sqlite_db, tenant_id=TENANT_B, user_id="bob",
                       signal_kind="clean_invocation")
    rows_a = list_user_trust(sqlite_db, TENANT, limit=10)
    rows_b = list_user_trust(sqlite_db, TENANT_B, limit=10)
    assert all(r["user_id"] == "alice" for r in rows_a)
    assert all(r["user_id"] == "bob" for r in rows_b)


# ── kya.requests (summarize_request / list_recent_requests) ──────


def test_summarize_request_works_on_sqlite(sqlite_db):
    """Regression: summarize_request hardcoded prov_schema + had
    PG-only ``(:cid)::uuid`` cast. Verify it works on SQLite now."""
    corr = new_correlation_id()
    inv = record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="a1",
        principal_kind="agent", principal_id="a1",
        mode="observed", outcome="success",
        correlation_id=corr)
    sqlite_db.commit()
    summary = summarize_request(
        sqlite_db, tenant_id=TENANT, correlation_id=corr)
    assert summary.total_invocations == 1
    assert summary.correlation_id == corr


def test_summarize_request_empty_on_unknown_correlation(sqlite_db):
    """Unknown correlation_id => empty RequestSummary, not an
    exception (the schema-prefix bug used to throw on SQLite)."""
    summary = summarize_request(
        sqlite_db, tenant_id=TENANT,
        correlation_id=new_correlation_id())
    assert summary.total_invocations == 0


def test_list_recent_requests_works_on_sqlite(sqlite_db):
    """Regression: list_recent_requests hardcoded prov_schema."""
    from datetime import datetime, timedelta, timezone
    corr = new_correlation_id()
    now = datetime.now(timezone.utc)
    # started_at is optional but the query filters on it -- pass
    # explicitly so the row matches the window predicate.
    record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="a1",
        principal_kind="agent", principal_id="a1",
        mode="observed", outcome="success",
        correlation_id=corr, started_at=now)
    sqlite_db.commit()
    out = list_recent_requests(
        sqlite_db, tenant_id=TENANT,
        since=now - timedelta(hours=1),
        limit=10)
    assert len(out) >= 1
    # Returns dicts with correlation_id keys
    assert any(str(r.get("correlation_id")) == corr for r in out)


def test_request_score_works_on_sqlite(sqlite_db):
    """request_score wraps summarize_request -- regression check
    that the upstream schema fix propagated."""
    corr = new_correlation_id()
    record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="a1",
        principal_kind="agent", principal_id="a1",
        mode="observed", outcome="success",
        correlation_id=corr)
    sqlite_db.commit()
    summary = summarize_request(
        sqlite_db, tenant_id=TENANT, correlation_id=corr)
    score = request_score(summary)
    # request_score returns an int (the rolled-up risk score)
    assert score is not None
    assert isinstance(score, int)


# ── kya.fault_attribution (agent_divergence_score) ────────────────


def test_agent_divergence_score_works_on_sqlite(sqlite_db):
    """Regression: agent_divergence_score had hardcoded
    prov_schema + PG-only ``FILTER (WHERE ...)`` + ``now() -
    interval``. Verify the non-PG branch produces a real report
    instead of insufficient_data fallback."""
    from datetime import datetime, timezone
    # Seed >=10 invocations (the classification threshold) with
    # mixed outcomes. started_at is OPTIONAL on kya_invocations
    # and must be passed explicitly for the divergence query's
    # window filter to match.
    now = datetime.now(timezone.utc)
    outcomes = ["success", "success", "success", "success",
                "success", "success", "refused", "refused",
                "blocked", "error", "error"]
    for outcome in outcomes:
        record_invocation(
            sqlite_db, tenant_id=TENANT, agent_key="divergent_agent",
            principal_kind="agent", principal_id="divergent_agent",
            mode="observed", outcome=outcome,
            started_at=now)
    sqlite_db.commit()

    report = agent_divergence_score(
        sqlite_db, tenant_id=TENANT, agent_key="divergent_agent",
        window_days=30)
    # Before this fix: the PG FILTER + ::interval syntax errored
    # on SQLite → fell into the try/except → returned
    # classification='insufficient_data' with interpretation
    # 'DB error or table not yet populated.' After fix: actual
    # counts populated.
    assert report.total_invocations == len(outcomes)
    assert report.refused_count == 2
    assert report.blocked_count == 1
    assert report.error_count == 2
    # Got real numbers, not the DB-error fallback message
    assert "DB error" not in (report.interpretation or "")


def test_agent_divergence_score_empty_when_no_invocations(sqlite_db):
    """No invocations for the agent => report with zero counts."""
    report = agent_divergence_score(
        sqlite_db, tenant_id=TENANT, agent_key="never_invoked",
        window_days=30)
    assert report.total_invocations == 0
