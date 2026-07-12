"""Tests for ``kya.pending_invocations`` — HITL persistence layer (#101).

Covers the full lifecycle: create → decide → find_ready_to_resume →
mark_resumed, plus expiry sweep, race conditions, replay-versioning,
list ordering, and edge cases (missing rows, double-decide, expired
approve).

Uses SQLite fixtures — the module's SQL is dialect-portable by design
(BLOB / TEXT / TIMESTAMP WITH TIME ZONE), so SQLite coverage exercises
the same code path as Postgres would.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text as _sql
from sqlalchemy.exc import OperationalError

from kya.pending_invocations import (
    DEFAULT_TTL_HOURS,
    PendingInvocation,
    VALID_STATUSES,
    _ENSURED_ENGINES,
    create_pending,
    decide,
    ensure_table,
    find_ready_to_resume,
    get_by_id,
    hash_policy_config,
    list_by_tenant,
    mark_resumed,
    sweep_expired,
)


NOW = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)


# ── Multi-dialect fixture ────────────────────────────────────────────
# Paper claims portability across PostgreSQL / SQLite / DuckDB / MySQL
# (main.pdf §3, "cross-backend portability"). Every persistence test
# runs against every dialect that is reachable in the current
# environment. SQLite is always available; DuckDB requires only
# ``duckdb-engine`` on PyPI; Postgres + MySQL need a running container
# whose URL is discovered from env.
#
# Discovery is defensive: probe each URL with a trivial connect, skip
# on failure so ``pytest`` on a laptop without docker still runs the
# SQLite + DuckDB rows.


_DIALECTS: list[tuple[str, str]] = [("sqlite", "sqlite:///:memory:")]

try:
    import duckdb_engine  # noqa: F401
    _DIALECTS.append(("duckdb", "duckdb:///:memory:"))
except ImportError:
    pass

_PG_URL = os.environ.get(
    "KYA_TEST_POSTGRES_URL",
    "postgresql+psycopg2://veldt:veldt_kya_2026@localhost:15432/veldt_kya_pending_test",
)
try:
    _pg_probe = create_engine(_PG_URL)
    with _pg_probe.connect() as _c:
        _c.execute(_sql("SELECT 1"))
    _DIALECTS.append(("postgresql", _PG_URL))
except (OperationalError, Exception):
    pass

_MYSQL_URL = os.environ.get("KYA_TEST_MYSQL_URL", "")
if _MYSQL_URL:
    try:
        _my_probe = create_engine(_MYSQL_URL)
        with _my_probe.connect() as _c:
            _c.execute(_sql("SELECT 1"))
        _DIALECTS.append(("mysql", _MYSQL_URL))
    except (OperationalError, Exception):
        pass


def _dialect_ids() -> list[str]:
    return [d[0] for d in _DIALECTS]


@pytest.fixture(params=_DIALECTS, ids=_dialect_ids())
def engine(request, tmp_path):
    """Fresh per-test engine on every reachable dialect.

    Tests parametrized on this fixture run once per dialect. For
    file-backed dialects (SQLite / DuckDB) we use ``:memory:`` so
    cleanup is automatic. For Postgres / MySQL we drop + recreate
    the table each test — same isolation cost as tmp_path for SQLite.
    """
    label, url = request.param
    if label in ("sqlite", "duckdb"):
        # Fresh in-memory engine per test. Python's id() is reused
        # after GC, so a previous test's engine object can share the
        # same id() as the new one — the ensure_table sentinel would
        # then skip DDL and the test finds no table. Clear the
        # sentinel unconditionally.
        eng = create_engine(url)
        _ENSURED_ENGINES.clear()
    else:
        # Real DB: drop the table then recreate so state is fresh.
        eng = create_engine(url)
        with eng.begin() as conn:
            conn.execute(_sql("DROP TABLE IF EXISTS kya_pending_invocations"))
        _ENSURED_ENGINES.clear()
    ensure_table(eng)
    yield eng
    if label not in ("sqlite", "duckdb"):
        with eng.begin() as conn:
            conn.execute(_sql("DROP TABLE IF EXISTS kya_pending_invocations"))
    _ENSURED_ENGINES.clear()


def _create(
    engine,
    *,
    tenant_id: str = "tenant-1",
    agent_key: str = "agent.x",
    principal_kind: str = "agent",
    principal_id: str = "agent-x-01",
    action: str = "mcp.filesystem.read",
    original_invocation_id: int | None = 1001,
    request_body_ciphertext: bytes = b"enc:hello",
    request_headers: dict[str, str] | None = None,
    policy_config_hash: str | None = None,
    now: datetime | None = None,
    ttl: timedelta | None = None,
) -> str:
    """Test helper — same defaults across tests so each test is compact."""
    return create_pending(
        engine,
        tenant_id=tenant_id,
        agent_key=agent_key,
        principal_kind=principal_kind,
        principal_id=principal_id,
        action=action,
        original_invocation_id=original_invocation_id,
        request_body_ciphertext=request_body_ciphertext,
        request_headers=request_headers or {"authorization": "Bearer x"},
        policy_config_hash=policy_config_hash or hash_policy_config({"v": 1}),
        now=now,
        ttl=ttl,
    )


# ═════════════════════════════════════════════════════════════════════
# ensure_table
# ═════════════════════════════════════════════════════════════════════


def test_ensure_table_is_idempotent(tmp_path):
    """Ops calls ensure_table() on every gateway boot; must be safe
    under repeat boots + engine reuse."""
    url = f"sqlite:///{tmp_path}/idem.db"
    eng = create_engine(url)
    ensure_table(eng)
    ensure_table(eng)  # must not raise
    ensure_table(eng)


def test_ensure_table_creates_expected_indexes(engine):
    """The sweeper's status+expires scan and the approver-UI's
    tenant+status list depend on the two indexes we ship.

    DuckDB's SQLAlchemy inspector does not enumerate user indexes
    (driver limitation, verified via ``duckdb-engine`` docs), so we
    skip this reflection-based check there. The indexes ARE created;
    we just cannot introspect them via SQLAlchemy on DuckDB."""
    if engine.dialect.name == "duckdb":
        pytest.skip("duckdb SQLAlchemy inspector does not enumerate indexes")
    from sqlalchemy import inspect
    indexes = {i["name"] for i in inspect(engine).get_indexes(
        "kya_pending_invocations"
    )}
    assert "ix_kya_pending_invocations_status_expires" in indexes
    assert "ix_kya_pending_invocations_tenant_status" in indexes


# ═════════════════════════════════════════════════════════════════════
# hash_policy_config — M5 replay pinning
# ═════════════════════════════════════════════════════════════════════


def test_policy_hash_is_deterministic():
    """Same config → same hash. Foundational to replay pinning."""
    a = hash_policy_config({"rbac": {"rules": []}, "min_trust": 5})
    b = hash_policy_config({"rbac": {"rules": []}, "min_trust": 5})
    assert a == b


def test_policy_hash_is_key_order_invariant():
    """Dict key order shouldn't affect the hash — canonical JSON."""
    a = hash_policy_config({"a": 1, "b": 2})
    b = hash_policy_config({"b": 2, "a": 1})
    assert a == b


def test_policy_hash_changes_on_content_change():
    """Any meaningful policy change must yield a different hash so
    the resume endpoint can detect drift."""
    a = hash_policy_config({"rbac": {"rules": ["allow"]}})
    b = hash_policy_config({"rbac": {"rules": ["deny"]}})
    assert a != b


def test_policy_hash_handles_non_json_serializable_input(caplog):
    """Ops sees a WARNING when the fallback repr() path fires — the
    hash still returns something usable for a single-process replay
    window but isn't cross-process stable."""
    import logging
    class NotSerializable:
        pass
    with caplog.at_level(logging.WARNING, logger="kya.pending_invocations"):
        result = hash_policy_config({"unserializable": NotSerializable()})
    assert isinstance(result, str)
    assert len(result) == 64  # sha256 hex


# ═════════════════════════════════════════════════════════════════════
# create_pending
# ═════════════════════════════════════════════════════════════════════


def test_create_returns_uuid(engine):
    pid = _create(engine, now=NOW)
    # Not just any string — must parse as a UUID.
    uuid.UUID(pid)


def test_create_writes_all_fields(engine):
    pid = _create(
        engine,
        tenant_id="tenant-42",
        agent_key="agent.filesystem",
        principal_kind="user",
        principal_id="alice",
        action="mcp.filesystem.write",
        original_invocation_id=9999,
        request_body_ciphertext=b"enc:secret",
        request_headers={"x-req-id": "abc"},
        policy_config_hash=hash_policy_config({"v": 2}),
        now=NOW,
    )
    row = get_by_id(engine, pid)
    assert row is not None
    assert row.tenant_id == "tenant-42"
    assert row.agent_key == "agent.filesystem"
    assert row.principal_kind == "user"
    assert row.principal_id == "alice"
    assert row.action == "mcp.filesystem.write"
    assert row.original_invocation_id == 9999
    assert row.request_body_ciphertext == b"enc:secret"
    assert row.request_headers == {"x-req-id": "abc"}
    assert row.status == "pending"
    assert row.decided_at is None
    assert row.decided_by is None
    assert row.resume_result_evidence_id is None


def test_create_defaults_expiry_to_24h(engine):
    pid = _create(engine, now=NOW)
    row = get_by_id(engine, pid)
    delta = row.expires_at - row.submitted_at
    # Allow a couple seconds of jitter from clock granularity.
    assert timedelta(hours=DEFAULT_TTL_HOURS) - timedelta(seconds=2) <= delta <= timedelta(hours=DEFAULT_TTL_HOURS) + timedelta(seconds=2)


def test_create_accepts_custom_ttl(engine):
    pid = _create(engine, now=NOW, ttl=timedelta(hours=2))
    row = get_by_id(engine, pid)
    assert (row.expires_at - row.submitted_at) == timedelta(hours=2)


def test_create_each_call_gets_unique_id(engine):
    ids = {_create(engine, now=NOW) for _ in range(50)}
    assert len(ids) == 50


def test_create_persists_binary_body_verbatim(engine):
    """Bodies are opaque ciphertext — every byte must round-trip."""
    body = bytes(range(256))
    pid = _create(engine, now=NOW, request_body_ciphertext=body)
    row = get_by_id(engine, pid)
    assert row.request_body_ciphertext == body


# ═════════════════════════════════════════════════════════════════════
# get_by_id
# ═════════════════════════════════════════════════════════════════════


def test_get_by_id_returns_none_for_missing(engine):
    assert get_by_id(engine, str(uuid.uuid4())) is None


def test_get_by_id_returns_immutable_view(engine):
    pid = _create(engine, now=NOW)
    row = get_by_id(engine, pid)
    assert isinstance(row, PendingInvocation)
    # frozen dataclass — attribute assignment must raise.
    with pytest.raises((AttributeError, TypeError, Exception)):
        row.status = "hijacked"  # type: ignore[misc]


# ═════════════════════════════════════════════════════════════════════
# decide
# ═════════════════════════════════════════════════════════════════════


def test_decide_approves_pending(engine):
    pid = _create(engine, now=NOW)
    won = decide(engine, pending_id=pid, decision="approved",
                 decided_by="admin-1", now=NOW + timedelta(hours=1))
    assert won is True
    row = get_by_id(engine, pid)
    assert row.status == "approved"
    assert row.decided_by == "admin-1"
    assert row.decided_at is not None


def test_decide_denies_pending(engine):
    pid = _create(engine, now=NOW)
    won = decide(engine, pending_id=pid, decision="denied",
                 decided_by="admin-1", now=NOW + timedelta(hours=1))
    assert won is True
    assert get_by_id(engine, pid).status == "denied"


def test_decide_rejects_invalid_decision(engine):
    pid = _create(engine, now=NOW)
    with pytest.raises(ValueError):
        decide(engine, pending_id=pid, decision="cool",  # type: ignore[arg-type]
               decided_by="admin-1", now=NOW)


def test_decide_double_call_only_first_wins(engine):
    """Two admins race to approve — the row-level WHERE clause ensures
    exactly one wins. Second call sees rowcount 0."""
    pid = _create(engine, now=NOW)
    first = decide(engine, pending_id=pid, decision="approved",
                   decided_by="admin-1", now=NOW + timedelta(hours=1))
    second = decide(engine, pending_id=pid, decision="denied",
                    decided_by="admin-2", now=NOW + timedelta(hours=1))
    assert first is True
    assert second is False
    # First writer's decision stands.
    assert get_by_id(engine, pid).status == "approved"
    assert get_by_id(engine, pid).decided_by == "admin-1"


def test_decide_rejects_expired_row(engine):
    """A decision arriving after expiry MUST NOT revive the row.
    Belt-and-braces alongside the sweeper — race between sweep and
    decide is safe."""
    pid = _create(engine, now=NOW, ttl=timedelta(hours=1))
    late = NOW + timedelta(hours=2)
    won = decide(engine, pending_id=pid, decision="approved",
                 decided_by="admin-late", now=late)
    assert won is False
    assert get_by_id(engine, pid).status == "pending"


def test_decide_rejects_missing_row(engine):
    won = decide(engine, pending_id=str(uuid.uuid4()),
                 decision="approved", decided_by="admin-1", now=NOW)
    assert won is False


# ═════════════════════════════════════════════════════════════════════
# find_ready_to_resume — the CRITICAL gate before replay
# ═════════════════════════════════════════════════════════════════════


def test_find_ready_returns_approved_not_expired_row(engine):
    pid = _create(engine, now=NOW)
    decide(engine, pending_id=pid, decision="approved",
           decided_by="admin-1", now=NOW + timedelta(minutes=5))
    ready = find_ready_to_resume(engine, pid, now=NOW + timedelta(minutes=10))
    assert ready is not None
    assert ready.id == pid


def test_find_ready_returns_none_when_pending(engine):
    """A pending row is not ready — must wait for approval."""
    pid = _create(engine, now=NOW)
    assert find_ready_to_resume(engine, pid, now=NOW) is None


def test_find_ready_returns_none_when_denied(engine):
    pid = _create(engine, now=NOW)
    decide(engine, pending_id=pid, decision="denied",
           decided_by="admin-1", now=NOW + timedelta(minutes=1))
    assert find_ready_to_resume(engine, pid, now=NOW + timedelta(minutes=5)) is None


def test_find_ready_returns_none_when_expired_after_approve(engine):
    """Approved but expiry has passed — the resume endpoint MUST NOT
    replay a stale approval. Belt with mark_resumed's own guard."""
    pid = _create(engine, now=NOW, ttl=timedelta(hours=1))
    decide(engine, pending_id=pid, decision="approved",
           decided_by="admin-1", now=NOW + timedelta(minutes=30))
    late = NOW + timedelta(hours=2)
    assert find_ready_to_resume(engine, pid, now=late) is None


def test_find_ready_returns_none_when_already_resumed(engine):
    """A row that has been marked resumed cannot be replayed a
    second time — the resume_result_evidence_id gate is authoritative."""
    pid = _create(engine, now=NOW)
    decide(engine, pending_id=pid, decision="approved",
           decided_by="admin-1", now=NOW + timedelta(minutes=1))
    ok = mark_resumed(engine, pending_id=pid, resume_result_evidence_id=42)
    assert ok is True
    assert find_ready_to_resume(engine, pid, now=NOW + timedelta(minutes=5)) is None


def test_find_ready_returns_none_for_missing(engine):
    assert find_ready_to_resume(engine, str(uuid.uuid4()), now=NOW) is None


# ═════════════════════════════════════════════════════════════════════
# mark_resumed — the loop-closing step
# ═════════════════════════════════════════════════════════════════════


def test_mark_resumed_only_flips_approved_rows(engine):
    pid = _create(engine, now=NOW)
    # Not approved yet — mark_resumed must refuse.
    ok = mark_resumed(engine, pending_id=pid, resume_result_evidence_id=1)
    assert ok is False
    assert get_by_id(engine, pid).status == "pending"


def test_mark_resumed_double_call_only_first_wins(engine):
    """Concurrent resume attempts race safely on the WHERE clause;
    only one gets to link the evidence id."""
    pid = _create(engine, now=NOW)
    decide(engine, pending_id=pid, decision="approved",
           decided_by="admin-1", now=NOW + timedelta(minutes=1))
    first = mark_resumed(engine, pending_id=pid, resume_result_evidence_id=100)
    second = mark_resumed(engine, pending_id=pid, resume_result_evidence_id=200)
    assert first is True
    assert second is False
    row = get_by_id(engine, pid)
    assert row.status == "resumed"
    assert row.resume_result_evidence_id == 100


# ═════════════════════════════════════════════════════════════════════
# list_by_tenant
# ═════════════════════════════════════════════════════════════════════


def test_list_by_tenant_returns_only_that_tenant(engine):
    a = _create(engine, tenant_id="tenant-a", now=NOW)
    _create(engine, tenant_id="tenant-a", now=NOW)
    _create(engine, tenant_id="tenant-b", now=NOW)
    rows = list_by_tenant(engine, tenant_id="tenant-a")
    assert {r.id for r in rows} == {a, rows[1].id}
    assert all(r.tenant_id == "tenant-a" for r in rows)


def test_list_by_tenant_orders_earliest_expiry_first(engine):
    """Approver-UI relevance: the row about to expire is the row the
    approver needs to see first."""
    older = _create(engine, tenant_id="t", now=NOW,
                    ttl=timedelta(hours=1))  # expires soon
    newer = _create(engine, tenant_id="t", now=NOW,
                    ttl=timedelta(hours=10))  # expires later
    rows = list_by_tenant(engine, tenant_id="t")
    assert rows[0].id == older
    assert rows[1].id == newer


def test_list_by_tenant_filters_by_status(engine):
    p = _create(engine, tenant_id="t", now=NOW)
    a = _create(engine, tenant_id="t", now=NOW)
    decide(engine, pending_id=a, decision="approved",
           decided_by="admin", now=NOW + timedelta(minutes=1))
    only_pending = list_by_tenant(engine, tenant_id="t", status="pending")
    assert {r.id for r in only_pending} == {p}
    only_approved = list_by_tenant(engine, tenant_id="t", status="approved")
    assert {r.id for r in only_approved} == {a}


def test_list_by_tenant_clamps_limit(engine):
    for _ in range(10):
        _create(engine, tenant_id="t", now=NOW)
    # limit=1 → 1; limit=99999 → all 10 (capped at 500).
    assert len(list_by_tenant(engine, tenant_id="t", limit=1)) == 1
    assert len(list_by_tenant(engine, tenant_id="t", limit=99999)) == 10


# ═════════════════════════════════════════════════════════════════════
# sweep_expired
# ═════════════════════════════════════════════════════════════════════


def test_sweep_flips_expired_pending_rows(engine):
    _create(engine, tenant_id="t", now=NOW, ttl=timedelta(minutes=30))
    _create(engine, tenant_id="t", now=NOW, ttl=timedelta(minutes=30))
    later = NOW + timedelta(hours=1)
    swept = sweep_expired(engine, now=later)
    assert swept == 2
    rows = list_by_tenant(engine, tenant_id="t")
    assert all(r.status == "expired" for r in rows)


def test_sweep_leaves_unexpired_rows(engine):
    _create(engine, tenant_id="t", now=NOW, ttl=timedelta(hours=10))
    swept = sweep_expired(engine, now=NOW + timedelta(minutes=30))
    assert swept == 0
    assert list_by_tenant(engine, tenant_id="t")[0].status == "pending"


def test_sweep_leaves_already_decided_rows(engine):
    """An approved-but-expired row is NOT swept to 'expired' — its
    'approved' state is a durable audit record. find_ready_to_resume
    still refuses to replay it because of the expires_at gate."""
    pid = _create(engine, tenant_id="t", now=NOW, ttl=timedelta(hours=1))
    decide(engine, pending_id=pid, decision="approved",
           decided_by="admin", now=NOW + timedelta(minutes=30))
    later = NOW + timedelta(hours=2)
    swept = sweep_expired(engine, now=later)
    assert swept == 0
    assert get_by_id(engine, pid).status == "approved"


def test_sweep_is_idempotent(engine):
    _create(engine, tenant_id="t", now=NOW, ttl=timedelta(minutes=1))
    later = NOW + timedelta(hours=1)
    first = sweep_expired(engine, now=later)
    second = sweep_expired(engine, now=later)
    assert first == 1
    assert second == 0


def test_sweep_respects_batch_size(engine):
    """A huge backlog processes in bounded chunks so a single cron tick
    can't hold the table lock indefinitely. Follow-up ticks pick up
    the remainder."""
    for _ in range(10):
        _create(engine, tenant_id="t", now=NOW, ttl=timedelta(minutes=1))
    later = NOW + timedelta(hours=1)
    first = sweep_expired(engine, now=later, batch_size=3)
    second = sweep_expired(engine, now=later, batch_size=3)
    third = sweep_expired(engine, now=later, batch_size=100)
    assert first == 3
    assert second == 3
    assert third == 4  # remainder


# ═════════════════════════════════════════════════════════════════════
# Full lifecycle end-to-end
# ═════════════════════════════════════════════════════════════════════


def test_full_hitl_lifecycle(engine):
    """Emission → approve → resume → mark_resumed → find_ready
    now returns None (already resumed)."""
    pid = _create(engine, now=NOW)

    # Approver decides.
    assert decide(engine, pending_id=pid, decision="approved",
                  decided_by="admin-1", now=NOW + timedelta(minutes=1)) is True

    # Resume endpoint queries the ready gate.
    ready = find_ready_to_resume(engine, pid, now=NOW + timedelta(minutes=2))
    assert ready is not None
    assert ready.request_body_ciphertext == b"enc:hello"
    assert ready.policy_config_hash  # M5 replay-pinning present.

    # Simulated replay produces evidence id 555; we link it back.
    assert mark_resumed(engine, pending_id=pid,
                        resume_result_evidence_id=555) is True

    # Row is now closed — a second resume attempt is refused.
    assert find_ready_to_resume(engine, pid, now=NOW + timedelta(minutes=3)) is None
    row = get_by_id(engine, pid)
    assert row.status == "resumed"
    assert row.resume_result_evidence_id == 555


def test_full_denied_lifecycle_never_becomes_resumable(engine):
    """A denied row cannot be resurrected by any subsequent write."""
    pid = _create(engine, now=NOW)
    decide(engine, pending_id=pid, decision="denied",
           decided_by="admin-1", now=NOW + timedelta(minutes=1))
    # Attempt to mark_resumed anyway.
    assert mark_resumed(engine, pending_id=pid,
                        resume_result_evidence_id=555) is False
    row = get_by_id(engine, pid)
    assert row.status == "denied"
    assert row.resume_result_evidence_id is None
