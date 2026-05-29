"""Unit tests for cross-agent / delegation-graph-aware correlation.

What this validates
-------------------
- ``process_evidence(correlation_id=...)`` exposes correlation_id as a
  first-class context field so rules can use it in ``correlate_by``.
- A chain whose ``correlate_by`` is ``[tenant_id, correlation_id]``
  advances across DIFFERENT principals as long as they share the
  correlation_id -- the actual definition of "cross-agent" detection.
- Different correlation_ids on the same principal stay isolated --
  chains don't bleed across requests.
- Footgun guard: when a rule needs a field that's missing/empty,
  the rule is SKIPPED for that event (not bucketed into a shared
  empty-string state slot).
- ``correlation_id_for_invocation(db, ...)`` walks the parent chain
  to recover correlation_id when a sub-agent forgot to propagate it.
- Backward compatibility: rules using the existing
  ``[tenant_id, principal_id]`` convention still work unchanged.

Backend: SQLite in-memory via init_storage + the prov_schema
translate-map -- exercises the same code paths the live PG test
covers on real Postgres.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import kya
from kya.attack_chains import (
    AttackChainEngine,
    InMemoryStateStore,
    correlation_id_for_invocation,
    load_rule,
)

TENANT = "11111111-2222-3333-4444-crossagent42"


# ── Helpers / fixtures ────────────────────────────────────────────


def _make_cross_agent_rule():
    return load_rule(
        {
            "version": 1,
            "id": "cross_agent_exfil",
            "severity": "high",
            "emits_signal": "rogue_cross_agent_exfil",
            "correlate_by": ["tenant_id", "correlation_id"],
            "steps": [
                {"id": "recon", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "file_read"}},
                {"id": "exfil", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "http_post"},
                 "after": "recon", "within_seconds": 300},
            ],
        },
        source_label="<test>",
    )


def _make_per_principal_rule():
    """Original per-principal correlate_by, for backward-compat."""
    return load_rule(
        {
            "version": 1,
            "id": "per_principal_exfil",
            "severity": "high",
            "emits_signal": "rogue_per_principal_exfil",
            "correlate_by": ["tenant_id", "principal_id"],
            "steps": [
                {"id": "recon", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "file_read"}},
                {"id": "exfil", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "http_post"},
                 "after": "recon", "within_seconds": 300},
            ],
        },
        source_label="<test>",
    )


def _engine(rule):
    fired: list[tuple[str, str]] = []

    def emitter(_db, _t, _p, signal_kind, _eid, r):
        fired.append((r.id, signal_kind))

    eng = AttackChainEngine(
        rules=[rule],
        state_store=InMemoryStateStore(),
        signal_emitter=emitter,
    )
    return eng, fired


@pytest.fixture
def sqlite_db():
    """SQLite in-memory session for the helper test (needs real
    kya_invocations table)."""
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None})
    session = sessionmaker(bind=eng)()
    kya.init_storage(session)
    yield session
    session.close()
    eng.dispose()


# ══════════════════════════════════════════════════════════════════
# THE defining cross-agent test
# ══════════════════════════════════════════════════════════════════


def test_chain_advances_across_principals_sharing_correlation_id():
    """Two different agents that share a correlation_id MUST advance
    the same chain. This is the entire point of cross-agent
    correlation -- the runtime claim KYA's paper makes about
    delegated agent graphs becomes literally true here."""
    engine, fired = _engine(_make_cross_agent_rule())

    # Agent A does step 1 of the chain.
    m1 = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/etc/secrets"},
        evidence_id=1, occurred_at_ts=100.0,
        correlation_id="req-corr-1",
    )
    assert m1 == [], "step 1 must advance, not fire"
    assert fired == []

    # Agent B (different principal) does step 2 of the SAME chain.
    m2 = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_b",  # different agent
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        evidence_id=2, occurred_at_ts=110.0,
        correlation_id="req-corr-1",  # same correlation_id
    )

    assert m2 == ["cross_agent_exfil"]
    assert fired == [("cross_agent_exfil", "rogue_cross_agent_exfil")]


def test_chain_does_not_advance_across_different_correlation_ids():
    """The inverse property: events with DIFFERENT correlation_ids
    must NOT bucket together, even on the same principal."""
    engine, fired = _engine(_make_cross_agent_rule())

    engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "file_read"},
        occurred_at_ts=100.0, correlation_id="req-A",
    )
    m2 = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        occurred_at_ts=110.0, correlation_id="req-B",  # DIFFERENT
    )

    assert m2 == [], "two separate requests must not complete one chain"
    assert fired == []


# ══════════════════════════════════════════════════════════════════
# Footgun guard
# ══════════════════════════════════════════════════════════════════


def test_rule_with_missing_correlate_field_is_skipped_not_bucketed():
    """If a rule's correlate_by references a field that's None/empty,
    the rule MUST be skipped for that event. Otherwise every event
    without a correlation_id would land in the same empty-string
    state slot and chains would silently complete on unrelated
    events."""
    engine, fired = _engine(_make_cross_agent_rule())

    # No correlation_id passed -- this rule needs it.
    engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "file_read"},
        occurred_at_ts=100.0,
        # correlation_id intentionally omitted
    )
    m2 = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_b",
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        occurred_at_ts=110.0,
        # correlation_id intentionally omitted
    )

    assert m2 == [], "rule with missing correlate field MUST skip"
    assert fired == []


def test_empty_string_correlation_id_is_also_skipped():
    """Defensive: an explicit empty string is treated like None."""
    engine, fired = _engine(_make_cross_agent_rule())
    engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "file_read"},
        occurred_at_ts=100.0, correlation_id="",
    )
    m2 = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_b",
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        occurred_at_ts=110.0, correlation_id="",
    )
    assert m2 == []
    assert fired == []


# ══════════════════════════════════════════════════════════════════
# Backward compatibility -- the existing per-principal pattern works
# ══════════════════════════════════════════════════════════════════


def test_per_principal_rule_still_works_unchanged():
    """The existing convention -- chains scoped to one principal --
    keeps working identically. This is the regression guard for the
    backward-compatibility promise."""
    engine, fired = _engine(_make_per_principal_rule())

    engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "file_read"},
        occurred_at_ts=100.0,
        # No correlation_id needed for per-principal rules.
    )
    m2 = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        occurred_at_ts=110.0,
    )
    assert m2 == ["per_principal_exfil"]
    assert fired == [("per_principal_exfil", "rogue_per_principal_exfil")]


def test_per_principal_rule_isolated_by_principal():
    """Per-principal rules must NOT advance across principals --
    confirms the existing isolation semantic is preserved."""
    engine, fired = _engine(_make_per_principal_rule())

    engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "file_read"},
        occurred_at_ts=100.0,
    )
    m2 = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_b",
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        occurred_at_ts=110.0,
    )
    assert m2 == [], "different principals must not complete a per-principal chain"
    assert fired == []


# ══════════════════════════════════════════════════════════════════
# correlation_id_for_invocation helper
# ══════════════════════════════════════════════════════════════════


def test_helper_returns_invocations_own_correlation_id(sqlite_db):
    """The common case: the invocation row has its own correlation_id."""
    now = datetime.now(timezone.utc)
    inv_id = kya.record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="a1",
        principal_kind="agent", principal_id="a1",
        mode="observed", outcome="success",
        correlation_id="corr-direct",
        started_at=now,
    )
    sqlite_db.commit()
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, inv_id) == "corr-direct"


def test_helper_walks_parent_chain_when_child_missing_correlation_id(sqlite_db):
    """Recovery from a sub-agent that forgot to propagate
    correlation_id: walk parent_invocation_id until we find one."""
    now = datetime.now(timezone.utc)
    parent_id = kya.record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="parent",
        principal_kind="agent", principal_id="parent",
        mode="observed", outcome="success",
        correlation_id="corr-parent",
        started_at=now,
    )
    # Child sets parent_invocation_id but NOT correlation_id.
    child_id = kya.record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="child",
        principal_kind="agent", principal_id="child",
        mode="observed", outcome="success",
        parent_invocation_id=parent_id,
        started_at=now,
    )
    sqlite_db.commit()
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, child_id) == "corr-parent"


def test_helper_returns_none_when_no_ancestor_has_correlation_id(sqlite_db):
    """No correlation_id anywhere in the chain -> None (engine treats
    that as 'cannot correlate, skip the rule')."""
    now = datetime.now(timezone.utc)
    parent_id = kya.record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="p",
        principal_kind="agent", principal_id="p",
        mode="observed", outcome="success", started_at=now,
        # no correlation_id
    )
    child_id = kya.record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="c",
        principal_kind="agent", principal_id="c",
        mode="observed", outcome="success", started_at=now,
        parent_invocation_id=parent_id,
        # no correlation_id
    )
    sqlite_db.commit()
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, child_id) is None


def test_helper_does_not_cross_tenant_boundary(sqlite_db):
    """A parent_invocation_id pointing at a row in a DIFFERENT tenant
    must NOT leak that tenant's correlation_id. The walk is
    tenant-scoped."""
    now = datetime.now(timezone.utc)
    # Seed an invocation in tenant T2.
    other_tenant = "22222222-3333-4444-5555-crossagent43"
    other_inv = kya.record_invocation(
        sqlite_db, tenant_id=other_tenant, agent_key="a",
        principal_kind="agent", principal_id="a",
        mode="observed", outcome="success",
        correlation_id="leaked-corr",
        started_at=now,
    )
    # Invocation in TENANT with parent_invocation_id pointing at the
    # other tenant's row (this would be malformed data, but we must
    # defend against it).
    inv_id = kya.record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="b",
        principal_kind="agent", principal_id="b",
        mode="observed", outcome="success",
        parent_invocation_id=other_inv,
        started_at=now,
    )
    sqlite_db.commit()
    # The walk is scoped to TENANT, so the cross-tenant parent is not
    # readable and we return None instead of "leaked-corr".
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, inv_id) is None


def test_helper_returns_none_on_invalid_input_without_raising(sqlite_db):
    """The helper is fail-soft. None / empty / non-numeric inputs MUST
    return None rather than crash callers (record_evidence sometimes
    gets passed an invocation row whose id column is null)."""
    # invocation_id = None
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, None) is None
    # invocation_id non-numeric
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, "not-a-number") is None
    # invocation_id zero or negative
    assert correlation_id_for_invocation(sqlite_db, TENANT, 0) is None
    assert correlation_id_for_invocation(sqlite_db, TENANT, -1) is None
    # empty tenant
    assert correlation_id_for_invocation(sqlite_db, "", 1) is None
    assert correlation_id_for_invocation(sqlite_db, None, 1) is None
    # max_hops invalid
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, 1, max_hops=0) is None
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, 1, max_hops=-3) is None


def test_helper_caps_walk_at_max_hops(sqlite_db):
    """Pathological loop / very-deep chain protection."""
    now = datetime.now(timezone.utc)
    # Build a depth-5 chain with NO correlation_id anywhere.
    parent = None
    leaf = None
    for _i in range(5):
        leaf = kya.record_invocation(
            sqlite_db, tenant_id=TENANT, agent_key="x",
            principal_kind="agent", principal_id="x",
            mode="observed", outcome="success",
            parent_invocation_id=parent, started_at=now,
        )
        parent = leaf
    sqlite_db.commit()
    # max_hops=2 is too shallow to traverse the 5-deep chain -- and
    # there's no correlation_id anyway -> None.
    assert correlation_id_for_invocation(
        sqlite_db, TENANT, leaf, max_hops=2) is None


# ══════════════════════════════════════════════════════════════════
# End-to-end: helper + engine wired together
# ══════════════════════════════════════════════════════════════════


def test_helper_plus_engine_full_loop_via_real_invocations(sqlite_db):
    """The integration KYA's downstream caller actually performs:
       1. Record a parent invocation (sets correlation_id).
       2. Record a child invocation under a different principal.
       3. Resolve correlation_id for each via the helper.
       4. Feed both into engine.process_evidence(correlation_id=...).
       5. Chain advances ACROSS the two agents and fires.
    """
    now = datetime.now(timezone.utc)
    parent_inv = kya.record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="agent_a",
        principal_kind="agent", principal_id="agent_a",
        mode="observed", outcome="success",
        correlation_id="loop-corr-1", started_at=now,
    )
    child_inv = kya.record_invocation(
        sqlite_db, tenant_id=TENANT, agent_key="agent_b",
        principal_kind="agent", principal_id="agent_b",
        mode="observed", outcome="success",
        parent_invocation_id=parent_inv, started_at=now,
        # child did NOT set correlation_id -- helper must recover it.
    )
    sqlite_db.commit()

    parent_corr = correlation_id_for_invocation(
        sqlite_db, TENANT, parent_inv)
    child_corr = correlation_id_for_invocation(
        sqlite_db, TENANT, child_inv)
    assert parent_corr == "loop-corr-1"
    assert child_corr == "loop-corr-1"  # recovered via parent walk

    engine, fired = _engine(_make_cross_agent_rule())
    engine.process_evidence(
        sqlite_db, tenant_id=TENANT, principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "file_read"},
        occurred_at_ts=100.0, correlation_id=parent_corr,
    )
    m2 = engine.process_evidence(
        sqlite_db, tenant_id=TENANT, principal_id="agent_b",
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        occurred_at_ts=110.0, correlation_id=child_corr,
    )
    assert m2 == ["cross_agent_exfil"]
    assert fired == [
        ("cross_agent_exfil", "rogue_cross_agent_exfil"),
    ]
