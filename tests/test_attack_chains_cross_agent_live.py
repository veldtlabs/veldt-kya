"""Live PG tests for cross-agent / delegation-graph correlation.

Gated on ``KYA_PG_URL`` -- when unset every test is SKIPPED so CI
without infrastructure stays green. When set, this file proves the
engine + helper work against real Postgres semantics (UUID
correlation_id columns, real ``parent_invocation_id`` BIGINT walks,
real prov_schema qualifier on the raw text() SQL inside the helper).

Run locally:

    KYA_PG_URL=postgresql+psycopg2://test:kya@localhost:15433/kyatest \
        python -m pytest tests/test_attack_chains_cross_agent_live.py -v
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import kya
from kya.attack_chains import (
    AttackChainEngine,
    InMemoryStateStore,
    correlation_id_for_invocation,
    load_rule,
)

_URL = os.environ.get("KYA_PG_URL", "").strip()
pytestmark = pytest.mark.skipif(
    not _URL,
    reason="KYA_PG_URL not set -- live PG cross-agent tests skipped",
)


@pytest.fixture
def pg_db():
    eng = create_engine(_URL)
    with eng.connect() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        conn.commit()
    session = sessionmaker(bind=eng)()
    kya.init_storage(session)
    yield session
    session.close()
    eng.dispose()


def _tenant() -> str:
    return str(uuid.uuid4())


def _cross_agent_rule():
    return load_rule(
        {
            "version": 1,
            "id": "cross_agent_pg",
            "severity": "high",
            "emits_signal": "rogue_cross_agent_pg",
            "correlate_by": ["tenant_id", "correlation_id"],
            "steps": [
                {"id": "recon", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "file_read"}},
                {"id": "exfil", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "http_post"},
                 "after": "recon", "within_seconds": 300},
            ],
        },
        source_label="<live-pg>",
    )


def _engine(rule):
    fired = []

    def emitter(_db, _t, _p, signal_kind, _eid, r):
        fired.append((r.id, signal_kind))

    return AttackChainEngine(
        rules=[rule],
        state_store=InMemoryStateStore(),
        signal_emitter=emitter,
    ), fired


# ══════════════════════════════════════════════════════════════════
# Helper resolves correlation_id from a REAL PG parent chain
# ══════════════════════════════════════════════════════════════════


def test_pg_helper_walks_real_parent_chain(pg_db):
    tenant = _tenant()
    now = datetime.now(timezone.utc)
    parent = kya.record_invocation(
        pg_db, tenant_id=tenant, agent_key="parent_pg",
        principal_kind="agent", principal_id="parent_pg",
        mode="observed", outcome="success",
        correlation_id="pg-corr-1", started_at=now,
    )
    child = kya.record_invocation(
        pg_db, tenant_id=tenant, agent_key="child_pg",
        principal_kind="agent", principal_id="child_pg",
        mode="observed", outcome="success",
        parent_invocation_id=parent, started_at=now,
        # child intentionally has no correlation_id of its own
    )
    grandchild = kya.record_invocation(
        pg_db, tenant_id=tenant, agent_key="gc_pg",
        principal_kind="agent", principal_id="gc_pg",
        mode="observed", outcome="success",
        parent_invocation_id=child, started_at=now,
    )
    pg_db.commit()

    # All three resolve to the same root correlation_id on real PG.
    assert correlation_id_for_invocation(
        pg_db, tenant, parent) == "pg-corr-1"
    assert correlation_id_for_invocation(
        pg_db, tenant, child) == "pg-corr-1"
    assert correlation_id_for_invocation(
        pg_db, tenant, grandchild) == "pg-corr-1"


# ══════════════════════════════════════════════════════════════════
# End-to-end on real PG: helper -> engine -> chain fires across agents
# ══════════════════════════════════════════════════════════════════


def test_pg_chain_fires_across_real_delegated_agents(pg_db):
    """The defining live test: parent invocation under agent A
    (correlation set), child invocation under agent B (no own
    correlation, inherited via parent_invocation_id). Helper resolves
    the chain id on real PG; engine fires a cross-agent chain that
    spans both principals."""
    tenant = _tenant()
    now = datetime.now(timezone.utc)
    parent = kya.record_invocation(
        pg_db, tenant_id=tenant, agent_key="agent_a",
        principal_kind="agent", principal_id="agent_a",
        mode="observed", outcome="success",
        correlation_id="pg-loop-1", started_at=now,
    )
    child = kya.record_invocation(
        pg_db, tenant_id=tenant, agent_key="agent_b",
        principal_kind="agent", principal_id="agent_b",
        mode="observed", outcome="success",
        parent_invocation_id=parent, started_at=now,
    )
    pg_db.commit()

    # Helper recovers the same correlation_id from both rows.
    corr_a = correlation_id_for_invocation(pg_db, tenant, parent)
    corr_b = correlation_id_for_invocation(pg_db, tenant, child)
    assert corr_a == corr_b == "pg-loop-1"

    engine, fired = _engine(_cross_agent_rule())

    # Step 1 done by agent A.
    m1 = engine.process_evidence(
        pg_db, tenant_id=tenant, principal_id="agent_a",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/etc/shadow"},
        occurred_at_ts=100.0, correlation_id=corr_a,
    )
    assert m1 == []
    assert fired == []

    # Step 2 done by DIFFERENT agent B -- shares correlation_id.
    m2 = engine.process_evidence(
        pg_db, tenant_id=tenant, principal_id="agent_b",
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        occurred_at_ts=110.0, correlation_id=corr_b,
    )
    assert m2 == ["cross_agent_pg"]
    assert fired == [("cross_agent_pg", "rogue_cross_agent_pg")]


# ══════════════════════════════════════════════════════════════════
# Tenant scoping holds on real PG
# ══════════════════════════════════════════════════════════════════


def test_pg_helper_does_not_cross_tenant_boundary(pg_db):
    """The tenant-scoped walk is critical security: a malformed
    parent_invocation_id pointing into another tenant must NOT leak
    that tenant's correlation_id. Verified on real PG."""
    tenant_a = _tenant()
    tenant_b = _tenant()
    now = datetime.now(timezone.utc)
    leak_inv = kya.record_invocation(
        pg_db, tenant_id=tenant_a, agent_key="leak",
        principal_kind="agent", principal_id="leak",
        mode="observed", outcome="success",
        correlation_id="must-not-leak", started_at=now,
    )
    cross_inv = kya.record_invocation(
        pg_db, tenant_id=tenant_b, agent_key="cross",
        principal_kind="agent", principal_id="cross",
        mode="observed", outcome="success",
        parent_invocation_id=leak_inv, started_at=now,
    )
    pg_db.commit()
    # tenant_b's walk MUST NOT recover tenant_a's correlation_id.
    assert correlation_id_for_invocation(
        pg_db, tenant_b, cross_inv) is None
