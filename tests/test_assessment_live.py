"""Live integration tests for the Assessment orchestrator.

Gated on ``KYA_PG_URL`` -- when unset every test is SKIPPED so CI
without infrastructure stays green. When set, these tests run the
full ``run_assessment()`` orchestrator end-to-end against a real
Postgres backend (the production-shaped store), not just SQLite +
``schema_translate_map``.

What this file proves over the unit suite
-----------------------------------------
- Real ``prov_schema`` qualifier on PG (the production code path).
- Real PG UUID / JSONB / TIMESTAMPTZ semantics for snapshots,
  invocations, evidence, RBAC grants, and principal_trust rows.
- A fully-seeded fleet (snapshot + grant + signal + evidence) feeds
  every pillar with non-trivial data and the report rolls up
  correctly.
- Ed25519-signed offline-verifiable export round-trip on PG.

Run locally (using the existing ``kya-test-pg`` container):

    KYA_PG_URL=postgresql+psycopg2://test:kya@localhost:15433/kyatest \
        python -m pytest tests/test_assessment_live.py -v
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import kya
from kya.assessment import AssessmentReport, run_assessment

_URL = os.environ.get("KYA_PG_URL", "").strip()
pytestmark = pytest.mark.skipif(
    not _URL,
    reason="KYA_PG_URL not set -- live PG assessment tests skipped",
)

_SEVERITY_RANK = {
    "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


# ── Fixtures + helpers ────────────────────────────────────────────


@pytest.fixture
def pg_db():
    """Real Postgres session with KYA storage initialized.

    Ensures ``prov_schema`` exists (idempotent) before delegating to
    ``init_storage`` so the test does not depend on schema-creation
    order between projects sharing the container.
    """
    eng = create_engine(_URL)
    with eng.connect() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        conn.commit()
    session = sessionmaker(bind=eng)()
    kya.init_storage(session)
    yield session
    session.close()
    eng.dispose()


def _unique_tenant() -> str:
    # Use uuid4 string so concurrent test runs and earlier seed data
    # never collide.
    return str(uuid.uuid4())


def _snapshot(db, tenant: str, agent_key: str, definition: dict | None = None):
    kya.snapshot_agent(
        db, tenant_id=tenant, agent_key=agent_key,
        definition=definition or {
            "agent_key": agent_key,
            "model": "openai/gpt-4o-mini",
            "tools": ["search_docs"],
            "access_level": "read",
            "data_classes": [],
        },
    )
    db.commit()


def _seed_evidence(db, tenant: str, agent_key: str) -> int:
    now = datetime.now(timezone.utc)
    inv = kya.record_invocation(
        db, tenant_id=tenant, agent_key=agent_key,
        principal_kind="agent", principal_id=agent_key,
        mode="observed", outcome="success", started_at=now,
    )
    kya.record_evidence(
        db, tenant_id=tenant, invocation_id=inv,
        evidence_kind="prompt",
        payload={"role": "user", "content": "live pg test"},
    )
    db.commit()
    return inv


def _make_ed25519_pem() -> str | None:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        return None
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


# ══════════════════════════════════════════════════════════════════
# End-to-end: fully-seeded fleet exercises every pillar on real PG
# ══════════════════════════════════════════════════════════════════


def test_pg_full_assessment_end_to_end(pg_db):
    tenant = _unique_tenant()
    agent = "agent_full_pg"

    # Snapshot a definition (provenance + trust scoring).
    _snapshot(pg_db, tenant, agent)

    # Grant an override-class action so authority mapping has a
    # genuinely-flagged high-severity finding.
    kya.grant_action(
        pg_db, tenant_id=tenant, principal_kind="agent",
        principal_id=agent, action="kya.delegation.override.set",
        granted_by=str(uuid.uuid4()),
    )

    # Real evidence so verify_chain has something to walk on PG.
    _seed_evidence(pg_db, tenant, agent)

    # Decay trust below the floor with real principal signals.
    for _ in range(15):
        kya.record_principal_signal(
            pg_db, tenant_id=tenant, principal_kind="agent",
            principal_id=agent, signal_kind="policy_violation",
        )
    pg_db.commit()

    report = run_assessment(
        pg_db, tenant_id=tenant,
        agent_keys=[agent], window_days=30,
    )

    assert isinstance(report, AssessmentReport)
    # Every pillar produced findings against real PG data.
    assert report.trust_scoring, "trust pillar produced no findings"
    assert report.authority_mapping, "authority pillar produced no findings"
    assert report.provenance_assessment, "provenance pillar produced no findings"
    assert report.evidence_chain_review, "evidence pillar produced no findings"
    # Trust pillar: at least one HIGH on principal trust.
    low_trust = [
        f for f in report.trust_scoring
        if f.severity == "high" and "trust low" in f.title.lower()
    ]
    assert low_trust, (
        "expected a HIGH-severity 'principal trust low' finding "
        "after 15 real policy_violation signals on PG")
    # Authority: high on the override grant.
    admin_findings = [
        f for f in report.authority_mapping
        if f.severity == "high" and "admin" in f.title.lower()
    ]
    assert admin_findings
    # Evidence: at least one verified chain on real PG.
    verified = [
        f for f in report.evidence_chain_review
        if "verified" in f.title.lower()
    ]
    assert verified
    # Headline rolls up to at least HIGH (admin grant + low trust).
    assert (
        _SEVERITY_RANK[report.headline_severity] >= _SEVERITY_RANK["high"]
    )
    # Real round-trip through JSON.
    raw = json.dumps(report.to_dict())
    parsed = json.loads(raw)
    assert parsed["tenant_id"] == tenant


# ══════════════════════════════════════════════════════════════════
# Drift detection on real PG
# ══════════════════════════════════════════════════════════════════


def test_pg_drift_detection_against_real_pg(pg_db):
    tenant = _unique_tenant()
    agent = "agent_drift_pg"
    _snapshot(pg_db, tenant, agent,
              {"agent_key": agent, "tools": ["v1"]})
    _snapshot(pg_db, tenant, agent,
              {"agent_key": agent, "tools": ["v2"]})

    report = run_assessment(
        pg_db, tenant_id=tenant,
        agent_keys=[agent], window_days=30,
    )
    drift = [
        f for f in report.provenance_assessment
        if f.severity == "medium" and "drift" in f.title.lower()
    ]
    assert drift, (
        "real-PG canonical_hash diff should emit a medium drift "
        "finding between two distinct snapshots")


# ══════════════════════════════════════════════════════════════════
# Signed export end-to-end on real PG
# ══════════════════════════════════════════════════════════════════


def test_pg_signed_export_attached_with_real_evidence(pg_db):
    pem = _make_ed25519_pem()
    if pem is None:
        pytest.skip("cryptography not installed")

    tenant = _unique_tenant()
    agent = "agent_se_pg"
    _seed_evidence(pg_db, tenant, agent)

    report = run_assessment(
        pg_db, tenant_id=tenant,
        agent_keys=[agent], window_days=30,
        signing_key_pem=pem,
    )

    # Real signed_export_ref attached after a real PG evidence row +
    # real Ed25519 signing.
    assert report.signed_export_ref is not None, (
        "expected signed_export_ref to be attached when "
        "signing_key_pem is provided AND at least one chain verified")
    # The finding for it must also be surfaced in the evidence pillar.
    refs = [
        f for f in report.evidence_chain_review
        if "signed evidence export" in f.title.lower()
    ]
    assert refs


# ══════════════════════════════════════════════════════════════════
# Per-tenant isolation: assessments don't bleed across tenants
# ══════════════════════════════════════════════════════════════════


def test_pg_tenant_isolation_keeps_findings_separate(pg_db):
    """Two unrelated tenants with similar data must produce independent
    reports -- a finding in one MUST NOT leak into the other."""
    t1 = _unique_tenant()
    t2 = _unique_tenant()

    # t1: high-severity setup.
    _snapshot(pg_db, t1, "agent_x")
    kya.grant_action(
        pg_db, tenant_id=t1, principal_kind="agent",
        principal_id="agent_x", action="kya.delegation.override.set",
        granted_by=str(uuid.uuid4()),
    )
    _seed_evidence(pg_db, t1, "agent_x")
    pg_db.commit()

    # t2: clean (no admin grants, no signals).
    _snapshot(pg_db, t2, "agent_x")
    _seed_evidence(pg_db, t2, "agent_x")
    pg_db.commit()

    r1 = run_assessment(
        pg_db, tenant_id=t1, agent_keys=["agent_x"], window_days=30)
    r2 = run_assessment(
        pg_db, tenant_id=t2, agent_keys=["agent_x"], window_days=30)

    # The defining isolation properties: t1's admin finding is
    # present in r1; the SAME finding does NOT leak into r2; r2 sees
    # only its own clean state ("no RBAC grants").
    t1_admin = [
        f for f in r1.authority_mapping
        if f.severity == "high" and "admin" in f.title.lower()
    ]
    t2_admin = [
        f for f in r2.authority_mapping
        if f.severity == "high" and "admin" in f.title.lower()
    ]
    t2_no_grants = [
        f for f in r2.authority_mapping
        if "no RBAC grants" in f.title
    ]
    assert t1_admin, "tenant 1 must surface its admin-grant finding"
    assert not t2_admin, (
        "tenant 2 MUST NOT inherit tenant 1's admin grant -- "
        "cross-tenant leakage")
    assert t2_no_grants, (
        "tenant 2 must surface its own 'no RBAC grants' state")
    # And the scope_agents field on each report is tenant-correct.
    assert r1.tenant_id == t1 and r2.tenant_id == t2
