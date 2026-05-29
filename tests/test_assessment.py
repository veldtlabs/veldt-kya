"""Tests for kya.assessment -- the 5-pillar Trust Assessment orchestrator.

Coverage strategy
-----------------
- Per-pillar behavioral tests: given seeded state, the pillar emits the
  expected shape of finding (severity + key title substring).
- Orchestrator integration: run_assessment composes all 5 pillars,
  rolls up the headline, and produces serializable output (to_dict,
  to_markdown).
- Fail-soft: monkeypatching a pillar to raise must not crash the
  assessment; the other pillars still run and the failed pillar
  surfaces a single informational finding.
- Signed export: with cryptography available + at least one verified
  chain, the report carries a signed_export_ref.

Backend: SQLite in-memory (the storage layer ships portable across
PG/MySQL/SQLite/DuckDB; SQLite is fastest for unit tests and exercises
the same prov_schema-translated code paths).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import kya
from kya.assessment import (
    PILLAR_TRUST,
    AssessmentReport,
    pillar_authority_mapping,
    pillar_evidence_chain_review,
    pillar_provenance_assessment,
    pillar_trust_scoring,
    run_assessment,
)

TENANT = "11111111-2222-3333-4444-assessment42"

_SEVERITY_RANK = {
    "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


# ── Fixtures + helpers ────────────────────────────────────────────


@pytest.fixture
def db():
    """In-memory SQLite session with KYA storage initialized."""
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None})
    session = sessionmaker(bind=eng)()
    kya.init_storage(session)
    yield session
    session.close()
    eng.dispose()


def _snapshot(db, agent_key: str = "agent_a", definition: dict | None = None):
    d = definition or {
        "agent_key": agent_key,
        "model": "openai/gpt-4o-mini",
        "tools": ["search_docs"],
        "access_level": "read",
        "data_classes": [],
    }
    kya.snapshot_agent(
        db, tenant_id=TENANT, agent_key=agent_key, definition=d)
    db.commit()


def _seed_evidence(db, agent_key: str = "agent_e") -> int:
    """Seed one invocation + one evidence row; return invocation id."""
    now = datetime.now(timezone.utc)
    inv_id = kya.record_invocation(
        db, tenant_id=TENANT, agent_key=agent_key,
        principal_kind="agent", principal_id=agent_key,
        mode="observed", outcome="success",
        started_at=now,
    )
    kya.record_evidence(
        db, tenant_id=TENANT, invocation_id=inv_id,
        evidence_kind="prompt",
        payload={"role": "user", "content": "hello"},
    )
    db.commit()
    return inv_id


def _titles(findings) -> list[str]:
    return [f.title for f in findings]


# ══════════════════════════════════════════════════════════════════
# AssessmentReport shape + serialization
# ══════════════════════════════════════════════════════════════════


def test_empty_scope_produces_clean_report(db):
    rpt = run_assessment(
        db, tenant_id=TENANT, agent_keys=[], window_days=30)
    assert isinstance(rpt, AssessmentReport)
    assert rpt.tenant_id == TENANT
    assert rpt.scope_agents == []
    # Evidence pillar still emits "no chains" when nothing to verify.
    assert any("no evidence chains" in f.title.lower()
               for f in rpt.evidence_chain_review)
    # Headline can't be worse than informational for an empty scope.
    assert _SEVERITY_RANK[rpt.headline_severity] <= _SEVERITY_RANK["low"]
    # All required keys present in to_dict.
    d = rpt.to_dict()
    required = {
        "tenant_id", "scope_agents", "window_days", "generated_at",
        "trust_scoring", "authority_mapping", "delegation_analysis",
        "provenance_assessment", "evidence_chain_review",
        "headline_severity", "summary", "signed_export_ref",
    }
    assert required <= set(d.keys())


def test_assessment_report_to_dict_is_json_serializable(db):
    _snapshot(db, "agent_a")
    rpt = run_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_a"], window_days=30)
    # Must round-trip through json without TypeErrors.
    raw = json.dumps(rpt.to_dict())
    parsed = json.loads(raw)
    assert parsed["tenant_id"] == TENANT
    assert isinstance(parsed["trust_scoring"], list)


def test_assessment_report_to_markdown_has_pillar_headers(db):
    _snapshot(db, "agent_a")
    rpt = run_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_a"], window_days=30)
    md = rpt.to_markdown()
    assert "# Autonomous Systems Trust Assessment" in md
    for header in (
        "## Trust Scoring", "## Authority Mapping",
        "## Delegation Analysis", "## Provenance Assessment",
        "## Evidence Chain Review",
    ):
        assert header in md


# ══════════════════════════════════════════════════════════════════
# Pillar 1 -- trust scoring
# ══════════════════════════════════════════════════════════════════


def test_trust_pillar_no_snapshot_emits_medium_finding(db):
    findings = pillar_trust_scoring(
        db, tenant_id=TENANT, agent_keys=["agent_unknown"],
        window_days=30)
    no_snap = [f for f in findings if "no version snapshot" in f.title.lower()]
    assert no_snap and no_snap[0].severity == "medium"
    assert no_snap[0].pillar == PILLAR_TRUST


def test_trust_pillar_with_snapshot_emits_score_finding(db):
    _snapshot(db, "agent_a")
    findings = pillar_trust_scoring(
        db, tenant_id=TENANT, agent_keys=["agent_a"], window_days=30)
    score_findings = [f for f in findings if "static risk" in f.title.lower()]
    assert score_findings
    # Each carries a numeric score reference for the agent.
    refs = score_findings[0].references
    assert refs and refs[0].get("agent_key") == "agent_a"


def test_trust_pillar_low_principal_trust_emits_high_finding(db):
    _snapshot(db, "agent_low")
    # Drop trust well below the floor (multiple policy violations).
    for _ in range(15):
        kya.record_principal_signal(
            db, tenant_id=TENANT, principal_kind="agent",
            principal_id="agent_low", signal_kind="policy_violation")
    db.commit()
    findings = pillar_trust_scoring(
        db, tenant_id=TENANT, agent_keys=["agent_low"], window_days=30)
    low_trust = [
        f for f in findings
        if f.severity == "high" and "trust low" in f.title.lower()
    ]
    assert low_trust, (
        "expected a HIGH-severity finding on principal trust < floor "
        "after 15 policy_violation signals")


# ══════════════════════════════════════════════════════════════════
# Pillar 2 -- authority mapping
# ══════════════════════════════════════════════════════════════════


def test_authority_pillar_no_grants_medium_finding(db):
    findings = pillar_authority_mapping(
        db, tenant_id=TENANT, agent_keys=["agent_x"], window_days=30)
    none_findings = [
        f for f in findings
        if "no RBAC grants" in f.title and f.severity == "medium"
    ]
    assert none_findings


def test_authority_pillar_admin_grant_high_finding(db):
    kya.grant_action(
        db, tenant_id=TENANT, principal_kind="agent",
        principal_id="agent_admin", action="kya.delegation.override.set",
        granted_by=str(uuid.uuid4()),
    )
    findings = pillar_authority_mapping(
        db, tenant_id=TENANT, agent_keys=["agent_admin"], window_days=30)
    high = [
        f for f in findings
        if f.severity == "high" and "admin" in f.title.lower()
    ]
    assert high


# ══════════════════════════════════════════════════════════════════
# Pillar 4 -- provenance
# ══════════════════════════════════════════════════════════════════


def test_provenance_single_version_informational(db):
    _snapshot(db, "agent_b")
    findings = pillar_provenance_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_b"], window_days=30)
    info = [
        f for f in findings
        if f.severity == "informational"
        and "baseline" in f.title.lower()
    ]
    assert info


def test_provenance_drift_detection(db):
    _snapshot(db, "agent_drift",
              definition={"agent_key": "agent_drift", "tools": ["a"]})
    _snapshot(db, "agent_drift",
              definition={"agent_key": "agent_drift", "tools": ["b"]})
    findings = pillar_provenance_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_drift"], window_days=30)
    drift = [
        f for f in findings
        if f.severity == "medium" and "drift" in f.title.lower()
    ]
    assert drift, "expected a medium-severity drift finding"


def test_provenance_no_drift_between_identical_snapshots(db):
    definition = {"agent_key": "agent_nodrift", "tools": ["search"]}
    _snapshot(db, "agent_nodrift", definition=definition)
    _snapshot(db, "agent_nodrift", definition=definition)
    findings = pillar_provenance_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_nodrift"], window_days=30)
    no_drift = [
        f for f in findings
        if "no drift" in f.title.lower()
    ]
    assert no_drift


# ══════════════════════════════════════════════════════════════════
# Pillar 5 -- evidence chain review
# ══════════════════════════════════════════════════════════════════


def test_evidence_pillar_no_chains_in_window(db):
    findings, signed = pillar_evidence_chain_review(
        db, tenant_id=TENANT, agent_keys=["agent_none"], window_days=30)
    assert signed is None
    assert any("no evidence chains" in f.title.lower() for f in findings)


def test_evidence_pillar_verified_chain_informational(db):
    _seed_evidence(db, "agent_e")
    findings, signed = pillar_evidence_chain_review(
        db, tenant_id=TENANT, agent_keys=["agent_e"], window_days=30)
    assert signed is None  # no signing key passed
    verified = [
        f for f in findings
        if "verified" in f.title.lower()
        and f.severity == "informational"
    ]
    assert verified, "expected an informational 'all chains verified' finding"


# ══════════════════════════════════════════════════════════════════
# Orchestrator integration
# ══════════════════════════════════════════════════════════════════


def test_run_assessment_returns_all_five_pillars(db):
    _snapshot(db, "agent_a")
    rpt = run_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_a"], window_days=30)
    # Every pillar field is a list, populated with at least the
    # default "informational" findings where applicable.
    for pillar_name, finds in rpt.per_pillar.items():
        assert isinstance(finds, list), pillar_name
    # Summary mentions the assessment + counts.
    assert "Trust Assessment" in rpt.summary
    assert "30 days" in rpt.summary
    # generated_at parses as a real ISO timestamp.
    datetime.fromisoformat(rpt.generated_at)


def test_run_assessment_headline_rolls_up_to_highest_severity(db):
    # An admin grant alone -> high severity finding.
    kya.grant_action(
        db, tenant_id=TENANT, principal_kind="agent",
        principal_id="agent_admin", action="kya.delegation.override.set",
        granted_by=str(uuid.uuid4()),
    )
    rpt = run_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_admin"], window_days=30)
    assert _SEVERITY_RANK[rpt.headline_severity] >= _SEVERITY_RANK["high"]


def test_run_assessment_pillar_failure_is_isolated(monkeypatch, db):
    """A pillar raising must NOT crash the assessment; it surfaces as
    a single 'pillar failed' finding while the other 4 still run."""
    from kya import assessment as a_mod

    def boom(**_kwargs):
        raise RuntimeError("simulated pillar failure")

    monkeypatch.setattr(a_mod, "pillar_trust_scoring", boom)
    rpt = run_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_x"], window_days=30)

    # Trust pillar has the synthetic failure finding.
    assert any("pillar failed" in f.title.lower()
               for f in rpt.trust_scoring)
    # Other pillars still ran (authority emits "no grants" finding).
    assert any("no RBAC grants" in f.title
               for f in rpt.authority_mapping)


# ══════════════════════════════════════════════════════════════════
# Signed export integration (requires cryptography)
# ══════════════════════════════════════════════════════════════════


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


def test_run_assessment_signed_export_attached_when_chain_present(db):
    pem = _make_ed25519_pem()
    if pem is None:
        pytest.skip("cryptography not installed -- signed export unavailable")
    _seed_evidence(db, "agent_se")
    rpt = run_assessment(
        db, tenant_id=TENANT, agent_keys=["agent_se"], window_days=30,
        signing_key_pem=pem,
    )
    # signed_export_ref attached on the report and surfaced as a
    # finding on the evidence pillar.
    assert rpt.signed_export_ref is not None
    assert any("signed evidence export" in f.title.lower()
               for f in rpt.evidence_chain_review)
