"""End-to-end proof that the KYA in-tenant feedback loop closes.

Skipped unless KYA_TEST_PG_URL is set — the suggestions+overrides SQL
uses PG-specific casts (`(:tid)::uuid`, `CAST(... AS jsonb)`, RETURNING)
which are only valid on PostgreSQL. The platform DB is always PG, so
this matches production.

Proves these steps actually chain together:

    incident (severity=critical, policy_type=pii_detection)
        ↓ propose_from_incident()
    kya_weight_suggestions (status=pending, scope=class_weights, key=pii, delta=+5)
        ↓ approve_suggestion()
    kya_weight_overrides (scope=class_weights, key=pii, value=current+5)
        ↓ get_effective_weights()
    effective pii weight reflects the new value
"""

from __future__ import annotations

import os
import uuid

import pytest


pytestmark = pytest.mark.skipif(
    "KYA_TEST_PG_URL" not in os.environ,
    reason="PG integration test — set KYA_TEST_PG_URL to enable",
)


@pytest.fixture
def db():
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    eng = create_engine(os.environ["KYA_TEST_PG_URL"])
    with eng.begin() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
    session = sessionmaker(bind=eng)()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        eng.dispose()


def test_in_tenant_feedback_loop_closes(db):
    """incident → suggestion → approve → weight changed."""
    import kya
    from kya.feedback import propose_from_incident
    from kya.tenant_weights import (
        ensure_tables, get_effective_weights, register_scope,
    )
    from kya.data_classes import CLASS_WEIGHTS

    ensure_tables(db)
    register_scope("class_weights", CLASS_WEIGHTS)

    tenant_id = str(uuid.uuid4())
    incident_id = 999_999  # synthetic — propose_from_incident only needs the dict

    # ── Baseline: what's the current effective pii weight for this tenant?
    baseline = get_effective_weights(db, "class_weights", tenant_id=tenant_id)
    baseline_pii = int(baseline["pii"])

    # ── Step 1: incident → suggestions
    suggestions = propose_from_incident(
        db,
        {
            "id": incident_id,
            "tenant_id": tenant_id,
            "severity": "critical",
            "policy_type": "pii_detection",
            "model_id": "agt_test_v1",
            "policy_id": 1,
            "resolved_at": "2026-05-20T00:00:00+00:00",
        },
    )
    assert len(suggestions) >= 1, "no suggestions generated"
    pii_suggestion = next((s for s in suggestions if s["key"] == "pii"), None)
    assert pii_suggestion is not None
    assert pii_suggestion["suggested_delta"] == +5
    assert pii_suggestion["suggested_value"] == baseline_pii + 5

    # ── Step 2: approve → apply
    decision = kya.approve_suggestion(
        db,
        suggestion_id=pii_suggestion["id"],
        approved_by=str(uuid.uuid4()),
        notes="loop-closes test",
    )
    assert decision["status"] == "applied", f"approve did not apply: {decision}"

    # ── Step 3: effective weight reflects the override
    after = get_effective_weights(db, "class_weights", tenant_id=tenant_id)
    assert int(after["pii"]) == baseline_pii + 5, (
        f"effective weight did not change: baseline={baseline_pii} after={after['pii']}"
    )


def test_resolve_incident_invokes_propose(db, monkeypatch):
    """The incidents.resolve_incident() call site actually invokes propose_from_incident.

    Skipped if the full Veldt app stack (fastapi etc.) isn't installed —
    resolve_incident lives in app/decisions/governance which the SDK does
    not ship. This test is for the platform repo, not SDK consumers.
    """
    try:
        from kya.feedback import propose_from_incident as real_propose
        import kya.feedback as _fb_mod
        import decisions.governance.incidents as _inc_mod
    except ImportError as e:
        pytest.skip(f"platform-only test (needs full app deps): {e}")

    captured: list[dict] = []

    def fake_propose(_db, incident_row):
        captured.append(incident_row)
        return real_propose(_db, incident_row)

    monkeypatch.setattr(_fb_mod, "propose_from_incident", fake_propose)

    # The resolve_incident path imports propose_from_incident at *call* time:
    #     `from kya.feedback import propose_from_incident`
    # Monkeypatching the module attribute is enough — the in-function
    # import binds to the attribute we replaced.

    # Build a real incident row via raw SQL — avoids pulling in the whole
    # GovernancePolicy fixture chain.
    from sqlalchemy import text
    tenant_id = str(uuid.uuid4())

    with db.connection() as conn:
        # tenants table is referenced via FK — short-circuit by inserting a
        # minimal row only if the table exists. If FK isn't enforced in
        # this test schema, skip.
        try:
            conn.execute(text("""
                INSERT INTO prov_schema.governance_policies
                    (id, tenant_id, name, policy_type, risk_level,
                     enforcement, phase, is_active)
                VALUES (1, :tid, 'test policy', 'pii_detection',
                        'high', 'block', 'pre', TRUE)
                ON CONFLICT (id) DO NOTHING
            """), {"tid": tenant_id})
        except Exception:
            pytest.skip("governance_policies schema not in scope for this test env")
        conn.execute(text("""
            INSERT INTO prov_schema.governance_incidents
                (tenant_id, policy_id, model_id, severity, action_taken,
                 resolution_status)
            VALUES (:tid, 1, 'agt_test', 'critical', 'block', 'open')
        """), {"tid": tenant_id})
        incident_id = conn.execute(text(
            "SELECT id FROM prov_schema.governance_incidents "
            "WHERE tenant_id = :tid ORDER BY id DESC LIMIT 1"
        ), {"tid": tenant_id}).scalar()
    db.commit()

    _inc_mod.resolve_incident(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        user_id=str(uuid.uuid4()),
        resolution_status="resolved",
        notes="proof of invocation",
    )

    assert len(captured) == 1, "resolve_incident did NOT call propose_from_incident"
    assert captured[0]["policy_type"] == "pii_detection"
    assert captured[0]["severity"] == "critical"
