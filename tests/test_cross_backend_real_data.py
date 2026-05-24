"""End-to-end integration tests with REAL DATA on multiple backends.

Exercises every public API that was converted from raw `text()` SQL
to SA Core in the prov_schema sweep — the actual functions SDK
consumers call, against actual database backends, with real
multi-row data + assertions on returned values + side effects.

Parameterized across SQLite (always) + PostgreSQL (if KYA_TEST_PG_URL
is set, runs in CI with the service container).

Covers:
  - tenant_weights: get_effective_weights, set_override, delete_override,
    list_overrides, list_recent_changes
  - feedback:       propose_from_incident, list_suggestions, _set_decision,
                    approve_suggestion (the apply-status update)
  - agent_aliases:  resolve_alias, list_aliases, delete_alias

This is the "real data" test the prov_schema sweep needs to satisfy:
not just "does the call return without raising", but "does the full
data lifecycle behave correctly cross-dialect".
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


# ── Backend parameterization ────────────────────────────────────────


@pytest.fixture(
    params=["sqlite", pytest.param("pg", marks=pytest.mark.skipif(
        "KYA_TEST_PG_URL" not in os.environ,
        reason="PG integration — set KYA_TEST_PG_URL"
    ))],
    ids=["sqlite", "pg"],
)
def db(request):
    """Yield a session bound to a fresh DB on the requested backend."""
    if request.param == "sqlite":
        eng = create_engine("sqlite:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None}
        )
    else:
        from sqlalchemy import text
        eng = create_engine(os.environ["KYA_TEST_PG_URL"])
        with eng.begin() as conn:
            # Reset prov_schema so PG runs are isolated.
            conn.execute(text("DROP SCHEMA IF EXISTS prov_schema CASCADE"))
            conn.execute(text("CREATE SCHEMA prov_schema"))
    Session = sessionmaker(bind=eng)
    session = Session()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        eng.dispose()


# ── tenant_weights: real data lifecycle ─────────────────────────────


def test_tenant_weights_full_lifecycle(db):
    """Platform set → tenant set → delete → list → audit log — all
    against real DB with multi-row state."""
    from kya import tenant_weights
    tenant_weights.register_scope("class_weights", {"pii": 15, "phi": 18})
    tenant_weights.ensure_tables(db)

    bank = "11111111-1111-1111-1111-111111111111"
    clinic = "22222222-2222-2222-2222-222222222222"

    # 1) Two platform writes for SAME (scope, key) — must coalesce to 1 row
    tenant_weights.set_override(db, scope="class_weights", key="pii",
                                 value=18, tenant_id=None,
                                 changed_by="00000000-0000-0000-0000-00000000aaaa")
    tenant_weights.set_override(db, scope="class_weights", key="pii",
                                 value=20, tenant_id=None,
                                 changed_by="00000000-0000-0000-0000-00000000aaaa")
    # Tenant overrides (different tenants, only-tighten)
    tenant_weights.set_override(db, scope="class_weights", key="pii",
                                 value=30, tenant_id=bank,
                                 changed_by="00000000-0000-0000-0000-00000000bbbb")
    tenant_weights.set_override(db, scope="class_weights", key="phi",
                                 value=25, tenant_id=clinic,
                                 changed_by="00000000-0000-0000-0000-00000000cccc")

    # 2) get_effective_weights must reflect the per-tenant view
    bank_eff = tenant_weights.get_effective_weights(db, "class_weights", tenant_id=bank)
    clinic_eff = tenant_weights.get_effective_weights(db, "class_weights", tenant_id=clinic)
    platform_eff = tenant_weights.get_effective_weights(db, "class_weights", tenant_id=None)
    assert bank_eff["pii"] == 30, f"bank pii should be 30 (own override), got {bank_eff['pii']}"
    assert bank_eff["phi"] == 18, f"bank phi should fall back to in-process default 18, got {bank_eff['phi']}"
    assert clinic_eff["pii"] == 20, f"clinic pii should be 20 (platform), got {clinic_eff['pii']}"
    assert clinic_eff["phi"] == 25, f"clinic phi should be 25 (own), got {clinic_eff['phi']}"
    assert platform_eff["pii"] == 20, f"platform pii should be 20 (last platform write), got {platform_eff['pii']}"

    # 3) list_overrides returns the expected multi-tenant view
    bank_list = tenant_weights.list_overrides(db, tenant_id=bank)
    bank_keys = {(o["tenant_id"], o["scope"], o["key"]) for o in bank_list}
    assert (None, "class_weights", "pii") in bank_keys, f"platform pii missing: {bank_keys}"
    assert (bank, "class_weights", "pii") in bank_keys, f"bank pii override missing: {bank_keys}"

    # 4) delete_override on platform-level must reduce visibility
    deleted = tenant_weights.delete_override(db, scope="class_weights", key="pii",
                                              tenant_id=None,
                                              changed_by="00000000-0000-0000-0000-00000000aaaa")
    assert deleted is True
    # After deleting the platform pii override, bank still has its own (30); clinic
    # falls back to the in-process default (15).
    after_clinic = tenant_weights.get_effective_weights(db, "class_weights", tenant_id=clinic)
    assert after_clinic["pii"] == 15, (
        f"clinic pii should fall back to in-process default 15 after platform delete, "
        f"got {after_clinic['pii']}"
    )

    # 5) list_recent_changes records the writes + delete in audit log
    changes = tenant_weights.list_recent_changes(db, tenant_id=bank, limit=50)
    actions = [c["action"] for c in changes]
    assert "set" in actions, f"expected at least one 'set' in audit log: {actions}"
    assert "delete" in actions, f"expected the 'delete' action in audit log: {actions}"


# ── feedback: real data lifecycle ───────────────────────────────────


def test_feedback_full_lifecycle(db):
    """propose → list → approve → status='applied' — full feedback loop."""
    import kya
    from kya import tenant_weights
    from kya.data_classes import CLASS_WEIGHTS
    from kya.feedback import (
        ensure_suggestions_table,
        list_suggestions,
        propose_from_incident,
    )
    tenant_weights.register_scope("class_weights", CLASS_WEIGHTS)
    tenant_weights.ensure_tables(db)
    ensure_suggestions_table(db)

    tenant = str(uuid.uuid4())
    incident = {
        "id": 7777,
        "tenant_id": tenant,
        "severity": "critical",
        "policy_type": "pii_detection",
        "model_id": "agt_realdata",
        "policy_id": 1,
        "resolved_at": "2026-05-23T00:00:00+00:00",
    }

    # 1) propose_from_incident inserts real rows on real DB
    suggestions = propose_from_incident(db, incident)
    assert len(suggestions) >= 1, f"propose returned no suggestions: {suggestions}"

    # 2) list_suggestions returns them
    listed = list_suggestions(db, tenant_id=tenant, status="pending")
    pii_ids = [s["id"] for s in listed if s["key"] == "pii"]
    assert len(pii_ids) == 1, f"expected 1 pending pii suggestion, got {len(pii_ids)}: {listed}"
    pii_id = pii_ids[0]

    # 3) Re-running propose must NOT duplicate (existing-pending check works)
    again = propose_from_incident(db, incident)
    listed_again = list_suggestions(db, tenant_id=tenant, status="pending")
    assert len(listed_again) == len(listed), (
        f"propose must not duplicate; before={len(listed)} after={len(listed_again)}; "
        f"second call returned {again}"
    )

    # 4) approve_suggestion: _set_decision UPDATE + status='applied' UPDATE
    decision = kya.approve_suggestion(
        db, suggestion_id=pii_id, approved_by=str(uuid.uuid4()),
        notes="real-data lifecycle test",
    )
    assert decision["status"] == "applied", f"expected applied, got {decision}"

    # 5) Status update must have fired — no longer in 'pending' list
    after = list_suggestions(db, tenant_id=tenant, status="pending")
    assert pii_id not in [s["id"] for s in after], (
        f"approved suggestion still showing as pending: {after}"
    )
    applied = list_suggestions(db, tenant_id=tenant, status="applied")
    assert pii_id in [s["id"] for s in applied], (
        f"approved suggestion not in applied list: {applied}"
    )


# ── agent_aliases: real data lifecycle ──────────────────────────────


def test_agent_aliases_full_lifecycle(db):
    """add → resolve → list → delete — alias hot-path works cross-dialect."""
    from kya import agent_aliases

    tenant = str(uuid.uuid4())
    agent_aliases.ensure_table(db)

    # 1) add three aliases pointing at the same canonical agent
    agent_aliases.add_alias(db, tenant_id=tenant, alias="loan_v1",
                            canonical_agent_key="loan_triage", note="legacy v1")
    agent_aliases.add_alias(db, tenant_id=tenant, alias="loan_v2_beta",
                            canonical_agent_key="loan_triage", note="beta name")
    agent_aliases.add_alias(db, tenant_id=tenant, alias="risk_v1",
                            canonical_agent_key="risk_review", note="legacy v1")

    # 2) resolve_alias finds each one
    assert agent_aliases.resolve_alias(db, tenant_id=tenant, alias="loan_v1") == "loan_triage"
    assert agent_aliases.resolve_alias(db, tenant_id=tenant, alias="loan_v2_beta") == "loan_triage"
    assert agent_aliases.resolve_alias(db, tenant_id=tenant, alias="risk_v1") == "risk_review"
    # Unknown alias returns None
    assert agent_aliases.resolve_alias(db, tenant_id=tenant, alias="does_not_exist") is None

    # 3) list_aliases returns the two for loan_triage in DESC created order
    loan_aliases = agent_aliases.list_aliases(db, tenant_id=tenant,
                                              canonical_agent_key="loan_triage")
    loan_names = {a["alias"] for a in loan_aliases}
    assert loan_names == {"loan_v1", "loan_v2_beta"}, (
        f"expected both loan aliases, got {loan_names}"
    )

    # 4) delete_alias removes one
    alias_id_to_drop = next(a["id"] for a in loan_aliases if a["alias"] == "loan_v1")
    assert agent_aliases.delete_alias(db, tenant_id=tenant, alias_id=alias_id_to_drop) is True
    # delete returns False for a non-existent id
    assert agent_aliases.delete_alias(db, tenant_id=tenant, alias_id=999999) is False

    # 5) After delete, resolve must miss
    assert agent_aliases.resolve_alias(db, tenant_id=tenant, alias="loan_v1") is None
    # The other one still resolves
    assert agent_aliases.resolve_alias(db, tenant_id=tenant, alias="loan_v2_beta") == "loan_triage"


# ── two-axis surface on real data ───────────────────────────────────


def test_score_agent_two_axis_on_real_agent_def():
    """Score a realistic agent_def (not synthetic minimal) and verify the
    two-axis fields surface correctly with non-trivial values."""
    from kya import score_agent

    r = score_agent({
        "agent_key": "production_loan_writer",
        "human_loop": "none",
        "tools": ["create_loan", "update_loan", "delete_pending_app"],
        "environment": "prod",
        "access_level": "write",
        "can_override": True,
        "can_revert": False,
        "data_classes": ["pii", "financial"],
        "compliance_scope": ["gdpr", "nydfs_500"],
        "owner_user_id": "00000000-0000-0000-0000-000000000001",
        "owner_team": "lending-platform",
        "on_call": "lending-oncall",
        "model_trust": "enterprise",
        "provenance": "internal",
        "signed_at": "2026-01-01T00:00:00Z",
        "review_status": "approved",
        "red_team_score": 80, "bias_score": 80, "fairness_score": 80,
        "input_sources": ["internal_api"],
    })
    assert r.score == 100, f"saturated production agent should score 100, got {r.score}"
    assert r.bucket == "critical"
    # Two-axis: concentration must equal interaction_multiplier
    assert r.concentration == r.interaction_multiplier
    assert r.concentration > 1.0, "autonomous_writer_in_prod multiplier should fire"
    # overrun must capture the suppressed amplification
    expected_overrun = max(0, int(round(r.additive_score * r.interaction_multiplier)) - 100)
    assert r.overrun == expected_overrun, (
        f"overrun mismatch: got {r.overrun}, expected {expected_overrun} "
        f"(additive={r.additive_score} mult={r.interaction_multiplier})"
    )
    assert r.overrun > 0, "saturated agent must show non-zero overrun"
