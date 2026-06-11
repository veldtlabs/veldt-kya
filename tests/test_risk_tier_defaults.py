"""Tests for Phase 3a — risk-tier defaults at first-sight.

When snapshot_on_first_sight() writes v1, look up the agent's risk
bucket via score_agent() and apply a delegation-policy override
ONLY for buckets that warrant it (critical → flag today).
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    init_storage,
    list_delegation_overrides,
    snapshot_on_first_sight,
)

TENANT = "00000000-0000-0000-0000-0000000000dd"


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


@pytest.fixture(autouse=True)
def clean_env():
    keys = ["KYA_RISK_TIER_AUTO_DEFAULTS", "KYA_DELEGATION_POLICY"]
    saved = {k: os.environ.pop(k, None) for k in keys}
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


# A definition that should score CRITICAL — admin tools + autonomous +
# write access + multiple data classes + no human loop = high risk.
_CRITICAL_DEF = {
    "agent_key": "CriticalA",
    "system_prompt": "Execute admin-level operations autonomously.",
    "tools": ["execute_sql", "delete_user", "modify_permissions",
              "send_email", "deploy_code", "manage_secrets"],
    "human_loop": "out_of_loop",
    "access_level": "admin",
    "data_classes": ["pii", "phi", "financial", "secret"],
    "environment": "prod",
    "model_trust": "open_source",  # weaker trust
    "can_override": True,
    "can_revert": True,
}


# A definition that should score LOW — read-only, narrow tools,
# strict human-loop, no sensitive data classes.
_LOW_DEF = {
    "agent_key": "SafeS",
    "system_prompt": "Look up the time of day.",
    "tools": ["get_time"],
    "human_loop": "in_the_loop",
    "access_level": "read",
    "data_classes": [],
    "environment": "dev",
    "model_trust": "frontier",
}


def _agent_overrides(db, agent_key):
    return list_delegation_overrides(
        db, tenant_id=TENANT,
        parent_agent_key=agent_key,
        include_inactive=False)


# ── Critical → flag override created ──────────────────────────────


def test_critical_agent_gets_flag_override_on_first_sight(db):
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="CriticalA",
        definition=_CRITICAL_DEF,
        note="critical risk first sight")
    overrides = _agent_overrides(db, "CriticalA")
    assert len(overrides) == 1
    assert overrides[0]["mode"] == "flag"
    assert overrides[0]["parent_agent_key"] == "CriticalA"
    assert "risk_bucket=critical" in (overrides[0]["reason"] or "")


def test_low_risk_agent_gets_no_override(db):
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="SafeS",
        definition=_LOW_DEF, note="low risk first sight")
    overrides = _agent_overrides(db, "SafeS")
    assert overrides == []


# ── Idempotency: re-snapshot same def doesn't add another override ──


def test_repeated_snapshot_does_not_duplicate_override(db):
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="CriticalRepeat",
        definition=_CRITICAL_DEF, note="first")
    # Second call with identical def → idempotent (returns v1, False)
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="CriticalRepeat",
        definition=_CRITICAL_DEF, note="second")
    overrides = _agent_overrides(db, "CriticalRepeat")
    assert len(overrides) == 1, \
        f"expected 1 override, got {len(overrides)}"


def test_drift_does_not_re_apply_risk_default(db):
    """A definition change on an EXISTING agent_key bumps the
    version but should NOT re-apply the risk-tier default
    (that's reserved for true first sight)."""
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="DriftCrit",
        definition=_CRITICAL_DEF, note="v1")
    # Drift: same agent_key, slightly different def → v2
    v2_def = dict(_CRITICAL_DEF)
    v2_def["tools"] = _CRITICAL_DEF["tools"] + ["new_admin_tool"]
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="DriftCrit",
        definition=v2_def, note="v2")
    overrides = _agent_overrides(db, "DriftCrit")
    # Still exactly one override (the original from first-sight)
    assert len(overrides) == 1


# ── Env var disable ──────────────────────────────────────────────


def test_env_var_disables_auto_default(db, monkeypatch):
    monkeypatch.setenv("KYA_RISK_TIER_AUTO_DEFAULTS", "0")
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="DisabledCrit",
        definition=_CRITICAL_DEF, note="should not get override")
    overrides = _agent_overrides(db, "DisabledCrit")
    assert overrides == []


def test_env_var_truthy_variants_disable(db, monkeypatch):
    for val in ("false", "FALSE", "no", "NO", "off", "OFF"):
        monkeypatch.setenv("KYA_RISK_TIER_AUTO_DEFAULTS", val)
        agent_key = f"DisabledCrit_{val}"
        snapshot_on_first_sight(
            db, tenant_id=TENANT, agent_key=agent_key,
            definition={**_CRITICAL_DEF, "agent_key": agent_key},
            note="")
        assert _agent_overrides(db, agent_key) == [], \
            f"agent {agent_key} got override when env={val}"


# ── Pre-existing operator override should NOT be overwritten ──────


def test_existing_explicit_override_blocks_auto_default(db):
    """If an operator has already set an override for this agent
    (in any form), the auto-default must NOT overwrite it."""
    from kya import set_delegation_override
    # Operator pre-sets a block override for this agent
    set_delegation_override(
        db, tenant_id=TENANT, mode="block",
        parent_agent_key="OperatorPriority",
        reason="manual: operator decision")
    # Now first-sight this agent (would normally get flag)
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="OperatorPriority",
        definition={**_CRITICAL_DEF, "agent_key": "OperatorPriority"},
        note="")
    overrides = _agent_overrides(db, "OperatorPriority")
    # Should be ONLY the operator's block, not the auto flag
    assert len(overrides) == 1
    assert overrides[0]["mode"] == "block"
    assert "manual" in (overrides[0]["reason"] or "")


# ── Fail-soft contract ───────────────────────────────────────────


def test_score_agent_exception_does_not_break_snapshot(db, monkeypatch):
    """If score_agent raises, the snapshot itself must still succeed
    and the helper must swallow silently."""
    from kya import risk
    monkeypatch.setattr(
        risk, "score_agent",
        lambda *a, **kw: (_ for _ in ()).throw(
            RuntimeError("scoring exploded")))
    v, is_new = snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="ScoreBroken",
        definition=_CRITICAL_DEF, note="")
    assert is_new is True
    assert v == 1
    # No override was written (score failed)
    overrides = _agent_overrides(db, "ScoreBroken")
    assert overrides == []
    # But the snapshot itself succeeded — there's an agent_versions row
    rows = db.execute(text(
        "SELECT version_no FROM agent_versions "
        "WHERE agent_key='ScoreBroken'")).fetchall()
    assert len(rows) == 1


def test_set_override_exception_does_not_break_snapshot(db,
                                                         monkeypatch):
    """If set_delegation_override raises, the snapshot survives."""
    from kya import delegation_overrides
    monkeypatch.setattr(
        delegation_overrides, "set_delegation_override",
        lambda *a, **kw: (_ for _ in ()).throw(
            RuntimeError("override write exploded")))
    v, is_new = snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="OverrideBroken",
        definition=_CRITICAL_DEF, note="")
    assert is_new is True
    # Snapshot succeeded
    rows = db.execute(text(
        "SELECT version_no FROM agent_versions "
        "WHERE agent_key='OverrideBroken'")).fetchall()
    assert len(rows) == 1


# ── Smoke: integration with delegation enforcement ────────────────


def test_created_by_propagates_to_override_changed_by(db):
    """The user_id (created_by) of whoever triggered the snapshot
    must show up in the override's changed_by audit field — so we
    don't lose attribution on the auto-default."""
    operator_uuid = "11111111-2222-3333-4444-555555555555"
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="AuditedCrit",
        definition={**_CRITICAL_DEF, "agent_key": "AuditedCrit"},
        created_by=operator_uuid,
        note="audited")
    overrides = _agent_overrides(db, "AuditedCrit")
    assert len(overrides) == 1
    assert overrides[0]["changed_by"] == operator_uuid


def test_tenant_scoping_isolation_in_auto_default(db):
    """Auto-default override for tenant A must not bleed into tenant B."""
    other_tenant = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="SharedKey",
        definition={**_CRITICAL_DEF, "agent_key": "SharedKey"},
        note="tenant TENANT only")
    # Tenant TENANT sees the auto-flag override
    a = _agent_overrides(db, "SharedKey")
    assert len(a) == 1
    assert a[0]["mode"] == "flag"
    # Other tenant — same agent_key — has NO override (different tenant)
    b = list_delegation_overrides(
        db, tenant_id=other_tenant,
        parent_agent_key="SharedKey")
    assert b == []


def test_critical_first_sight_then_resolver_returns_flag(db, monkeypatch):
    """End-to-end smoke: first-sight a critical agent (gets auto
    flag override applied), then ask the resolver what mode applies
    for any (CritOrch, *, *) scope — it should return flag from the
    auto-applied override, not observe from the env default."""
    from kya import resolve_effective_mode
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "observe")

    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="CritOrch",
        definition={**_CRITICAL_DEF, "agent_key": "CritOrch"},
        note="first sight, gets flag auto-default")

    mode, source = resolve_effective_mode(
        db, tenant_id=TENANT,
        parent_agent_key="CritOrch",
        sub_agent_key="AnySub",
        violation_kind="access_escalation")
    assert mode == "flag", f"expected flag, got {mode} from {source}"
    assert "CritOrch" in source


def test_critical_first_sight_flags_real_violation(db, monkeypatch):
    """End-to-end: first-sight a CRITICAL parent that's restricted
    (read-access) AND a sub-agent that escalates to admin → the
    violation should land in flag mode (the auto-applied override
    on the parent), even though env default is observe."""
    from kya import record_invocation, snapshot_agent
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "observe")

    # A "critical risk" parent that's still nominally read-access
    # (autonomous + many tools + sensitive data classes = critical)
    critical_read_def = {
        "agent_key": "CritReadOrch",
        "system_prompt": "Autonomous critical agent with broad reach.",
        "tools": ["get_user", "lookup_emr", "fetch_financial",
                  "read_secret", "scan_pii", "audit_log",
                  "tail_logs", "query_db"],
        "human_loop": "out_of_loop",
        "access_level": "read",  # ← critical but READ-only
        "data_classes": ["pii", "phi", "financial", "secret"],
        "environment": "prod",
        "model_trust": "open_source",
    }
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="CritReadOrch",
        definition=critical_read_def, note="critical read-only")

    # Sub-agent escalates from parent.read to admin
    snapshot_agent(db, tenant_id=TENANT, agent_key="AdminSub",
                   definition={"agent_key": "AdminSub",
                                "access_level": "admin"},
                   note="sub escalates")

    # The auto-flag override on CritReadOrch should override the
    # env=observe default for this delegation
    record_invocation(
        db, tenant_id=TENANT, agent_key="AdminSub",
        principal_kind="agent", principal_id="CritReadOrch")
    rows = db.execute(text(
        "SELECT mode_active FROM kya_delegation_violations "
        "WHERE sub_agent_key='AdminSub'")).fetchall()
    assert len(rows) >= 1
    # The escalation violation should be in flag mode
    modes = {r[0] for r in rows}
    assert "flag" in modes, f"expected flag in modes, got {modes}"
