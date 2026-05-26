"""Unit tests for kya/delegation_policy.py."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    DELEGATION_POLICY_MODES,
    DelegationPolicyError,
    check_delegation,
    enforce_delegation_policy,
    init_storage,
    record_invocation,
    snapshot_agent,
)


TENANT = "00000000-0000-0000-0000-000000000123"


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None})
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


@pytest.fixture(autouse=True)
def clean_env():
    """Reset the policy env var between tests."""
    prev = os.environ.pop("KYA_DELEGATION_POLICY", None)
    yield
    if prev is not None:
        os.environ["KYA_DELEGATION_POLICY"] = prev
    else:
        os.environ.pop("KYA_DELEGATION_POLICY", None)


# ── Pure check_delegation behavior ─────────────────────────────────


def test_check_clean_no_violations():
    parent = {"access_level": "write", "data_classes": ["pii"],
              "human_loop": "in_the_loop", "tools": []}
    sub = {"access_level": "read", "data_classes": [],
           "human_loop": "in_the_loop", "tools": []}
    assert check_delegation(parent, sub) == []


def test_check_access_escalation():
    parent = {"access_level": "read"}
    sub = {"access_level": "write"}
    v = check_delegation(parent, sub)
    assert len(v) == 1
    assert v[0]["violation_kind"] == "access_escalation"
    assert v[0]["sub_value"] == "write"


def test_check_data_class_widening():
    parent = {"data_classes": ["pii"]}
    sub = {"data_classes": ["pii", "phi"]}
    v = check_delegation(parent, sub)
    assert len(v) == 1
    assert v[0]["violation_kind"] == "data_class_widening"
    assert v[0]["extra"] == ["phi"]


def test_check_human_loop_relaxation():
    parent = {"human_loop": "in_the_loop"}
    sub = {"human_loop": "autonomous"}
    v = check_delegation(parent, sub)
    assert len(v) == 1
    assert v[0]["violation_kind"] == "human_loop_relax"


def test_check_human_loop_tightening_is_allowed():
    parent = {"human_loop": "autonomous"}
    sub = {"human_loop": "in_the_loop"}
    assert check_delegation(parent, sub) == []


def test_check_equal_access_is_allowed():
    parent = {"access_level": "write"}
    sub = {"access_level": "write"}
    assert check_delegation(parent, sub) == []


def test_check_multiple_violations_accumulate():
    parent = {"access_level": "read", "data_classes": ["pii"],
              "human_loop": "in_the_loop"}
    sub = {"access_level": "admin", "data_classes": ["pii", "phi"],
           "human_loop": "out_of_loop"}
    v = check_delegation(parent, sub)
    kinds = {x["violation_kind"] for x in v}
    assert kinds == {"access_escalation", "data_class_widening",
                     "human_loop_relax"}


def test_check_unknown_access_level_is_ignored():
    parent = {"access_level": "frobozz"}
    sub = {"access_level": "admin"}
    assert check_delegation(parent, sub) == []


def test_check_missing_dimension_skipped():
    # Parent has no access_level → that dimension is skipped.
    # Both have no data_classes → that dimension is also skipped.
    # Net: no violations.
    parent = {"data_classes": []}
    sub = {"access_level": "admin", "data_classes": []}
    assert check_delegation(parent, sub) == []


def test_check_data_classes_absent_in_parent_skips_dimension():
    # Field MISSING from parent_def → treated as "unknown" and skipped.
    # Avoids noisy flags against bare-essentials orchestrator defs.
    parent = {"access_level": "read"}
    sub = {"data_classes": ["pii"]}
    assert check_delegation(parent, sub) == []


def test_check_data_classes_empty_in_parent_still_enforces():
    # Field present but EXPLICITLY EMPTY → caller is saying "this
    # principal has zero data access". Sub adding any class IS widening.
    parent = {"access_level": "read", "data_classes": []}
    sub = {"data_classes": ["pii"]}
    v = check_delegation(parent, sub)
    assert len(v) == 1
    assert v[0]["violation_kind"] == "data_class_widening"
    assert v[0]["extra"] == ["pii"]


def test_check_handles_non_dict_input():
    assert check_delegation(None, {"access_level": "admin"}) == []
    assert check_delegation({"access_level": "read"}, None) == []


# ── enforce_delegation_policy: persistence + modes ─────────────────


def _snapshot_both(db, parent_def, sub_def):
    """Helper — snapshot parent and sub-agent definitions."""
    snapshot_agent(db, tenant_id=TENANT,
                   agent_key=parent_def["agent_key"],
                   definition=parent_def, note="test")
    snapshot_agent(db, tenant_id=TENANT,
                   agent_key=sub_def["agent_key"],
                   definition=sub_def, note="test")


def _count_violations(db, sub_agent_key):
    rows = db.execute(text(
        "SELECT violation_kind, mode_active, blocked "
        "FROM kya_delegation_violations "
        "WHERE sub_agent_key = :s"
    ), {"s": sub_agent_key}).fetchall()
    return rows


def test_enforce_observe_persists_and_returns_violations(db):
    parent = {"agent_key": "P_obs", "access_level": "read"}
    sub = {"agent_key": "S_obs", "access_level": "admin"}
    _snapshot_both(db, parent, sub)
    violations = enforce_delegation_policy(
        db, tenant_id=TENANT,
        sub_invocation_id=999, parent_invocation_id=998,
        parent_agent_key="P_obs", sub_agent_key="S_obs",
        mode="observe",
    )
    assert len(violations) == 1
    assert violations[0]["violation_kind"] == "access_escalation"
    rows = _count_violations(db, "S_obs")
    assert len(rows) == 1
    assert rows[0][1] == "observe"
    assert rows[0][2] in (0, False)


def test_enforce_block_raises_and_persists_blocked_row(db):
    parent = {"agent_key": "P_blk", "access_level": "read"}
    sub = {"agent_key": "S_blk", "access_level": "admin"}
    _snapshot_both(db, parent, sub)
    with pytest.raises(DelegationPolicyError) as exc_info:
        enforce_delegation_policy(
            db, tenant_id=TENANT,
            sub_invocation_id=42, parent_invocation_id=41,
            parent_agent_key="P_blk", sub_agent_key="S_blk",
            mode="block",
        )
    err = exc_info.value
    assert err.parent_agent_key == "P_blk"
    assert err.sub_agent_key == "S_blk"
    assert len(err.violations) == 1

    rows = _count_violations(db, "S_blk")
    assert len(rows) == 1
    assert rows[0][1] == "block"
    assert rows[0][2] in (1, True)


def test_enforce_flag_logs_and_persists(db, caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="kya.delegation_policy")
    parent = {"agent_key": "P_flg", "human_loop": "in_the_loop"}
    sub = {"agent_key": "S_flg", "human_loop": "out_of_loop"}
    _snapshot_both(db, parent, sub)
    violations = enforce_delegation_policy(
        db, tenant_id=TENANT,
        sub_invocation_id=10, parent_invocation_id=9,
        parent_agent_key="P_flg", sub_agent_key="S_flg",
        mode="flag",
    )
    assert len(violations) == 1
    rows = _count_violations(db, "S_flg")
    assert len(rows) == 1
    assert rows[0][1] == "flag"
    assert any("delegation policy violation" in rec.message.lower()
               for rec in caplog.records)


def test_enforce_clean_persists_nothing(db):
    parent = {"agent_key": "P_clean", "access_level": "admin",
              "data_classes": ["pii", "phi"], "human_loop": "in_the_loop"}
    sub = {"agent_key": "S_clean", "access_level": "read",
           "data_classes": ["pii"], "human_loop": "in_the_loop"}
    _snapshot_both(db, parent, sub)
    violations = enforce_delegation_policy(
        db, tenant_id=TENANT,
        sub_invocation_id=1, parent_invocation_id=2,
        parent_agent_key="P_clean", sub_agent_key="S_clean",
        mode="block",
    )
    assert violations == []
    rows = _count_violations(db, "S_clean")
    assert rows == []


def test_enforce_failsoft_on_missing_snapshot(db):
    """No snapshots → no check possible → return [] silently."""
    # Don't snapshot anything
    violations = enforce_delegation_policy(
        db, tenant_id=TENANT,
        sub_invocation_id=1, parent_invocation_id=2,
        parent_agent_key="missing_parent", sub_agent_key="missing_sub",
        mode="block",
    )
    assert violations == []
    rows = _count_violations(db, "missing_sub")
    assert rows == []


# ── End-to-end: record_invocation auto-fires the check ─────────────


def test_record_invocation_fires_check_on_agent_principal(db, monkeypatch):
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "observe")
    parent = {"agent_key": "OrchA", "access_level": "read"}
    sub = {"agent_key": "SubA", "access_level": "admin"}
    _snapshot_both(db, parent, sub)

    inv_id = record_invocation(
        db, tenant_id=TENANT, agent_key="SubA",
        principal_kind="agent", principal_id="OrchA",
        parent_invocation_id=None, mode="observed", outcome="success",
    )
    assert isinstance(inv_id, int)
    rows = _count_violations(db, "SubA")
    assert len(rows) == 1
    assert rows[0][0] == "access_escalation"


def test_record_invocation_skips_check_for_user_principal(db, monkeypatch):
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "block")
    sub = {"agent_key": "SubU", "access_level": "admin"}
    snapshot_agent(db, tenant_id=TENANT, agent_key="SubU",
                   definition=sub, note="test")
    # principal_kind="user" — no parent agent to compare against,
    # so the check should not fire even in block mode
    inv_id = record_invocation(
        db, tenant_id=TENANT, agent_key="SubU",
        principal_kind="user", principal_id="alice@example.com",
        mode="observed", outcome="success",
    )
    assert isinstance(inv_id, int)
    assert _count_violations(db, "SubU") == []


def test_record_invocation_block_mode_raises_and_marks_blocked(db,
                                                                monkeypatch):
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "block")
    parent = {"agent_key": "OrchB", "access_level": "read"}
    sub = {"agent_key": "SubB", "access_level": "admin"}
    _snapshot_both(db, parent, sub)
    with pytest.raises(DelegationPolicyError):
        record_invocation(
            db, tenant_id=TENANT, agent_key="SubB",
            principal_kind="agent", principal_id="OrchB",
            mode="observed", outcome="success",
        )
    # The invocation row should still exist (with outcome=blocked) for
    # audit purposes — block mode is about preventing the *continuation*
    # of the delegation, not erasing the attempt.
    rows = db.execute(text(
        "SELECT outcome FROM kya_invocations "
        "WHERE agent_key='SubB' AND principal_id='OrchB'"
    )).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "blocked"

    viols = _count_violations(db, "SubB")
    assert len(viols) == 1
    assert viols[0][2] in (1, True)


def test_default_mode_is_observe(db):
    # No env var set
    parent = {"agent_key": "P_def", "access_level": "read"}
    sub = {"agent_key": "S_def", "access_level": "admin"}
    _snapshot_both(db, parent, sub)
    # Should not raise (observe default), but should still record
    inv_id = record_invocation(
        db, tenant_id=TENANT, agent_key="S_def",
        principal_kind="agent", principal_id="P_def",
        mode="observed", outcome="success",
    )
    assert isinstance(inv_id, int)
    rows = _count_violations(db, "S_def")
    assert len(rows) == 1
    assert rows[0][1] == "observe"


def test_unknown_mode_falls_back_to_observe(db, monkeypatch):
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "frobozz")
    parent = {"agent_key": "P_unk", "access_level": "read"}
    sub = {"agent_key": "S_unk", "access_level": "admin"}
    _snapshot_both(db, parent, sub)
    # Should not raise (falls back to observe)
    record_invocation(
        db, tenant_id=TENANT, agent_key="S_unk",
        principal_kind="agent", principal_id="P_unk",
        mode="observed", outcome="success",
    )
    rows = _count_violations(db, "S_unk")
    assert len(rows) == 1
    assert rows[0][1] == "observe"


def test_modes_constant_exposed():
    assert "observe" in DELEGATION_POLICY_MODES
    assert "flag" in DELEGATION_POLICY_MODES
    assert "block" in DELEGATION_POLICY_MODES
