"""Phase 5b — RBAC tests. Off-by-default contract + grant/revoke
CRUD + has_action resolution + require_action enforcement across
soft/flag/block modes."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    AccessDeniedError,
    InvalidActionError,
    InvalidRbacModeError,
    RBAC_ACTIONS,
    RBAC_MODES,
    active_rbac_mode,
    configure_rbac,
    grant_action,
    has_action,
    init_storage,
    list_grants,
    require_action,
    revoke_action,
)


TENANT_A = "11111111-2222-3333-4444-eeeeeeeeeeee"
TENANT_B = "11111111-2222-3333-4444-ffffffffffff"
OPERATOR = "00000000-0000-0000-0000-000000000001"


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
    saved = os.environ.pop("KYA_RBAC_ENFORCEMENT", None)
    yield
    if saved is not None:
        os.environ["KYA_RBAC_ENFORCEMENT"] = saved
    else:
        os.environ.pop("KYA_RBAC_ENFORCEMENT", None)


# ── Mode configuration ─────────────────────────────────────────────


def test_default_mode_is_off():
    assert active_rbac_mode() == "off"


def test_configure_rbac_sets_env_and_returns_mode():
    assert configure_rbac("flag") == "flag"
    assert active_rbac_mode() == "flag"
    assert os.environ["KYA_RBAC_ENFORCEMENT"] == "flag"


def test_configure_rbac_normalizes_case():
    assert configure_rbac("  BLOCK  ") == "block"


def test_configure_rbac_rejects_unknown_mode():
    with pytest.raises(InvalidRbacModeError):
        configure_rbac("frobozz")


def test_modes_constant_exposed():
    assert {"off", "flag", "block"} == set(RBAC_MODES)


def test_actions_closed_set_exposed():
    assert "kya.budget.write" in RBAC_ACTIONS
    assert "kya.*" in RBAC_ACTIONS
    assert "kya.evidence.read" in RBAC_ACTIONS
    assert "frobozz" not in RBAC_ACTIONS


# ── Off-by-default contract ────────────────────────────────────────


def test_require_action_off_default(db):
    """No env, no kwarg → require_action returns True without
    even hitting the DB."""
    assert require_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="never-granted",
        action="kya.budget.write") is True


def test_require_action_off_skips_check(db):
    """Even with no grants in the DB, off-mode passes through."""
    # No grants set up at all
    assert require_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="ghost",
        action="kya.budget.write",
        mode="off") is True


# ── Grant CRUD ─────────────────────────────────────────────────────


def test_grant_action_creates_row(db):
    gid = grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.write",
        granted_by=OPERATOR,
        reason="Alice runs the budget team")
    assert isinstance(gid, int) and gid > 0


def test_grant_action_idempotent(db):
    gid1 = grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="bob",
        action="kya.budget.read")
    gid2 = grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="bob",
        action="kya.budget.read")
    assert gid1 == gid2  # same row, no duplicates


def test_grant_action_unknown_raises(db):
    with pytest.raises(InvalidActionError):
        grant_action(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id="alice",
            action="frobozz")


def test_grant_action_empty_tenant_raises(db):
    with pytest.raises(ValueError, match="tenant_id"):
        grant_action(
            db, tenant_id="",
            principal_kind="user", principal_id="alice",
            action="kya.budget.read")


def test_revoke_action_existing_returns_true(db):
    grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="charlie",
        action="kya.cost.read")
    assert revoke_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="charlie",
        action="kya.cost.read") is True


def test_revoke_action_missing_returns_false(db):
    assert revoke_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="ghost",
        action="kya.cost.read") is False


# ── list_grants ────────────────────────────────────────────────────


def test_list_grants_scopes_by_tenant(db):
    grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.read")
    grant_action(
        db, tenant_id=TENANT_B,
        principal_kind="user", principal_id="alice",
        action="kya.budget.read")
    a = list_grants(db, tenant_id=TENANT_A)
    b = list_grants(db, tenant_id=TENANT_B)
    assert len(a) == 1
    assert len(b) == 1
    # Cross-tenant isolation
    assert a[0]["principal_id"] == "alice"
    assert b[0]["principal_id"] == "alice"
    # Different rows from different tenant scopes
    assert a[0]["id"] != b[0]["id"]


def test_list_grants_filter_by_principal(db):
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="user", principal_id="alice",
                 action="kya.budget.read")
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="user", principal_id="bob",
                 action="kya.cost.read")
    alice_grants = list_grants(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice")
    assert len(alice_grants) == 1
    assert alice_grants[0]["action"] == "kya.budget.read"


# ── has_action ─────────────────────────────────────────────────────


def test_has_action_after_grant(db):
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="user", principal_id="alice",
                 action="kya.budget.write")
    assert has_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.write") is True


def test_has_action_denied_without_grant(db):
    assert has_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.write") is False


def test_wildcard_grants_everything(db):
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="user", principal_id="admin",
                 action="kya.*")
    # Wildcard grants any KYA action
    assert has_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="admin",
        action="kya.budget.write") is True
    assert has_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="admin",
        action="kya.evidence.export") is True


def test_expired_grant_not_active(db):
    past = datetime.now(timezone.utc) - timedelta(days=1)
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="user", principal_id="dave",
                 action="kya.budget.read",
                 expires_at=past)
    assert has_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="dave",
        action="kya.budget.read") is False


# ── require_action enforcement ─────────────────────────────────────


def test_require_action_block_mode_denies(db, monkeypatch):
    monkeypatch.setenv("KYA_RBAC_ENFORCEMENT", "block")
    with pytest.raises(AccessDeniedError) as exc_info:
        require_action(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id="evil",
            action="kya.budget.write")
    err = exc_info.value
    assert err.principal_id == "evil"
    assert err.action == "kya.budget.write"


def test_require_action_block_mode_allows_when_granted(db, monkeypatch):
    monkeypatch.setenv("KYA_RBAC_ENFORCEMENT", "block")
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="user", principal_id="alice",
                 action="kya.budget.write")
    assert require_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.write") is True


def test_require_action_flag_mode_logs_and_allows(db, monkeypatch, caplog):
    import logging
    monkeypatch.setenv("KYA_RBAC_ENFORCEMENT", "flag")
    caplog.set_level(logging.WARNING, logger="kya.rbac")
    # No grant — would deny in block, but flag mode allows
    assert require_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="eve",
        action="kya.evidence.export") is True
    # The flag-mode warning was logged
    assert any("(flag) denied" in r.message and "eve" in r.message
               for r in caplog.records)


def test_require_action_unknown_action_raises(db, monkeypatch):
    monkeypatch.setenv("KYA_RBAC_ENFORCEMENT", "block")
    with pytest.raises(InvalidActionError):
        require_action(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id="alice",
            action="frobozz")


# ── Default-deny on DB error ────────────────────────────────────


def test_require_action_validates_action_before_off_short_circuit(db):
    """Regression for review BUG #5 — invalid action must raise
    EVEN when mode=off. Validation happens before the off-mode
    short-circuit so typos are caught everywhere."""
    with pytest.raises(InvalidActionError):
        require_action(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id="alice",
            action="kya.budet.write",  # typo
            mode="off")


def test_has_action_default_deny_on_db_error(db, monkeypatch):
    """Confirm fail-closed posture: any DB error returns False."""
    monkeypatch.setattr(
        db, "execute",
        lambda *a, **kw: (_ for _ in ()).throw(
            RuntimeError("db down")))
    assert has_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.write") is False


# ── Trust-based block (min_trust kwarg) ────────────────────────────


def test_require_action_min_trust_passes_when_score_high(db):
    """min_trust=45 + trust=51 + grant present -> ALLOWED."""
    configure_rbac("block")
    from kya import record_principal_signal
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="good-agent", signal_kind="clean_invocation")
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="agent", principal_id="good-agent",
                 action="kya.budget.write", granted_by=TENANT_A)
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="good-agent", action="kya.budget.write",
        min_trust=45) is True


def test_require_action_min_trust_blocks_when_score_below(db):
    """min_trust=45 + trust=44 + grant present -> BLOCKED."""
    configure_rbac("block")
    from kya import record_principal_signal
    # Decay trust below threshold: start at 50, then 7-point penalty
    # (policy_violation default delta) lands at 43 < 45
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="bad-agent", signal_kind="clean_invocation")
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="bad-agent", signal_kind="policy_violation")
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="agent", principal_id="bad-agent",
                 action="kya.budget.write", granted_by=TENANT_A)
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id="bad-agent", action="kya.budget.write",
            min_trust=45)


def test_require_action_min_trust_flag_mode_allows_with_log(db):
    """flag mode -> low trust still passes but logs WARNING."""
    configure_rbac("flag")
    from kya import record_principal_signal
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="bad-agent2", signal_kind="clean_invocation")
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="bad-agent2", signal_kind="policy_violation")
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="agent", principal_id="bad-agent2",
                 action="kya.budget.write", granted_by=TENANT_A)
    # Flag mode: returns True (allowed) but emits security event.
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="bad-agent2", action="kya.budget.write",
        min_trust=45) is True


def test_require_action_min_trust_via_env(db, monkeypatch):
    """KYA_RBAC_MIN_TRUST_<ACTION> env var applies same as kwarg."""
    configure_rbac("block")
    monkeypatch.setenv("KYA_RBAC_MIN_TRUST_KYA_BUDGET_WRITE", "45")
    from kya import record_principal_signal
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="env-bad", signal_kind="clean_invocation")
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="env-bad", signal_kind="policy_violation")
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="agent", principal_id="env-bad",
                 action="kya.budget.write", granted_by=TENANT_A)
    with pytest.raises(AccessDeniedError):
        # No min_trust kwarg -- picks up the env.
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id="env-bad", action="kya.budget.write")


def test_require_action_min_trust_default_trust_behavior(db):
    """Principals with no signal history get the starting default
    trust (50). Verify the threshold check uses that default rather
    than failing-closed -- preserves 'innocent until proven guilty'.

    min_trust=45: default 50 >= 45 -> ALLOWED
    min_trust=60: default 50  < 60 -> BLOCKED
    """
    configure_rbac("block")
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="agent", principal_id="ghost",
                 action="kya.budget.write", granted_by=TENANT_A)
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="ghost", action="kya.budget.write",
        min_trust=45) is True
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id="ghost", action="kya.budget.write",
            min_trust=60)


def test_require_action_no_min_trust_keeps_legacy_behavior(db):
    """Without min_trust (kwarg or env), behavior is identical to
    pre-#42 -- pure grant check. Backward-compat regression."""
    configure_rbac("block")
    grant_action(db, tenant_id=TENANT_A,
                 principal_kind="user", principal_id="legacy",
                 action="kya.budget.write", granted_by=TENANT_A)
    # No trust row, no min_trust kwarg -> ALLOWED via grant alone.
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="user",
        principal_id="legacy", action="kya.budget.write") is True
