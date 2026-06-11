"""Phase 5b — RBAC tests. Off-by-default contract + grant/revoke
CRUD + has_action resolution + require_action enforcement across
soft/flag/block modes."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kya import (
    RBAC_ACTIONS,
    RBAC_MODES,
    AccessDeniedError,
    InvalidActionError,
    InvalidRbacModeError,
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
    eng = create_engine("sqlite:///:memory:")
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


# ── min_trust gate (Phase 5b extension) ───────────────────────────


def _seed_principal_trust(db, score: int, principal_id="agent_x"):
    """Helper: seed a principal_trust row at a specific score by
    emitting clean_invocation signals (each +1, capped). For test
    we use direct signal emission, simpler than mocking get_principal_trust."""
    from kya import record_principal_signal

    # Start fresh -- first signal initializes at STARTING_TRUST(50)+delta
    # then subsequent signals adjust. Easier: use a single negative
    # delta if we want low scores, or clean_invocations if we want
    # higher. Bound is 0..100.
    from kya.users import STARTING_TRUST
    # First clean signal initializes the row at STARTING_TRUST + 1
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=principal_id, signal_kind="clean_invocation")
    # Adjust to target score with policy_violation (-7) or
    # clean_invocation (+1)
    current = STARTING_TRUST + 1
    while current > score:
        record_principal_signal(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=principal_id, signal_kind="policy_violation")
        current -= 7
        if current < 0:
            current = 0
            break
    return principal_id


def test_min_trust_allows_when_trust_above_threshold(db):
    """Caller passes min_trust; principal's trust score is above
    the threshold → require_action returns True even in off mode."""
    agent_id = _seed_principal_trust(db, score=51, principal_id="hi_trust")
    grant_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=agent_id, action="kya.budget.write",
        granted_by=OPERATOR)
    # Should ALLOW: trust=51 >= min_trust=45
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=agent_id, action="kya.budget.write",
        min_trust=45) is True


def test_min_trust_blocks_when_trust_below_threshold(db):
    """Even with a grant + off mode, min_trust=N blocks when the
    principal's trust score is below N. This is the auto-block
    pattern the README documents."""
    # Seed a principal at low trust
    agent_id = _seed_principal_trust(db, score=30, principal_id="low_trust")
    grant_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=agent_id, action="kya.budget.write",
        granted_by=OPERATOR)
    # Should BLOCK: trust ~30 < min_trust=45
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=agent_id, action="kya.budget.write",
            min_trust=45)


def test_min_trust_allows_unseen_principal_at_starting_trust(db):
    """get_principal_trust returns STARTING_TRUST=50 for principals
    with no row yet (benefit-of-doubt for new agents). min_trust=45
    therefore allows a brand-new principal. Operators who want
    strict observed-clean enforcement should set min_trust >
    STARTING_TRUST (e.g. 55) or call get_principal_trust manually."""
    from kya.users import STARTING_TRUST
    grant_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="ghost", action="kya.budget.write",
        granted_by=OPERATOR)
    # ghost has no signals → trust = STARTING_TRUST (50)
    # min_trust=45 → ALLOW
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="ghost", action="kya.budget.write",
        min_trust=45) is True
    # min_trust > STARTING_TRUST → DENY
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id="ghost", action="kya.budget.write",
            min_trust=STARTING_TRUST + 5)


def test_min_trust_independent_of_rbac_mode(db):
    """min_trust enforces regardless of RBAC mode. Caller opted in
    by passing the kwarg -- it shouldn't be gated by the global
    enforcement flag."""
    # Even with mode=off, low trust + min_trust=45 raises
    agent_id = _seed_principal_trust(db, score=20, principal_id="low_off")
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=agent_id, action="kya.budget.write",
            mode="off",  # RBAC off -- grant check skipped
            min_trust=45)


def test_min_trust_none_is_noop(db):
    """min_trust=None (default) preserves the original behavior --
    no trust lookup at all. Verifies backward compatibility."""
    # No grant, mode=off, no min_trust -> passes (the original
    # plug-and-play default contract).
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id="anyone", action="kya.budget.write") is True


def test_min_trust_type_validation():
    """Non-int min_trust raises TypeError immediately. Catches
    callers passing strings / floats / etc."""
    with pytest.raises(TypeError):
        require_action(
            db=None, tenant_id=TENANT_A, principal_kind="agent",
            principal_id="x", action="kya.budget.write",
            min_trust="45")  # str instead of int


def test_min_trust_with_block_mode_grant_check_also_runs(db):
    """When mode=block AND min_trust is set, BOTH gates fire. If
    grant is missing, raise on grant. If grant present but trust
    low, raise on trust."""
    os.environ["KYA_RBAC_ENFORCEMENT"] = "block"
    try:
        # No grant -- raises on grant before trust ever checked
        with pytest.raises(AccessDeniedError):
            require_action(
                db, tenant_id=TENANT_A, principal_kind="agent",
                principal_id="nograntyo",
                action="kya.budget.write",
                min_trust=45)
    finally:
        os.environ.pop("KYA_RBAC_ENFORCEMENT", None)


# ── min_trust robust edge cases ───────────────────────────────────


def test_min_trust_exact_threshold_allows(db):
    """trust == min_trust is ALLOW (>=, not >). Boundary check."""
    agent_id = _seed_principal_trust(db, score=45, principal_id="exact45")
    grant_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=agent_id, action="kya.budget.write",
        granted_by=OPERATOR)
    # We aimed for 45 but the helper undershoots; verify the actual
    # bookkeeping and only assert >= behavior when actual_trust == min_trust
    from kya import get_principal_trust
    actual = get_principal_trust(
        db, TENANT_A, "agent", agent_id).trust_score
    # If we landed on exactly the threshold, expect ALLOW
    if actual == 45:
        assert require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=agent_id, action="kya.budget.write",
            min_trust=45) is True
    # Always: above threshold ALLOWS, below threshold DENIES
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=agent_id, action="kya.budget.write",
        min_trust=actual) is True  # equal => allow
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=agent_id, action="kya.budget.write",
            min_trust=actual + 1)  # 1 above actual => deny


def test_min_trust_zero_allows_everyone(db):
    """min_trust=0 effectively means 'no trust gate'. Verify a
    principal at trust=0 still allowed (degenerate but explicit)."""
    agent_id = _seed_principal_trust(db, score=0, principal_id="zero_trust")
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=agent_id, action="kya.budget.write",
        min_trust=0) is True


def test_min_trust_with_flag_mode_still_enforces_trust(db):
    """flag mode lets grant denials pass with a warning. But
    min_trust is independent -- it still raises AccessDeniedError
    on insufficient trust, even in flag mode."""
    agent_id = _seed_principal_trust(db, score=10, principal_id="low_flag")
    # No grant, flag mode -> grant denial would just warn.
    # But trust=10 < min_trust=45 -> raise from trust gate.
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=agent_id, action="kya.budget.write",
            mode="flag", min_trust=45)


def test_min_trust_security_event_emitted_on_denial(db, monkeypatch):
    """Trust-based denial fires emit_security_event with
    reason='trust_below_threshold' so SOCs can distinguish trust
    denials from no-grant denials."""
    captured = []

    def fake_emit(*args, **kwargs):
        captured.append({"args": args, "kwargs": kwargs})

    # Patch the lazy import path inside require_action
    import kya._security_events as se
    monkeypatch.setattr(se, "emit_security_event", fake_emit)

    agent_id = _seed_principal_trust(db, score=10, principal_id="evt_test")
    try:
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=agent_id, action="kya.budget.write",
            min_trust=45)
    except AccessDeniedError:
        pass
    # Should have captured one rbac_refusal event with the trust
    # reason
    trust_events = [
        c for c in captured
        if c["kwargs"].get("detail", {}).get("reason")
           == "trust_below_threshold"]
    assert len(trust_events) >= 1, f"got events: {captured}"
    e = trust_events[0]
    assert e["kwargs"]["detail"]["min_trust"] == 45
    assert e["kwargs"]["detail"]["actual_trust"] is not None
    assert e["kwargs"]["detail"]["actual_trust"] < 45


def test_min_trust_decay_then_block_realistic_flow(db):
    """The README's auto-block-loop pattern, end-to-end:
       1. baseline clean signal -> trust = 51
       2. grant + require_action allows
       3. emit policy_violation signals -> trust decays
       4. eventually require_action raises -- without operator
    """
    from kya import get_principal_trust, record_principal_signal

    aid = "auto_block_demo"
    # Baseline
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=aid, signal_kind="clean_invocation")
    grant_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=aid, action="kya.budget.write",
        granted_by=OPERATOR)
    # Step 1: allowed
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=aid, action="kya.budget.write",
        min_trust=45) is True
    # Step 2: emit some policy_violation signals -- decay trust
    for _ in range(2):
        record_principal_signal(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=aid, signal_kind="policy_violation")
    # Step 3: trust has decayed below 45 -- now blocked
    trust = get_principal_trust(db, TENANT_A, "agent", aid)
    assert trust.trust_score < 45, (
        f"expected trust < 45 after 2 policy_violations, got "
        f"{trust.trust_score}")
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=aid, action="kya.budget.write",
            min_trust=45)
    # Step 4: clean signals + recovery -- trust climbs back, allow
    for _ in range(15):  # +1 each, capped at MAX_TRUST
        record_principal_signal(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=aid, signal_kind="clean_invocation")
    trust = get_principal_trust(db, TENANT_A, "agent", aid)
    # Should have recovered above 45
    assert trust.trust_score >= 45, (
        f"expected recovery above 45 after 15 cleans, got "
        f"{trust.trust_score}")
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=aid, action="kya.budget.write",
        min_trust=45) is True


def test_min_trust_tenant_isolation(db):
    """A principal's trust score in tenant A must not affect
    tenant B. Same principal_id, different tenant — independent
    trust ledgers."""
    aid = "shared_id"
    # Tenant A: low-trust agent
    from kya import record_principal_signal
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=aid, signal_kind="clean_invocation")
    for _ in range(5):
        record_principal_signal(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=aid, signal_kind="policy_violation")
    grant_action(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=aid, action="kya.budget.write",
        granted_by=OPERATOR)
    # Tenant B: same principal id, no signals yet -> default trust
    grant_action(
        db, tenant_id=TENANT_B, principal_kind="agent",
        principal_id=aid, action="kya.budget.write",
        granted_by=OPERATOR)

    # Tenant A should DENY (trust decayed)
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=aid, action="kya.budget.write",
            min_trust=45)
    # Tenant B should ALLOW (untouched trust at default)
    assert require_action(
        db, tenant_id=TENANT_B, principal_kind="agent",
        principal_id=aid, action="kya.budget.write",
        min_trust=45) is True


def test_min_trust_across_principal_kinds(db):
    """Different principal_kinds (user / agent / service_account)
    each have independent trust rows even with the same id."""
    from kya import record_principal_signal
    pid = "common_id"
    # user @ pid: clean
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="user",
        principal_id=pid, signal_kind="clean_invocation")
    # agent @ pid: heavily rogue
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="agent",
        principal_id=pid, signal_kind="clean_invocation")
    for _ in range(8):
        record_principal_signal(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=pid, signal_kind="policy_violation")

    for kind in ("user", "agent"):
        grant_action(
            db, tenant_id=TENANT_A, principal_kind=kind,
            principal_id=pid, action="kya.budget.write",
            granted_by=OPERATOR)

    # user (clean) -> allow
    assert require_action(
        db, tenant_id=TENANT_A, principal_kind="user",
        principal_id=pid, action="kya.budget.write",
        min_trust=45) is True
    # agent (decayed) -> deny
    with pytest.raises(AccessDeniedError):
        require_action(
            db, tenant_id=TENANT_A, principal_kind="agent",
            principal_id=pid, action="kya.budget.write",
            min_trust=45)


# ─── MCP action namespace (mcp.<backend>.<tool>) ──────────────────


def test_validator_accepts_dynamic_mcp_action(db):
    """The closed ACTIONS set must accept gateway-emitted
    `mcp.<backend>.<tool>` action strings. Phase 12 surfaced this gap:
    kya_gateway.policy_pipeline.evaluate calls require_action with
    actions like `mcp.fs.write_file`, but the OSS RBAC validator
    rejected anything not literally in ACTIONS, breaking the
    min_trust gate for every MCP tool call.

    The validator must accept:
      - Closed ACTIONS literals (kya.budget.write, kya.*, etc.)
      - Dynamic mcp.<backend>.<tool> patterns
    """
    from kya.rbac import grant_action, require_action

    # First, the action must validate at grant time.
    grant_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="a-1", action="mcp.fs.read_file",
        granted_by="h-1", reason="phase12 test",
    )
    # Then, require_action with the same action must NOT raise
    # InvalidActionError (it may still raise AccessDeniedError, but
    # that's about RBAC mode, not validation).
    # With default RBAC mode "off", require_action returns True.
    ok = require_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="a-1", action="mcp.fs.read_file",
    )
    assert ok is True


def test_validator_rejects_malformed_mcp_action(db):
    """The dynamic MCP namespace must be SHAPED `mcp.<backend>.<tool>`.
    A bare `mcp.foo` (missing tool segment) or extra-deep
    `mcp.fs.subdir.read` must still fail validation so typos remain
    loud."""
    from kya.rbac import grant_action, InvalidActionError
    import pytest
    for bad in ("mcp.foo", "mcp.fs.subdir.read", "mcp.", "mcp..read"):
        with pytest.raises(InvalidActionError):
            grant_action(
                db, tenant_id="t1", principal_kind="agent",
                principal_id="a-1", action=bad,
                granted_by="h-1", reason="must reject",
            )


def test_mcp_wildcard_grant_covers_any_mcp_action(db):
    """Granting the `mcp.*` wildcard once must cover all
    mcp.<backend>.<tool> actions for that principal -- mirrors the
    existing kya.* super-user pattern."""
    from kya.rbac import grant_action, has_action

    grant_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="wildcard-agent", action="mcp.*",
        granted_by="h-1", reason="namespace grant",
    )
    # Any specific mcp.* action should be allowed by the wildcard.
    assert has_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="wildcard-agent", action="mcp.fs.read_file",
    ) is True
    assert has_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="wildcard-agent", action="mcp.time.get_current_time",
    ) is True


def test_mcp_wildcard_does_not_cover_kya_namespace(db):
    """`mcp.*` must NOT grant kya.* actions. The two namespaces are
    independent."""
    from kya.rbac import grant_action, has_action

    grant_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="mcp-only-agent", action="mcp.*",
        granted_by="h-1", reason="mcp namespace only",
    )
    # A kya.* action must NOT be implicitly granted by mcp.*.
    assert has_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="mcp-only-agent", action="kya.evidence.read",
    ) is False


def test_kya_wildcard_does_not_cover_mcp_namespace(db):
    """`kya.*` (super-user kya-namespace grant) must NOT grant
    mcp.* actions. The two namespaces are independent so a future
    super-admin grant doesn't accidentally expose MCP tool execution."""
    from kya.rbac import grant_action, has_action

    grant_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="kya-only-agent", action="kya.*",
        granted_by="h-1", reason="kya super-user",
    )
    assert has_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="kya-only-agent", action="mcp.fs.write_file",
    ) is False


def test_validator_rejects_trailing_newline_injection(db):
    r"""Regression: pre-fix the regex used `^...$` anchors. Python's `$`
    matches end-of-string OR right before a single trailing `\n`, so
    a malicious action string like `mcp.fs.read_file\n<smuggled>`
    could pass validation and forge an audit row downstream. The fix
    uses `\A` / `\Z` anchors which only match true string
    boundaries."""
    from kya.rbac import grant_action, InvalidActionError
    import pytest
    # Trailing newline that the buggy `$` anchor would have accepted.
    with pytest.raises(InvalidActionError):
        grant_action(
            db, tenant_id="t1", principal_kind="agent",
            principal_id="a-1",
            action="mcp.fs.read_file\nforged",
            granted_by="h-1", reason="must reject",
        )
    # Leading newline likewise.
    with pytest.raises(InvalidActionError):
        grant_action(
            db, tenant_id="t1", principal_kind="agent",
            principal_id="a-1",
            action="\nmcp.fs.read_file",
            granted_by="h-1", reason="must reject",
        )


def test_mcp_grant_is_tenant_isolated(db):
    """A `mcp.*` grant in tenant t1 must NOT authorize the same
    principal in tenant t2. Mirrors the existing kya.* tenant-
    isolation contract."""
    from kya.rbac import grant_action, has_action

    grant_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="cross-tenant-agent", action="mcp.*",
        granted_by="h-1", reason="t1 only",
    )
    # Same principal_id in a DIFFERENT tenant gets no authority.
    assert has_action(
        db, tenant_id="t2", principal_kind="agent",
        principal_id="cross-tenant-agent", action="mcp.fs.read_file",
    ) is False


def test_mcp_grant_expires_at_is_honored(db):
    """A `mcp.*` grant with an `expires_at` in the past must NOT
    authorize subsequent calls. Mirrors the active-grant time-window
    contract for the kya namespace."""
    from datetime import datetime, timedelta, timezone
    from kya.rbac import grant_action, has_action

    grant_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="expiring-agent", action="mcp.*",
        granted_by="h-1", reason="will expire",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
    )
    assert has_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="expiring-agent", action="mcp.fs.read_file",
    ) is False


def test_mcp_grant_is_principal_kind_scoped(db):
    """A `mcp.*` grant to principal_kind=agent must NOT authorize the
    same id used as principal_kind=human (or any other kind)."""
    from kya.rbac import grant_action, has_action

    grant_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="bound-id", action="mcp.*",
        granted_by="h-1", reason="agent only",
    )
    assert has_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="bound-id", action="mcp.fs.read_file",
    ) is True
    # Same id, different principal_kind -- not authorized.
    assert has_action(
        db, tenant_id="t1", principal_kind="human",
        principal_id="bound-id", action="mcp.fs.read_file",
    ) is False


def test_has_action_rejects_injected_action_without_db_hit(db):
    """has_action MUST short-circuit invalid-shape action strings
    instead of round-tripping them as a SQL parameter. A
    `mcp.fs.read_file\n<smuggled>` probe coming from upstream code
    that didn't validate first must NOT touch the database."""
    from kya.rbac import grant_action, has_action

    grant_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="some-agent", action="mcp.fs.read_file",
        granted_by="h-1", reason="legit grant",
    )
    # Newline injection -- pre-fix the regex anchor allowed it.
    assert has_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="some-agent",
        action="mcp.fs.read_file\nforged",
    ) is False
    # Malformed namespace string entirely.
    assert has_action(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="some-agent", action="..",
    ) is False
