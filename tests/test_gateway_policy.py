"""Tests for kya_gateway.policy_pipeline.

Focused on the orchestration logic (RBAC matching, default-deny, action
wildcards, verdict assembly). Real KYA primitives (rate_limit,
tenant_budget, require_action) are not invoked in these tests — they're
imported lazily and gracefully skipped when unavailable.
"""
from __future__ import annotations

from kya_gateway.config import (
    PayloadCapsConfig,
    PolicyConfig,
    RBACConfig,
    RBACRule,
)
from kya_gateway.identity import BoundPrincipal
from kya_gateway.policy_pipeline import (
    _action_matches,
    _rbac_evaluate,
    evaluate,
)


def _principal(kind: str = "agent") -> BoundPrincipal:
    return BoundPrincipal(
        principal_kind=kind,
        principal_id="planner",
        method="bearer_jwt",
        external_subject="planner",
        external_issuer=None,
    )


# ─── _action_matches ────────────────────────────────────────────────


def test_action_matches_exact():
    assert _action_matches("mcp.filesystem.read", ["mcp.filesystem.read"]) is True


def test_action_matches_wildcard_namespace():
    assert _action_matches("mcp.filesystem.read", ["mcp.filesystem.*"]) is True
    assert _action_matches("mcp.filesystem.write", ["mcp.filesystem.*"]) is True


def test_action_matches_global_wildcard():
    assert _action_matches("anything.at.all", ["*"]) is True


def test_action_no_match():
    assert _action_matches("mcp.postgres.read", ["mcp.filesystem.*"]) is False


# ─── _rbac_evaluate ─────────────────────────────────────────────────


def test_rbac_default_deny_with_no_matching_rule():
    rbac = RBACConfig(default="deny", rules=[])
    assert _rbac_evaluate(rbac, "agent", "mcp.x.read") == "deny"


def test_rbac_matching_rule_wins():
    rbac = RBACConfig(default="deny", rules=[
        RBACRule(principal_kind="agent",
                 actions=["mcp.filesystem.read"],
                 verdict="allow"),
    ])
    assert _rbac_evaluate(rbac, "agent", "mcp.filesystem.read") == "allow"
    # Different action falls through to default
    assert _rbac_evaluate(rbac, "agent", "mcp.filesystem.write") == "deny"


def test_rbac_require_human_verdict():
    rbac = RBACConfig(default="deny", rules=[
        RBACRule(principal_kind="agent",
                 actions=["mcp.fs.write"],
                 verdict="require_human"),
    ])
    assert _rbac_evaluate(rbac, "agent", "mcp.fs.write") == "require_human"


def test_rbac_principal_kind_filter():
    """A rule that targets agents shouldn't fire for users."""
    rbac = RBACConfig(default="deny", rules=[
        RBACRule(principal_kind="agent",
                 actions=["mcp.x.read"],
                 verdict="allow"),
    ])
    assert _rbac_evaluate(rbac, "user", "mcp.x.read") == "deny"


# ─── evaluate() — end-to-end orchestration ─────────────────────────


def test_evaluate_allows_when_no_policy_block_configured():
    """Empty policy config defaults to allow (KYA's role is to evaluate,
    not to default to deny in the absence of rules)."""
    cfg = PolicyConfig(min_trust=0)
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=100,
        invocation_id=None,
        cfg=cfg,
    )
    assert v.verdict == "allow"
    assert v.reason_codes == []


def test_evaluate_payload_too_large():
    cfg = PolicyConfig(
        min_trust=0,
        payload_caps=PayloadCapsConfig(max_bytes=1024),
    )
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=2048,
        invocation_id=None,
        cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "PAYLOAD_TOO_LARGE" in v.reason_codes


def test_evaluate_rbac_deny():
    cfg = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[]),
    )
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=100,
        invocation_id=None,
        cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "RBAC_DENY" in v.reason_codes


def test_evaluate_require_human():
    cfg = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[
            RBACRule(principal_kind="agent",
                     actions=["mcp.x.write"],
                     verdict="require_human"),
        ]),
    )
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.write",
        payload_bytes=100,
        invocation_id=None,
        cfg=cfg,
    )
    assert v.verdict == "require_human"
    assert "REQUIRES_HUMAN" in v.reason_codes


# ─── B1: fail-CLOSED when primitives raise runtime errors ─────────────
#
# Each KYA primitive (check_rate, check_invocation_replay, should_refuse,
# require_action) may raise on DB / network / config errors at runtime.
# The pipeline must NOT propagate these as 500 (operationally bad), nor
# silently skip (security catastrophe — that's fail-open). It must
# explicitly return Verdict(deny, "<PRIMITIVE>_ERROR").


def _install_module(monkeypatch, name: str, **attrs):
    """Inject a synthetic module under ``name`` with given attributes."""
    import sys
    import types
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, name, mod)
    return mod


def test_rate_limit_runtime_error_fails_closed(monkeypatch):
    """check_rate raising an OperationalError must produce deny, not propagate."""
    from kya_gateway.config import RateLimitConfig

    def boom(*args, **kw):
        raise RuntimeError("DB connection lost")
    _install_module(monkeypatch, "kya.rate_limit", check_rate=boom)

    cfg = PolicyConfig(
        min_trust=0,
        # Any valid rate-limit value works for this fail-closed
        # test; the boom helper above intercepts check_rate before
        # the actual rate value matters. Was `requests_per_minute=10`
        # pre-rename; the new validator requires >= 60.
        rate_limit=RateLimitConfig(requests_per_minute=60),
    )
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=100,
        invocation_id=None,
        cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "RATE_LIMIT_ERROR" in v.reason_codes


def test_replay_runtime_error_fails_closed(monkeypatch):
    """check_invocation_replay raising must produce deny, not propagate."""
    def boom(*args, **kw):
        raise RuntimeError("replay store unreachable")
    _install_module(monkeypatch, "kya.replay_protection",
                    check_invocation_replay=boom)

    cfg = PolicyConfig(min_trust=0)
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=100,
        invocation_id=42,  # non-None so the replay branch runs
        cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "REPLAY_ERROR" in v.reason_codes


def test_budget_runtime_error_fails_closed(monkeypatch):
    """should_refuse raising must produce deny, not propagate."""
    from kya_gateway.config import BudgetConfig

    def boom(*args, **kw):
        raise RuntimeError("budget DB unreachable")
    _install_module(monkeypatch, "kya.tenant_budget", should_refuse=boom)

    cfg = PolicyConfig(
        min_trust=0,
        tenant_budget=BudgetConfig(daily_usd=100.0),
    )
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=100,
        invocation_id=None,
        cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "BUDGET_ERROR" in v.reason_codes


def test_min_trust_runtime_error_fails_closed(monkeypatch):
    """require_action raising a non-AccessDeniedError must fail closed."""
    import sys
    import types

    class _FakeAccessDeniedError(Exception):
        pass

    def boom(*args, **kw):
        raise RuntimeError("trust store unreachable")

    fake_kya = types.ModuleType("kya")
    fake_kya.AccessDeniedError = _FakeAccessDeniedError
    fake_kya.require_action = boom
    monkeypatch.setitem(sys.modules, "kya", fake_kya)

    cfg = PolicyConfig(min_trust=50)
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=100,
        invocation_id=None,
        cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "MIN_TRUST_ERROR" in v.reason_codes


# ─── Replay protection actually works when wired in ────────────────


def test_replay_detected_when_check_returns_false(monkeypatch):
    """check_invocation_replay returning False → REPLAY_DETECTED."""
    def is_fresh(*args, **kw):
        return False  # replay
    _install_module(monkeypatch, "kya.replay_protection",
                    check_invocation_replay=is_fresh)

    cfg = PolicyConfig(min_trust=0)
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=100,
        invocation_id=99,
        cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "REPLAY_DETECTED" in v.reason_codes
