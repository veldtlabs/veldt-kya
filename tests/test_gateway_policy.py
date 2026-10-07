"""Tests for kya_gateway.policy_pipeline.

Focused on the orchestration logic (RBAC matching, default-deny, action
wildcards, verdict assembly). Real KYA primitives (rate_limit,
tenant_budget, require_action) are not invoked in these tests — they're
imported lazily and gracefully skipped when unavailable.
"""
from __future__ import annotations

import pytest

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
    """Legacy alias sunset: a RBAC rule directly constructed
    with the legacy verdict "require_human" is normalized at the
    ``_rbac_evaluate`` boundary inside ``evaluate()``. Downstream
    Verdict carries the canonical form. Source-of-truth alias map
    lives in ``policy_pipeline`` — asserted through the constant.
    """
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
    from kya_gateway.policy_pipeline import _LEGACY_VERDICT_ALIASES
    assert v.verdict == _LEGACY_VERDICT_ALIASES["require_human"]
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


# ─── The pipeline turns a False from the replay check into a deny ───
#
# This section header used to read "replay protection actually works
# when wired in", which the test below does not establish. It installs a
# synthetic kya.replay_protection whose check returns False, so it
# proves the pipeline translates that return value into deny +
# REPLAY_DETECTED. It passes with the real primitive deleted, and did
# pass throughout every release in which the stage never ran.
#
# Whether replay protection works is established by
# test_replayed_invocation_is_denied_through_the_pipeline, which uses
# the real primitive against a real store.


def test_replay_detected_when_check_returns_false(monkeypatch):
    """A False from the check must become deny + REPLAY_DETECTED.

    Wiring only: the primitive here is synthetic. See the section note
    above for what this does not prove.
    """
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


def test_grant_check_runs_without_min_trust(monkeypatch):
    """The grant check must not depend on an unrelated trust threshold.

    ``require_action`` was called only when ``min_trust > 0``, so a
    principal whose grant had been revoked in ``kya_role_grants`` still
    passed the gateway unless an operator happened to have configured a
    trust threshold as well.
    """
    import sys
    import types

    class _FakeAccessDeniedError(Exception):
        pass

    calls = []

    def _deny(*args, **kw):
        calls.append(kw)
        raise _FakeAccessDeniedError("no grant")

    fake_kya = types.ModuleType("kya")
    fake_kya.AccessDeniedError = _FakeAccessDeniedError
    fake_kya.require_action = _deny
    monkeypatch.setitem(sys.modules, "kya", fake_kya)

    cfg = PolicyConfig(min_trust=0)
    v = evaluate(
        db=None,
        tenant_id="tenant-alpha",
        principal=_principal(),
        action="mcp.x.read",
        payload_bytes=100,
        cfg=cfg,
        invocation_id=1,
    )
    assert calls, "require_action was never called with min_trust=0"
    assert calls[0]["min_trust"] is None, (
        "min_trust=0 must not be passed as a trust threshold"
    )
    assert v.verdict == "deny"
    assert "RBAC_GRANT_DENIED" in v.reason_codes
    # the pre-existing code is preserved so operator alerting keyed on
    # it keeps matching
    assert "MIN_TRUST_NOT_MET" in v.reason_codes


# ──────────────────────────────────────────────────────────────────────
# A stage that cannot import its primitive must say so where an operator
# will see it. Every primitive the pipeline gates on ships in the core
# package and imports no optional dependency, so an ImportError is a
# missing symbol — a defect — and not a deployment variant.
#
# _install_module is used below to FORCE the error path. It is never used
# to supply the symbol under test: a test that manufactures the thing it
# is checking proves the test, not the system.


def _module_without(monkeypatch, name: str):
    """Put a real-looking module at ``name`` that has no attributes.

    ``from <name> import <symbol>`` then raises ImportError, which is the
    condition under test.
    """
    return _install_module(monkeypatch, name)


def test_missing_replay_primitive_logs_at_error(monkeypatch, caplog):
    """Skipping replay protection must be reported at ERROR, not DEBUG."""
    import logging
    _module_without(monkeypatch, "kya.replay_protection")

    cfg = PolicyConfig(min_trust=0)
    with caplog.at_level(logging.DEBUG, logger="kya_gateway.policy_pipeline"):
        evaluate(
            db=None,
            tenant_id="tenant-alpha",
            principal=_principal(),
            action="mcp.x.read",
            payload_bytes=100,
            invocation_id=42,       # non-None so the replay branch runs
            cfg=cfg,
        )

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, (
        "replay protection was skipped and nothing was logged at ERROR — "
        "an operator reading ERROR sees a healthy pipeline"
    )
    assert any("replay-protection stage SKIPPED" in r.getMessage()
               for r in errors), [r.getMessage() for r in errors]


def test_missing_budget_primitive_logs_at_error(monkeypatch, caplog):
    """Same contract on a second stage, so the first is not a one-off."""
    import logging
    from kya_gateway.config import BudgetConfig
    _module_without(monkeypatch, "kya.tenant_budget")

    cfg = PolicyConfig(min_trust=0,
                       tenant_budget=BudgetConfig(daily_usd=10.0))
    with caplog.at_level(logging.DEBUG, logger="kya_gateway.policy_pipeline"):
        evaluate(
            db=None,
            tenant_id="tenant-alpha",
            principal=_principal(),
            action="mcp.x.read",
            payload_bytes=100,
            invocation_id=None,
            cfg=cfg,
        )

    assert any(
        r.levelno >= logging.ERROR
        and "tenant-budget stage SKIPPED" in r.getMessage()
        for r in caplog.records
    ), [(r.levelname, r.getMessage()) for r in caplog.records]


def test_no_import_guard_hides_a_missing_first_party_symbol():
    """Every ``except ImportError`` guard must name a symbol that exists.

    This is the check whose absence let two stages ship dead. An import
    behind ``except ImportError`` makes a symbol that was never written
    indistinguishable at runtime from one that is merely absent, so the
    handler reports a missing install for a module that is installed.

    It swept by hand once and missed two guards in
    ``kya_gateway/identity.py``, so it sweeps the AST now. Third-party
    guards (presidio, redis, pyjwt) are excluded: those are genuine
    optional dependencies and their absence is a real deployment
    variant. First-party ones are not.
    """
    import ast
    import importlib
    import pathlib

    roots = [pathlib.Path(p) for p in ("kya", "kya_gateway")]
    if not all(r.is_dir() for r in roots):
        pytest.skip("source tree not present (installed-wheel run)")

    def _handles_import_error(try_node):
        for h in try_node.handlers:
            ty = h.type
            if isinstance(ty, ast.Name) and ty.id == "ImportError":
                return True
            if isinstance(ty, ast.Tuple) and any(
                    getattr(e, "id", "") == "ImportError" for e in ty.elts):
                return True
        return False

    missing = []
    for root in roots:
        for path in root.rglob("*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:                       # pragma: no cover
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Try):
                    continue
                if not _handles_import_error(node):
                    continue
                for sub in ast.walk(node):
                    if not isinstance(sub, ast.ImportFrom):
                        continue
                    mod_name = sub.module or ""
                    if not (mod_name in ("kya", "kya_gateway")
                            or mod_name.startswith(("kya.", "kya_gateway."))):
                        continue
                    try:
                        mod = importlib.import_module(mod_name)
                    except ImportError as exc:
                        missing.append(
                            f"{path}:{sub.lineno} module {mod_name} "
                            f"unimportable ({exc})")
                        continue
                    for alias in sub.names:
                        if not hasattr(mod, alias.name):
                            missing.append(
                                f"{path}:{sub.lineno} "
                                f"{mod_name}.{alias.name}")

    assert not missing, (
        "these guarded imports name first-party symbols that do not "
        "exist, so the code behind each guard never runs: "
        + "; ".join(missing)
    )


# ──────────────────────────────────────────────────────────────────────
# Replay protection, through the real request path.
#
# The stage below shipped dead for every release of this package: the
# pipeline imported a symbol that did not exist, the ImportError was
# swallowed, and two tests passed because they synthesised the module.
# These tests use the real primitive against a real store, because the
# only question worth asking is whether a replayed invocation is denied.
#
# They skip when no store is configured. That is not a soft option: the
# primitive is deliberately fail-open when the store is unreachable, so
# without one these assertions would pass while proving nothing.

def _replay_store_or_skip():
    import os
    url = os.environ.get("KYA_VALKEY_URL", "").strip()
    if not url:
        pytest.skip("KYA_VALKEY_URL unset — replay protection fails open "
                    "without a store, so this cannot be asserted here")
    try:
        import redis
        redis.Redis.from_url(url, socket_connect_timeout=2).ping()
    except Exception as exc:
        pytest.skip(f"replay store at KYA_VALKEY_URL unreachable: {exc}")
    return url


def test_replayed_invocation_is_denied_through_the_pipeline(monkeypatch):
    """A second evaluate() on the same invocation_id must deny."""
    import uuid
    _replay_store_or_skip()
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")

    tenant = "tenant-" + uuid.uuid4().hex[:10]
    invocation = 777001
    cfg = PolicyConfig(min_trust=0)

    def _call():
        return evaluate(
            db=None,
            tenant_id=tenant,
            principal=_principal(),
            action="mcp.x.read",
            payload_bytes=100,
            invocation_id=invocation,
            cfg=cfg,
        )

    first = _call()
    assert first.verdict != "deny" or "REPLAY_DETECTED" not in first.reason_codes, (
        f"first use of an invocation was treated as a replay: {first}")

    second = _call()
    assert second.verdict == "deny", (
        f"a replayed invocation_id was not denied: {second}")
    assert "REPLAY_DETECTED" in second.reason_codes, second.reason_codes


def test_replay_reservation_is_scoped_to_the_tenant(monkeypatch):
    """One tenant's invocation id must not mask another's.

    The reservation namespace is why tenant_id and principal_id are
    required arguments rather than defaulted.
    """
    import uuid
    _replay_store_or_skip()
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")

    invocation = 777002
    cfg = PolicyConfig(min_trust=0)

    def _call(tenant):
        return evaluate(
            db=None,
            tenant_id=tenant,
            principal=_principal(),
            action="mcp.x.read",
            payload_bytes=100,
            invocation_id=invocation,
            cfg=cfg,
        )

    a = "tenant-" + uuid.uuid4().hex[:10]
    b = "tenant-" + uuid.uuid4().hex[:10]
    _call(a)                      # reserve under tenant a
    other = _call(b)              # same id, different tenant
    assert "REPLAY_DETECTED" not in other.reason_codes, (
        "tenant b was denied for an invocation id reserved by tenant a — "
        "the reservation namespace is not scoped"
    )
