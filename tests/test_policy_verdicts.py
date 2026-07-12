"""Tests for ``kya.policy_verdicts`` — verdict handler registry (#100).

Covers the dispatch semantics + every shipped default handler.

Fixtures reset the registry between tests so we don't leak state:
``reset_registry`` calls ``clear()`` + ``register_default_handlers()``
after each test. Tests that want a totally-blank registry use
``blank_registry`` which only calls ``clear()``.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from kya import policy_verdicts as pv
from kya.policy_verdicts import (
    MUTATION_KEYS,
    AllowHandler,
    GatewayDenyHandler,
    GatewayRequireHumanHandler,
    HandlerResult,
    VerdictContext,
    VerdictHandler,
    apply,
    clear,
    is_registered_exact,
    register,
    register_default_handlers,
    registered_verdicts,
    resolves,
    swap,
    unregister,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_registry():
    """Every test starts with a fresh set of default handlers.

    Autouse so no test can forget — cross-test leakage on a global
    registry is a nightmare to debug. ``clear()`` + re-register
    default handlers is cheap (~microseconds).
    """
    clear()
    register_default_handlers()
    yield
    clear()
    register_default_handlers()


@pytest.fixture
def blank_registry():
    """Explicit opt-in: test wants zero handlers registered."""
    clear()
    return None


def _ctx(
    verdict: str = "allow",
    layer: pv.ContextLayer = "gateway",
    reason_codes: list[str] | None = None,
    rich: dict | None = None,
    tenant_id: str = "tenant-1",
    principal_kind: str = "agent",
    principal_id: str = "agent-x",
    action: str = "mcp.filesystem.read",
    upstream_body: bytes | None = None,
    upstream_status: int | None = None,
) -> VerdictContext:
    """Build a VerdictContext with sensible defaults for tests."""
    return VerdictContext(
        verdict=verdict,
        reason_codes=list(reason_codes or []),
        tenant_id=tenant_id,
        principal_kind=principal_kind,
        principal_id=principal_id,
        action=action,
        layer=layer,
        upstream_body=upstream_body,
        upstream_status=upstream_status,
        rich=dict(rich or {}),
    )


# ═════════════════════════════════════════════════════════════════════
# Registry mechanics
# ═════════════════════════════════════════════════════════════════════


def test_defaults_are_registered_after_import(blank_registry):
    """A fresh clear() leaves the registry empty until we re-populate.
    Prove that then re-populating restores every OSS-shipped verdict.

    Note: action-gate handlers (redact/throttle/block) live in
    ``kya_pro.policy.verdict_handlers`` — they are NOT part of the
    OSS defaults. Pro-side tests verify those.
    """
    assert registered_verdicts() == []
    register_default_handlers()
    assert set(registered_verdicts()) == {
        "allow", "deny", "require_human",
    }


def test_register_stores_handler_by_verdict_and_layer(blank_registry):
    @dataclass(frozen=True)
    class Custom:
        verdict: str = "allow"
        layer: pv.HandlerLayer = "gateway"
        def apply(self, ctx): return HandlerResult(forward=True)

    handler = Custom()
    returned = register(handler)
    assert returned is handler
    assert is_registered_exact("allow", "gateway")
    assert not is_registered_exact("allow", "action_gate")


def test_register_overwrites_same_key(blank_registry):
    """Re-registering under the same (verdict, layer) key silently
    replaces — the documented plugin/override contract."""
    @dataclass(frozen=True)
    class First:
        verdict: str = "deny"
        layer: pv.HandlerLayer = "gateway"
        marker: str = "first"
        def apply(self, ctx): return HandlerResult(forward=False, http_status=403)

    @dataclass(frozen=True)
    class Second:
        verdict: str = "deny"
        layer: pv.HandlerLayer = "gateway"
        marker: str = "second"
        def apply(self, ctx): return HandlerResult(forward=False, http_status=418)

    register(First())
    register(Second())

    result = apply(_ctx(verdict="deny"))
    assert result.http_status == 418


def test_unregister_removes_only_that_key(blank_registry):
    register(AllowHandler())         # (allow, both)
    register(GatewayDenyHandler())   # (deny, gateway)

    unregister("deny", "gateway")
    assert not is_registered_exact("deny", "gateway")
    assert is_registered_exact("allow", "both")


def test_unregister_missing_key_is_noop(blank_registry):
    """No exception when unregistering something that was never there —
    matches ``dict.pop(..., None)`` semantics."""
    unregister("nonexistent", "gateway")  # must not raise


def test_clear_wipes_registry():
    clear()
    assert registered_verdicts() == []
    # Sanity: default handlers were there before clear (autouse fixture).


# ═════════════════════════════════════════════════════════════════════
# Dispatch semantics
# ═════════════════════════════════════════════════════════════════════


def test_apply_dispatches_exact_layer_match_first(blank_registry):
    """A gateway-specific handler beats a both-layer handler when
    ctx.layer==gateway. That's how ``deny`` (gateway-specific) coexists
    with ``allow`` (both)."""
    @dataclass(frozen=True)
    class Both:
        verdict: str = "test"
        layer: pv.HandlerLayer = "both"
        def apply(self, ctx): return HandlerResult(forward=True, mutations={"tag": "both"})

    @dataclass(frozen=True)
    class GatewayOnly:
        verdict: str = "test"
        layer: pv.HandlerLayer = "gateway"
        def apply(self, ctx): return HandlerResult(forward=True, mutations={"tag": "gateway"})

    register(Both())
    register(GatewayOnly())

    at_gateway = apply(_ctx(verdict="test", layer="gateway"))
    at_action_gate = apply(_ctx(verdict="test", layer="action_gate"))

    assert at_gateway.mutations == {"tag": "gateway"}
    # No action_gate-specific handler registered → falls back to "both".
    assert at_action_gate.mutations == {"tag": "both"}


def test_apply_falls_back_to_both_layer_when_specific_missing(blank_registry):
    @dataclass(frozen=True)
    class BothOnly:
        verdict: str = "unicorn"
        layer: pv.HandlerLayer = "both"
        def apply(self, ctx): return HandlerResult(forward=True, mutations={"m": True})

    register(BothOnly())
    result = apply(_ctx(verdict="unicorn", layer="action_gate"))
    assert result.mutations == {"m": True}


def test_apply_unknown_verdict_at_gateway_fails_closed(blank_registry, caplog):
    """H2 — a policy engine that can't interpret its own verdict must
    NOT silently allow the call. Novel verdicts (``sanction``,
    ``quarantine``) on an older gateway would slip through under
    a uniform fail-open. At the gateway layer we fail CLOSED."""
    import logging
    with caplog.at_level(logging.ERROR, logger="kya.policy_verdicts"):
        result = apply(_ctx(verdict="sanction", layer="gateway"))
    assert result.forward is False
    assert result.http_status == 500
    assert result.jsonrpc_error_code == -32099
    assert result.response_body["error"] == "unknown_verdict"
    assert result.response_body["verdict"] == "sanction"
    # ERROR log level surfaces the drift on ops dashboards.
    assert any(rec.levelname == "ERROR" and "sanction" in rec.message
               for rec in caplog.records)


@pytest.mark.parametrize("pro_verdict", ["redact", "throttle", "block"])
def test_pro_verdicts_at_action_gate_fail_open_when_pro_handlers_absent(
    pro_verdict, caplog,
):
    """Self-hosted-lite regression — a deploy that ships OSS but not
    Pro (`register_default_action_gate_handlers()` never called) will
    see redact/throttle/block verdicts fall through the registry at
    layer=action_gate. Under H2, that path fails OPEN with a WARNING
    (upstream already ran; refusing to ship the result would be a
    worse failure than passing it through).

    If a future refactor changed this to fail-closed, self-hosted-lite
    ingest paths would spike 500s the moment a policy engine emits
    redact/throttle — this test catches that regression."""
    import logging
    # NOTE: autouse fixture only registered OSS defaults — Pro defaults
    # are NOT loaded here, matching the self-hosted-lite production
    # shape.
    with caplog.at_level(logging.WARNING, logger="kya.policy_verdicts"):
        result = apply(_ctx(verdict=pro_verdict, layer="action_gate"))
    assert result.forward is True, (
        f"{pro_verdict}@action_gate should fail-open on OSS-only deploy"
    )
    assert result.http_status is None
    # L3 fix — must be a WARNING (not DEBUG or INFO). A future refactor
    # that dropped the log level would silently lose ops signal on the
    # self-hosted-lite path; this assertion catches that regression.
    assert any(
        rec.levelname == "WARNING" and pro_verdict in rec.message
        for rec in caplog.records
    ), (
        f"expected a WARNING mentioning {pro_verdict}, got "
        f"{[(r.levelname, r.message) for r in caplog.records]}"
    )


def test_apply_unknown_verdict_at_action_gate_fails_open(blank_registry, caplog):
    """H2 addendum — at action_gate, upstream has already run. Refusing
    to ship its result over an unknown-verdict configuration would be
    a worse failure mode than passing it through. Fail open with a
    WARNING so ops sees the drift."""
    import logging
    with caplog.at_level(logging.WARNING, logger="kya.policy_verdicts"):
        result = apply(_ctx(verdict="mystery", layer="action_gate"))
    assert result.forward is True
    assert result.http_status is None
    assert any(rec.levelname == "WARNING" and "mystery" in rec.message
               for rec in caplog.records)


def test_apply_unknown_verdict_does_not_raise():
    """Explicit guarantee — even with a totally blank registry, apply()
    must return a HandlerResult, never raise. Both layers."""
    clear()
    for layer in ("gateway", "action_gate"):
        result = apply(_ctx(verdict="whatever", layer=layer))
        assert isinstance(result, HandlerResult)


def test_registered_verdicts_filters_by_layer():
    """Layer filter includes the layer AND the ``both`` fallback —
    that matches how _resolve() actually finds handlers at that layer.

    Only OSS handlers here; action-gate defaults live in Pro."""
    at_gateway = registered_verdicts(layer="gateway")
    at_action_gate = registered_verdicts(layer="action_gate")

    # deny + require_human are gateway-only.
    assert "deny" in at_gateway
    assert "require_human" in at_gateway
    assert "deny" not in at_action_gate
    assert "require_human" not in at_action_gate
    # allow is both — appears in each.
    assert "allow" in at_gateway
    assert "allow" in at_action_gate


def test_registered_verdicts_none_returns_all():
    """layer=None returns every registered verdict — OSS defaults only."""
    assert set(registered_verdicts()) == {
        "allow", "deny", "require_human",
    }


# ═════════════════════════════════════════════════════════════════════
# Default handler behavior
# ═════════════════════════════════════════════════════════════════════


def test_allow_handler_forwards_at_both_layers():
    result_g = apply(_ctx(verdict="allow", layer="gateway"))
    result_a = apply(_ctx(verdict="allow", layer="action_gate"))
    for r in (result_g, result_a):
        assert r.forward is True
        assert r.http_status is None
        assert r.response_body is None
        assert r.mutations == {}


def test_deny_handler_short_circuits_403_with_reason_codes():
    result = apply(_ctx(
        verdict="deny",
        layer="gateway",
        reason_codes=["RBAC_DENY", "BUDGET_EXCEEDED"],
    ))
    assert result.forward is False
    assert result.http_status == 403
    assert result.response_body == {
        "error": "policy_deny",
        "reason_codes": ["RBAC_DENY", "BUDGET_EXCEEDED"],
        "verdict": "deny",
    }


def test_deny_handler_only_active_at_gateway_layer(blank_registry):
    """deny is registered at layer=gateway. At action_gate with no
    other handler for ``deny``, apply() must fail-open."""
    register(GatewayDenyHandler())
    result = apply(_ctx(verdict="deny", layer="action_gate"))
    # No action_gate-specific handler + no both-layer handler for deny → fail-open.
    assert result.forward is True
    assert result.http_status is None


def test_deny_response_body_reason_codes_are_a_fresh_copy():
    """Guarantee: the handler doesn't leak its internal list. Mutating
    the returned reason_codes must not affect the ctx's list.

    Regression guard: ``frozen=True`` on the dataclass doesn't help if
    a MUTABLE list is shared by reference — the recipient could edit
    it and poison a subsequent audit write."""
    ctx = _ctx(verdict="deny", reason_codes=["A"])
    result = apply(ctx)
    result.response_body["reason_codes"].append("MUTATED")
    assert ctx.reason_codes == ["A"]  # not mutated


def test_require_human_handler_emits_428_with_www_authenticate():
    result = apply(_ctx(
        verdict="require_human",
        layer="gateway",
        reason_codes=["REQUIRES_HUMAN"],
    ))
    assert result.forward is False
    assert result.http_status == 428
    assert result.response_headers.get("WWW-Authenticate") == (
        'KYA-Human-Approval realm="kya-gateway"'
    )
    assert result.response_body["error"] == "human_approval_required"
    assert result.response_body["verdict"] == "require_human"


def test_require_human_signals_pending_row_via_mutations():
    """The mutations bag tells #101's persistence layer to write a
    kya_pending_invocations row and stamp the id on the response."""
    result = apply(_ctx(verdict="require_human", layer="gateway"))
    assert result.mutations.get("hitl.needs_pending_row") is True


# NOTE: Redact / Throttle / Block handler tests live in
# ``kya_pro/tests/test_policy_verdicts_action_gate.py``. Those
# handlers ship in ``kya_pro.policy.verdict_handlers`` because the
# action gate is a Pro-only surface.


# ═════════════════════════════════════════════════════════════════════
# Type + immutability contracts
# ═════════════════════════════════════════════════════════════════════


def test_verdict_context_is_frozen():
    """VerdictContext must be immutable — handlers cannot mutate it
    and affect downstream handlers or the caller's audit record."""
    ctx = _ctx()
    with pytest.raises((AttributeError, TypeError, Exception)):
        ctx.verdict = "hijacked"  # type: ignore[misc]


def test_handler_result_is_frozen():
    """HandlerResult must be immutable — the caller can't mutate what
    the handler returned mid-pipeline."""
    result = HandlerResult(forward=True)
    with pytest.raises((AttributeError, TypeError, Exception)):
        result.forward = False  # type: ignore[misc]


def test_verdict_handler_protocol_is_runtime_checkable():
    """isinstance(x, VerdictHandler) works — tests + registration
    code can duck-type check without importing Protocol details."""
    assert isinstance(AllowHandler(), VerdictHandler)
    assert isinstance(GatewayDenyHandler(), VerdictHandler)


def test_registering_broken_handler_raises_at_register_time(blank_registry):
    """H3 fix — a handler missing .apply() must be rejected AT
    REGISTRATION so the operator gets a stack trace at deploy
    time, not a 500 at first-user-request time."""
    class NoApply:
        verdict = "custom"
        layer = "gateway"
        # No apply() method.

    with pytest.raises(TypeError, match="apply"):
        register(NoApply())


def test_registering_wrong_layer_raises_typerror(blank_registry):
    class BadLayer:
        verdict = "custom"
        layer = "nonsense"
        def apply(self, ctx): return HandlerResult()

    with pytest.raises(TypeError, match="layer"):
        register(BadLayer())


def test_registering_empty_verdict_raises_typerror(blank_registry):
    class EmptyVerdict:
        verdict = ""
        layer = "gateway"
        def apply(self, ctx): return HandlerResult()

    with pytest.raises(TypeError, match="verdict"):
        register(EmptyVerdict())


def test_registering_non_string_verdict_raises_typerror(blank_registry):
    class NumericVerdict:
        verdict = 42
        layer = "gateway"
        def apply(self, ctx): return HandlerResult()

    with pytest.raises(TypeError, match="verdict"):
        register(NumericVerdict())


# ═════════════════════════════════════════════════════════════════════
# Real-world integration expectations
# ═════════════════════════════════════════════════════════════════════


def test_deny_at_gateway_matches_current_server_behavior():
    """Regression guard: the shipped GatewayDenyHandler produces the
    same shape the gateway's ad-hoc if/elif currently produces. When
    server.py is refactored to consume the registry (later in this
    task), the on-the-wire response must not change."""
    result = apply(_ctx(
        verdict="deny",
        layer="gateway",
        reason_codes=["RBAC_DENY"],
    ))
    # Match: status_code=403, body has verdict + reason_codes.
    assert result.http_status == 403
    body = result.response_body
    assert body is not None
    assert body["verdict"] == "deny"
    assert body["reason_codes"] == ["RBAC_DENY"]


def test_require_human_at_gateway_matches_current_server_behavior():
    """Regression guard for the current 428 emission."""
    result = apply(_ctx(
        verdict="require_human",
        layer="gateway",
        reason_codes=["REQUIRES_HUMAN"],
    ))
    assert result.http_status == 428
    assert 'KYA-Human-Approval' in result.response_headers.get("WWW-Authenticate", "")
    body = result.response_body
    assert body is not None
    assert body["verdict"] == "require_human"


def test_operator_can_swap_default_handler_with_custom_impl():
    """The override contract: an operator's plugin can register a
    handler under the same key to change behavior. Documented as
    the plugin extension point."""
    @dataclass(frozen=True)
    class CustomDeny:
        verdict: str = "deny"
        layer: pv.HandlerLayer = "gateway"
        def apply(self, ctx: VerdictContext) -> HandlerResult:
            return HandlerResult(
                forward=False,
                http_status=451,  # Unavailable for Legal Reasons — operator's choice
                response_body={"tag": "custom"},
            )

    register(CustomDeny())
    result = apply(_ctx(verdict="deny", layer="gateway"))
    assert result.http_status == 451
    assert result.response_body == {"tag": "custom"}


def test_oss_verdict_matrix_dispatches_without_error():
    """Sanity: every OSS-shipped verdict at every documented context
    layer dispatches to A handler and returns a HandlerResult. Guards
    against a missing default in register_default_handlers.

    Action-gate verdicts (redact / throttle / block) are covered by
    the Pro-side test file."""
    verdicts = ["allow", "deny", "require_human"]
    layers: list[pv.ContextLayer] = ["gateway", "action_gate"]
    for v in verdicts:
        for l in layers:
            result = apply(_ctx(verdict=v, layer=l))
            assert isinstance(result, HandlerResult), (
                f"{v}@{l} did not return HandlerResult"
            )


# ═════════════════════════════════════════════════════════════════════
# B1 / B2 — JSON-RPC envelope + signal_kind preservation
# ═════════════════════════════════════════════════════════════════════


def test_deny_handler_emits_jsonrpc_error_code_minus_32001():
    """B1 — the gateway wraps handler output in make_error(req_id,
    code, msg, data=body). Missing jsonrpc_error_code would break
    every SDK pattern-matching on the numeric code."""
    result = apply(_ctx(verdict="deny", layer="gateway"))
    assert result.jsonrpc_error_code == -32001


def test_require_human_handler_emits_jsonrpc_error_code_minus_32007():
    """B1 — RFC 6585 428 pairs with JSON-RPC -32007 on the current
    wire format. Verify the handler carries the code so the gateway
    envelope stays compatible."""
    result = apply(_ctx(verdict="require_human", layer="gateway"))
    assert result.jsonrpc_error_code == -32007


# action_gate block error code test lives in
# ``kya_pro/tests/test_policy_verdicts_action_gate.py``.


def test_unknown_verdict_at_gateway_emits_jsonrpc_error_code_minus_32099():
    result = apply(_ctx(verdict="new_verdict", layer="gateway"))
    assert result.jsonrpc_error_code == -32099


def test_signal_kind_is_carried_by_verdict_context():
    """B2 — VerdictContext must preserve signal_kind so the gateway's
    trust-ledger write keeps its audit correlation key. Missing this
    field would leave every future ledger row ambiguous."""
    ctx = _ctx(
        verdict="deny",
        layer="gateway",
        reason_codes=["RBAC_DENY"],
    )
    # signal_kind defaults to None — that's fine for test contexts,
    # but the field must exist so the real gateway can populate it.
    assert hasattr(ctx, "signal_kind")
    assert ctx.signal_kind is None

    ctx2 = VerdictContext(
        verdict="deny", reason_codes=["RBAC_DENY"],
        tenant_id="t", principal_kind="agent", principal_id="a",
        action="mcp.read", layer="gateway",
        signal_kind="rbac_refusal",
    )
    assert ctx2.signal_kind == "rbac_refusal"


def test_action_gate_allow_forwards_and_preserves_upstream_body():
    """L2 — at action-gate, allow means "keep the upstream response".
    Handler returns forward=True with response_body=None. The caller
    then keeps ctx.upstream_body untouched. Explicit test so the
    contract doesn't drift."""
    upstream = b'{"result": {"ok": true}}'
    result = apply(_ctx(
        verdict="allow", layer="action_gate",
        upstream_body=upstream, upstream_status=200,
    ))
    assert result.forward is True
    assert result.response_body is None
    assert result.http_status is None
    # Caller is expected to ship ctx.upstream_body — no test-level
    # simulation of the caller here, but the invariant is documented.


# ═════════════════════════════════════════════════════════════════════
# H1 — thread-safety of registry mutations
# ═════════════════════════════════════════════════════════════════════


def test_register_default_handlers_is_atomic_under_concurrent_apply(blank_registry):
    """Multi-key registration must be a single atomic step from the
    perspective of a concurrent apply() call. Simulates: config-reload
    thread re-populates the registry while a request thread reads it."""
    import threading
    import time

    # Wire up a "hot swap" that clears + re-adds the defaults many
    # times, while another thread hammers apply() for a verdict that
    # SHOULD always resolve to a handler.
    stop = threading.Event()
    seen_missing = []

    def reload_loop():
        while not stop.is_set():
            swap([
                AllowHandler(),
                GatewayDenyHandler(),
                GatewayRequireHumanHandler(),
            ])

    def query_loop():
        # apply() must ALWAYS find a deny handler here — swap()
        # guarantees the registry is never partially populated.
        # Reviewer-2 catch: at layer=gateway, BOTH the deny-handler-hit
        # path AND the fail-closed miss path return forward=False, so
        # forward alone doesn't distinguish. Check http_status: deny
        # handler returns 403, fail-closed miss returns 500. A partial
        # swap would produce 500s during the race window.
        for _ in range(500):
            result = apply(_ctx(verdict="deny", layer="gateway"))
            if result.http_status != 403:
                seen_missing.append(result.http_status)

    reloader = threading.Thread(target=reload_loop, daemon=True)
    querier = threading.Thread(target=query_loop, daemon=True)
    reloader.start()
    querier.start()
    querier.join(timeout=5)
    stop.set()
    reloader.join(timeout=2)

    assert seen_missing == [], (
        f"apply() saw a partial registry {len(seen_missing)} times — "
        "swap() must be atomic w.r.t. concurrent readers"
    )


def test_swap_validates_all_handlers_before_replacing(blank_registry):
    """A bad handler in the middle of a swap() list must not corrupt
    the registry — validate all first, then commit."""
    register(AllowHandler())  # baseline: allow is registered

    class Broken:
        verdict = "x"
        layer = "gateway"
        # No apply.

    with pytest.raises(TypeError):
        swap([GatewayDenyHandler(), Broken()])

    # Registry unchanged because swap() rejected the whole list.
    assert is_registered_exact("allow", "both")
    assert not is_registered_exact("deny", "gateway")


# ═════════════════════════════════════════════════════════════════════
# M2 — resolves() vs is_registered_exact() semantics
# ═════════════════════════════════════════════════════════════════════


def test_resolves_returns_true_when_apply_would_find_a_handler():
    """resolves() reflects _resolve() — includes the both-layer
    fallback. is_registered_exact() does not."""
    # allow is registered at (allow, both).
    assert resolves("allow", "gateway")
    assert resolves("allow", "action_gate")
    assert not is_registered_exact("allow", "gateway")
    assert not is_registered_exact("allow", "action_gate")
    assert is_registered_exact("allow", "both")


def test_resolves_returns_false_for_unregistered_verdict():
    assert not resolves("neverseen", "gateway")


# ═════════════════════════════════════════════════════════════════════
# M3 — MUTATION_KEYS enforces spelling consistency
# ═════════════════════════════════════════════════════════════════════


def test_all_default_oss_handler_mutations_are_documented_in_mutation_keys():
    """Every mutation key an OSS-shipped handler emits must be listed
    in MUTATION_KEYS. Guards against typo drift shipping to production.

    Pro-shipped handlers maintain their own MUTATION_KEYS_ACTION_GATE
    and their own equivalent test."""
    seen_keys = set()
    seen_keys.update(apply(_ctx(verdict="require_human", layer="gateway")).mutations.keys())
    unknown = seen_keys - MUTATION_KEYS
    assert not unknown, (
        f"OSS handlers emitted mutation keys not listed in MUTATION_KEYS: "
        f"{unknown}. Update MUTATION_KEYS if intentional, fix the typo "
        "otherwise."
    )


# ═════════════════════════════════════════════════════════════════════
# M4 — throttle numeric hardening
# ═════════════════════════════════════════════════════════════════════


# Throttle boundary tests live in
# ``kya_pro/tests/test_policy_verdicts_action_gate.py``.


# ═════════════════════════════════════════════════════════════════════
# Edge cases (verdict names, empty inputs)
# ═════════════════════════════════════════════════════════════════════


def test_verdict_name_with_special_characters_still_dispatches(blank_registry):
    """Verdict names are string-keyed — special chars must not break
    the lookup. This isn't a security boundary (verdict emitter is
    trusted), but defensive against future config plumbing."""
    @dataclass(frozen=True)
    class Weird:
        verdict: str = "verdict-with:special.chars/v1"
        layer: pv.HandlerLayer = "gateway"
        def apply(self, ctx): return HandlerResult(forward=False, http_status=403)

    register(Weird())
    result = apply(_ctx(
        verdict="verdict-with:special.chars/v1",
        layer="gateway",
    ))
    assert result.http_status == 403


def test_apply_with_empty_reason_codes_still_ok():
    result = apply(_ctx(verdict="deny", layer="gateway", reason_codes=[]))
    assert result.response_body["reason_codes"] == []
