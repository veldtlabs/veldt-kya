"""Contract tests for the ``PolicyEvaluator`` Protocol + registry.

Parametrized against a set of evaluators — every evaluator that
ships (OSS or Pro) must pass these. The contract enforces the
non-negotiable invariants of the abstraction:

    * Duck-typed Protocol conformance.
    * Non-empty ``name`` + ``policy_hash``.
    * ``verdict`` in the canonical Figure-4 vocabulary.
    * Input immutability — evaluators MUST NOT mutate their input.
    * No exceptions raised on empty attributes / chain.

Registry mechanics live in a separate section — same file so a
misconfigured registry (e.g. a Protocol-non-conformant evaluator
sneaking through) is caught by these tests before any consumer
depends on ``get_evaluator("native")``.
"""
from __future__ import annotations

import dataclasses

import pytest

from kya.policy_evaluator import (
    EvaluationInput,
    PolicyEvaluator,
    VerdictResult,
    _register_native_default,
    get_evaluator,
    register_evaluator,
    unregister_evaluator,
)


# The paper §Figure-4 canonical verdict vocabulary. Evaluators MUST
# return one of these — anything else means the ``VerdictHandler``
# registry (``policy_verdicts``) fails-closed at dispatch time.
CANONICAL_VERDICTS = frozenset({
    "allow", "deny", "redact", "throttle",
    "flag_for_review", "block", "anonymize",
})


# ── Stubs for parametrization ────────────────────────────────────────


class NoOpAllowEvaluator:
    """Minimal always-allow evaluator. Verifies the contract accepts
    the simplest possible conformant implementation."""

    name = "noop-allow"

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        return VerdictResult(
            verdict="allow",
            reasons=("noop_allow",),
            policy_hash="noop-hash",
            evaluator_name=self.name,
        )


class NoOpDenyEvaluator:
    """Minimal always-deny evaluator. Verifies the contract accepts
    the deny path with equal fidelity to allow."""

    name = "noop-deny"

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        return VerdictResult(
            verdict="deny",
            reasons=("noop_deny",),
            policy_hash="noop-hash",
            evaluator_name=self.name,
        )


def _native_evaluator():
    # Lazy import so the module-import order in the test session
    # matches the real production import order.
    from kya import NativeEvaluator
    return NativeEvaluator()


def _valid_input() -> EvaluationInput:
    return EvaluationInput(
        tenant_id="tenant-contract-test",
        principal_kind="agent",
        principal_id="agent-x",
        action="invoke_tool",
        resource="tool://echo",
        attributes={"foo": "bar"},
        chain=["orchestrator", "agent-x"],
    )


EVALUATORS: list = [
    _native_evaluator(),
    NoOpAllowEvaluator(),
    NoOpDenyEvaluator(),
]


# ── Fixture: keep the registry pristine across tests ─────────────────


@pytest.fixture(autouse=True)
def _restore_registry():
    """Autouse so no test can forget — cross-test leakage on a
    module-global registry is a nightmare to debug. Cheap: a single
    unregister + re-register per test."""
    yield
    # Drop anything registered during the test, then restore the
    # default "native" binding so subsequent tests see a clean state.
    from kya.policy_evaluator import _REGISTRY
    for name in list(_REGISTRY.keys()):
        unregister_evaluator(name)
    _register_native_default()


# ═════════════════════════════════════════════════════════════════════
# Protocol conformance + result invariants (parametrized)
# ═════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("evaluator", EVALUATORS, ids=lambda e: e.name)
def test_evaluator_satisfies_protocol(evaluator):
    """Duck-typed Protocol check. Anything with ``.name`` (str) and a
    callable ``.evaluate`` passes."""
    assert isinstance(evaluator, PolicyEvaluator)


@pytest.mark.parametrize("evaluator", EVALUATORS, ids=lambda e: e.name)
def test_evaluator_name_is_non_empty_str(evaluator):
    """A missing/blank name would silently collide in the registry."""
    assert isinstance(evaluator.name, str)
    assert evaluator.name, "evaluator.name must be non-empty"


@pytest.mark.parametrize("evaluator", EVALUATORS, ids=lambda e: e.name)
def test_evaluate_returns_verdict_result(evaluator):
    result = evaluator.evaluate(_valid_input())
    assert isinstance(result, VerdictResult)


@pytest.mark.parametrize("evaluator", EVALUATORS, ids=lambda e: e.name)
def test_result_evaluator_name_matches(evaluator):
    """VerdictResult.evaluator_name must match the producing evaluator
    so the ledger can attribute the verdict without an extra lookup."""
    result = evaluator.evaluate(_valid_input())
    assert result.evaluator_name == evaluator.name


@pytest.mark.parametrize("evaluator", EVALUATORS, ids=lambda e: e.name)
def test_result_policy_hash_is_populated(evaluator):
    """Every verdict must carry a policy hash — that's the anchor for
    the §157 §3 policy→outcome integrity promise. Missing hashes
    break Watchtower's cross-check + break audit correlation."""
    result = evaluator.evaluate(_valid_input())
    assert isinstance(result.policy_hash, str)
    assert result.policy_hash, (
        f"evaluator {evaluator.name!r} returned an empty policy_hash; "
        f"the ledger cannot verify the policy at decision time without it"
    )


@pytest.mark.parametrize("evaluator", EVALUATORS, ids=lambda e: e.name)
def test_result_verdict_in_canonical_vocabulary(evaluator):
    """A verdict outside the Figure-4 set would fail-closed at the
    handler-dispatch layer. Catch drift at the evaluator boundary."""
    result = evaluator.evaluate(_valid_input())
    assert result.verdict in CANONICAL_VERDICTS, (
        f"evaluator {evaluator.name!r} returned non-canonical verdict "
        f"{result.verdict!r}. Allowed: {sorted(CANONICAL_VERDICTS)}"
    )


@pytest.mark.parametrize("evaluator", EVALUATORS, ids=lambda e: e.name)
def test_evaluate_does_not_mutate_input(evaluator):
    """Evaluators MUST NOT mutate their input. ``EvaluationInput``
    is frozen at the dataclass level, but nested dicts/lists are
    still mutable containers — verify by rebuilding the input via
    ``dataclasses.replace`` and asserting field-equal."""
    inp = _valid_input()
    snapshot_attributes = dict(inp.attributes)
    snapshot_chain = list(inp.chain)
    snapshot_replaced = dataclasses.replace(inp)

    evaluator.evaluate(inp)

    # Field-level equality catches "evaluator swapped a mutable
    # container in-place" without needing deep-copy machinery.
    assert inp == snapshot_replaced
    assert inp.attributes == snapshot_attributes
    assert inp.chain == snapshot_chain


@pytest.mark.parametrize("evaluator", EVALUATORS, ids=lambda e: e.name)
def test_evaluate_survives_empty_attributes_and_chain(evaluator):
    """Ergonomic guardrail — a caller that constructs an
    EvaluationInput with no attributes/chain (common for the
    simplest LLM invocation case) must not trip the evaluator."""
    inp = EvaluationInput(
        tenant_id="t", principal_kind="agent",
        principal_id="p", action="a",
    )
    # If the evaluator raises here, the request path would 500.
    result = evaluator.evaluate(inp)
    assert isinstance(result, VerdictResult)


# ═════════════════════════════════════════════════════════════════════
# VerdictResult immutability locks (round-3 review — P3-1 defense-in-depth)
# ═════════════════════════════════════════════════════════════════════


def test_verdict_result_coerces_list_reasons_to_tuple():
    """P3-1 lock — a caller passing ``reasons=["a", "b"]`` (list, not
    tuple) must land as a tuple inside the frozen dataclass. Without
    the coercion, a mutable list would slip through and violate the
    frozen-immutability guarantee downstream.

    Sabotage: comment out the ``__post_init__`` body in
    ``policy_evaluator.py::VerdictResult`` — this test goes RED and
    ``type(result.reasons)`` becomes ``list``.
    """
    result = VerdictResult(verdict="allow", reasons=["a", "b"])
    assert type(result.reasons) is tuple, (
        f"reasons must be coerced to tuple; got {type(result.reasons).__name__}"
    )
    assert result.reasons == ("a", "b")


def test_verdict_result_preserves_tuple_reasons_unchanged():
    """Idempotency check — a caller already passing a tuple should
    get back the same tuple (no wasteful re-wrapping)."""
    original = ("x", "y", "z")
    result = VerdictResult(verdict="deny", reasons=original)
    assert result.reasons == original
    assert type(result.reasons) is tuple


def test_verdict_result_coerces_generator_to_tuple():
    """A caller passing a generator (e.g. from a list comprehension
    with a filter) still lands as a tuple. Guards against the future
    edge case where reasons come from an ad-hoc pipeline."""
    gen = (r for r in ["one", "two"])
    result = VerdictResult(verdict="allow", reasons=gen)
    assert type(result.reasons) is tuple
    assert result.reasons == ("one", "two")


# ═════════════════════════════════════════════════════════════════════
# Registry mechanics
# ═════════════════════════════════════════════════════════════════════


def test_native_is_registered_by_default():
    """The OSS bootstrap in ``policy_evaluator.py`` registers
    ``"native"`` at import time. Break this promise and the whole
    "zero-config verdict production" ergonomic disappears."""
    got = get_evaluator("native")
    from kya import NativeEvaluator
    assert isinstance(got, NativeEvaluator)


def test_get_evaluator_returns_the_registered_instance():
    """Identity, not just value equality — re-registering later must
    override the SAME name so callers see the new binding."""
    class CustomEvaluator:
        name = "custom-round-trip"
        def evaluate(self, inp):
            return VerdictResult(
                verdict="allow", reasons=("custom",),
                policy_hash="custom-hash", evaluator_name=self.name,
            )

    instance = CustomEvaluator()
    register_evaluator("custom-round-trip", instance)
    assert get_evaluator("custom-round-trip") is instance


def test_register_evaluator_rejects_non_protocol_object():
    """A plain object() has no .name/.evaluate — must be rejected at
    register() time, not at first-user-request time."""
    with pytest.raises(TypeError):
        register_evaluator("bad-object", object())


def test_register_evaluator_rejects_missing_evaluate():
    """Passes the .name check but not .evaluate — catches the subtle
    typo case where a developer names a method ``evalute``."""
    class BrokenEvaluator:
        name = "broken"
        # no `evaluate` method

    with pytest.raises(TypeError, match="evaluate must be callable"):
        register_evaluator("broken", BrokenEvaluator())


def test_register_evaluator_rejects_empty_name():
    """Empty-name registrations would collide silently in the dict."""
    class NamelessEvaluator:
        name = ""
        def evaluate(self, inp):  # pragma: no cover — never reached
            raise AssertionError

    with pytest.raises(TypeError):
        register_evaluator("nameless", NamelessEvaluator())


def test_get_evaluator_raises_on_missing():
    """KeyError signals 'no such name' — a plain None would trap the
    caller into an AttributeError deep in evaluate()."""
    with pytest.raises(KeyError, match="no evaluator registered"):
        get_evaluator("does-not-exist-xyz")


def test_unregister_removes_binding():
    class CustomEvaluator:
        name = "custom-unreg"
        def evaluate(self, inp):
            return VerdictResult(
                verdict="allow", reasons=("custom",),
                policy_hash="h", evaluator_name=self.name,
            )

    register_evaluator("custom-unreg", CustomEvaluator())
    assert get_evaluator("custom-unreg") is not None
    unregister_evaluator("custom-unreg")
    with pytest.raises(KeyError):
        get_evaluator("custom-unreg")


def test_unregister_missing_is_noop():
    """Silent no-op — matches ``dict.pop(name, None)`` ergonomics so
    tests don't have to guard the call."""
    unregister_evaluator("never-registered-abc")  # should not raise


def test_register_is_idempotent_by_name():
    """Re-registering the same name silently replaces the prior
    binding — this is by design, mirrors ``policy_verdicts.register``."""
    class V1:
        name = "idem-test"
        def evaluate(self, inp):
            return VerdictResult(
                verdict="allow", reasons=("v1",),
                policy_hash="h", evaluator_name=self.name,
            )

    class V2:
        name = "idem-test"
        def evaluate(self, inp):
            return VerdictResult(
                verdict="deny", reasons=("v2",),
                policy_hash="h", evaluator_name=self.name,
            )

    register_evaluator("idem-test", V1())
    register_evaluator("idem-test", V2())
    got = get_evaluator("idem-test")
    result = got.evaluate(EvaluationInput(
        tenant_id="t", principal_kind="agent",
        principal_id="p", action="a",
    ))
    assert result.verdict == "deny"
    assert result.reasons == ("v2",)
