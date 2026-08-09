"""NativeEvaluator short-circuit on gateway inputs, and attribution
enrichment on the fallback path.

Load-bearing promises:
    Short-circuit:
        1. For gateway-shape inputs (no ``estimated_cost_usd`` / no
           ``data_classification`` / action not a registered weight
           scope), the default NativeEvaluator's ``evaluate()`` is
           NEVER called. Proof: subclass NativeEvaluator with a call
           counter and assert it stays 0 across N pipeline calls.
        2. When the short-circuit is disabled (test overrides
           ``would_short_circuit`` to always return False), ``evaluate()``
           IS called — counter == N. That polarity flip proves the fast-
           path is the mechanism absorbing the calls.
        3. When an input DOES carry a signal a rule would inspect (e.g.
           ``estimated_cost_usd``), the short-circuit does NOT fire —
           evaluate() must still run so the rule gets a chance.

    FIX-6:
        4. On the short-circuit path, the returned fallback ``Verdict``
           carries ``rich["policy_hash"]`` (synthesised via cached
           ``get_effective_policy_hash``) + ``rich["evaluator_name"] ==
           "native"``. Ledger attribution is preserved.
"""
from __future__ import annotations

import pytest

import kya.policy_hash as ph
from kya._native_evaluator import NativeEvaluator
from kya.policy_evaluator import (
    EvaluationInput,
    VerdictResult,
    register_evaluator,
    unregister_evaluator,
)
from kya_gateway.config import PolicyConfig
from kya_gateway.identity import BoundPrincipal
from kya_gateway.policy_pipeline import evaluate


def _principal(kind: str = "agent") -> BoundPrincipal:
    return BoundPrincipal(
        principal_kind=kind,
        principal_id="planner",
        method="bearer_jwt",
        external_subject="planner",
        external_issuer=None,
    )


class _CountingNativeEvaluator(NativeEvaluator):
    """NativeEvaluator subclass that counts ``evaluate()`` invocations."""

    name = "counting-native"

    def __init__(self, *, session_factory=None):
        super().__init__(session_factory=session_factory)
        self.calls = 0

    def evaluate(self, inp):
        self.calls += 1
        return super().evaluate(inp)


@pytest.fixture
def counting_native():
    ev = _CountingNativeEvaluator()
    register_evaluator("counting-native", ev)
    # Reset cache so tests are independent
    ph.invalidate_policy_hash_cache()
    yield ev
    unregister_evaluator("counting-native")


def test_short_circuit_skips_evaluate_on_gateway_inputs(counting_native):
    """N=100 gateway-shape requests → 0 calls into NativeEvaluator.evaluate()."""
    cfg = PolicyConfig(min_trust=0, policy_evaluator_name="counting-native")
    for _ in range(100):
        v = evaluate(
            db=None, tenant_id="tenant-alpha", principal=_principal(),
            action="mcp.x.read",  # not a registered weight scope
            payload_bytes=100, invocation_id=None, cfg=cfg,
        )
        assert v.verdict == "allow"
    assert counting_native.calls == 0, (
        f"expected 0 evaluate() calls under short-circuit, got "
        f"{counting_native.calls} — fast-path is not firing"
    )


def test_short_circuit_disabled_produces_n_calls(counting_native, monkeypatch):
    """SABOTAGE: patch ``would_short_circuit`` to always return False.
    100 requests → 100 evaluate() calls. Polarity flip of the primary
    test. If this assertion doesn't hold, the fast-path wasn't the
    mechanism absorbing the calls.
    """
    monkeypatch.setattr(
        _CountingNativeEvaluator, "would_short_circuit",
        lambda self, inp: False,
    )
    cfg = PolicyConfig(min_trust=0, policy_evaluator_name="counting-native")
    for _ in range(100):
        evaluate(
            db=None, tenant_id="tenant-alpha", principal=_principal(),
            action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
        )
    assert counting_native.calls == 100, (
        f"expected 100 evaluate() calls with fast-path disabled, got "
        f"{counting_native.calls}"
    )


def test_short_circuit_does_not_fire_when_estimated_cost_set(monkeypatch):
    """If a hypothetical caller (Pro layer) enriched EvaluationInput
    with ``estimated_cost_usd``, the budget rule COULD fire, so
    short-circuit must NOT skip. Directly probe ``would_short_circuit``
    since the gateway pipeline doesn't currently plumb that attribute
    (it will when the Pro cost-estimator layer lands)."""
    ev = NativeEvaluator()
    inp_no_cost = EvaluationInput(
        tenant_id="t", principal_kind="agent", principal_id="p",
        action="mcp.x.read",
    )
    assert ev.would_short_circuit(inp_no_cost) is True

    inp_with_cost = EvaluationInput(
        tenant_id="t", principal_kind="agent", principal_id="p",
        action="mcp.x.read",
        attributes={"estimated_cost_usd": 0.01},
    )
    assert ev.would_short_circuit(inp_with_cost) is False, (
        "short-circuit fired on an input with estimated_cost_usd — the "
        "budget rule would be skipped silently"
    )


def test_short_circuit_does_not_fire_when_restricted_data():
    ev = NativeEvaluator()
    inp = EvaluationInput(
        tenant_id="t", principal_kind="agent", principal_id="p",
        action="mcp.x.read",
        attributes={"data_classification": "restricted"},
    )
    assert ev.would_short_circuit(inp) is False


def test_short_circuit_does_not_fire_when_action_is_registered_scope(monkeypatch):
    """If the action string matches a registered ``kya.tenant_weights``
    scope, the tenant-weight rule COULD fire — must NOT short-circuit."""
    from kya import tenant_weights
    monkeypatch.setattr(tenant_weights, "known_scopes", lambda: {"custom.scope"})
    ev = NativeEvaluator()
    inp = EvaluationInput(
        tenant_id="t", principal_kind="agent", principal_id="p",
        action="custom.scope",
    )
    assert ev.would_short_circuit(inp) is False


# ── FIX-6 attribution enrichment ──────────────────────────────────


def test_fallback_carries_policy_hash_on_short_circuit(counting_native, monkeypatch):
    """On the short-circuit path, the fallback Verdict must still carry
    ``policy_hash`` + ``evaluator_name`` so ledger attribution survives
    Phase 4 evidence writes."""
    # Force a known synthesised hash by stubbing the cached primitive
    monkeypatch.setattr(
        ph, "_compute_effective_policy_hash_uncached",
        lambda db, tenant_id: f"policy-hash-sha256-v1:short-{tenant_id}",
    )
    ph.invalidate_policy_hash_cache()

    cfg = PolicyConfig(min_trust=0, policy_evaluator_name="counting-native")
    v = evaluate(
        db=None, tenant_id="tenant-alpha", principal=_principal(),
        action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    assert v.verdict == "allow"
    assert v.rich.get("evaluator_name") == "native", v.rich
    assert v.rich.get("policy_hash") == "policy-hash-sha256-v1:short-tenant-alpha", v.rich
    assert v.rich.get("evaluator_short_circuited") is True


def test_fallback_carries_attribution_on_allow_response(monkeypatch):
    """When the evaluator DOES run and returns "allow" (e.g. NativeEvaluator
    default_allow branch OR any Pro evaluator's allow), the fallback
    Verdict must be enriched with the evaluator's policy_hash +
    evaluator_name so attribution survives."""

    class _AllowingEval:
        name = "attribution-eval"

        def evaluate(self, inp):
            return VerdictResult(
                verdict="allow",
                reasons=("attrib_allow",),
                policy_hash="policy-hash-sha256-v1:attrib-xyz",
                evaluator_name=self.name,
            )

    register_evaluator("attribution-eval", _AllowingEval())
    try:
        cfg = PolicyConfig(min_trust=0, policy_evaluator_name="attribution-eval")
        v = evaluate(
            db=None, tenant_id="tenant-alpha", principal=_principal(),
            action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
        )
        assert v.verdict == "allow"
        assert v.rich.get("policy_hash") == "policy-hash-sha256-v1:attrib-xyz"
        assert v.rich.get("evaluator_name") == "attribution-eval"
    finally:
        unregister_evaluator("attribution-eval")


# ── FIX-A (Phase-4-P0): db= threading through dispatch chain ──────
#
# Load-bearing promise: on a cold cache + short-circuit path, the
# gateway's live DB session is threaded from ``evaluate()`` through
# ``_dispatch`` → ``_emit_via_evaluator`` → ``_fallback_with_native_
# attribution`` → ``get_effective_policy_hash(db=..., ...)`` so a real
# hash is computed and lands in ``Verdict.rich["policy_hash"]``.
#
# Sabotage-verify: patch ``_dispatch`` (via the source-of-truth seam
# in the policy_pipeline module) to NOT forward db= into
# ``_emit_via_evaluator`` and assert the test flips RED (hash missing).


def test_short_circuit_populates_policy_hash_with_db(counting_native):
    """Threading a live session through ``evaluate()`` must produce a
    ``policy_hash`` breadcrumb on the short-circuit path even when the
    TTL cache is cold.

    Uses a captured-db recorder in place of the primitive so we can
    verify (a) the primitive was called AT ALL from this path and
    (b) it was called WITH the session the pipeline was handed. We
    don't stand up a real DB because the seam under test is the db
    threading, not the primitive's tenant-weights walk (already
    covered by test_policy_hash_ttl_cache.py).
    """
    captured: dict[str, object] = {}

    def _fake_compute(db, tenant_id):
        captured["db"] = db
        captured["tenant_id"] = tenant_id
        return f"policy-hash-sha256-v1:cold-{tenant_id}"

    import unittest.mock as _mock
    ph.invalidate_policy_hash_cache()
    sentinel_db = object()   # stand-in for a live SQLAlchemy Session

    cfg = PolicyConfig(min_trust=0, policy_evaluator_name="counting-native")
    with _mock.patch.object(
        ph, "_compute_effective_policy_hash_uncached", _fake_compute,
    ):
        v = evaluate(
            db=sentinel_db, tenant_id="tenant-alpha",
            principal=_principal(), action="mcp.x.read",
            payload_bytes=100, invocation_id=None, cfg=cfg,
        )

    assert v.verdict == "allow"
    # Non-empty hash string ended up in `rich`
    assert isinstance(v.rich.get("policy_hash"), str)
    assert v.rich["policy_hash"], "policy_hash present but empty"
    assert v.rich["policy_hash"] == "policy-hash-sha256-v1:cold-tenant-alpha"
    # And critically: the same `db` sentinel we handed evaluate() made
    # it all the way to the primitive, proving the threading, not the
    # cache, produced the hash.
    assert captured.get("db") is sentinel_db, (
        f"db= was NOT forwarded through _dispatch → _emit_via_evaluator "
        f"→ _fallback_with_native_attribution; got {captured.get('db')!r}"
    )
    assert captured.get("tenant_id") == "tenant-alpha"


def test_short_circuit_db_threading_sabotaged_drops_hash(
    counting_native, monkeypatch,
):
    """SABOTAGE polarity flip: rebind ``_emit_via_evaluator`` on the
    policy_pipeline module so ``db=`` is DROPPED before the attribution
    helper sees it. On a truly cold cache with our fake compute set to
    RAISE when db is None, the fallback must land WITHOUT a policy_hash
    breadcrumb — proving the FIX-A threading is what made the primary
    test green (not any secondary code path).
    """
    from kya_gateway import policy_pipeline as pp

    def _sabotaged_compute(db, tenant_id):
        if db is None:
            raise RuntimeError(
                "sabotage: primitive refuses cold-cache computes without db"
            )
        return f"policy-hash-sha256-v1:cold-{tenant_id}"

    monkeypatch.setattr(
        ph, "_compute_effective_policy_hash_uncached", _sabotaged_compute,
    )
    ph.invalidate_policy_hash_cache()

    # Rebind _emit_via_evaluator to drop the db= kwarg — mimics the
    # pre-FIX-A code path.
    real_emit = pp._emit_via_evaluator

    def _emit_without_db(evaluator, inp, fallback, *, db=None):
        return real_emit(evaluator, inp, fallback, db=None)

    monkeypatch.setattr(pp, "_emit_via_evaluator", _emit_without_db)

    sentinel_db = object()
    cfg = PolicyConfig(min_trust=0, policy_evaluator_name="counting-native")
    v = evaluate(
        db=sentinel_db, tenant_id="tenant-alpha",
        principal=_principal(), action="mcp.x.read",
        payload_bytes=100, invocation_id=None, cfg=cfg,
    )
    # Verdict still allow (attribution is metadata, never blocks a verdict)
    assert v.verdict == "allow"
    # Hash breadcrumb is MISSING — this is the RED state under sabotage.
    assert "policy_hash" not in v.rich, (
        f"expected policy_hash absent under sabotage, got {v.rich!r} — "
        "if this fails, another code path is populating policy_hash and "
        "the FIX-A threading wasn't load-bearing"
    )
