"""Native-evaluator-specific tests + sabotage-verify test.

Two roles for this file:

    1. Prove ``NativeEvaluator`` composes the existing OSS primitives
       (``tenant_budget``, ``tenant_weights``, ``policy_hash``) rather
       than re-implementing them. Composition is verified by
       monkeypatching the primitive and observing the evaluator's
       output flip — if it didn't, the evaluator has a duplicated code
       path and the abstraction leaks.

    2. Sabotage-verify the registry swap. Per the load-bearing test
       pattern in ``feedback_sabotage_verify.md``, every promise gets
       a companion test that patches the primitive to a broken state
       and asserts the test stays RED. If the test stays green after
       sabotage, it wasn't proving anything.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from kya._native_evaluator import NativeEvaluator
from kya.policy_evaluator import (
    EvaluationInput,
    VerdictResult,
    _register_native_default,
    get_evaluator,
    register_evaluator,
    unregister_evaluator,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _restore_registry():
    """Isolate cross-test registry state — mirrors the fixture in
    ``test_policy_evaluator_contract.py``. Autouse so no test can
    forget."""
    yield
    from kya.policy_evaluator import _REGISTRY
    for name in list(_REGISTRY.keys()):
        unregister_evaluator(name)
    _register_native_default()


def _sqlite_session_factory():
    """Return a factory that hands out fresh sessions on a shared
    in-memory sqlite engine. Ensures the weight-overrides + budget
    tables exist so DB-backed rules have something to compose against.
    """
    engine = create_engine("sqlite+pysqlite:///:memory:")
    # Create the weight-override tables once so
    # ``get_effective_policy_hash`` and ``get_effective_weights`` don't
    # trip on a missing table.
    from kya.tenant_weights import ensure_tables as ensure_weight_tables
    from kya.tenant_budget import ensure_tables as ensure_budget_tables
    with Session(engine) as sess:
        ensure_weight_tables(sess)
        try:
            ensure_budget_tables(sess)
        except Exception:
            # Budget tables aren't required for every test — the
            # weight-only tests happily skip if this fails.
            pass
        sess.commit()

    def _factory():
        return Session(engine)

    return _factory


def _basic_input(**overrides) -> EvaluationInput:
    defaults = dict(
        tenant_id="tenant-native-test",
        principal_kind="agent",
        principal_id="agent-x",
        action="invoke_tool",
    )
    defaults.update(overrides)
    return EvaluationInput(**defaults)


# ═════════════════════════════════════════════════════════════════════
# Default-allow path
# ═════════════════════════════════════════════════════════════════════


def test_default_allow_with_empty_attributes():
    """No budget, no weight override, no restricted-data attribute →
    the default-allow rule fires."""
    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input())

    assert result.verdict == "allow"
    assert result.reasons == ("policy_default_allow",)
    assert result.signal_kind == "clean_invocation"
    assert result.evaluator_name == "native"
    assert result.policy_hash, "policy_hash must be populated even on allow"


def test_default_allow_without_db_session_still_works():
    """No session factory installed, no explicit factory — the DB-
    backed rules skip themselves and the default-allow rule takes
    the call. Proves the graceful-degradation contract."""
    ev = NativeEvaluator(session_factory=lambda: None)
    result = ev.evaluate(_basic_input())
    assert result.verdict == "allow"
    # policy_hash still populated via the fall-back path (hash of {}).
    assert result.policy_hash


# ═════════════════════════════════════════════════════════════════════
# Attribute-based scoped deny
# ═════════════════════════════════════════════════════════════════════


def test_restricted_data_denies_agent_principal():
    """Non-human + restricted data classification → deny."""
    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(
        principal_kind="agent",
        attributes={"data_classification": "restricted"},
    ))
    assert result.verdict == "deny"
    assert result.reasons == ("restricted_data_requires_human",)
    assert result.signal_kind == "governance_block"


def test_restricted_data_denies_service_principal():
    """"service" (or anything that isn't 'human') also denies."""
    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(
        principal_kind="service",
        attributes={"data_classification": "restricted"},
    ))
    assert result.verdict == "deny"
    assert result.reasons == ("restricted_data_requires_human",)


def test_restricted_data_allows_human_principal():
    """The whole point of the rule — humans are allowed to handle
    restricted data."""
    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(
        principal_kind="human",
        attributes={"data_classification": "restricted"},
    ))
    assert result.verdict == "allow"


def test_non_restricted_classification_does_not_fire():
    """The rule scopes to classification=='restricted' only — any
    other value (or absence) leaves the request alone."""
    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(
        attributes={"data_classification": "public"},
    ))
    assert result.verdict == "allow"


# ═════════════════════════════════════════════════════════════════════
# Budget-cap composition
# ═════════════════════════════════════════════════════════════════════


def test_budget_rule_composes_tenant_budget_should_refuse(monkeypatch):
    """PROVES composition — patch the underlying ``should_refuse``
    primitive to report the tenant is over cap and verify the
    evaluator emits the budget-exceeded verdict. If the evaluator
    duplicates the logic instead of calling the primitive, this
    monkeypatch would be ignored and the test goes RED."""
    from kya import tenant_budget as tb

    calls: list[dict] = []

    def _fake_should_refuse(db, *, tenant_id, scope_key, intended_cost_usd, scope="tenant", window=None):
        calls.append({
            "tenant_id": tenant_id,
            "scope_key": scope_key,
            "intended_cost_usd": intended_cost_usd,
            "scope": scope,
        })
        return tb.Decision(
            verdict="refuse",
            reason="budget_exhausted (1h): $150.00 / $100.00",
            current_usd=150.0,
            threshold_usd=100.0,
            forecast=None,
        )

    monkeypatch.setattr(tb, "should_refuse", _fake_should_refuse)

    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(
        attributes={"estimated_cost_usd": 25.0},
    ))

    assert result.verdict == "deny"
    assert result.reasons == ("budget_exceeded",)
    assert result.signal_kind == "budget_exceeded"
    assert result.evidence_payload.get("current_usd") == 150.0
    assert result.evidence_payload.get("threshold_usd") == 100.0

    # Composition proof — the primitive WAS called, exactly once, with
    # the input attributes the evaluator surfaced. If the evaluator
    # bypassed the primitive, calls[] would be empty and this fails.
    assert len(calls) == 1
    assert calls[0]["tenant_id"] == "tenant-native-test"
    assert calls[0]["intended_cost_usd"] == pytest.approx(25.0)


def test_budget_rule_skipped_when_no_cost_attribute():
    """No ``estimated_cost_usd`` → the rule doesn't fire. Ensures the
    budget rule is opt-in, not implicit."""
    from kya import tenant_budget as tb

    def _boom_should_refuse(*a, **kw):  # pragma: no cover
        raise AssertionError(
            "should_refuse called when no estimated_cost_usd — "
            "budget rule should have short-circuited"
        )

    # Patch to prove the primitive is NEVER called on the no-cost path.
    import unittest.mock
    with unittest.mock.patch.object(tb, "should_refuse", _boom_should_refuse):
        ev = NativeEvaluator(session_factory=_sqlite_session_factory())
        result = ev.evaluate(_basic_input())
        assert result.verdict == "allow"


def test_budget_rule_allows_when_primitive_returns_allow(monkeypatch):
    """Cost supplied but the primitive says allow → default-allow
    (or the next rule) takes the call."""
    from kya import tenant_budget as tb

    def _allow(db, *, tenant_id, scope_key, intended_cost_usd, scope="tenant", window=None):
        return tb.Decision(
            verdict="allow", reason="",
            current_usd=5.0, threshold_usd=100.0, forecast=None,
        )

    monkeypatch.setattr(tb, "should_refuse", _allow)

    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(
        attributes={"estimated_cost_usd": 5.0},
    ))
    assert result.verdict == "allow"


# ═════════════════════════════════════════════════════════════════════
# Tenant weight composition
# ═════════════════════════════════════════════════════════════════════


def test_tenant_weight_rule_composes_get_effective_weights(monkeypatch):
    """PROVES composition — patch ``get_effective_weights`` to report
    a hard-deny weight for (scope=<action>, key=<principal_kind>) and
    verify the evaluator emits the scoped-deny verdict."""
    from kya import tenant_weights as tw

    calls: list[dict] = []

    def _fake_get_effective_weights(db, scope, tenant_id=None):
        calls.append({"scope": scope, "tenant_id": tenant_id})
        # Return a weight at the hard-deny sentinel for the principal
        # kind the evaluator will look up.
        return {"agent": 100}

    # Also patch known_scopes so the evaluator considers our action
    # a legitimate scope to consult.
    monkeypatch.setattr(tw, "known_scopes", lambda: ["class_weights", "invoke_tool"])
    monkeypatch.setattr(tw, "get_effective_weights", _fake_get_effective_weights)

    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(action="invoke_tool"))

    assert result.verdict == "deny"
    assert result.reasons == ("tenant_scoped_deny",)
    assert result.signal_kind == "governance_block"
    assert result.evidence_payload.get("weight_value") == 100
    assert result.evidence_payload.get("scope") == "invoke_tool"
    assert result.evidence_payload.get("key") == "agent"

    # Composition proof: the primitive was called with the exact
    # tuple the evaluator claims to consult.
    assert any(
        c["scope"] == "invoke_tool" and c["tenant_id"] == "tenant-native-test"
        for c in calls
    ), f"get_effective_weights was not called with the scope=action tuple: {calls}"


def test_tenant_weight_rule_skips_when_scope_not_registered(monkeypatch):
    """If the action doesn't correspond to a registered weight scope,
    the rule silently skips — matches the "only surfaces when
    configured" ergonomics of the weight subsystem."""
    from kya import tenant_weights as tw

    monkeypatch.setattr(tw, "known_scopes", lambda: ["class_weights"])

    def _boom(*a, **kw):  # pragma: no cover
        raise AssertionError(
            "get_effective_weights called for an unregistered scope"
        )

    monkeypatch.setattr(tw, "get_effective_weights", _boom)

    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(action="unregistered_action"))
    assert result.verdict == "allow"


def test_tenant_weight_rule_allows_when_below_threshold(monkeypatch):
    """Weight below the hard-deny sentinel → the rule doesn't fire.
    Prevents an over-eager deny on tenants that are simply tightening
    (weight=60) without asking for a full block."""
    from kya import tenant_weights as tw

    monkeypatch.setattr(tw, "known_scopes", lambda: ["invoke_tool"])
    monkeypatch.setattr(
        tw, "get_effective_weights",
        lambda db, scope, tenant_id=None: {"agent": 60},
    )

    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(action="invoke_tool"))
    assert result.verdict == "allow"


# ═════════════════════════════════════════════════════════════════════
# Graceful degradation
# ═════════════════════════════════════════════════════════════════════


def test_graceful_degradation_no_db_no_crash():
    """Session factory returns None → every DB-backed rule skips.
    The evaluator still returns allow (no rules fired). Proves the
    "never break the request path on infra outage" contract."""
    ev = NativeEvaluator(session_factory=lambda: None)
    result = ev.evaluate(_basic_input(
        attributes={"estimated_cost_usd": 25.0},
    ))
    assert result.verdict == "allow"


def test_graceful_degradation_session_factory_raises():
    """Factory itself throws → treated the same as returning None.
    A broken DB factory can't be allowed to poison the evaluator."""

    def _raising_factory():
        raise RuntimeError("simulated DB outage")

    ev = NativeEvaluator(session_factory=_raising_factory)
    result = ev.evaluate(_basic_input())
    assert result.verdict == "allow"


def test_graceful_degradation_budget_primitive_raises(monkeypatch):
    """If the primitive itself raises, the rule is skipped and the
    evaluator falls through — NOT fails closed. Fail-closed on rule-
    level errors would take down every request path the first time
    a primitive had a hiccup."""
    from kya import tenant_budget as tb

    def _raising_should_refuse(*a, **kw):
        raise RuntimeError("simulated budget subsystem hiccup")

    monkeypatch.setattr(tb, "should_refuse", _raising_should_refuse)

    ev = NativeEvaluator(session_factory=_sqlite_session_factory())
    result = ev.evaluate(_basic_input(
        attributes={"estimated_cost_usd": 25.0},
    ))
    # No verdict emitted by the budget rule → default-allow.
    assert result.verdict == "allow"


# ═════════════════════════════════════════════════════════════════════
# Fail-closed on unexpected internal error
# ═════════════════════════════════════════════════════════════════════


def test_fail_closed_on_internal_exception(monkeypatch):
    """If a rule-frame raises unexpectedly, the evaluator returns
    DENY. Silent-allow on a broken evaluator would defeat the point
    of the abstraction.

    Session-resolution and hash-computation errors do NOT trigger
    fail-closed — those degrade gracefully (see the graceful-degrade
    tests above). Only rule-execution frames fail closed. That
    distinction is intentional: a missing DB session in a self-hosted
    OSS deployment should not deny every action; a rule that blew up
    is a real bug that must not silently allow.
    """

    def _boom_rule(self, db, inp):
        raise RuntimeError("simulated rule-frame failure")

    monkeypatch.setattr(NativeEvaluator, "_check_budget", _boom_rule)

    ev = NativeEvaluator()
    result = ev.evaluate(_basic_input())
    assert result.verdict == "deny"
    assert result.reasons[0] == "evaluator_error"
    # Exception message travels in reasons[1] so the ledger can index
    # it without a separate log grep.
    assert "simulated rule-frame failure" in " ".join(result.reasons)
    # P4-1 lock (round-2 review finding) — fail-closed path MUST
    # preserve policy_hash so audit-attribution isn't silently lost
    # when the evaluator itself breaks. Hash is computed BEFORE the
    # rule-execution try block; the fail-closed emitter reads it.
    assert result.policy_hash, (
        "policy_hash must be populated on fail-closed — audit "
        "attribution requires a hash even when the evaluator errors"
    )


def test_fail_closed_preserves_policy_hash_when_hash_available(monkeypatch):
    """P4-1 lock — fail-closed path emits the SAME policy_hash the
    pre-try compute resolved, not the sentinel. Distinct from the
    test above because it asserts the value, not just non-emptiness."""

    resolved_hashes = []

    def _fake_compute(self, db, tenant_id):
        h = "sha256:test-hash-for-fail-closed-preservation"
        resolved_hashes.append(h)
        return h

    def _boom_rule(self, db, inp):
        raise RuntimeError("boom")

    monkeypatch.setattr(NativeEvaluator, "_compute_policy_hash", _fake_compute)
    monkeypatch.setattr(NativeEvaluator, "_check_budget", _boom_rule)

    ev = NativeEvaluator()
    result = ev.evaluate(_basic_input())
    assert result.verdict == "deny"
    assert result.reasons[0] == "evaluator_error"
    # The fail-closed VerdictResult carries the pre-try policy_hash.
    assert result.policy_hash == resolved_hashes[0]


def test_fail_closed_uses_sentinel_when_compute_policy_hash_raises(monkeypatch):
    """P4-1 defense-in-depth lock (round-3 review finding). If a future
    refactor makes ``_compute_policy_hash`` raise (removing its own
    ``try/except``), the outer defensive wrapper at the top of
    ``evaluate()`` MUST catch it and substitute the ``POLICY_HASH_
    UNAVAILABLE`` sentinel — the fail-closed emitter must never see
    an empty policy_hash.

    Sabotage: remove the outer ``except`` around ``_compute_policy_hash``
    call in ``evaluate()`` — this test goes RED (uncaught RuntimeError).
    """
    from kya._native_evaluator import POLICY_HASH_UNAVAILABLE

    def _boom_compute(self, db, tenant_id):
        raise RuntimeError("compute helper regressed to raising")

    def _boom_rule(self, db, inp):
        raise RuntimeError("rule frame also broken")

    monkeypatch.setattr(NativeEvaluator, "_compute_policy_hash", _boom_compute)
    monkeypatch.setattr(NativeEvaluator, "_check_budget", _boom_rule)

    ev = NativeEvaluator()
    result = ev.evaluate(_basic_input())
    # Fail-closed path fired (rule raised)
    assert result.verdict == "deny"
    assert result.reasons[0] == "evaluator_error"
    # And policy_hash is the sentinel, not empty string
    assert result.policy_hash == POLICY_HASH_UNAVAILABLE, (
        f"fail-closed path must substitute sentinel when compute raises; "
        f"got {result.policy_hash!r}"
    )


def test_policy_hash_unavailable_sentinel_when_hash_policy_raises(monkeypatch):
    """P2-1 lock — when both the effective-policy lookup AND the
    empty-policy fallback fail, ``_compute_policy_hash`` returns the
    ``POLICY_HASH_UNAVAILABLE`` sentinel, NOT an empty string. Empty
    strings silently violate the ``VerdictResult.policy_hash`` non-
    empty contract; the sentinel is a stable, greppable marker
    consumers can detect.
    """
    from kya._native_evaluator import POLICY_HASH_UNAVAILABLE

    def _boom(*_a, **_kw):
        raise RuntimeError("hash_policy is completely broken")

    # Patch BOTH: get_effective_policy_hash raises (db path fails) and
    # hash_policy raises (empty-policy fallback fails). Emulates a
    # runtime where the entire policy_hash module is broken.
    monkeypatch.setattr(
        "kya.policy_hash.get_effective_policy_hash", _boom,
    )
    monkeypatch.setattr("kya.policy_hash.hash_policy", _boom)

    ev = NativeEvaluator()
    # We don't actually need a real DB — passing None still triggers
    # the fallback path (which we've broken via the second monkeypatch).
    ph = ev._compute_policy_hash(None, "some-tenant")
    assert ph == POLICY_HASH_UNAVAILABLE
    assert ph != ""  # extra-explicit: never empty string


# ═════════════════════════════════════════════════════════════════════
# Sabotage-verify — proves the registry swap is not a lie
# ═════════════════════════════════════════════════════════════════════


def test_sabotage_verdict_flip_proves_registry_swap():
    """If we swap the evaluator, verdicts must change. If not, the
    registry is a lie.

    Sabotage-verify pattern: this test is only load-bearing if it
    genuinely goes RED under a broken registry. To verify:

        1. Temporarily comment out `register_evaluator(...)` below
           so the sabotage evaluator is never installed.
        2. Re-run the test; the ``saboteur.evaluate(...).verdict ==
           "deny"`` assertion goes RED because ``get_evaluator`` still
           returns the native evaluator, which returns "allow".

    Confirmed RED on 2026-08-07 by exactly that experiment.
    """

    class SabotageDenyEvaluator:
        name = "sabotage-deny"
        def evaluate(self, inp):
            return VerdictResult(
                verdict="deny",
                reasons=("sabotage",),
                policy_hash="sabotage",
                evaluator_name=self.name,
            )

    inp = EvaluationInput(
        tenant_id="t", principal_kind="agent",
        principal_id="p", action="a",
    )

    # Native → allow
    native = get_evaluator("native")
    assert native.evaluate(inp).verdict == "allow"

    # Swap → deny
    # SABOTAGE_VERIFY: commenting out the next line simulates the
    # broken-registry state — confirmed 2026-08-07 that the assertion
    # below then goes RED with KeyError.
    register_evaluator("sabotage-deny", SabotageDenyEvaluator())  # SABOTAGE_MARKER
    saboteur = get_evaluator("sabotage-deny")
    assert saboteur.evaluate(inp).verdict == "deny"
    assert saboteur.evaluate(inp).evaluator_name == "sabotage-deny"

    unregister_evaluator("sabotage-deny")
