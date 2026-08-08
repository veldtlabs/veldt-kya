"""NativeEvaluator — the OSS default policy evaluator.

Composes existing OSS primitives; does NOT reimplement any rule
logic that already lives elsewhere in ``kya/``.

Composition map
---------------
* Budget-cap rule       → ``kya.tenant_budget.should_refuse``
* Weight-scoped deny    → ``kya.tenant_weights.get_effective_weights``
* Policy hash           → ``kya.policy_hash.get_effective_policy_hash``
                          (with a graceful fallback to ``hash_policy({})``
                          when no DB session is available, and a
                          sentinel ``POLICY_HASH_UNAVAILABLE`` when
                          both DB + fallback fail)

The attribute-based restricted-data rule is genuinely new logic — it
has no existing primitive to compose with — so it lives inline here.
That's flagged in the composition audit table for the review round.

Interpretation layered on top of primitives
-------------------------------------------
* ``_HARD_DENY_WEIGHT_THRESHOLD = 100`` is NativeEvaluator's own
  interpretation of the ``tenant_weights`` primitive's integer weight
  scale — "at or above this value, treat as a scoped deny." The
  ``tenant_weights`` primitive itself has no "hard deny" concept; it
  just stores + resolves ints with only-tighten enforcement. If a
  future primitive introduces a first-class deny sentinel, refactor
  this rule to compose against it instead of interpreting the value.

DB session sourcing
-------------------
Every composed primitive needs a SQLAlchemy Session. Rather than
force ``NativeEvaluator.evaluate()`` to grow a ``db=`` parameter (which
would break the ``PolicyEvaluator`` Protocol shape shared with future
DB-less evaluators like an in-memory RBAC-only checker), the evaluator
resolves a session on demand via one of:

    1. An explicit ``session_factory`` kwarg passed to ``__init__``
       (test-friendly override).
    2. ``kya._session_factory.get_session()`` — the shared SDK-side
       factory installed via ``kya.set_session_factory(...)``.

If neither yields a session, the rules that need one degrade
gracefully: they skip themselves + log at DEBUG, leaving the other
rules to run. Never raises from ``evaluate()``.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .policy_evaluator import EvaluationInput, VerdictResult

logger = logging.getLogger(__name__)


# Signal-kind vocabulary used by the ledger. Mirrors the values
# ``policy_verdicts.VerdictContext.signal_kind`` documents so a
# downstream handler can pass them straight through without a
# translation layer.
_SIGNAL_BUDGET = "budget_exceeded"
_SIGNAL_GOVERNANCE = "governance_block"
_SIGNAL_CLEAN = "clean_invocation"

# Sentinel value for "tenant weight override indicates hard deny".
# Weights are integers in [0, 100] with higher = tighter (see
# ``kya.data_classes.CLASS_WEIGHTS`` and the ``tenant_weights``
# only-tighten docstring). A tenant that pushes a weight to >= 100
# has raised the bar as high as it goes — treat that as a scoped
# deny for the corresponding (action, principal_kind) tuple.
_HARD_DENY_WEIGHT_THRESHOLD = 100

# Reasons vocabulary. Kept as module constants so consumers pattern-
# match against one source of truth.
_R_BUDGET = "budget_exceeded"
_R_TENANT_SCOPED = "tenant_scoped_deny"
_R_RESTRICTED = "restricted_data_requires_human"
_R_DEFAULT_ALLOW = "policy_default_allow"
_R_ERROR_PREFIX = "evaluator_error"

# Sentinel value emitted when the effective policy hash cannot be
# computed (import failure, DB error + fallback failure, or evaluator
# fail-closed path). The ``VerdictResult.policy_hash`` contract is
# "always non-empty" — this sentinel satisfies the contract while
# still being unambiguously distinguishable from a real hash. Ledger
# consumers grep for this to detect audit-attribution gaps.
POLICY_HASH_UNAVAILABLE = "policy-hash-unavailable"


class NativeEvaluator:
    """The OSS default evaluator. Composes ``tenant_budget``,
    ``tenant_weights``, and ``policy_hash`` primitives.

    Instantiate with the default settings for typical use::

        from kya import NativeEvaluator, register_evaluator
        register_evaluator("native", NativeEvaluator())

    Tests can inject a specific SQLAlchemy session factory to bypass
    the SDK-wide ``kya.set_session_factory`` mechanism::

        NativeEvaluator(session_factory=lambda: my_test_session)
    """

    name = "native"

    def __init__(
        self,
        *,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._explicit_session_factory = session_factory

    # ── Session sourcing ─────────────────────────────────────────────

    def _get_session(self) -> Any | None:
        """Resolve a DB session, or ``None`` if unavailable.

        Order of preference:
            1. Explicit factory passed at construction.
            2. ``kya._session_factory.get_session()`` (SDK-wide).

        A ``None`` return means "no DB — skip DB-dependent rules".
        Never raises: any exception in the factory is logged at DEBUG
        and treated as "no session available".
        """
        factory = self._explicit_session_factory
        if factory is not None:
            try:
                return factory()
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "[kya.native_eval] explicit session_factory raised: %s",
                    exc,
                )
                return None
        try:
            from ._session_factory import get_session
            return get_session()
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[kya.native_eval] _session_factory.get_session raised: %s",
                exc,
            )
            return None

    # ── Policy-hash composition ──────────────────────────────────────

    def _compute_policy_hash(self, db: Any | None, tenant_id: str) -> str:
        """Delegate to ``kya.policy_hash`` for the policy hash.

        With a DB session, produces the full effective-policy hash
        via ``get_effective_policy_hash``. Without one, falls back
        to hashing an empty policy so the ``VerdictResult.policy_hash``
        contract (non-empty string) is still met — but callers can
        detect the fallback because the hash of ``{}`` is a known
        constant (empty-policy sentinel).
        """
        try:
            from .policy_hash import get_effective_policy_hash, hash_policy
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[kya.native_eval] policy_hash import failed: %s", exc,
            )
            return POLICY_HASH_UNAVAILABLE

        if db is not None:
            try:
                return get_effective_policy_hash(db, tenant_id=tenant_id)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "[kya.native_eval] get_effective_policy_hash "
                    "failed: %s — falling back to empty-policy hash", exc,
                )
        # Fallback: hash of {} — stable, cross-runtime, and clearly
        # distinguishable from a real effective-policy hash by the
        # value alone. Meets the "non-empty string" contract.
        try:
            return hash_policy({})
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[kya.native_eval] hash_policy({}) failed: %s", exc,
            )
            return POLICY_HASH_UNAVAILABLE

    # ── Rule 1: budget cap ───────────────────────────────────────────

    def _check_budget(
        self,
        db: Any | None,
        inp: EvaluationInput,
    ) -> VerdictResult | None:
        """Delegate to ``kya.tenant_budget.should_refuse``.

        Fires only when the caller supplies ``estimated_cost_usd`` in
        ``inp.attributes`` — that's the signal that this call has a
        cost dimension to enforce against. Returns ``None`` when the
        rule doesn't fire, letting the next rule get a look.
        """
        cost = inp.attributes.get("estimated_cost_usd")
        if cost is None:
            return None
        try:
            cost_usd = float(cost)
        except (TypeError, ValueError):
            logger.debug(
                "[kya.native_eval] estimated_cost_usd not a number: %r", cost,
            )
            return None
        if cost_usd <= 0:
            return None
        if db is None:
            logger.debug(
                "[kya.native_eval] budget rule skipped — no DB session",
            )
            return None

        try:
            from .tenant_budget import should_refuse
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[kya.native_eval] tenant_budget import failed: %s", exc,
            )
            return None

        # scope_key convention: use the principal id when the
        # principal is an agent (matches ``record_cost_event``'s
        # per-agent scope), otherwise fall back to the tenant-wide
        # "*" key. Callers wanting different budgeting semantics can
        # supply an explicit ``budget_scope_key`` attribute.
        scope_key = inp.attributes.get("budget_scope_key")
        if not scope_key:
            scope_key = inp.principal_id if inp.principal_kind == "agent" else "*"
        scope = inp.attributes.get("budget_scope", "agent" if inp.principal_kind == "agent" else "tenant")

        try:
            decision = should_refuse(
                db,
                tenant_id=inp.tenant_id,
                scope_key=scope_key,
                intended_cost_usd=cost_usd,
                scope=scope,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[kya.native_eval] should_refuse raised: %s", exc,
            )
            return None

        if decision.verdict != "refuse":
            return None

        return VerdictResult(
            verdict="deny",
            reasons=(_R_BUDGET,),
            evidence_payload={
                "budget_reason": decision.reason,
                "current_usd": decision.current_usd,
                "threshold_usd": decision.threshold_usd,
            },
            signal_kind=_SIGNAL_BUDGET,
            evaluator_name=self.name,
        )

    # ── Rule 2: tenant weight scoped deny ────────────────────────────

    def _check_tenant_weight(
        self,
        db: Any | None,
        inp: EvaluationInput,
    ) -> VerdictResult | None:
        """Delegate to ``kya.tenant_weights.get_effective_weights``.

        Looks up the tenant's effective weight override for the
        (scope=action, key=principal_kind) tuple. When the resolved
        value is at or above the hard-deny sentinel, denies with a
        scoped-deny reason.

        Requires the ``inp.action`` to correspond to a registered
        weight scope (see ``kya.tenant_weights.known_scopes``). If the
        scope isn't registered, the rule silently skips — matches the
        "only surfaces when configured" ergonomics of the rest of the
        weight subsystem.
        """
        if db is None:
            logger.debug(
                "[kya.native_eval] tenant-weight rule skipped — no DB",
            )
            return None

        try:
            from .tenant_weights import get_effective_weights, known_scopes
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[kya.native_eval] tenant_weights import failed: %s", exc,
            )
            return None

        try:
            scopes = set(known_scopes())
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[kya.native_eval] known_scopes raised: %s", exc,
            )
            return None
        if inp.action not in scopes:
            return None

        try:
            weights = get_effective_weights(
                db, inp.action, tenant_id=inp.tenant_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[kya.native_eval] get_effective_weights raised: %s", exc,
            )
            return None

        value = weights.get(inp.principal_kind)
        if value is None:
            return None
        try:
            value_int = int(value)
        except (TypeError, ValueError):
            return None
        if value_int < _HARD_DENY_WEIGHT_THRESHOLD:
            return None

        return VerdictResult(
            verdict="deny",
            reasons=(_R_TENANT_SCOPED,),
            evidence_payload={
                "scope": inp.action,
                "key": inp.principal_kind,
                "weight_value": value_int,
                "hard_deny_threshold": _HARD_DENY_WEIGHT_THRESHOLD,
            },
            signal_kind=_SIGNAL_GOVERNANCE,
            evaluator_name=self.name,
        )

    # ── Rule 3: attribute-based scoped deny ──────────────────────────
    # NOTE (composition audit): this rule has no existing primitive to
    # compose with — the "restricted data must be handled by a human"
    # semantic isn't encoded anywhere else in the OSS surface today.
    # New logic lives inline. Flagged in the report so a future
    # refactor moves it under a shared primitive if the semantic
    # generalises.

    def _check_restricted_data(
        self,
        inp: EvaluationInput,
    ) -> VerdictResult | None:
        classification = inp.attributes.get("data_classification")
        if classification != "restricted":
            return None
        if inp.principal_kind == "human":
            return None
        return VerdictResult(
            verdict="deny",
            reasons=(_R_RESTRICTED,),
            evidence_payload={
                "data_classification": classification,
                "principal_kind": inp.principal_kind,
            },
            signal_kind=_SIGNAL_GOVERNANCE,
            evaluator_name=self.name,
        )

    # ── Rule 4: default allow ────────────────────────────────────────

    def _default_allow(self) -> VerdictResult:
        return VerdictResult(
            verdict="allow",
            reasons=(_R_DEFAULT_ALLOW,),
            signal_kind=_SIGNAL_CLEAN,
            evaluator_name=self.name,
        )

    # ── Fast-path check (task #318 FIX-1) ───────────────────────────

    def would_short_circuit(self, inp: EvaluationInput) -> bool:
        """Return True when NativeEvaluator can prove no rule will fire.

        The gateway policy pipeline calls this BEFORE ``evaluate()`` on
        every request; if it returns True the pipeline skips the
        evaluator and falls back to the rule's inline candidate verdict
        (which for the default-allow case is ``"allow"``). This avoids
        the N-scope DB fan-out inside ``_compute_policy_hash`` for
        gateway-shaped inputs that carry NONE of the attributes any of
        NativeEvaluator's rules would inspect.

        Rules inspected (must stay in sync with ``evaluate()``):

            * ``_check_budget``  → fires only if ``estimated_cost_usd``
              is present in ``inp.attributes``.
            * ``_check_tenant_weight`` → fires only if ``inp.action``
              matches a registered ``kya.tenant_weights`` scope key.
              Checked via ``known_scopes()``; if the scopes registry
              hasn't been populated yet (fresh import / test isolation)
              the check safely returns True (no rule can fire against
              zero scopes).
            * ``_check_restricted_data`` → fires only if
              ``inp.attributes["data_classification"] == "restricted"``.

        Returns True ONLY when we can prove all three rules will
        short-circuit to None. Any doubt (e.g. import failure looking
        up ``known_scopes``) returns False so ``evaluate()`` still runs
        — safety first over latency.
        """
        attrs = inp.attributes
        # Rule 3: restricted-data
        if attrs.get("data_classification") == "restricted":
            return False
        # Rule 1: budget cap
        if attrs.get("estimated_cost_usd") is not None:
            return False
        # Rule 2: tenant weight scope match
        try:
            from .tenant_weights import known_scopes
            scopes = known_scopes()
        except Exception:  # noqa: BLE001
            # If we can't check safely, err on the side of running
            # the full evaluator — never skip a rule that MIGHT fire.
            return False
        if inp.action in scopes:
            return False
        return True

    # ── Public entrypoint ────────────────────────────────────────────

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        """Run the rule stack. Never raises.

        On unexpected internal error, fails CLOSED — returns
        ``verdict="deny"`` with reasons=("evaluator_error", ...). A
        silent allow on a broken evaluator would defeat the purpose
        of the abstraction; fail-closed is the safe default for a
        governance-layer primitive.
        """
        # Hoist policy_hash + session resolution above the try block
        # so the fail-closed path (below) can still emit them. Both
        # helpers are contractually non-raising — see their docstrings
        # + the graceful-degrade tests. The try below only wraps the
        # rule-execution frames, which can raise from user-supplied
        # composition targets or unexpected primitive bugs.
        try:
            db = self._get_session()
        except Exception:  # noqa: BLE001 — defensive; _get_session catches internally
            db = None
        try:
            policy_hash = self._compute_policy_hash(db, inp.tenant_id)
        except Exception:  # noqa: BLE001 — defensive; _compute_policy_hash catches internally
            policy_hash = POLICY_HASH_UNAVAILABLE

        try:
            # Rules run in declaration order. First one that fires
            # (i.e. returns non-None) short-circuits the stack; the
            # attribute-restricted rule is intentionally last of the
            # deny rules so a tenant weight override or budget cap
            # gets first say.
            for rule in (
                lambda: self._check_budget(db, inp),
                lambda: self._check_tenant_weight(db, inp),
                lambda: self._check_restricted_data(inp),
            ):
                result = rule()
                if result is not None:
                    # Re-emit with the resolved policy_hash + evaluator
                    # name so every VerdictResult carries the same
                    # audit metadata regardless of which rule fired.
                    return _with_hash(result, policy_hash, self.name)

            return _with_hash(
                self._default_allow(), policy_hash, self.name,
            )
        except Exception as exc:  # noqa: BLE001
            # Fail-closed by contract — an evaluator that can't reach
            # a verdict must not silently allow. Log at ERROR so ops
            # sees the drift; return a deny that names the failure
            # in a stable reason code the ledger can index. Emits
            # ``policy_hash`` from the pre-try compute (or the
            # ``POLICY_HASH_UNAVAILABLE`` sentinel if that itself
            # failed) so ledger attribution is preserved even on
            # the fail-closed path.
            logger.error(
                "[kya.native_eval] unexpected error in evaluate(): %s",
                exc, exc_info=True,
            )
            return VerdictResult(
                verdict="deny",
                reasons=(_R_ERROR_PREFIX, str(exc)),
                evidence_payload={"exception_type": type(exc).__name__},
                policy_hash=policy_hash,
                evaluator_name=self.name,
                signal_kind=_SIGNAL_GOVERNANCE,
            )


def _with_hash(
    result: VerdictResult, policy_hash: str, evaluator_name: str,
) -> VerdictResult:
    """Return a new ``VerdictResult`` with ``policy_hash`` +
    ``evaluator_name`` set. ``VerdictResult`` is frozen so we can't
    mutate in place.
    """
    return VerdictResult(
        verdict=result.verdict,
        reasons=result.reasons,
        evidence_payload=result.evidence_payload,
        policy_hash=policy_hash,
        evaluator_name=evaluator_name,
        signal_kind=result.signal_kind,
    )


__all__ = ["NativeEvaluator"]
