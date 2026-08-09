"""The KYA decision stack — assembled, not invented.

For each MCP ``tools/call`` the gateway intercepts, this pipeline:

    1. RBAC check (allow / deny / require_human)
    2. payload-cap check
    3. rate-limit + burst-anomaly check
    4. replay-protection check
    5. tenant-budget check
    6. min_trust gate (via require_action)

Every step delegates to the existing primitive in :mod:`kya` — there is
zero policy logic in this module. If a check fails, the pipeline returns
a :class:`Verdict` with verdict="deny" and a structured ``reason_codes``
list the gateway puts onto the audit record.

This module's job is **orchestration**: order, fail-closed semantics,
and turning exceptions from the primitives into a single typed return
value the gateway can act on without try/except scattered everywhere.

Every verdict-producing site routes through the ``kya.PolicyEvaluator``
abstraction. The gateway rule runs its primitive
(RBAC match, ``check_rate``, ``should_refuse``, ...) as before, then
delegates the FINAL verdict emission through ``evaluator.evaluate(inp)``.
The evaluator gets the last word:

    * If ``evaluator.evaluate()`` returns a non-``"allow"`` verdict, the
      pipeline maps it back to a :class:`Verdict` and returns it.
    * If the evaluator returns ``"allow"``, the pipeline falls back to
      the rule's inline candidate :class:`Verdict` — preserving the
      exact wire behaviour when the default :class:`NativeEvaluator` is
      used (its default_allow branch fires for gateway-shaped inputs it
      doesn't recognise).

This dispatch pattern lets a downstream consumer register an LLM-judge
evaluator that flips a rate-limit "deny" into a "flag_for_review"
without editing the gateway pipeline. Sabotage-swap tests register a
``SabotageDenyEvaluator`` to prove the wiring is real end-to-end.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from kya_gateway.config import PolicyConfig, RBACConfig
from kya_gateway.identity import BoundPrincipal

logger = logging.getLogger(__name__)


# ─── Legacy verdict alias mapping ──────────────────────────────────
#
# ``require_human`` was renamed to ``flag_for_review`` in the canonical
# Layer-2 vocabulary. We NORMALIZE the legacy alias at every boundary
# (config parse + evaluator adapter + rbac evaluate) so no internal
# code path ever sees the legacy string as a live verdict — it exists
# only long enough to warn on and convert.
#
# No hardcoded verdict strings or sunset versions. The alias mapping +
# sunset version + canonical target live in ``kya._verdict_aliases`` —
# a single source of truth shared by this module and
# ``kya.policy_verdicts``. Re-exported here as module-level names so
# existing test call sites and ``kya_gateway.server`` imports keep
# working unchanged.
from kya._verdict_aliases import (
    _CANONICAL_HUMAN_APPROVAL_VERDICT,
    _DEPRECATION_SUNSET,
    _LEGACY_VERDICT_ALIASES,
)


def _normalize_legacy_verdict(
    verdict: str, *, context: str,
) -> str:
    """Return the canonical verdict for a possibly-legacy input.

    When ``verdict`` is a legacy alias (see ``_LEGACY_VERDICT_ALIASES``),
    log a WARN referencing ``_DEPRECATION_SUNSET`` and return the
    canonical form. Otherwise return ``verdict`` unchanged.

    ``context`` is a short human-readable label (e.g. "adapter",
    "config") that lets operators locate the caller in log output.

    Boundary-normalization pattern
    ------------------------------
    Every layer that consumes a caller-supplied verdict runs this same
    conversion at its ingress boundary so no internal code path ever
    sees the legacy string as a live value. Current callers:

    * ``kya_gateway.config._parse_rbac`` — YAML config parse boundary
    * ``kya_gateway.policy_pipeline._verdict_result_to_gateway_verdict``
      — evaluator adapter boundary
    * ``kya_gateway.policy_pipeline.evaluate`` — RBAC evaluate boundary

    Downstream wire-input validators mirror this pattern using the same
    shared ``kya._verdict_aliases`` constants.
    """
    if verdict in _LEGACY_VERDICT_ALIASES:
        canonical = _LEGACY_VERDICT_ALIASES[verdict]
        logger.warning(
            "[KYA-GATEWAY] verdict %r is a deprecated alias for %r "
            "(%s boundary) — normalizing. Alias removed in "
            "veldt-kya %s.",
            verdict, canonical, context, _DEPRECATION_SUNSET,
        )
        return canonical
    return verdict


@dataclass(frozen=True)
class Verdict:
    """The result of running an MCP request through the policy stack.

    ``verdict`` is one of:
        ``"allow"``            — KYA recommends the customer platform proceed
        ``"deny"``             — KYA recommends the customer platform stop
        ``"flag_for_review"``  — KYA recommends escalation to a human approver
        ``"require_human"``    — deprecated alias for ``flag_for_review`` (#105)

    Always assume the customer platform is the one that **enforces**.
    KYA's role is to **score, sign, and record** — never to block by
    itself.

    ``reason_codes`` is a stable enum-like list (no free-form strings)
    so downstream consumers (attack chain rules, dashboards) can match
    on them. Examples:
        ``RBAC_DENY``, ``MIN_TRUST_NOT_MET``, ``BUDGET_EXCEEDED``,
        ``REPLAY_DETECTED``, ``RATE_LIMIT``, ``PAYLOAD_TOO_LARGE``,
        ``REQUIRES_HUMAN``.

    ``signal_kind`` is the trust signal the gateway will record on the
    principal's trust ledger.
    """

    verdict: str
    reason_codes: list[str] = field(default_factory=list)
    signal_kind: str = "clean_invocation"
    rich: dict[str, Any] = field(default_factory=dict)


# ─── Evaluator dispatch helpers ─────────────────────────────────────
#
# The gateway rules already produce candidate verdicts
# via their existing primitive calls; the evaluator either replaces
# that verdict (non-``"allow"`` response) or defers to it (``"allow"``
# response). Fail-closed semantics: if the evaluator itself raises or
# the registry lookup misses, the pipeline uses the rule's candidate
# verdict — which is the same fail-closed deny the pipeline emitted
# pre-Phase-3. Never surfaces a fail-open from the abstraction layer.


def _resolve_evaluator(name: str):
    """Look up the evaluator; return ``None`` on any failure.

    Never raises: a missing evaluator name (typo in YAML, custom
    evaluator not registered yet at boot) must not crash the pipeline.
    Returning ``None`` tells the dispatch helper to skip the evaluator
    stage and use the rule's inline candidate verdict directly —
    preserving the pre-Phase-3 wire behaviour on lookup failure.
    """
    try:
        from kya import get_evaluator
    except ImportError:
        logger.debug(
            "[KYA-GATEWAY] kya.get_evaluator unavailable; skipping "
            "evaluator dispatch and using inline rule verdicts"
        )
        return None
    try:
        return get_evaluator(name)
    except Exception as exc:  # noqa: BLE001 — includes KeyError from registry
        logger.warning(
            "[KYA-GATEWAY] evaluator lookup failed name=%r err=%s "
            "— falling back to inline rule verdicts",
            name, exc,
        )
        return None


def _build_eval_input(
    *,
    tenant_id: str,
    principal: BoundPrincipal,
    action: str,
    payload_bytes: int,
    invocation_id: int | None,
    rule: str,
    candidate_verdict: str,
    candidate_reasons: list[str],
    candidate_signal_kind: str,
    extra: dict[str, Any] | None = None,
):
    """Assemble the ``EvaluationInput`` for a rule-triggered evaluation.

    Rule name + the rule's candidate verdict/reasons/signal_kind ride
    in ``attributes`` so a Pro evaluator can pattern-match on them
    (e.g. "if the gateway said BUDGET_EXCEEDED, defer to my LLM judge
    for a warmer-tone flag_for_review"). Everything the primitive
    knew about the request is on the input so custom evaluators aren't
    forced to re-derive it.

    Returns ``None`` on ImportError. The gateway tests
    (``test_min_trust_runtime_error_fails_closed`` +
    ``test_rate_limit_runtime_error_fails_closed``) monkey-patch
    ``sys.modules["kya"]`` with a bare stub that lacks
    ``EvaluationInput``. That's a legitimate operational scenario
    (partial import) — the pipeline's fail-closed behaviour still
    fires via the rule's inline candidate verdict, and the caller
    (``_emit_via_evaluator``) returns the fallback ``Verdict`` on a
    ``None`` input. Never propagates.
    """
    try:
        from kya import EvaluationInput
    except ImportError as exc:
        logger.debug(
            "[KYA-GATEWAY] kya.EvaluationInput unavailable — evaluator "
            "dispatch will be skipped for this rule: %s", exc,
        )
        return None

    attrs: dict[str, Any] = {
        "gateway_rule": rule,
        "gateway_candidate_verdict": candidate_verdict,
        "gateway_candidate_reason_codes": tuple(candidate_reasons),
        "gateway_candidate_signal_kind": candidate_signal_kind,
        "payload_bytes": payload_bytes,
        "invocation_id": invocation_id,
    }
    if extra:
        attrs.update(extra)
    return EvaluationInput(
        tenant_id=tenant_id,
        principal_kind=principal.principal_kind,
        principal_id=principal.principal_id,
        action=action,
        attributes=attrs,
    )


def _verdict_result_to_gateway_verdict(vr, *, fallback: Verdict) -> Verdict:
    """Map ``kya.VerdictResult`` → gateway ``Verdict``.

    Adapter preserves the gateway's public :class:`Verdict` shape
    (``verdict``, ``reason_codes``, ``signal_kind``, ``rich``) so
    ``kya_gateway/server.py`` and downstream consumers stay unchanged.

    Reason codes: prefer the evaluator's ``reasons`` when non-empty
    (evaluator had specific findings); fall back to the gateway rule's
    candidate ``reason_codes`` when the evaluator returned an empty
    tuple. That keeps SabotageDeny-style stubs (which don't bother
    filling reasons) from erasing the rule's diagnostic breadcrumb.

    Signal kind: prefer the evaluator's ``signal_kind`` when set;
    fall back to the gateway rule's ``signal_kind`` when the evaluator
    left it as ``None``. Same rationale as reason_codes.

    ``rich`` carries the evaluator's ``evidence_payload`` plus a
    ``policy_hash`` + ``evaluator_name`` breadcrumb so audit consumers
    can attribute the verdict to the specific evaluator that fired.

    Verdict allowlist. ``VerdictResult.verdict`` is an unvalidated
    str — a typo (``"denny"``), a legacy enum spelling, or a new-vocab
    response from a custom evaluator would silently slip past
    ``server.py``'s explicit ``deny`` / ``flag_for_review`` branches
    and produce a 200-OK silent allow. Instead: if the verdict string
    isn't in the canonical vocabulary (see ``_VALID_VERDICTS`` above),
    log a WARNING and return the ``fallback`` unchanged. The gateway's
    rule verdict is always in-vocab so the fallback path is always safe.

    Legacy alias strings (see ``_LEGACY_VERDICT_ALIASES``) are
    normalized to the canonical form BEFORE the allowlist check runs,
    so no downstream code ever sees the legacy verdict as a live
    value. A WARN is emitted so operators see the drift. Frozen
    VerdictResult is not mutated — we operate on a local
    ``canonical_verdict`` and rebuild the gateway Verdict.
    """
    # Normalize legacy alias FIRST so downstream (allowlist +
    # everything after) only ever sees the canonical form.
    canonical_verdict = _normalize_legacy_verdict(
        vr.verdict, context="adapter",
    )
    if canonical_verdict not in _VALID_VERDICTS:
        logger.warning(
            "[KYA-GATEWAY] evaluator emitted unknown verdict=%r "
            "(evaluator_name=%r) — falling back to gateway rule verdict "
            "%r to avoid silent-allow on typo / new-vocab drift",
            vr.verdict, getattr(vr, "evaluator_name", "<unknown>"),
            fallback.verdict,
        )
        return fallback
    reasons = list(vr.reasons) if vr.reasons else list(fallback.reason_codes)
    signal_kind = vr.signal_kind if vr.signal_kind else fallback.signal_kind
    rich: dict[str, Any] = dict(vr.evidence_payload) if vr.evidence_payload else {}
    if vr.policy_hash:
        rich.setdefault("policy_hash", vr.policy_hash)
    if vr.evaluator_name:
        rich.setdefault("evaluator_name", vr.evaluator_name)
    return Verdict(
        verdict=canonical_verdict,
        reason_codes=reasons,
        signal_kind=signal_kind,
        rich=rich,
    )


# Canonical verdict vocabulary. Used by
# ``_verdict_result_to_gateway_verdict`` to reject typos and
# unknown-vocab strings before they slip past the gateway's
# verdict-consumption branches. Keep this list in sync with
# ``policy_verdicts.VerdictContext``'s handler registry vocabulary
# (allow/deny/redact/throttle/flag_for_review/block/anonymize).
#
# Legacy aliases (see ``_LEGACY_VERDICT_ALIASES``) are NORMALIZED to
# canonical form BEFORE this allowlist runs, so ``require_human`` is
# intentionally NOT listed here — an evaluator emitting it lands as
# ``flag_for_review`` after ``_normalize_legacy_verdict`` fires. The
# alias sunsets in ``_DEPRECATION_SUNSET``.
from kya.canonicals import CANONICAL_VERDICTS as _CANONICAL_VERDICTS

_VALID_VERDICTS: frozenset[str] = _CANONICAL_VERDICTS


def _emit_via_evaluator(
    evaluator,
    inp,
    fallback: Verdict,
    *,
    db=None,
) -> Verdict:
    """Dispatch a rule's candidate verdict through the evaluator.

    Semantic contract:
        * ``evaluator is None``  → return ``fallback`` (registry miss;
          pre-evaluator behaviour).
        * ``inp is None``        → return ``fallback`` (input assembly
          failed — e.g. ``kya.EvaluationInput`` unimportable because a
          test stubbed the ``kya`` module. Fail-closed via the rule's
          own decision.)
        * ``NativeEvaluator.would_short_circuit(inp)`` returns True →
          skip the ``evaluate()`` call entirely. We have proven no rule
          will fire, so the wasted N-scope DB fan-out inside
          ``_compute_policy_hash`` is avoided. The returned fallback
          is enriched with a synthesised ``policy_hash`` (from the
          cached ``get_effective_policy_hash``) + ``evaluator_name=
          "native"`` so ledger attribution is preserved.
        * Evaluator raises       → return ``fallback`` (fail-closed
          via the rule's inline verdict, which is itself the safe
          decision the primitive computed).
        * Evaluator returns ``"allow"`` → return ``fallback`` enriched
          with the evaluator's ``policy_hash`` + ``evaluator_name``
          breadcrumb so audit consumers keep attribution even on
          default-allow paths.
        * Evaluator returns non-``"allow"`` → map through the adapter
          and return the evaluator's verdict (overrides the rule).

    ``db``: the enclosing session, threaded from
    ``evaluate()`` → ``_dispatch()`` → here so the short-circuit
    attribution path can compute the effective policy hash against a
    live session on a cold cache. Defaults to ``None`` for backward
    compatibility with test-fake scenarios; the attribution helper
    logs a WARN (never silent) when it can't produce a hash.

    This is the only place the pipeline touches ``PolicyEvaluator``
    for verdict production — every rule funnels through here so a
    sabotage-swap test only has to prove ONE call-path is honoured.
    """
    if evaluator is None or inp is None:
        return fallback

    # Short-circuit the default NativeEvaluator on gateway-
    # shape inputs that carry no attribute the evaluator would inspect.
    # Import lazily to avoid a cross-package import cycle at module
    # load time. Only NativeEvaluator gets this fast-path — a custom
    # evaluator always runs (it may pattern-match on the gateway rule
    # name / candidate verdict that the input carries in `attributes`).
    try:
        from kya._native_evaluator import NativeEvaluator
    except ImportError:
        NativeEvaluator = None  # type: ignore[assignment]
    if NativeEvaluator is not None and isinstance(evaluator, NativeEvaluator):
        try:
            if evaluator.would_short_circuit(inp):
                # Enrich the fallback with a policy_hash +
                # evaluator_name breadcrumb so audit consumers keep
                # attribution even when we skip evaluate(). Delegates
                # to the (now cached) get_effective_policy_hash for
                # the tenant so it's cheap.
                return _fallback_with_native_attribution(
                    fallback, inp, db=db,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[KYA-GATEWAY] NativeEvaluator.would_short_circuit "
                "raised: %s — proceeding to full evaluate()", exc,
            )

    try:
        result = evaluator.evaluate(inp)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "[KYA-GATEWAY] evaluator.evaluate raised: %s "
            "— falling back to inline rule verdict", exc,
        )
        return fallback
    if result.verdict == "allow":
        # Evaluator defers to the rule's decision (or wasn't
        # opinionated about this rule's input shape). Preserve the
        # gateway's inline candidate verbatim so backward compat holds
        # for the default NativeEvaluator — but enrich `rich` with
        # the evaluator's `policy_hash` + `evaluator_name` so
        # attribution is preserved.
        return _fallback_with_result_attribution(fallback, result)
    return _verdict_result_to_gateway_verdict(result, fallback=fallback)


def _fallback_with_native_attribution(
    fallback: Verdict, inp, *, db=None,
) -> Verdict:
    """Enrich ``fallback`` with a policy_hash + evaluator_name breadcrumb
    when NativeEvaluator was short-circuited.

    We didn't call ``evaluate()`` so there's no VerdictResult to copy
    from. Synthesise via the (cached) ``get_effective_policy_hash`` so
    ledger attribution still works.

    ``db`` is threaded from the caller so a cold-cache hit on the
    short-circuit path can still compute a real hash instead of
    silently degrading. When ``db is None`` (test fakes / caller
    without a session) AND the cache misses AND the compute raises, we
    log at WARNING (not DEBUG) so downstream evidence attribution gaps
    are visible in ops logs — no silent swallow.
    """
    rich = dict(fallback.rich) if fallback.rich else {}
    try:
        from kya.policy_hash import get_effective_policy_hash
        # Threaded ``db`` lets the primitive walk tenant_weights on a
        # cache miss. When ``db is None`` the primitive can still
        # return a cached value; on a cold-cache miss it may raise.
        policy_hash = get_effective_policy_hash(
            db=db, tenant_id=inp.tenant_id,
        )
        rich.setdefault("policy_hash", policy_hash)
    except Exception as exc:  # noqa: BLE001
        # Loud on db=None cold-cache paths so evidence-attribution
        # regressions surface in ops logs; DEBUG when a session was
        # threaded through and the compute still failed (upstream bug
        # that will surface via its own error path). Either way, never
        # silent.
        if db is None:
            logger.warning(
                "[KYA-GATEWAY] short-circuit policy_hash synth failed "
                "with db=None (cold-cache attribution gap): %s — "
                "fallback returned without policy_hash breadcrumb", exc,
            )
        else:
            logger.debug(
                "[KYA-GATEWAY] short-circuit policy_hash synth failed "
                "with db threaded: %s — fallback returned without "
                "policy_hash breadcrumb", exc,
            )
    rich.setdefault("evaluator_name", "native")
    rich.setdefault("evaluator_short_circuited", True)
    return Verdict(
        verdict=fallback.verdict,
        reason_codes=list(fallback.reason_codes),
        signal_kind=fallback.signal_kind,
        rich=rich,
    )


def _fallback_with_result_attribution(
    fallback: Verdict, result,
) -> Verdict:
    """Enrich ``fallback`` with the evaluator's ``policy_hash`` +
    ``evaluator_name`` on the default-allow path.

    The evaluator ran and returned ``"allow"`` — we defer to the rule's
    candidate verdict for the actual decision, but propagate the
    evaluator's audit metadata so downstream attribution isn't lost.
    """
    if not (result.policy_hash or result.evaluator_name):
        return fallback
    rich = dict(fallback.rich) if fallback.rich else {}
    if result.policy_hash:
        rich.setdefault("policy_hash", result.policy_hash)
    if result.evaluator_name:
        rich.setdefault("evaluator_name", result.evaluator_name)
    return Verdict(
        verdict=fallback.verdict,
        reason_codes=list(fallback.reason_codes),
        signal_kind=fallback.signal_kind,
        rich=rich,
    )


def evaluate(
    *,
    db,
    tenant_id: str,
    principal: BoundPrincipal,
    action: str,
    payload_bytes: int,
    invocation_id: int | None,
    cfg: PolicyConfig,
) -> Verdict:
    """Run an MCP request through the configured policy stack.

    Args:
        db: A KYA session.
        tenant_id: KYA tenant the request belongs to.
        principal: The resolved BoundPrincipal.
        action: A canonical action string like ``mcp.filesystem.read``.
        payload_bytes: Size of the request payload.
        invocation_id: The KYA invocation row the gateway has already
            recorded for this request (used by replay protection).
        cfg: The policy block from the gateway config.

    Returns:
        A :class:`Verdict`. Always returns — never raises.
    """
    reasons: list[str] = []
    # Resolve the evaluator ONCE at the top so the
    # per-rule dispatch helpers can pass it through. Cheap
    # registry-dict lookup; caching per-call is overkill.
    evaluator = _resolve_evaluator(cfg.policy_evaluator_name)

    def _dispatch(rule: str, candidate: Verdict, **extra) -> Verdict:
        """Thin closure so per-rule sites don't have to repeat the
        input-assembly boilerplate. Captures ``tenant_id`` / ``principal``
        / etc. from ``evaluate()``'s scope so the emission sites read
        as ``return _dispatch("rbac", Verdict(deny, ...))``.

        Phase-4-P0 FIX-A: closes over the enclosing ``db`` session so
        the short-circuit attribution path (see
        ``_fallback_with_native_attribution``) can compute the effective
        policy hash on a cold cache without silently swallowing the
        exception the ``db=None`` code path would raise.
        """
        inp = _build_eval_input(
            tenant_id=tenant_id,
            principal=principal,
            action=action,
            payload_bytes=payload_bytes,
            invocation_id=invocation_id,
            rule=rule,
            candidate_verdict=candidate.verdict,
            candidate_reasons=candidate.reason_codes,
            candidate_signal_kind=candidate.signal_kind,
            extra=extra or None,
        )
        return _emit_via_evaluator(evaluator, inp, candidate, db=db)

    # ─── RBAC ───────────────────────────────────────────────────
    if cfg.rbac is not None:
        rbac_outcome = _rbac_evaluate(cfg.rbac, principal.principal_kind, action)
        # FIX-C: normalize legacy alias at this boundary so a caller
        # who constructed RBACRule directly (bypassing the config-parse
        # normalization in ``kya_gateway.config._parse_rbac``) still
        # gets canonical semantics downstream. WARN fires on legacy
        # inputs referencing _DEPRECATION_SUNSET.
        rbac_outcome = _normalize_legacy_verdict(
            rbac_outcome, context="rbac-evaluate",
        )
        if rbac_outcome == "deny":
            return _dispatch(
                "rbac",
                Verdict(
                    verdict="deny",
                    reason_codes=["RBAC_DENY"],
                    signal_kind="rbac_refusal",
                ),
                rbac_outcome=rbac_outcome,
            )
        if rbac_outcome == _CANONICAL_HUMAN_APPROVAL_VERDICT:
            reasons.append("REQUIRES_HUMAN")

    # ─── Payload caps ───────────────────────────────────────────
    if cfg.payload_caps is not None and payload_bytes > cfg.payload_caps.max_bytes:
        return _dispatch(
            "payload_caps",
            Verdict(
                verdict="deny",
                reason_codes=["PAYLOAD_TOO_LARGE"],
                signal_kind="payload_too_large",
            ),
            payload_max_bytes=cfg.payload_caps.max_bytes,
        )

    # ─── Rate limit ─────────────────────────────────────────────
    # Fail-closed contract: ImportError → primitive not installed → skip
    # with debug log. Any OTHER exception (DB/network/etc.) → deny with
    # a "_ERROR" reason code so the audit chain captures the operational
    # state and the caller doesn't silently slip through.
    if cfg.rate_limit is not None:
        try:
            from kya.rate_limit import check_rate
        except ImportError:
            logger.debug("[KYA-GATEWAY] kya.rate_limit unavailable; skipping rate check")
        else:
            try:
                # Pass through whichever mode the operator set.
                # RateLimitConfig.__post_init__ guarantees exactly one
                # is non-None, so the check_rate validator never fires.
                rate_ok = check_rate(
                    db,
                    tenant_id=tenant_id,
                    principal_kind=principal.principal_kind,
                    principal_id=principal.principal_id,
                    requests_per_minute=cfg.rate_limit.requests_per_minute,
                    min_interval_seconds=cfg.rate_limit.min_interval_seconds,
                )
            except Exception as exc:
                logger.warning("[KYA-GATEWAY] check_rate raised: %s", exc)
                return _dispatch(
                    "rate_limit_error",
                    Verdict(
                        verdict="deny",
                        reason_codes=["RATE_LIMIT_ERROR"],
                        signal_kind="rate_limit_exceeded",
                    ),
                    primitive_error=str(exc),
                )
            if not rate_ok:
                return _dispatch(
                    "rate_limit",
                    Verdict(
                        verdict="deny",
                        reason_codes=["RATE_LIMIT"],
                        signal_kind="rate_limit_exceeded",
                    ),
                )

    # ─── Replay protection ─────────────────────────────────────
    if invocation_id is not None:
        try:
            from kya.replay_protection import check_invocation_replay
        except ImportError:
            logger.debug("[KYA-GATEWAY] kya.replay_protection unavailable; skipping")
        else:
            try:
                replay_ok = check_invocation_replay(db, invocation_id=invocation_id)
            except Exception as exc:
                logger.warning("[KYA-GATEWAY] check_invocation_replay raised: %s", exc)
                return _dispatch(
                    "replay_error",
                    Verdict(
                        verdict="deny",
                        reason_codes=["REPLAY_ERROR"],
                        signal_kind="replay_detected",
                    ),
                    primitive_error=str(exc),
                )
            if not replay_ok:
                return _dispatch(
                    "replay",
                    Verdict(
                        verdict="deny",
                        reason_codes=["REPLAY_DETECTED"],
                        signal_kind="replay_detected",
                    ),
                )

    # ─── Tenant budget ─────────────────────────────────────────
    if cfg.tenant_budget and cfg.tenant_budget.daily_usd is not None:
        try:
            from kya.tenant_budget import should_refuse
        except ImportError:
            logger.debug("[KYA-GATEWAY] kya.tenant_budget unavailable; skipping")
        else:
            try:
                refuse = should_refuse(
                    db,
                    tenant_id=tenant_id,
                    daily_cap_usd=cfg.tenant_budget.daily_usd,
                )
            except Exception as exc:
                logger.warning("[KYA-GATEWAY] should_refuse raised: %s", exc)
                return _dispatch(
                    "budget_error",
                    Verdict(
                        verdict="deny",
                        reason_codes=["BUDGET_ERROR"],
                        signal_kind="budget_error",
                    ),
                    primitive_error=str(exc),
                )
            if refuse == "refuse":
                return _dispatch(
                    "budget",
                    Verdict(
                        verdict="deny",
                        reason_codes=["BUDGET_EXCEEDED"],
                        signal_kind="budget_exceeded",
                    ),
                    daily_cap_usd=cfg.tenant_budget.daily_usd,
                )

    # ─── min_trust gate ────────────────────────────────────────
    if cfg.min_trust > 0:
        try:
            from kya import AccessDeniedError, require_action
        except ImportError:
            logger.debug("[KYA-GATEWAY] kya.require_action unavailable; skipping")
            AccessDeniedError = None  # type: ignore[assignment]
            require_action = None     # type: ignore[assignment]
        if require_action is not None:
            try:
                require_action(
                    db,
                    tenant_id=tenant_id,
                    principal_kind=principal.principal_kind,
                    principal_id=principal.principal_id,
                    action=action,
                    min_trust=cfg.min_trust,
                )
            except AccessDeniedError:
                return _dispatch(
                    "min_trust",
                    Verdict(
                        verdict="deny",
                        reason_codes=["MIN_TRUST_NOT_MET"],
                        signal_kind="governance_block",
                    ),
                    min_trust=cfg.min_trust,
                )
            except Exception as exc:
                logger.warning("[KYA-GATEWAY] require_action raised: %s", exc)
                return _dispatch(
                    "min_trust_error",
                    Verdict(
                        verdict="deny",
                        reason_codes=["MIN_TRUST_ERROR"],
                        signal_kind="governance_block",
                    ),
                    primitive_error=str(exc),
                )

    # ─── All checks passed ─────────────────────────────────────
    if "REQUIRES_HUMAN" in reasons:
        # Canonical Layer-2 vocabulary is ``flag_for_review``;
        # ``require_human`` remains accepted at the registry via an
        # alias handler. Emit canonical going forward, sourcing the
        # string from ``_CANONICAL_HUMAN_APPROVAL_VERDICT`` so a
        # single edit in ``kya._verdict_aliases`` ripples here.
        return _dispatch(
            _CANONICAL_HUMAN_APPROVAL_VERDICT,
            Verdict(
                verdict=_CANONICAL_HUMAN_APPROVAL_VERDICT,
                reason_codes=reasons,
                signal_kind="governance_block",
            ),
        )
    return _dispatch(
        "default_allow",
        Verdict(verdict="allow", reason_codes=[], signal_kind="clean_invocation"),
    )


# ─── RBAC helper ────────────────────────────────────────────────────


def _rbac_evaluate(rbac: RBACConfig, principal_kind: str, action: str) -> str:
    """Evaluate the rule list for a principal_kind + action pair.

    Returns one of "allow" / "deny" / "require_human".
    """
    for rule in rbac.rules:
        if rule.principal_kind != principal_kind:
            continue
        if _action_matches(action, rule.actions):
            return rule.verdict
    return rbac.default


def _action_matches(action: str, patterns: list[str]) -> bool:
    """Action matcher with `.` namespacing and `*` wildcard support.

    ``mcp.filesystem.read`` matches:
        * ``mcp.filesystem.read``
        * ``mcp.filesystem.*``
        * ``mcp.*``
        * ``*``
    """
    for p in patterns:
        if p == action:
            return True
        if p.endswith(".*") and action.startswith(p[:-1]):
            return True
        if p == "*":
            return True
    return False
