"""
Attack-chain orchestration engine.

Single responsibility: given a new evidence event, advance any
matching partial-match states; on full match, call the signal
emitter. Knows about matchers (via _matchers), rule shape (via
_loader's AttackChainRule), and state (via the StateStore interface).
Does NOT know about the DB, evidence persistence, or how rules were
loaded -- that's the caller's job.

The engine is the only thing record_evidence() hooks into. The
hook is off-by-default; only fires when:
  - KYA_ATTACK_CHAIN_RULES_DIR env is set OR
  - The caller has explicitly created an engine via get_default_engine()

Extension points (the "avoid the redesign trap" surface):
  * signal_emitter: callable(db, tenant_id, principal_id, signal_kind,
                             trigger_evidence_id, rule) -> None
    Default wraps record_principal_signal. Customers register their
    own (Slack, PagerDuty, security-event sink) without forking KYA.
  * Custom matchers: register via _matchers (out of scope here)
  * Custom state stores: subclass StateStore (out of scope here)
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterable
from typing import Any

from ._loader import (
    AttackChainRule,
    StepSpec,
    load_rules_from_dir,
)
from ._matchers import all_match, field_value
from ._state import (
    InMemoryStateStore,
    PartialMatch,
    StateStore,
    ValkeyStateStore,
)

logger = logging.getLogger(__name__)


# Type alias for the pluggable signal emitter. Engine calls this with
# context when a chain fully matches; the default implementation does
# record_principal_signal, but operators can swap in anything.
SignalEmitter = Callable[
    [Any, str, str, str, int | None, AttackChainRule],  # db, tenant, principal, signal_kind, trigger_evidence_id, rule
    None,
]


def default_signal_emitter(
    db: Any,
    tenant_id: str,
    principal_id: str,
    signal_kind: str,
    trigger_evidence_id: int | None,
    rule: AttackChainRule,
) -> None:
    """Out-of-the-box emitter: wraps record_principal_signal.

    Customers wanting different behavior (e.g., webhook + DB +
    Slack) replace this with their own callable when constructing
    AttackChainEngine."""
    try:
        from kya.principals import record_principal_signal
    except ImportError as exc:
        logger.debug(
            "[KYA-CHAINS] record_principal_signal unavailable: %s", exc)
        return
    try:
        record_principal_signal(
            db,
            tenant_id=tenant_id,
            principal_kind="user",  # default; rules can override later
            principal_id=principal_id,
            signal_kind=signal_kind,
            attributes={
                "attack_chain_rule_id": rule.id,
                "attack_chain_severity": rule.severity,
                "attack_chain_trigger_evidence_id":
                    trigger_evidence_id,
            },
        )
    except Exception as exc:
        # Fail-soft: never let chain emission break the request path.
        logger.warning(
            "[KYA-CHAINS] signal emit for rule %s failed: %s",
            rule.id, exc)


class AttackChainEngine:
    """Process evidence events against a set of attack-chain rules.

    Engine instances are STATELESS w.r.t. rules (rules are passed at
    construction). State (partial matches) lives in the StateStore.
    Lets you reuse one engine across many tenants without bleeding
    state between them (the correlate_by key includes tenant_id).

    Typical lifecycle:
      engine = AttackChainEngine(rules=load_rules_from_dir(...))
      # Then in record_evidence():
      engine.process_evidence(db, tenant_id=..., principal_id=...,
                              evidence_kind=..., payload=...,
                              evidence_id=...)
    """

    def __init__(
        self,
        rules: Iterable[AttackChainRule],
        *,
        state_store: StateStore | None = None,
        signal_emitter: SignalEmitter | None = None,
    ) -> None:
        self.rules: list[AttackChainRule] = list(rules)
        self.state_store: StateStore = state_store or InMemoryStateStore()
        self.signal_emitter: SignalEmitter = (
            signal_emitter or default_signal_emitter)
        # Pre-index rules by id for fast lookup during state ops.
        self._rules_by_id: dict[str, AttackChainRule] = {
            r.id: r for r in self.rules}

    # ── Public entry point ────────────────────────────────────────

    def process_evidence(
        self,
        db: Any,
        *,
        tenant_id: str,
        principal_id: str,
        evidence_kind: str,
        payload: dict,
        evidence_id: int | None = None,
        occurred_at_ts: float | None = None,
    ) -> list[str]:
        """Advance any partial matches against this evidence.

        Returns the list of rule_ids that FULLY MATCHED (i.e., emitted
        a signal) on this call. Most calls return [] (the common case
        -- evidence doesn't complete a chain).

        Fail-soft: any internal error in matching is logged and
        swallowed so the caller's record_evidence path isn't broken
        by a malformed rule.
        """
        if not self.rules:
            return []  # nothing configured
        now_ts = occurred_at_ts or time.monotonic()
        matched_ids: list[str] = []

        # Build the correlate-key value tuple ONCE for this event.
        # All rules share the same convention: their `correlate_by`
        # field names are looked up from a synthetic context dict
        # {tenant_id, principal_id, evidence_kind, payload}.
        event_ctx = {
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "evidence_kind": evidence_kind,
            "payload": payload,
        }

        for rule in self.rules:
            try:
                if self._advance_rule(
                        db, rule, event_ctx, now_ts, evidence_id):
                    matched_ids.append(rule.id)
            except Exception as exc:
                logger.warning(
                    "[KYA-CHAINS] rule %s raised during process: %s",
                    rule.id, exc)
        return matched_ids

    # ── Internal: per-rule advancement ────────────────────────────

    def _advance_rule(
        self,
        db: Any,
        rule: AttackChainRule,
        event_ctx: dict,
        now_ts: float,
        evidence_id: int | None,
    ) -> bool:
        """Try to advance partial-match state for one rule against
        the current event. Returns True iff a full match fired."""
        # Build the correlate key for this event.
        correlate_key = tuple(
            str(field_value(event_ctx, p) or "")
            for p in rule.correlate_by
        )

        existing = self.state_store.get(rule.id, correlate_key)
        if existing is None:
            # No partial state yet -- can this event start step 0?
            step0 = rule.steps[0]
            if not self._event_matches_step(event_ctx, step0):
                return False
            pm = PartialMatch(
                rule_id=rule.id,
                correlate_key=correlate_key,
                current_step_idx=1,
                steps_ts=[now_ts],
                steps_evidence_ids=[evidence_id]
                    if evidence_id is not None else [],
            )
            if len(rule.steps) == 1:
                # Single-step rule -- emit immediately.
                self._emit(db, rule, correlate_key, evidence_id)
                return True
            self.state_store.update(pm)
            return False

        # Partial state exists; check the NEXT expected step.
        next_idx = existing.current_step_idx
        if next_idx >= len(rule.steps):
            # Shouldn't happen (complete states are cleared on emit)
            # but defensive: clear and ignore.
            self.state_store.delete(rule.id, correlate_key)
            return False

        next_step = rule.steps[next_idx]
        if not self._event_matches_step(event_ctx, next_step):
            # Doesn't advance. Optionally check global window cap to
            # expire long-stale partial matches.
            if (rule.window_seconds is not None and
                    existing.steps_ts and
                    now_ts - existing.steps_ts[0] > rule.window_seconds):
                self.state_store.delete(rule.id, correlate_key)
            return False

        # Per-step `within_seconds` check vs `after` predecessor.
        if next_step.after is not None and next_step.within_seconds:
            after_idx = next(
                (i for i, s in enumerate(rule.steps)
                 if s.id == next_step.after),
                None)
            if (after_idx is not None
                    and after_idx < len(existing.steps_ts)):
                gap = now_ts - existing.steps_ts[after_idx]
                if gap > next_step.within_seconds:
                    # Step matched the field spec but the time window
                    # closed -- this is a partial-match abort.
                    self.state_store.delete(rule.id, correlate_key)
                    return False

        # Advance.
        existing.current_step_idx += 1
        existing.steps_ts.append(now_ts)
        if evidence_id is not None:
            existing.steps_evidence_ids.append(evidence_id)
        self.state_store.update(existing)

        if existing.current_step_idx >= len(rule.steps):
            # Full match.
            self._emit(db, rule, correlate_key, evidence_id)
            self.state_store.delete(rule.id, correlate_key)
            return True
        return False

    def _event_matches_step(self, event_ctx: dict, step: StepSpec) -> bool:
        if step.evidence_kind != event_ctx.get("evidence_kind"):
            return False
        # Match spec fields are evaluated against the full event_ctx
        # (so spec can reference "payload.X", "tenant_id", etc.).
        return all_match(event_ctx, step.match)

    def _emit(
        self,
        db: Any,
        rule: AttackChainRule,
        correlate_key: tuple[str, ...],
        trigger_evidence_id: int | None,
    ) -> None:
        """Call the configured signal_emitter. The (tenant_id,
        principal_id) values come from the correlate_key positions
        that match the rule's correlate_by list."""
        # correlate_by is [tenant_id, principal_id, ...]. Pull the
        # canonical fields by name (defaulting to "" if missing).
        kv = dict(zip(rule.correlate_by, correlate_key))
        tenant_id = kv.get("tenant_id", "")
        principal_id = kv.get("principal_id", "")
        try:
            self.signal_emitter(
                db, tenant_id, principal_id,
                rule.emits_signal, trigger_evidence_id, rule)
            logger.info(
                "[KYA-CHAINS] rule %r matched -- emitted %s for "
                "tenant=%s principal=%s",
                rule.id, rule.emits_signal, tenant_id, principal_id)
        except Exception as exc:
            logger.warning(
                "[KYA-CHAINS] signal_emitter raised for rule %s: %s",
                rule.id, exc)


# ── Default engine (lazy, env-driven) ──────────────────────────────


_DEFAULT_ENGINE: AttackChainEngine | None = None
_DEFAULT_ENGINE_LOCK_KEY = "_kya_chains_default_engine"


def resolve_state_store() -> StateStore:
    """Pick a StateStore for the default engine based on env.

    Env contract (``KYA_ATTACK_CHAIN_STATE``):
      * ``auto`` (default) -- use ``ValkeyStateStore`` when a Valkey
        client is reachable (so multi-worker fleets get cross-process
        chain detection for free); otherwise fall back to
        ``InMemoryStateStore``.
      * ``memory`` -- always use ``InMemoryStateStore`` (per-process).
      * ``valkey`` -- always use ``ValkeyStateStore`` (fails soft to
        no-op if no client is configured -- operators who set this
        MUST also configure ``KYA_VALKEY_URL``).

    Exposed publicly so callers building their own engine can use the
    same env-driven selection without re-implementing the logic.
    """
    raw = os.environ.get("KYA_ATTACK_CHAIN_STATE", "auto")
    mode = raw.strip().lower()
    if mode == "memory":
        return InMemoryStateStore()
    if mode == "valkey":
        # Forced Valkey: warn loudly if no client is available so a
        # misconfigured operator (e.g., set state=valkey but forgot
        # KYA_VALKEY_URL) sees that chain detection is silently a
        # no-op until they fix it. Without this warning the store
        # would still construct and fail-soft on every method.
        try:
            from kya._valkey import get_valkey
            if get_valkey() is None:
                logger.warning(
                    "[KYA-CHAINS] KYA_ATTACK_CHAIN_STATE=valkey but "
                    "no Valkey client is available "
                    "(KYA_VALKEY_URL/REDIS_URL not set, redis-py not "
                    "installed, or connection failed). Chain "
                    "detection will be a no-op until Valkey is "
                    "reachable. Set KYA_ATTACK_CHAIN_STATE=memory if "
                    "single-process operation is intended.")
        except Exception as exc:
            logger.debug(
                "[KYA-CHAINS] valkey availability probe raised: %s",
                exc)
        return ValkeyStateStore()
    if mode not in ("auto", ""):
        # Unknown value -- fall back to auto rather than crash, but
        # surface the typo so it gets fixed.
        logger.warning(
            "[KYA-CHAINS] unknown KYA_ATTACK_CHAIN_STATE=%r; expected "
            "one of: auto, memory, valkey. Falling back to 'auto'.",
            raw)
    # auto: prefer Valkey when reachable.
    try:
        from kya._valkey import get_valkey
        if get_valkey() is not None:
            logger.info(
                "[KYA-CHAINS] default state store: ValkeyStateStore "
                "(cross-process chain detection active)")
            return ValkeyStateStore()
    except Exception as exc:
        logger.debug(
            "[KYA-CHAINS] valkey probe failed, using in-memory: %s",
            exc)
    return InMemoryStateStore()


def get_default_engine() -> AttackChainEngine | None:
    """Return the process-wide default engine, building it lazily on
    first call from KYA_ATTACK_CHAIN_RULES_DIR env.

    State-store selection follows :func:`resolve_state_store` -- with
    a reachable Valkey, chains correlate across workers/processes
    automatically.

    Returns None when no rules dir is configured -- callers (e.g.,
    record_evidence) treat None as "feature disabled, no-op".
    """
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is not None:
        return _DEFAULT_ENGINE
    rules_dir = os.environ.get("KYA_ATTACK_CHAIN_RULES_DIR", "").strip()
    if not rules_dir:
        return None
    try:
        rules = load_rules_from_dir(rules_dir)
    except Exception as exc:
        logger.warning(
            "[KYA-CHAINS] failed to load rules from %s: %s",
            rules_dir, exc)
        return None
    if not rules:
        return None
    _DEFAULT_ENGINE = AttackChainEngine(
        rules=rules, state_store=resolve_state_store())
    logger.info(
        "[KYA-CHAINS] default engine loaded %d rules from %s",
        len(rules), rules_dir)
    return _DEFAULT_ENGINE


def reset_default_engine() -> None:
    """Test helper: clear the cached default engine so a fresh
    env-driven load happens on next get_default_engine() call."""
    global _DEFAULT_ENGINE
    _DEFAULT_ENGINE = None
