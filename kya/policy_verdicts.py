"""Policy verdict handler registry — one dispatch layer for every verdict.

Motivation
----------
Before this module, each policy verdict was handled by an ad-hoc
``if/elif`` chain inside the gateway (``deny`` → 403, ``require_human``
→ 428, ``allow`` → forward). Adding a new verdict — ``redact``,
``throttle``, action-gate ``block`` — meant editing the pipeline AND
every consumer. This module inverts that: register a handler once, the
pipeline dispatches to it.

Two integration points share the same registry:

    Gateway (``kya_gateway.server``)
        Pre-invocation. Uses ``layer="gateway"`` handlers to decide
        whether to short-circuit (403 deny, 428 require_human) or
        forward the call.

    Action gate (``kya_pro.dashboard_api``)
        Post-invocation. Uses ``layer="action_gate"`` handlers to
        mutate the response before shipping (redact fields, tighten
        throttles, swap out blocked results).

Same dictionary of handlers, different ``layer`` filter. Adding a new
verdict is one handler class + one ``register()`` call — zero pipeline
edits.

Design notes
------------
* Handlers are **pure**. They take a ``VerdictContext``, return a
  ``HandlerResult``. Side effects (writing ``kya_pending_invocations``
  rows, incrementing rate-limit counters, streaming evidence to the
  ledger) live in the caller, applied AFTER the handler returns based
  on what the ``mutations`` bag carries.

* The registry is **module-global** because there is only ever one
  active policy per process. Tests use ``unregister()`` + re-register
  to swap in stubs — no threading; ``pytest`` runs tests sequentially
  within a file, and cross-file leakage is guarded by the
  ``restore_default_handlers`` fixture in ``tests/conftest.py``.

* ``forward=True`` with a ``response_body`` set is the "action-gate
  mutation" pattern: the upstream call ran, its body came back, and
  the handler is rewriting it. ``forward=False`` is the short-circuit
  pattern: the handler is producing the response itself, upstream
  never sees the request (gateway layer) or its output is being
  swapped (action-gate layer for the ``block`` verdict).

* Unknown verdicts fail **open** — return ``HandlerResult(forward=True)``
  with no mutations. Rationale: an unknown verdict is either a bug in
  the verdict emitter or an operator running an old gateway against a
  newer policy config. Failing closed would take down production for a
  benign forward compatibility gap. Failing open is logged so ops sees
  the drift.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Literal, Optional, Protocol, TypedDict, runtime_checkable

logger = logging.getLogger(__name__)


# Set of mutation keys the shipped OSS handlers emit. Downstream
# consumers (#101 gateway integration) grep against this set to
# enforce no typo drift ships silently. Handlers are still allowed to
# emit arbitrary keys — this is a convention, not a schema — but
# shipped OSS keys must be listed here.
#
# Pro-side handlers (action-gate redact/throttle/block) live in
# ``kya_pro.policy.verdict_handlers`` and maintain their own
# ``MUTATION_KEYS_ACTION_GATE`` set. The full system-wide set is the
# union of the two.
MUTATION_KEYS: frozenset[str] = frozenset({
    "hitl.needs_pending_row",
})


# Typed view over the mutations bag for the shipped handlers. Uses
# TypedDict's functional syntax because the runtime keys are dotted
# ("hitl.needs_pending_row") — not valid Python identifiers, so the
# class syntax with `field_name: type` can't express them. The
# functional form takes a str→type mapping and produces a TypedDict
# whose keys mypy/pyright will check against the real runtime dict.
#
# Handlers emit HandlerResult(mutations=..., ...) — consumers may
# type-annotate that dict as Mutations for editor + type-checker
# support. Emitting an unknown key is legal (forward compat) but
# emitting a KNOWN key with a wrong type is a bug — this catches it.
Mutations = TypedDict(
    "Mutations",
    {
        "hitl.needs_pending_row": bool,
    },
    total=False,
)


# ── Types ────────────────────────────────────────────────────────────


ContextLayer = Literal["gateway", "action_gate"]
"""Layer a VerdictContext originates from.

A ``VerdictContext`` is always either "gateway" (pre-invocation) or
"action_gate" (post-invocation). It is never "both" — the caller knows
where it lives. "both" is a handler-registration option only.
"""

HandlerLayer = Literal["gateway", "action_gate", "both"]
"""Layers a handler wishes to service.

"both" is a wildcard: the same handler responds to lookups from either
layer. Used by verdicts whose semantic is layer-independent (``allow``
is the canonical example).
"""


@dataclass(frozen=True)
class VerdictContext:
    """Everything a handler needs to make its decision, and nothing more.

    Kept read-only so a handler cannot mutate what a downstream handler
    or the caller sees. Verdict-specific inputs (redact-field lists,
    throttle multipliers) go in ``rich`` — a free-form bag so new
    verdicts don't require expanding this class.
    """
    verdict: str
    reason_codes: list[str]
    tenant_id: str
    principal_kind: str
    principal_id: str
    action: str
    layer: ContextLayer
    # B2 fix: signal_kind is what the gateway writes to the trust
    # ledger — dropping it would break audit correlation. Populated
    # by the gateway from the Verdict.signal_kind produced upstream.
    signal_kind: Optional[str] = None
    """Trust-ledger signal name — audit correlation key.

    Values are the enum-like ledger tags: ``rbac_refusal``,
    ``governance_block``, ``budget_exceeded``, ``rate_limit_exceeded``,
    ``clean_invocation`` etc. Optional at the context layer so
    callers building test contexts don't have to invent one, but the
    gateway integration MUST populate it — the audit chain expects it.
    """
    # ── Optional context for action-gate handlers ────────────────────
    upstream_body: Optional[bytes] = None
    """The response body from upstream. Only populated at layer=action_gate."""
    upstream_status: Optional[int] = None
    """The response status from upstream. Only populated at layer=action_gate."""
    rich: dict[str, Any] = field(default_factory=dict)
    """Verdict-specific config passed through from the policy engine.

    Example keys: ``redact_fields`` (list[str] JSONPath), ``throttle_
    multiplier`` (float 0-1), ``throttle_duration_sec`` (int).
    """


@dataclass(frozen=True)
class HandlerResult:
    """What a handler decides.

    Composable — the caller can fold results from multiple handlers
    into a single outgoing response by merging ``response_headers``
    and ``mutations`` dicts.
    """
    forward: bool = True
    """True to continue the pipeline; False to short-circuit."""
    http_status: Optional[int] = None
    """Status code when short-circuiting. Ignored when forward=True."""
    jsonrpc_error_code: Optional[int] = None
    """JSON-RPC error code for the gateway envelope.

    B1 fix — the gateway wraps handler output in ``make_error(req_id,
    code, msg, data=body)`` on the wire. Without this field, adopting
    the registry at the gateway layer would break every existing
    caller pattern-matching on the numeric code (``-32001`` for deny,
    ``-32007`` for require_human). Handlers populate it; the gateway
    integration reads it. Ignored at the action-gate layer where the
    envelope shape is different.
    """
    response_body: Optional[dict[str, Any]] = None
    """JSON body. When forward=False, replaces the response entirely.

    When forward=True and layer=action_gate, replaces the upstream
    body while preserving upstream status — that's how ``redact``
    delivers a mutated response without hijacking the status code.
    """
    response_headers: dict[str, str] = field(default_factory=dict)
    """Headers to add to the outgoing response.

    The caller merges these with pipeline defaults (X-Request-Id,
    OpenTelemetry trace context, etc.). Handler headers win on
    collision — the handler had the most specific view.
    """
    mutations: dict[str, Any] = field(default_factory=dict)
    """Named side effects the caller applies AFTER the handler returns.

    Kept as a bag rather than typed fields so new handlers can add
    new mutation keys without forcing a HandlerResult schema bump.
    Examples::

        mutations = {
            "hitl.needs_pending_row": True,
            "redact.fields": ["$.result.email", "$.result.ssn"],
            "throttle.multiplier": 0.5,
            "throttle.duration_sec": 300,
        }

    Callers pattern-match on the keys they know about; unknown keys
    are ignored (forward compatibility).
    """


@runtime_checkable
class VerdictHandler(Protocol):
    """A handler encapsulates what to do when a verdict fires.

    Handlers are duck-typed — anything with the three attributes
    below passes ``isinstance(x, VerdictHandler)`` at runtime. That
    lets tests use inline callables + dataclasses interchangeably
    without forcing a base class.
    """
    verdict: str
    layer: HandlerLayer
    def apply(self, ctx: VerdictContext) -> HandlerResult: ...


# ── Registry ─────────────────────────────────────────────────────────


# Key is (verdict, layer) so the same verdict CAN have layer-specific
# handlers when the semantics differ — canonical example: `block` is
# gateway-deny at layer=gateway (pre-invocation refusal) and result-
# swap at layer=action_gate (post-invocation kill switch).
#
# H1 fix — copy-on-write registry. Writers acquire _REGISTRY_LOCK,
# build a NEW dict, then atomically reassign the module-global
# _REGISTRY name. Readers (`_resolve`, `apply`, `registered_verdicts`)
# capture the current reference once and do their lookups against
# that snapshot. Python reference assignment is GIL-atomic, so a
# reader never observes a partial-swap dict — it sees either the
# old snapshot end-to-end or the new snapshot end-to-end.
#
# Trade-off: writers pay a full dict copy per mutation (O(n) in the
# handler count, which is <20 for the shipped set + any plugins).
# Reads stay lock-free. This is the correct trade for a policy
# engine where reads are ~1000× more frequent than writes.
_REGISTRY: dict[tuple[str, HandlerLayer], VerdictHandler] = {}
_REGISTRY_LOCK = threading.Lock()

_VALID_LAYERS: frozenset[HandlerLayer] = frozenset(
    {"gateway", "action_gate", "both"}
)


def _validate_handler(handler: Any) -> None:
    """H3 fix — reject broken handlers at register() time.

    Attribute-existence checks alone would let a subclass with a
    non-callable ``apply`` slip in and 500 the first user who
    triggered the verdict. This checks the real invariants: verdict
    is a non-empty string, layer is one of the allowed literals,
    and apply is a callable.
    """
    if not hasattr(handler, "verdict") or not isinstance(
        handler.verdict, str
    ) or not handler.verdict:
        raise TypeError(
            f"handler.verdict must be a non-empty str, got "
            f"{handler.verdict!r}"
        )
    if not hasattr(handler, "layer") or handler.layer not in _VALID_LAYERS:
        raise TypeError(
            f"handler.layer must be one of {sorted(_VALID_LAYERS)}, "
            f"got {getattr(handler, 'layer', None)!r}"
        )
    if not callable(getattr(handler, "apply", None)):
        raise TypeError(
            f"handler.apply must be callable, got "
            f"{type(getattr(handler, 'apply', None)).__name__}"
        )


def register(handler: VerdictHandler) -> VerdictHandler:
    """Register a handler under its ``(verdict, layer)`` key.

    Idempotent by key — re-registering silently overrides the previous
    binding. Deliberate: tests, plugins, and operator-side overrides
    can swap in a custom handler without an ``unregister()`` dance.

    Raises ``TypeError`` if the handler is missing required attributes
    or has a non-callable ``apply``. That catches misconfigured plugins
    at registration time instead of at first-user-request time.

    Copy-on-write — see the note above ``_REGISTRY``. Concurrent
    readers see either the pre-register snapshot or the post-register
    snapshot, never a torn write.

    Returns the handler so this composes as a decorator::

        @register
        class MyDenyHandler:
            verdict = "deny"
            layer = "gateway"
            def apply(self, ctx): ...
    """
    global _REGISTRY
    _validate_handler(handler)
    key = (handler.verdict, handler.layer)
    with _REGISTRY_LOCK:
        new_registry = dict(_REGISTRY)
        new_registry[key] = handler
        _REGISTRY = new_registry
    return handler


def unregister(verdict: str, layer: HandlerLayer) -> None:
    """Remove a handler. Primarily for tests + hot-reload scenarios.

    No-op if the key is absent — matches ``dict.pop(..., None)``
    semantics so callers don't have to guard the call.
    """
    global _REGISTRY
    key = (verdict, layer)
    with _REGISTRY_LOCK:
        if key not in _REGISTRY:
            return
        new_registry = dict(_REGISTRY)
        del new_registry[key]
        _REGISTRY = new_registry


def clear() -> None:
    """Drop every registered handler.

    Used by tests that want a clean slate before registering their
    own fixtures. Production callers should never invoke this — the
    ``register_default_handlers`` re-population is not automatic.
    """
    global _REGISTRY
    with _REGISTRY_LOCK:
        _REGISTRY = {}


def swap(handlers: list[VerdictHandler]) -> None:
    """Atomically replace the entire registry.

    H1 core — hot-reload scenarios need "clear + re-add" to be a
    SINGLE atomic step from a concurrent ``apply()``'s perspective.
    Under the copy-on-write pattern this is trivial: build the new
    dict, reassign the reference once. Concurrent readers see either
    the pre-swap snapshot or the post-swap snapshot end-to-end.

    Validates every handler first, so a bad handler in the middle of
    the list doesn't leave the registry half-swapped.
    """
    global _REGISTRY
    for h in handlers:
        _validate_handler(h)
    new_registry: dict[tuple[str, HandlerLayer], VerdictHandler] = {}
    for h in handlers:
        new_registry[(h.verdict, h.layer)] = h
    with _REGISTRY_LOCK:
        _REGISTRY = new_registry


def _resolve(verdict: str, layer: ContextLayer) -> Optional[VerdictHandler]:
    """Return the handler for this verdict + layer, or None.

    Lookup order:
      1. Exact ``(verdict, layer)`` match — layer-specific handler wins.
      2. ``(verdict, "both")`` fallback — layer-agnostic handler.

    That ordering means an operator can register a specialized
    action-gate override for ``allow`` without invalidating the
    default ``both``-layer handler used at the gateway.

    Lock-free by way of copy-on-write. Capture the registry reference
    ONCE at the start so both lookups happen against the same snapshot
    — otherwise a concurrent ``swap()`` between the two ``.get()``
    calls could return a resolved handler that has since been
    replaced with something different.
    """
    snapshot = _REGISTRY
    exact = snapshot.get((verdict, layer))
    if exact is not None:
        return exact
    return snapshot.get((verdict, "both"))


def apply(ctx: VerdictContext) -> HandlerResult:
    """Dispatch to the registered handler for this context.

    Returns the handler's result. When no handler is registered:

    * At ``layer="gateway"`` — **fail-CLOSED**: return a 500 with
      ``jsonrpc_error_code=-32099``. Rationale: a policy engine that
      cannot interpret its own verdict must not silently allow the
      call. Novel verdicts (``sanction``, ``quarantine``) on an older
      gateway would otherwise slip through. Ops sees an ERROR log +
      the 500 spike on the observability dashboard's error KPI.

    * At ``layer="action_gate"`` — **fail-OPEN**: return
      ``forward=True``. The invocation already ran; refusing to ship
      its result over a stale gateway config would be a worse failure
      mode. WARNING log surfaces the drift.

    Both paths return a ``HandlerResult`` — apply() never raises.
    """
    handler = _resolve(ctx.verdict, ctx.layer)
    if handler is not None:
        return handler.apply(ctx)

    if ctx.layer == "gateway":
        logger.error(
            "[policy_verdicts] unknown verdict at gateway layer — "
            "failing CLOSED. verdict=%r tenant=%s action=%s",
            ctx.verdict, ctx.tenant_id, ctx.action,
        )
        return HandlerResult(
            forward=False,
            http_status=500,
            jsonrpc_error_code=_JSONRPC_ERR_UNKNOWN_VERDICT,
            response_body={
                "error": "unknown_verdict",
                "verdict": ctx.verdict,
                "reason_codes": list(ctx.reason_codes),
            },
        )

    # action_gate — fail-open (upstream already ran).
    logger.warning(
        "[policy_verdicts] unknown verdict at action_gate layer — "
        "failing open (forward). verdict=%r tenant=%s action=%s",
        ctx.verdict, ctx.tenant_id, ctx.action,
    )
    return HandlerResult(forward=True)


def registered_verdicts(layer: Optional[HandlerLayer] = None) -> list[str]:
    """List currently-registered verdict names, sorted.

    Used by tests and admin surfaces (Platform admin observability →
    "what verdicts does this deployment know about?"). When ``layer``
    is set, filters to handlers registered for that layer OR "both".
    """
    if layer is None:
        return sorted({v for v, _ in _REGISTRY.keys()})
    return sorted({
        v for v, l in _REGISTRY.keys()
        if l == layer or l == "both"
    })


def is_registered_exact(verdict: str, layer: HandlerLayer) -> bool:
    """Is this exact ``(verdict, layer)`` key bound?

    M2 fix — renamed from ``is_registered`` for clarity, since it
    checks the EXACT key without the ``both``-layer fallback. Use
    ``resolves()`` when you want to know "can apply() find something
    for this ctx" (which includes the fallback).
    """
    return (verdict, layer) in _REGISTRY


def resolves(verdict: str, layer: ContextLayer) -> bool:
    """Would ``apply()`` find a handler for this verdict + layer?

    M2 addendum — returns True whenever ``_resolve()`` returns
    non-None. Includes the ``both``-layer fallback that
    ``is_registered_exact`` deliberately excludes.
    """
    return _resolve(verdict, layer) is not None


# ── Default handlers ────────────────────────────────────────────────
# Each verdict from the site copy gets a default. Tasks #101 and #102
# replace the stub bodies with real behavior; these ship today so
# integration tests can prove the dispatch path independently of
# per-verdict implementation.


@dataclass(frozen=True)
class AllowHandler:
    """Both-layer allow — proceed. Reason codes are informational."""
    verdict: str = "allow"
    layer: HandlerLayer = "both"

    def apply(self, ctx: VerdictContext) -> HandlerResult:
        return HandlerResult(forward=True)


# JSON-RPC error codes emitted by the gateway. Kept as module
# constants so the gateway integration layer + tests reference one
# source of truth. Values match kya_gateway.errors.
#
# Note: -32008 (action-gate block) lives in
# ``kya_pro.policy.verdict_handlers`` where the action-gate handler
# ships. Kept out of this module so an OSS-only deploy can't
# accidentally register an ActionGateBlockHandler.
_JSONRPC_ERR_POLICY_DENY = -32001
_JSONRPC_ERR_HUMAN_APPROVAL_REQUIRED = -32007
_JSONRPC_ERR_UNKNOWN_VERDICT = -32099


@dataclass(frozen=True)
class GatewayDenyHandler:
    """Gateway-layer deny — hard 403 with reason codes.

    Matches the current ``kya_gateway.server`` enforce-mode behavior
    so this handler can drop in without changing what callers see on
    the wire. Sets ``jsonrpc_error_code=-32001`` so the gateway's
    ``make_error()`` envelope preserves numeric-code compatibility
    for downstream SDK clients that pattern-match on it.
    """
    verdict: str = "deny"
    layer: HandlerLayer = "gateway"

    def apply(self, ctx: VerdictContext) -> HandlerResult:
        return HandlerResult(
            forward=False,
            http_status=403,
            jsonrpc_error_code=_JSONRPC_ERR_POLICY_DENY,
            response_body={
                "error": "policy_deny",
                "reason_codes": list(ctx.reason_codes),
                "verdict": "deny",
            },
        )


@dataclass(frozen=True)
class GatewayRequireHumanHandler:
    """Gateway-layer require_human — HTTP 428 Precondition Required.

    RFC 6585 §3: the action is not denied, it needs a precondition
    (human approval) before it can proceed. Sets a
    ``hitl.needs_pending_row`` mutation flag so #101's persistence
    layer knows to write a ``kya_pending_invocations`` row before the
    response goes out — the gateway can then stamp
    ``X-Kya-Pending-Id`` on the outgoing headers so the SDK can poll.

    ``jsonrpc_error_code=-32007`` preserves wire compatibility for
    existing SDK clients pattern-matching on the numeric code.
    """
    verdict: str = "require_human"
    layer: HandlerLayer = "gateway"

    def apply(self, ctx: VerdictContext) -> HandlerResult:
        return HandlerResult(
            forward=False,
            http_status=428,
            jsonrpc_error_code=_JSONRPC_ERR_HUMAN_APPROVAL_REQUIRED,
            response_body={
                "error": "human_approval_required",
                "reason_codes": list(ctx.reason_codes),
                "verdict": "require_human",
            },
            response_headers={
                "WWW-Authenticate": 'KYA-Human-Approval realm="kya-gateway"',
            },
            mutations={"hitl.needs_pending_row": True},
        )


# Action-gate handlers (redact, throttle, block) live in
# ``kya_pro.policy.verdict_handlers`` — see that file for the full
# rationale. Short version: the action gate is a Pro-only surface,
# its enforcement primitives (dynamic-throttle table, JSONPath
# response filter, evidence-chain block-record ordering) are Pro
# code, and shipping stub versions here would either duplicate that
# logic or ship permanent no-ops in OSS. Pro calls
# ``register_default_action_gate_handlers()`` at startup to bind
# them into this same registry.


# ── Bootstrap ────────────────────────────────────────────────────────


def register_default_handlers() -> None:
    """Register the shipped-with-kya (OSS) handlers.

    Registers the gateway-side handlers (allow / deny / require_human)
    that the OSS ``kya_gateway.server`` emits. Idempotent — safe to
    call multiple times (re-register overrides). Callers can register
    their own handler under the same key after this returns to swap
    the shipped default.

    Action-gate handlers (redact / throttle / block) ship in the Pro
    package. Import + call
    ``kya_pro.policy.register_default_action_gate_handlers()`` at Pro
    startup to bind them into this same registry.
    """
    for handler in (
        AllowHandler(),
        GatewayDenyHandler(),
        GatewayRequireHumanHandler(),
    ):
        register(handler)


# M1 fix — DO NOT register on import. Auto-registration at import
# time meant any test importing this module got the defaults whether
# it wanted them or not, and cross-test leakage was possible when
# other test files transitively imported us. Callers explicitly opt
# in: gateway server calls register_default_handlers() at startup;
# the tests/conftest.py autouse fixture calls it per-test.


__all__ = [
    "ContextLayer",
    "HandlerLayer",
    "MUTATION_KEYS",
    "Mutations",
    "VerdictContext",
    "HandlerResult",
    "VerdictHandler",
    "register",
    "unregister",
    "clear",
    "swap",
    "apply",
    "registered_verdicts",
    "is_registered_exact",
    "resolves",
    "AllowHandler",
    "GatewayDenyHandler",
    "GatewayRequireHumanHandler",
    "register_default_handlers",
]
