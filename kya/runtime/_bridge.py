"""The runtime-security bridge.

One entrypoint -- :func:`record_runtime_event` -- accepts a canonical
:class:`RuntimeEvent` and:

1. Binds it to a KYA principal (or marks it ``unbound`` if no hint
   resolves; **never drops silently**).
2. Hands it to the attack-chain engine so multi-step rules can
   correlate runtime alerts with agent tool-calls (#41's DAG grammar,
   #40's cross-agent correlation, and #42's Sigma rules all see these
   events as ``evidence_kind="runtime_<source_tool>"``).
3. Returns a result describing exactly what happened so the calling
   collector can log / alert / page on its side.

The bridge is **fail-soft**: a misbehaving parser, a misconfigured
binding, or an engine exception is logged and surfaced in the result.
The caller never has to wrap calls in try/except for KYA-side bugs.

Principal binding is intentionally pluggable but kept simple in this
slice: the hint strategy chain consults the parser's hints in order
and stops at the first that resolves to a known principal. The actual
resolvers (label lookup, k8s SA mapping, SPIFFE table) plug in via
:func:`set_principal_resolver`. Without a resolver, only ``explicit``
hints bind -- ``unbound`` events still flow through the evidence
attach + attack-chain pipeline so nothing is lost.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ._canonical import (
    RuntimeEvent,
    SourceTool,
)
from ._registry import (
    RuntimeParserError,
    autodetect_parser,
    get_parser,
)
from ._resolvers import (
    Resolver,
    build_default_resolver_chain,
)

logger = logging.getLogger(__name__)


# ── Result ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RuntimeIngestResult:
    """What the bridge did with one event.

    Attributes:
        accepted: True if the event was parsed (or supplied
            canonically) and the bridge attempted attack-chain
            dispatch + evidence attach. False if parsing failed.
        source_tool: The source tool used (parser name).
        tenant_id, principal_id: Resolved values, or None if the
            event remains unbound. Unbound events still get attack-
            chain dispatched on rules that don't require a principal
            (e.g. honeypot patterns).
        principal_binding_method: Which hint kind / strategy
            resolved the principal. ``"unbound"`` when nothing
            matched, ``"explicit"`` when the event came in pre-bound.
        attack_chain_matches: Rule IDs that matched (empty list when
            no rules fired). Comes straight from
            ``AttackChainEngine.process_evidence``.
        evidence_id: HMAC-chained evidence row id when the bridge
            recorded one. ``None`` when no DB session was supplied
            OR when no ``invocation_id`` was supplied (the ledger
            chains under (tenant, invocation), so an anchor is
            required -- see :func:`record_runtime_event`).
        error: Free-text description if ``accepted`` is False. ``None``
            on the happy path.
    """

    accepted: bool
    source_tool: SourceTool | None
    tenant_id: str | None
    principal_id: str | None
    principal_binding_method: str
    attack_chain_matches: list[str]
    evidence_id: int | None = None
    error: str | None = None


# ── Principal resolver ─────────────────────────────────────────────
#
# Default = the auto-chain (see ``_resolvers.py``). Callers can swap
# in their own resolver via :func:`set_principal_resolver` -- useful
# for tests and for premium overrides that add IdP-aware strategies.
#
# A resolver is a callable taking ``RuntimeEvent`` and returning
# ``(tenant_id, principal_id, method_label) | None``. The label is
# free-text and surfaces in ``RuntimeIngestResult.principal_binding_method``
# so operators can tell which strategy bound the event.

_resolver: Resolver | None = build_default_resolver_chain()


def set_principal_resolver(resolver: Resolver | None) -> None:
    """Replace (or remove) the principal resolver used by the bridge.

    The default is the auto-chain from
    :func:`build_default_resolver_chain` (explicit cache -> docker
    label -> k8s annotation stub -> name convention -> process-user
    map). Pass ``None`` to disable resolution entirely; only events
    pre-bound with ``tenant_id`` + ``principal_id`` will bind.

    Tests call this to isolate from process-level Docker config. The
    premium parser bundle uses it to swap in a richer chain that
    includes the production K8s informer + framework adapters.
    """
    global _resolver
    _resolver = resolver


def reset_principal_resolver_to_default() -> None:
    """Reset the resolver to a fresh default auto-chain. Tests use
    this in teardown; production code shouldn't need it."""
    global _resolver
    _resolver = build_default_resolver_chain()


def _resolve_principal(
    ev: RuntimeEvent,
) -> tuple[str | None, str | None, str]:
    """Resolve (tenant_id, principal_id, binding_method) for one event.

    Pre-bound events win over the resolver chain -- if the caller
    knows the principal, we trust them. Otherwise the chain runs;
    each strategy is tried in order, first hit wins. If nothing binds,
    we return ``unbound`` and the bridge still dispatches the event
    (evidence chain skipped without an invocation_id; attack-chain
    rules that don't require a principal still match).
    """
    if ev.tenant_id and ev.principal_id:
        return ev.tenant_id, ev.principal_id, "explicit"

    # Convenience: a single explicit-kind hint can bind without a
    # resolver. Keeps tests / minimal deployments working when the
    # auto-chain is intentionally disabled.
    for h in ev.principal_hints:
        if h.kind == "explicit" and h.value:
            return ev.tenant_id, h.value, "hint:explicit"

    if _resolver is None:
        return ev.tenant_id, ev.principal_id, "unbound"

    try:
        resolved = _resolver(ev)
    except Exception:  # noqa: BLE001
        logger.exception("[KYA-RUNTIME] principal resolver raised")
        resolved = None

    if resolved:
        tid, pid, method = resolved
        if tid and pid:
            return tid, pid, method

    return ev.tenant_id, ev.principal_id, "unbound"


# ── Attack-chain dispatch (lazy import) ────────────────────────────

# Imported lazily so importing ``kya.runtime`` does not eagerly pull
# the attack_chains stack. Most runtime events still benefit from
# evidence attach even when attack_chains isn't configured.
def _dispatch_attack_chains(
    db: Any, ev: RuntimeEvent, tenant_id: str | None,
    principal_id: str | None,
) -> list[str]:
    try:
        from kya.attack_chains import get_default_engine
    except Exception:  # noqa: BLE001 -- attack_chains optional
        return []
    try:
        engine = get_default_engine()
    except Exception:  # noqa: BLE001
        logger.exception("[KYA-RUNTIME] could not obtain attack-chain engine")
        return []
    if engine is None:
        return []
    try:
        return engine.process_evidence(
            db,
            tenant_id=tenant_id or "",
            principal_id=principal_id or "",
            evidence_kind=f"runtime_{ev.source_tool}",
            payload=_event_to_payload(ev),
            occurred_at_ts=ev.occurred_at_ts,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "[KYA-RUNTIME] attack-chain dispatch failed for rule=%s tool=%s",
            ev.source_rule_id, ev.source_tool,
        )
        return []


def _event_to_payload(ev: RuntimeEvent) -> dict[str, Any]:
    """Flatten a RuntimeEvent into the dotted-payload shape the
    attack-chain matchers expect. Mirrors how PR #42's Sigma adapter
    lands fields under ``payload.*`` -- runtime fields land under
    ``payload.<field>`` for symmetry with the existing rule library.
    """
    payload: dict[str, Any] = {
        "source_tool": ev.source_tool,
        "source_rule_id": ev.source_rule_id,
        "severity": ev.severity,
        "action": ev.action,
        "message": ev.message,
    }
    if ev.container_id:
        payload["container_id"] = ev.container_id
    if ev.container_image:
        payload["container_image"] = ev.container_image
    if ev.pod_name:
        payload["pod_name"] = ev.pod_name
    if ev.namespace:
        payload["namespace"] = ev.namespace
    if ev.node:
        payload["node"] = ev.node
    if ev.process:
        if ev.process.image:
            payload["proc.image"] = ev.process.image
        if ev.process.name:
            payload["proc.name"] = ev.process.name
        if ev.process.cmdline:
            payload["proc.cmdline"] = ev.process.cmdline
        if ev.process.user:
            payload["proc.user"] = ev.process.user
        if ev.process.pid is not None:
            payload["proc.pid"] = ev.process.pid
        if ev.process.ppid is not None:
            payload["proc.ppid"] = ev.process.ppid
    if ev.tags:
        payload["tags"] = list(ev.tags)
    return payload


# ── Entrypoints ────────────────────────────────────────────────────


def _attach_evidence_chain(
    db: Any, ev: RuntimeEvent, tenant_id: str | None,
    invocation_id: int | None, correlation_id: str | None,
) -> int | None:
    """Write a row into the HMAC-signed evidence ledger.

    Returns the evidence row id when attached, ``None`` otherwise.

    Skipped (without raising) when:
    * ``db`` is None -- caller is not persisting (test / dry-run).
    * ``invocation_id`` is None -- the ledger chains under
      (tenant, invocation). The caller MUST anchor each runtime event
      to an invocation -- either the agent invocation correlated with
      it, or a long-lived "runtime-only" invocation per principal
      (see ``examples/runtime_falco_collector.py`` -- the recommended
      pattern is one runtime anchor per (tenant, principal,
      container) carried by the collector).
    * ``tenant_id`` is None -- ledger rows are tenant-scoped; an
      unbound event is still attack-chain dispatched, just not signed
      into a specific tenant's chain.
    """
    if db is None or invocation_id is None or not tenant_id:
        return None
    try:
        from kya.evidence import record_evidence
    except Exception:  # noqa: BLE001
        logger.exception("[KYA-RUNTIME] kya.evidence import failed")
        return None
    try:
        return record_evidence(
            db,
            tenant_id=tenant_id,
            invocation_id=invocation_id,
            # New canonical evidence_kind family. Attack-chain rules
            # in PR #41 + #42 already match on
            # ``runtime_<source_tool>`` via the dispatch path; the
            # ledger row uses the same kind so chain-walks find both.
            evidence_kind=f"runtime_{ev.source_tool}",
            payload=_event_to_payload(ev),
            source=f"runtime.{ev.source_tool}",
            correlation_id=correlation_id,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "[KYA-RUNTIME] record_evidence failed for rule=%s tool=%s",
            ev.source_rule_id, ev.source_tool,
        )
        return None


def record_runtime_event(
    event: RuntimeEvent,
    *,
    db: Any | None = None,
    invocation_id: int | None = None,
    correlation_id: str | None = None,
) -> RuntimeIngestResult:
    """Ingest one already-canonical event.

    This is the bridge's primary entry. Use it when you already
    produced a :class:`RuntimeEvent` (e.g. from a Tetragon sidecar
    that emits canonical events directly).

    Args:
        event: Canonical runtime event.
        db: SQLAlchemy session. Optional -- when None the bridge
            still does in-memory attack-chain dispatch (useful for
            tests / dry-run pipelines) but skips evidence-ledger
            attach.
        invocation_id: The kya_invocations row this event anchors
            to. **Required for evidence-chain attach** because the
            HMAC chain is per (tenant, invocation). Collectors
            normally pass either (a) the agent invocation correlated
            with this runtime event, or (b) a long-lived "runtime
            anchor" invocation they created per (tenant, principal,
            container). Without it, attack-chain dispatch still
            runs but no signed ledger row is written.
        correlation_id: Shared id used by PR #40's cross-agent rules
            to group events from cooperating principals. Optional.
    """
    tid, pid, method = _resolve_principal(event)
    matches = _dispatch_attack_chains(db, event, tid, pid)
    evidence_id = _attach_evidence_chain(
        db, event, tid, invocation_id, correlation_id,
    )
    return RuntimeIngestResult(
        accepted=True,
        source_tool=event.source_tool,
        tenant_id=tid,
        principal_id=pid,
        principal_binding_method=method,
        attack_chain_matches=matches,
        evidence_id=evidence_id,
        error=None,
    )


def ingest(
    raw: dict,
    *,
    source_tool: SourceTool | None = None,
    db: Any | None = None,
    invocation_id: int | None = None,
    correlation_id: str | None = None,
) -> RuntimeIngestResult:
    """Ingest a raw payload from any registered runtime-security tool.

    Args:
        raw: The tool's native JSON payload (already parsed to a
            dict; the bridge does not own JSON loading because real
            collectors stream NDJSON / unix-socket / Kafka).
        source_tool: When set, force this parser; when ``None``, the
            registry's autodetect picks the first parser that claims
            the payload.
        db: SQLAlchemy session (or None for tests).
        invocation_id: Forwarded to :func:`record_runtime_event` for
            evidence-chain attach (see its docstring).
        correlation_id: Forwarded to :func:`record_runtime_event`.

    Returns:
        A :class:`RuntimeIngestResult` describing the outcome.
    """
    if source_tool is not None:
        parser = get_parser(source_tool)
        if parser is None:
            return RuntimeIngestResult(
                accepted=False,
                source_tool=source_tool,
                tenant_id=None, principal_id=None,
                principal_binding_method="unbound",
                attack_chain_matches=[],
                error=f"no parser registered for source_tool={source_tool!r}",
            )
        try:
            event = parser.parse(raw)
        except RuntimeParserError as exc:
            return RuntimeIngestResult(
                accepted=False,
                source_tool=source_tool,
                tenant_id=None, principal_id=None,
                principal_binding_method="unbound",
                attack_chain_matches=[],
                error=f"parser rejected payload: {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "[KYA-RUNTIME] parser %s raised on parse", source_tool)
            return RuntimeIngestResult(
                accepted=False,
                source_tool=source_tool,
                tenant_id=None, principal_id=None,
                principal_binding_method="unbound",
                attack_chain_matches=[],
                error=f"parser raised: {exc!r}",
            )
        if event is None:
            return RuntimeIngestResult(
                accepted=False,
                source_tool=source_tool,
                tenant_id=None, principal_id=None,
                principal_binding_method="unbound",
                attack_chain_matches=[],
                error="parser returned None",
            )
        return record_runtime_event(
            event, db=db,
            invocation_id=invocation_id,
            correlation_id=correlation_id,
        )

    # Autodetect path
    detected = autodetect_parser(raw)
    if detected is None:
        return RuntimeIngestResult(
            accepted=False,
            source_tool=None,
            tenant_id=None, principal_id=None,
            principal_binding_method="unbound",
            attack_chain_matches=[],
            error=("no registered parser recognised the payload "
                   "(pass source_tool= to force one)"),
        )
    tool, _ = detected
    return ingest(
        raw, source_tool=tool, db=db,
        invocation_id=invocation_id,
        correlation_id=correlation_id,
    )
