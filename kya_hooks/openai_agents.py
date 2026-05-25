"""
OpenAI Agents SDK adapter for KYA hooks.

Wraps the SDK's `RunHooks` to automatically emit KYA events for
out-of-scope tool calls and data leaks. Replaces ~80 lines of custom
RunHooks code with a single call.

Usage
-----
    from kya_hooks import KyaClient, openai_agents_hooks
    from agents import Runner

    client = KyaClient(base_url="http://kya:17000", token=...)
    hooks = openai_agents_hooks(
        client,
        allowed_tools_per_agent={
            "ResearchAgent": {"lookup", "search"},
            "ReporterAgent": {"calculator"},
        },
    )
    result = await Runner.run(my_agent, prompt, hooks=hooks)

Lazy import — does not require `openai-agents` to be installed unless
the customer actually calls this function. KYA core has zero SDK deps.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from ._snapshot import maybe_snapshot_first_sight
from .client import KyaClient
from .scanner import DataLeakScanner

logger = logging.getLogger(__name__)


def _agent_def_from_openai_agent(agent: Any) -> dict[str, Any]:
    """Best-effort canonical KYA def from an OpenAI Agents SDK Agent.

    The SDK's ``Agent`` exposes ``name``, ``instructions``, ``tools``,
    ``model``. Safety-related fields (``access_level``,
    ``data_classes``, ``human_loop``) aren't part of the SDK schema —
    we leave them unset so the delegation policy fail-softs gracefully
    on missing dimensions (per kya.delegation_policy semantics)."""
    tool_names: list[str] = []
    for t in getattr(agent, "tools", None) or []:
        n = getattr(t, "name", None) or getattr(t, "__name__", None)
        if n: tool_names.append(n)
    return {
        "agent_key": getattr(agent, "name", "unknown_agent"),
        "name": getattr(agent, "name", None),
        "system_prompt": getattr(agent, "instructions", None) or "",
        "tools": tool_names,
        "model": getattr(agent, "model", None) or "unknown",
    }


def openai_agents_hooks(
    client: KyaClient,
    allowed_tools_per_agent: dict[str, set[str]] | None = None,
    scanner: DataLeakScanner | None = None,
    correlation_id: str | None = None,
    *,
    tenant_id: str | None = None,
    session_factory: Callable[[], Any] | None = None,
    snapshot_on_first_sight: bool = True,
):
    """Build a RunHooks subclass instance wired to a KyaClient.

    Parameters
    ----------
    client : KyaClient
        The KYA client to POST events to.
    allowed_tools_per_agent : dict[agent_name -> set[tool_name]] | None
        Per-agent tool allow-lists. A tool call NOT in the agent's set
        fires `oos_tool` against KYA. Pass `None` to disable OOS detection.
    scanner : DataLeakScanner | None
        Content scanner for tool outputs. Defaults to a standard
        PHI/PII/financial/secret scanner.
    correlation_id : str | None
        Shared correlation ID for the run. If provided, every event
        posted by these hooks includes it — letting KYA build the
        request rollup automatically.
    tenant_id : str | None
        Enables snapshot-on-first-sight. When supplied (alongside an
        accessible session_factory or KYA_DB_URL), the first time the
        hook observes each Agent it writes an ``agent_versions`` row
        with the agent's current definition. Required for the
        delegation-policy enforcement (kya.delegation_policy) to have
        parent + sub snapshots to compare. If None, snapshotting is
        skipped and the delegation check fail-softs to permissive.
    session_factory : callable | None
        Zero-arg callable returning a SQLAlchemy ``Session``. If None,
        ``kya.default_session`` is used (KYA_DB_URL → sqlite fallback).
    snapshot_on_first_sight : bool
        Master switch for the first-sight snapshot path. Defaults True.
        Set False to disable without removing the tenant_id parameter.

    Returns
    -------
    A `RunHooks` instance ready to pass to `Runner.run(..., hooks=...)`.
    """
    # Lazy import — only fails if customer actually uses this adapter.
    try:
        from agents import Agent, RunContextWrapper, RunHooks
    except ImportError as exc:
        raise ImportError(
            "openai_agents_hooks() requires `pip install openai-agents`."
        ) from exc

    _allowed = allowed_tools_per_agent or {}
    _scanner = scanner or DataLeakScanner()

    class _KyaRunHooks(RunHooks):
        """Auto-generated RunHooks bound to a KyaClient."""

        def __init__(self):
            self.observations: list[dict] = []

        async def on_tool_start(self, context: RunContextWrapper, agent: Agent, tool):
            agent_key = agent.name
            tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "unknown_tool")
            # First-sight snapshot — closes the gap that would otherwise
            # leave delegation policy fail-softing for new agents.
            try:
                maybe_snapshot_first_sight(
                    tenant_id=tenant_id, agent_key=agent_key,
                    agent_def=_agent_def_from_openai_agent(agent),
                    session_factory=session_factory,
                    enabled=snapshot_on_first_sight,
                )
            except Exception as exc:
                logger.debug("[KYA] first-sight snapshot raised: %s", exc)
            allow = _allowed.get(agent_key)
            if allow is not None and tool_name not in allow:
                try:
                    client.record_oos_tool(agent_key=agent_key, tool=tool_name)
                    self.observations.append({"event": "oos_tool", "agent": agent_key, "tool": tool_name})
                except Exception as exc:
                    logger.warning("[KYA] oos_tool post failed: %s", exc)

        async def on_handoff(self, context: RunContextWrapper, from_agent: Agent, to_agent: Agent):
            # Snapshot BOTH agents on first sight — the orchestrator
            # (from_agent) and the sub-agent (to_agent) — so the
            # delegation-policy check has parent + sub definitions to
            # compare on every subsequent on_tool_start.
            for ag in (from_agent, to_agent):
                try:
                    maybe_snapshot_first_sight(
                        tenant_id=tenant_id, agent_key=ag.name,
                        agent_def=_agent_def_from_openai_agent(ag),
                        session_factory=session_factory,
                        enabled=snapshot_on_first_sight,
                    )
                except Exception as exc:
                    logger.debug("[KYA] first-sight snapshot raised: %s", exc)
            # Record handoffs as clean invocations of the receiving agent.
            try:
                client.record_invocation(
                    agent_key=to_agent.name,
                    mode="observed",
                    outcome="in_progress",
                    principal_kind="agent",
                    principal_id=from_agent.name,
                    correlation_id=correlation_id,
                )
                self.observations.append({"event": "handoff", "from": from_agent.name, "to": to_agent.name})
            except Exception as exc:
                logger.warning("[KYA] handoff post failed: %s", exc)

        async def on_tool_end(self, context: RunContextWrapper, agent: Agent, tool, result):
            agent_key = agent.name
            result_str = str(result or "")
            for match in _scanner.scan_unique_classes(result_str):
                try:
                    client.record_data_leak(
                        agent_key=agent_key,
                        data_class=match.data_class,
                        evidence=f"tool={getattr(tool, 'name', '?')},pattern={match.pattern_label}",
                    )
                    self.observations.append({
                        "event": "data_leak",
                        "agent": agent_key,
                        "data_class": match.data_class,
                        "pattern": match.pattern_label,
                    })
                except Exception as exc:
                    logger.warning("[KYA] data_leak post failed: %s", exc)

    return _KyaRunHooks()
