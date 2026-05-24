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

from .client import KyaClient
from .scanner import DataLeakScanner

logger = logging.getLogger(__name__)


def openai_agents_hooks(
    client: KyaClient,
    allowed_tools_per_agent: dict[str, set[str]] | None = None,
    scanner: DataLeakScanner | None = None,
    correlation_id: str | None = None,
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
            allow = _allowed.get(agent_key)
            if allow is not None and tool_name not in allow:
                try:
                    client.record_oos_tool(agent_key=agent_key, tool=tool_name)
                    self.observations.append({"event": "oos_tool", "agent": agent_key, "tool": tool_name})
                except Exception as exc:
                    logger.warning("[KYA] oos_tool post failed: %s", exc)

        async def on_handoff(self, context: RunContextWrapper, from_agent: Agent, to_agent: Agent):
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
