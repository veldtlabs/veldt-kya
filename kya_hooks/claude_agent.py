"""
Anthropic Claude Agent SDK adapter for KYA hooks.

Wraps the SDK's HookMatcher / PreToolUse / PostToolUse callbacks to
emit KYA events automatically.

Usage
-----
    from claude_agent_sdk import ClaudeAgentOptions
    from kya_hooks import KyaClient, claude_agent_hooks

    client = KyaClient(base_url="http://kya:17000", token=...)
    options = ClaudeAgentOptions(
        ...,
        permission_mode="bypassPermissions",
        hooks=claude_agent_hooks(
            client,
            agent_key="MyClaudeAgent",
            allowed_tools={"mcp__myserver__lookup", "Read", "Grep"},
        ),
    )

Lazy import — does not require `claude-agent-sdk` to be installed
unless the customer actually calls this function.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from .client import KyaClient
from .scanner import DataLeakScanner

logger = logging.getLogger(__name__)


def claude_agent_hooks(
    client: KyaClient,
    *,
    agent_key: str,
    allowed_tools: Optional[set[str]] = None,
    scanner: Optional[DataLeakScanner] = None,
    correlation_id: Optional[str] = None,
    matcher: str = "mcp__.*",
):
    """Build a hooks dict to pass into `ClaudeAgentOptions(hooks=...)`.

    Parameters
    ----------
    client : KyaClient
        The KYA client to POST events to.
    agent_key : str
        Stable identifier for this Claude agent in KYA. Used in all
        emitted events.
    allowed_tools : set[str] | None
        Allow-list of tool names. Any tool name NOT in this set fires
        an `oos_tool` event. Note that MCP-registered tools have
        `mcp__{server}__{name}` prefixes — include the prefixed form
        OR pass a custom matcher (see below).
    scanner : DataLeakScanner | None
        Content scanner for tool outputs. Defaults provided.
    correlation_id : str | None
        Shared correlation ID for the run.

    Returns
    -------
    A dict suitable for `ClaudeAgentOptions(hooks=...)`. Two matchers
    registered: PreToolUse and PostToolUse, both pinned to `mcp__.*`
    by default; expand to `.*` if you want to instrument non-MCP tools too.
    """
    try:
        from claude_agent_sdk import HookMatcher
    except ImportError as exc:
        raise ImportError(
            "claude_agent_hooks() requires `pip install claude-agent-sdk`."
        ) from exc

    _scanner = scanner or DataLeakScanner()
    _allowed = allowed_tools  # None means "OOS detection disabled"

    async def pre_tool_hook(input_data, tool_use_id, context):  # noqa: ARG001
        tool_name = input_data.get("tool_name", "unknown")
        if _allowed is not None and tool_name not in _allowed:
            try:
                client.record_oos_tool(agent_key=agent_key, tool=tool_name)
            except Exception as exc:
                logger.warning("[KYA] oos_tool post failed: %s", exc)
        return {}

    async def post_tool_hook(input_data, tool_use_id, context):  # noqa: ARG001
        tool_response = input_data.get("tool_response", {})
        result_str = (
            json.dumps(tool_response, default=str)
            if isinstance(tool_response, dict)
            else str(tool_response)
        )
        for match in _scanner.scan_unique_classes(result_str):
            try:
                client.record_data_leak(
                    agent_key=agent_key,
                    data_class=match.data_class,
                    evidence=f"tool={input_data.get('tool_name','?')},pattern={match.pattern_label}",
                )
            except Exception as exc:
                logger.warning("[KYA] data_leak post failed: %s", exc)
        return {}

    # Default matcher 'mcp__.*' fires on MCP-registered tools (which most
    # production Claude agents use). Override matcher='.*' to instrument
    # built-in tools (Read/Bash/etc.) — but expect more noise.
    return {
        "PreToolUse":  [HookMatcher(matcher=matcher, hooks=[pre_tool_hook])],
        "PostToolUse": [HookMatcher(matcher=matcher, hooks=[post_tool_hook])],
    }
