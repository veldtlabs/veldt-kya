"""
KYA Hooks SDK — framework-agnostic instrumentation for KYA.

The core proposition: customers writing agent code shouldn't have to
hand-craft 80-line RunHooks/HookCallback subclasses that POST to KYA.
This module ships a thin client + framework-specific instrumentation
that does the wiring for them.

Usage
-----
Direct client (any framework, any language):

    from kya_hooks import KyaClient

    client = KyaClient(base_url="http://kya:17000", token="...", tenant_id="...")
    client.record_invocation(agent_key="MyAgent", mode="hybrid", outcome="success")
    client.record_rogue("oos_tool", agent_key="MyAgent", tool="delete_db")

OpenAI Agents SDK instrumentation:

    from agents import Agent, Runner
    from kya_hooks import openai_agents_hooks

    hooks = openai_agents_hooks(client, allowed_tools_per_agent={...})
    result = await Runner.run(my_agent, prompt, hooks=hooks)

Claude Agent SDK instrumentation:

    from claude_agent_sdk import ClaudeAgentOptions
    from kya_hooks import claude_agent_hooks

    options = ClaudeAgentOptions(
        ...,
        hooks=claude_agent_hooks(client, agent_key="MyClaudeAgent",
                                 allowed_tools={...}),
    )

Design
------
- Pure stdlib + requests for the client (no agent-SDK deps at install time)
- Framework adapters are lazy-imported — `openai_agents_hooks()` imports
  the openai-agents package only when called, not at module load
- Same data-leak detector across frameworks (DataLeakScanner) so behavior
  is consistent regardless of which SDK is in front
- All KYA event POSTs include `actor_agent_key` defaulting to `agent_key`
  for autonomous attribution (discovered during real runs in Scenario 8)
"""
from .claude_agent import claude_agent_hooks
from .client import KyaClient, KyaClientError
from .mcp import wrap_mcp_client
from .openai_agents import openai_agents_hooks
from .scanner import DataLeakScanner, ScanMatch

__all__ = [
    "KyaClient",
    "KyaClientError",
    "DataLeakScanner",
    "ScanMatch",
    "openai_agents_hooks",
    "claude_agent_hooks",
    "wrap_mcp_client",
]

__version__ = "0.1.0"
