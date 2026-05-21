"""
Framework adapter — normalize external agent definitions to KYA's
canonical schema so any agent can be scored, versioned, and monitored.

KYA's canonical schema (what `risk.score_agent` consumes):
    {
        "agent_key":     str,             # stable identifier
        "name":          str,             # display name
        "description":   str,             # one-liner
        "model":         str,             # model id
        "tools":         list[str],       # tool names the agent can call
        "denied_tools":  list[str],       # explicit deny list (rare)
        "human_loop":    "none" | "on_the_loop" | "hybrid" | "in_the_loop",
        "access_level":  "read" | "write",
        "can_override":  bool,
        "can_revert":    bool,
        "required_roles": list[str],
        "system_prompt": str,
        "framework":     str,             # original framework (audit trail)
        "raw":           dict,             # original definition (audit trail)
    }

Built-in adapters
-----------------
- "veldt"            → Veldt's native dict
- "langchain"        → LangChain AgentExecutor / Tool list
- "crewai"           → CrewAI Agent
- "openai"           → OpenAI Assistants API
- "autogen"          → Microsoft AutoGen ConversableAgent
- "semantic_kernel"  → MS Semantic Kernel agent / plugin spec
- "llamaindex"       → LlamaIndex AgentRunner / ReActAgent
- "haystack"         → Haystack Agent pipeline
- "mcp"              → Anthropic MCP server agent definition
- "bedrock"          → AWS Bedrock Agent
- "vertex"           → Google Vertex AI Agent Builder
- "swarm"            → OpenAI Swarm (deprecated / educational)
- "openai_agents"    → OpenAI Agents SDK (production successor to Swarm)
- "claude_agent"     → Anthropic Claude Agent SDK (formerly Claude Code SDK)
- "generic"          → Universal fallback — best-effort JSON parse
- "auto"             → Detect framework from the def shape

Pluggable registry
------------------
ANY caller can register their own adapter at runtime:

    from kya import register_adapter
    def from_my_framework(raw):
        return {"name": raw["x"], "tools": [...], ...}
    register_adapter("my_framework", from_my_framework)

Adapters are duck-typed and accept EITHER a Python object (with attribute
access) OR the serialized dict the framework produces. The KYA core never
imports framework packages at module load time — frameworks remain
optional dependencies of the caller, not of KYA.
"""

from collections.abc import Callable
from typing import Any

# Keep the type alias loose so library users aren't constrained to the
# built-in names — anything registered via register_adapter() is valid.
SupportedFramework = str

# Conservative defaults — most permissive value where the framework
# doesn't express the concept, so misconfiguration trends UP in risk
# rather than getting silently absolved.
_DEFAULTS = {
    "name": "",
    "description": "",
    "model": "",
    "tools": [],
    "skills": [],  # Round 12 — first-class skill bundles
    "denied_tools": [],
    "human_loop": "none",
    "access_level": "write",
    "can_override": False,
    "can_revert": False,
    "required_roles": [],
    "system_prompt": "",
    # data_classes / security_caps: None means "let score_agent infer
    # from the tool catalog". A list (even empty) overrides inference.
    "data_classes": None,
    "security_caps": None,
    # provenance / model_trust: free-form labels the score weights.
    "provenance": "unknown",
    "model_trust": "unknown",
    # compliance scope (Round 6) — list of regulatory regimes.
    "compliance_scope": [],
    # Input sources (Round 6) — where the agent INGESTS from.
    "input_sources": [],
    # ── Round 8 fields ─────────────────────────────────────────────
    # Ownership (#18)
    "owner_user_id": None,
    "owner_team": None,
    "on_call": None,
    "escalation_chain": None,
    # Approval status (#19)
    "review_status": None,
    "review_expires_at": None,
    "reviewed_by": None,
    "reviewed_at": None,
    # Lifecycle (#22)
    "first_deployed_at": None,
    "created_at": None,
    "changes_last_30d": None,
    # Supply chain (#20)
    "external_dependencies": None,
    "mcp_servers": None,
    "external_apis": None,
    "plugins": None,
    # Deployment environment (#21)
    "environment": None,
    "deployment_env": None,
    # Output provenance / citation (#23)
    "cites_sources": None,
    "citation_score": None,
    "reproducibility": None,
    # Trust audits (#24)
    "red_team_score": None,
    "bias_score": None,
    "fairness_score": None,
    "last_audit_at": None,
    # Cost burn (#25)
    "monthly_budget_usd": None,
    "cost_last_24h_usd": None,
    "cost_last_1h_usd": None,
    "token_budget_remaining": None,
    "cost_anomaly_factor": None,
    # Lineage (Round 7) — pass through if declared
    "parent_agent_key": None,
    "lineage": None,
    "signature": None,
}


def _attr(obj: Any, key: str, default=None):
    """Read `key` from an object OR a dict — supports both."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _tools_to_names(tools_attr) -> list[str]:
    """Normalize a tools collection to a flat list of names.

    Accepts:
      - list[str]                  → ["search", "create"]
      - list[Tool-like]            → objects with .name
      - list[dict]                 → OpenAI-style {"type": "function", "function": {"name": "x"}}
                                     or {"name": "x"}
      - None                       → []
    """
    if not tools_attr:
        return []
    out: list[str] = []
    for t in tools_attr:
        if isinstance(t, str):
            out.append(t)
        elif isinstance(t, dict):
            # OpenAI Assistants shape: {"type":"function","function":{"name":...}}
            if "function" in t and isinstance(t["function"], dict):
                name = t["function"].get("name")
            else:
                name = t.get("name") or t.get("tool_name")
            if name:
                out.append(name)
        else:
            name = getattr(t, "name", None) or getattr(t, "__name__", None)
            if name:
                out.append(name)
    return out


# ── Per-framework normalizers ────────────────────────────────────────────


def _from_veldt(raw: Any) -> dict:
    """Pass-through with defaults applied. Accepts Veldt's own dict."""
    out = dict(_DEFAULTS)
    if isinstance(raw, dict):
        for k in _DEFAULTS:
            if k in raw and raw[k] is not None:
                out[k] = raw[k]
        out["agent_key"] = raw.get("agent_key") or raw.get("id") or out["name"] or "unknown"
    return out


def _from_langchain(raw: Any) -> dict:
    """LangChain AgentExecutor or serialized dict.

    Reads `.tools` (list of Tool objects with .name), `.agent.llm`
    indirectly for model name, and `verbose` is irrelevant. LangChain has
    no native human_loop concept — defaults to 'none' (autonomous), which
    is conservative.
    """
    out = dict(_DEFAULTS)
    tools = _attr(raw, "tools") or []
    out["tools"] = _tools_to_names(tools)
    out["name"] = _attr(raw, "name", "") or "langchain_agent"
    out["description"] = _attr(raw, "description", "") or ""
    # Model — LangChain nests it under .agent.llm
    agent = _attr(raw, "agent")
    if agent is not None:
        llm = _attr(agent, "llm")
        if llm is not None:
            out["model"] = _attr(llm, "model", "") or _attr(llm, "model_name", "") or ""
    out["agent_key"] = _attr(raw, "agent_key") or out["name"] or "langchain_agent"
    return out


def _from_crewai(raw: Any) -> dict:
    """CrewAI Agent — `role` + `goal` + `tools` + `allow_delegation`."""
    out = dict(_DEFAULTS)
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    role = _attr(raw, "role", "") or ""
    goal = _attr(raw, "goal", "") or ""
    backstory = _attr(raw, "backstory", "") or ""
    out["name"] = role or "crewai_agent"
    out["description"] = goal or ""
    out["system_prompt"] = backstory or ""
    # CrewAI's allow_delegation is a weak signal — surface it under
    # access_level but don't claim it implies override/revert authority.
    out["model"] = _attr(raw, "llm_model", "") or _attr(raw, "model", "") or ""
    out["agent_key"] = _attr(raw, "agent_key") or (
        role.lower().replace(" ", "_") if role else "crewai_agent"
    )
    return out


def _from_openai(raw: Any) -> dict:
    """OpenAI Assistants API — flat dict with `model`, `tools`, `instructions`."""
    out = dict(_DEFAULTS)
    out["model"] = _attr(raw, "model", "") or ""
    out["name"] = _attr(raw, "name", "") or "openai_assistant"
    out["description"] = _attr(raw, "description", "") or ""
    out["system_prompt"] = _attr(raw, "instructions", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    out["agent_key"] = _attr(raw, "id") or _attr(raw, "agent_key") or out["name"]
    return out


def _from_autogen(raw: Any) -> dict:
    """Microsoft AutoGen ConversableAgent.

    Attributes consulted: `.name`, `.system_message`, `.llm_config` (dict
    with model), `.function_map` or `.tools`. `human_input_mode` maps
    directly to KYA's human_loop taxonomy.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "autogen_agent"
    out["description"] = _attr(raw, "description", "") or ""
    out["system_prompt"] = _attr(raw, "system_message", "") or ""
    # AutoGen function_map is a dict[str, callable]; tools may also be a list
    func_map = _attr(raw, "function_map")
    if isinstance(func_map, dict) and func_map:
        out["tools"] = list(func_map.keys())
    else:
        out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    llm_config = _attr(raw, "llm_config") or {}
    if isinstance(llm_config, dict):
        out["model"] = llm_config.get("model") or llm_config.get("model_name") or ""
    # AutoGen human_input_mode: NEVER / TERMINATE / ALWAYS
    mode = (_attr(raw, "human_input_mode", "") or "").upper()
    out["human_loop"] = {
        "ALWAYS": "in_the_loop",
        "TERMINATE": "on_the_loop",
        "NEVER": "none",
    }.get(mode, "none")
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_semantic_kernel(raw: Any) -> dict:
    """Microsoft Semantic Kernel agent / plugin spec.

    Fields consulted: `.name`, `.instructions`, `.plugins`/`.functions`,
    `.execution_settings.service_id` (model).
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "semantic_kernel_agent"
    out["description"] = _attr(raw, "description", "") or ""
    out["system_prompt"] = _attr(raw, "instructions", "") or _attr(raw, "system_message", "") or ""
    tools = _attr(raw, "plugins") or _attr(raw, "functions") or _attr(raw, "tools") or []
    out["tools"] = _tools_to_names(tools)
    exec_settings = _attr(raw, "execution_settings") or {}
    if isinstance(exec_settings, dict):
        out["model"] = exec_settings.get("ai_model_id") or exec_settings.get("service_id") or ""
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_llamaindex(raw: Any) -> dict:
    """LlamaIndex AgentRunner / ReActAgent / FunctionAgent.

    Fields: `.agent.tools` (or just `.tools`), `.llm.model`, `.system_prompt`.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "llamaindex_agent"
    out["description"] = _attr(raw, "description", "") or ""
    out["system_prompt"] = _attr(raw, "system_prompt", "") or ""
    # LlamaIndex sometimes nests via .agent.*
    inner = _attr(raw, "agent")
    tools_attr = _attr(inner, "tools") if inner is not None else _attr(raw, "tools")
    out["tools"] = _tools_to_names(tools_attr or [])
    llm = _attr(raw, "llm") or (_attr(inner, "llm") if inner is not None else None)
    if llm is not None:
        out["model"] = _attr(llm, "model", "") or _attr(llm, "model_name", "") or ""
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_haystack(raw: Any) -> dict:
    """Haystack Agent / pipeline.

    Fields: `.name` (or pipeline id), `.tools`, `.model_name`, `.prompt_node.prompt_template`.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "haystack_agent"
    out["description"] = _attr(raw, "description", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    pn = _attr(raw, "prompt_node")
    if pn is not None:
        out["model"] = _attr(pn, "model_name_or_path", "") or _attr(pn, "model", "") or ""
        pt = _attr(pn, "prompt_template")
        if pt is not None:
            out["system_prompt"] = _attr(pt, "prompt", "") or str(pt)
    out["model"] = out["model"] or _attr(raw, "model_name", "") or ""
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_mcp(raw: Any) -> dict:
    """Anthropic Model Context Protocol — server-side agent capability spec.

    MCP servers expose tools via JSON-RPC. Definition shape:
      {"name": ..., "version": ..., "tools": [{"name": ..., "description": ...}, ...]}
    """
    out = dict(_DEFAULTS)
    if isinstance(raw, dict):
        out["name"] = raw.get("name") or raw.get("server_name") or "mcp_agent"
        out["description"] = raw.get("description", "") or ""
        out["tools"] = _tools_to_names(raw.get("tools") or [])
        out["model"] = raw.get("model", "") or ""
        out["system_prompt"] = raw.get("instructions") or raw.get("system_prompt") or ""
        out["agent_key"] = raw.get("agent_key") or raw.get("server_name") or out["name"]
    else:
        out["name"] = _attr(raw, "name", "") or "mcp_agent"
        out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
        out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_bedrock(raw: Any) -> dict:
    """AWS Bedrock Agent — `bedrock-agent` API shape.

    Fields: `.agentName`, `.foundationModel`, `.instruction`,
    `.actionGroups[].actionGroupExecutor`, `.knowledgeBases`.
    """
    out = dict(_DEFAULTS)
    if isinstance(raw, dict):
        out["name"] = raw.get("agentName") or raw.get("name") or "bedrock_agent"
        out["description"] = raw.get("description", "") or ""
        out["model"] = raw.get("foundationModel") or raw.get("model") or ""
        out["system_prompt"] = raw.get("instruction") or ""
        # Action groups → tool names
        ags = raw.get("actionGroups") or []
        out["tools"] = [
            ag.get("actionGroupName") or ag.get("name") or f"action_group_{i}"
            for i, ag in enumerate(ags)
            if isinstance(ag, dict)
        ]
        out["agent_key"] = raw.get("agentId") or raw.get("agent_key") or out["name"]
    else:
        out["name"] = _attr(raw, "agentName", "") or _attr(raw, "name", "") or "bedrock_agent"
        out["tools"] = []
        out["agent_key"] = _attr(raw, "agentId") or _attr(raw, "agent_key") or out["name"]
    return out


def _from_vertex(raw: Any) -> dict:
    """Google Vertex AI Agent Builder.

    Fields: `.display_name`, `.model_name`, `.tools`, `.system_instruction`.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "display_name", "") or _attr(raw, "name", "") or "vertex_agent"
    out["description"] = _attr(raw, "description", "") or ""
    out["model"] = _attr(raw, "model_name", "") or _attr(raw, "model", "") or ""
    out["system_prompt"] = _attr(raw, "system_instruction", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    out["agent_key"] = _attr(raw, "agent_key") or _attr(raw, "name") or out["name"]
    return out


def _from_generic(raw: dict) -> dict:
    """Generic JSON — best-effort canonical extraction.

    Maps the most common field names (lowercased) onto the canonical
    schema. Anything unrecognized falls through to conservative defaults.
    Used as the universal fallback when framework is unknown OR when the
    caller passes framework="auto" and detection fails.

    Handles the wide variety of "tool" key names across frameworks:
    tools, functions, function_map, actions, capabilities, plugins,
    skills, abilities, operations, ops, commands.
    """
    out = dict(_DEFAULTS)
    if not isinstance(raw, dict):
        raw = {"name": str(raw)}
    # Direct mappings
    for k in _DEFAULTS:
        if k in raw and raw[k] is not None:
            out[k] = raw[k]
    # Skills (Round 12 — first-class). When the caller sends `skills`
    # with structure, preserve it; also flatten any bundled tools into
    # the `tools` list so existing tool-level scoring continues to work.
    from .skills import flatten_to_tools, normalize_skills

    skill_input = raw.get("skills") or raw.get("plugins") or raw.get("abilities")
    if (
        skill_input
        and isinstance(skill_input, (list, dict))
        and (
            # Only treat as first-class skills when the input looks structured
            # enough (dicts with names, or a name->spec map). Bare string lists
            # fall through to the legacy tools-alias path below.
            isinstance(skill_input, dict)
            or any(
                isinstance(s, dict) for s in (skill_input if isinstance(skill_input, list) else [])
            )
        )
    ):
        out["skills"] = normalize_skills(skill_input)
    else:
        out["skills"] = normalize_skills(skill_input) if skill_input else []

    # Tool-name aliases — superset across frameworks. Tools may come
    # directly OR get flattened from the skills bundle.
    explicit_tools = _tools_to_names(
        raw.get("tools")
        or raw.get("functions")
        or raw.get("function_map")
        or raw.get("actions")
        or raw.get("capabilities")
        or raw.get("operations")
        or raw.get("ops")
        or raw.get("commands")
        or []
    )
    bundled_tools = flatten_to_tools(out["skills"])
    # Dedup while preserving order
    seen: set[str] = set()
    merged_tools: list[str] = []
    for t in list(explicit_tools) + list(bundled_tools):
        if t and t not in seen:
            seen.add(t)
            merged_tools.append(t)
    # Fallback: if neither tools nor skills declared, accept the legacy
    # `skills`/`abilities` string-list shape as tools.
    if not merged_tools and skill_input:
        merged_tools = _tools_to_names(skill_input)
    out["tools"] = merged_tools
    out["name"] = (
        raw.get("name")
        or raw.get("title")
        or raw.get("agent_name")
        or raw.get("display_name")
        or raw.get("role")
        or "agent"
    )
    out["description"] = (
        raw.get("description") or raw.get("desc") or raw.get("goal") or raw.get("summary") or ""
    )
    out["model"] = (
        raw.get("model")
        or raw.get("model_name")
        or raw.get("foundationModel")
        or raw.get("llm")
        or ""
    )
    out["system_prompt"] = (
        raw.get("system_prompt")
        or raw.get("instructions")
        or raw.get("instruction")
        or raw.get("system_message")
        or raw.get("backstory")
        or raw.get("prompt")
        or ""
    )
    out["agent_key"] = raw.get("agent_key") or raw.get("id") or raw.get("agentId") or out["name"]
    return out


def _from_agents_md(raw: Any) -> dict:
    """AGENTS.md format — Markdown file with YAML/TOML frontmatter declaring
    agent capabilities.

    Convention (informal, used by several projects): the .md file starts
    with `---` frontmatter containing name, description, tools, model,
    etc.; the body is the system_prompt. Callers should pre-parse the
    frontmatter into a dict before handing it to KYA — we don't bundle
    a Markdown parser here (keeps KYA dependency-free).

    Expected dict shape:
        {
            "name": "...",
            "description": "...",
            "tools": [...],
            "model": "...",
            "body": "the system prompt (everything after the frontmatter)",
        }
    """
    if not isinstance(raw, dict):
        raw = {}
    out = _from_generic(raw)
    # AGENTS.md convention: prompt is in "body" if present
    if not out.get("system_prompt") and raw.get("body"):
        out["system_prompt"] = raw["body"]
    return out


def _from_skill_manifest(raw: Any) -> dict:
    """Generic skill manifest — `skills.yaml` / `skill.json` / `manifest.json`.

    Not Anthropic-specific. Veldt has skills.yaml, Semantic Kernel had
    skills (now plugins), many internal frameworks use skill manifests.
    Common shape:
        name / description / model / tools (or skills/abilities/functions)
        / instructions (or system_prompt / prompt) / version / permissions

    Use this framework name when ingesting a generic skill-manifest YAML
    or JSON file from any source. The `claude_skill` framework is a
    distinct alias for the Anthropic-specific manifest format.
    """
    if not isinstance(raw, dict):
        raw = {}
    out = _from_generic(raw)  # generic already handles `skills`/`abilities`/etc.
    if not out.get("system_prompt"):
        out["system_prompt"] = raw.get("instructions") or raw.get("prompt") or ""
    return out


def _from_claude_skill(raw: Any) -> dict:
    """Anthropic Claude Skills manifest — same shape as skill_manifest but
    typically pre-flagged with `provenance=imported` and `model=claude`."""
    out = _from_skill_manifest(raw)
    if not out.get("model"):
        out["model"] = "claude"
    if isinstance(raw, dict) and not raw.get("provenance"):
        out["provenance"] = "imported"
    return out


def _from_swarm(raw: Any) -> dict:
    """OpenAI Swarm Agent (legacy/educational — superseded by openai_agents).

    Schema: {name, instructions, functions, model}. Functions are raw Python
    callables; schema is auto-derived from signature/docstring at runtime.
    For the production successor see `_from_openai_agents`.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "swarm_agent"
    out["system_prompt"] = _attr(raw, "instructions", "") or ""
    out["model"] = _attr(raw, "model", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "functions") or [])
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_openai_agents(raw: Any) -> dict:
    """OpenAI Agents SDK (https://github.com/openai/openai-agents-python).

    Production successor to Swarm. Schema differences from Swarm:
      - `tools` (typed FunctionTool objects with .name/.description/.params_json_schema),
        NOT `functions` of raw callables
      - First-class `handoffs: list[Agent | Handoff]` rendered to the LLM as
        `transfer_to_<name>` tools — surfaced into our canonical `tools` list
        so risk scoring counts them
      - `input_guardrails` / `output_guardrails` — capability signal
      - `mcp_servers` — MCP tool sources merged at runtime
      - `instructions` may be a Callable (dynamic) — recorded as a sentinel
        rather than executed
      - `model` may be a `Model` object — stringified to opaque label

    Model-agnostic: `model` is recorded as a free-form string. The SDK
    itself supports `LitellmModel` for non-OpenAI providers; the adapter
    doesn't care which.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "openai_agents_agent"
    out["description"] = _attr(raw, "description", "") or ""

    # instructions can be str or Callable; record sentinel for dynamic
    instructions = _attr(raw, "instructions", "")
    if callable(instructions):
        out["system_prompt"] = "<dynamic instructions>"
    else:
        out["system_prompt"] = instructions or ""

    # model can be str or Model object; stringify either way
    model = _attr(raw, "model", "")
    if model and not isinstance(model, str):
        out["model"] = (
            _attr(model, "model", None) or _attr(model, "name", None) or type(model).__name__
        )
    else:
        out["model"] = model or ""

    # tools: typed FunctionTool objects expose .name; also accept dicts
    tools = _tools_to_names(_attr(raw, "tools") or [])

    # handoffs: fold into the tools list as `transfer_to_<name>` to match
    # how the SDK renders them to the LLM. This makes blast-radius scoring
    # account for handoff targets the same as any other tool.
    handoffs = _attr(raw, "handoffs") or []
    for h in handoffs:
        target_name = (
            _attr(h, "name", None)
            or _attr(h, "agent_name", None)
            or (_attr(_attr(h, "agent", None), "name", None) if _attr(h, "agent", None) else None)
        )
        if target_name:
            tools.append(f"transfer_to_{target_name}")
    out["tools"] = tools

    # mcp_servers: surface as input_sources (MCP servers feed external data in)
    mcp_servers = _attr(raw, "mcp_servers") or []
    if mcp_servers:
        out["input_sources"] = [
            _attr(s, "name", None) or _attr(s, "server_name", None) or "mcp_server"
            for s in mcp_servers
        ]

    # guardrails presence → human_loop signal (on_the_loop with active checks)
    has_input_gr = bool(_attr(raw, "input_guardrails") or [])
    has_output_gr = bool(_attr(raw, "output_guardrails") or [])
    if has_input_gr or has_output_gr:
        out["human_loop"] = "on_the_loop"

    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_claude_agent(raw: Any) -> dict:
    """Anthropic Claude Agent SDK (formerly Claude Code SDK).

    Repos: claude-agent-sdk-python / claude-agent-sdk-typescript. The
    SDK exposes a runtime Agent / Query object distinct from:
      - `claude_skill` (declarative skill manifest)
      - `mcp` (MCP server-side capability spec)

    Schema (Python SDK):
      - model: str (e.g. "claude-sonnet-4-5", "claude-haiku-4-5")
      - system_prompt: str
      - tools: list[Tool] OR list[str] (allowed tool names)
      - allowed_tools: list[str] (explicit allow-list)
      - disallowed_tools: list[str] (deny list)
      - permission_mode: "default" | "acceptEdits" | "bypassPermissions" | "plan"
      - mcp_servers: list[McpServer] — registered MCP tool sources
      - max_turns: int
      - setting_sources: list[str] — "filesystem", "api", etc.
      - cwd: str
      - hooks: dict[str, list[Callable]]

    permission_mode → human_loop:
      bypassPermissions → none       (autonomous)
      default           → on_the_loop (human reviews tool calls before execution)
      acceptEdits       → on_the_loop (auto-approves file edits, surfaces rest)
      plan              → in_the_loop (must produce a plan, then human approves)

    Model-agnostic note: Anthropic's SDK is Claude-first by default but
    supports custom model providers via `model_provider`. We record `model`
    as opaque; downstream `model_trust` weighting handles classification.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "claude_agent"
    out["description"] = _attr(raw, "description", "") or ""
    out["model"] = _attr(raw, "model", "") or "claude"
    out["system_prompt"] = _attr(raw, "system_prompt", "") or ""

    # Tools: SDK accepts list[Tool] OR list[str] OR allowed_tools allow-list.
    # Prefer explicit allowed_tools when present (it's the security gate).
    allowed = _attr(raw, "allowed_tools", None)
    tools_field = _attr(raw, "tools", None)
    if allowed:
        out["tools"] = _tools_to_names(allowed)
    elif tools_field:
        out["tools"] = _tools_to_names(tools_field)
    else:
        out["tools"] = []

    out["denied_tools"] = _tools_to_names(_attr(raw, "disallowed_tools") or [])

    # MCP servers → input sources
    mcp_servers = _attr(raw, "mcp_servers") or []
    if mcp_servers:
        out["mcp_servers"] = [
            _attr(s, "name", None) or _attr(s, "server_name", None) or "mcp_server"
            for s in mcp_servers
        ]
        out["input_sources"] = list(out["mcp_servers"])

    # permission_mode → human_loop
    mode = (_attr(raw, "permission_mode", "") or "").strip()
    out["human_loop"] = {
        "bypassPermissions": "none",
        "default": "on_the_loop",
        "acceptEdits": "on_the_loop",
        "plan": "in_the_loop",
    }.get(mode, "on_the_loop")

    # Anthropic provenance signal — first-party SDK on Anthropic models
    if not _attr(raw, "provenance", None):
        out["provenance"] = "first_party"

    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_pydantic_ai(raw: Any) -> dict:
    """Pydantic AI Agent.

    Pydantic AI exposes `.model`, `.system_prompt`, `.tools` (list of
    Tool objects with .name).
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "pydantic_ai_agent"
    out["model"] = _attr(raw, "model", "") or ""
    out["system_prompt"] = _attr(raw, "system_prompt", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_smol(raw: Any) -> dict:
    """HuggingFace Smol Agents.

    Schema: CodeAgent / ToolCallingAgent with .tools, .model, .system_prompt.
    Smol Agents that execute code by default → security_caps=['code_execution'].
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "smol_agent"
    out["model"] = _attr(raw, "model", "") or ""
    out["system_prompt"] = _attr(raw, "system_prompt", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    # CodeAgent class implies code_execution capability
    cls = type(raw).__name__ if not isinstance(raw, dict) else raw.get("class", "")
    if "CodeAgent" in str(cls):
        out["security_caps"] = ["code_execution"]
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_letta(raw: Any) -> dict:
    """Letta (formerly MemGPT) Agent.

    Letta agents have persistent memory + a tool list. Persistent memory
    of user interactions implies PII data class by default.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "letta_agent"
    out["description"] = _attr(raw, "description", "") or ""
    out["model"] = _attr(raw, "llm_config") or _attr(raw, "model", "") or ""
    if isinstance(out["model"], dict):
        out["model"] = out["model"].get("model") or ""
    out["system_prompt"] = _attr(raw, "system", "") or _attr(raw, "system_prompt", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    # Persistent memory → likely PII unless caller overrides
    if _attr(raw, "memory") is not None or _attr(raw, "core_memory") is not None:
        out["data_classes"] = ["pii"]
    out["agent_key"] = _attr(raw, "id") or _attr(raw, "agent_key") or out["name"]
    return out


def _from_strands(raw: Any) -> dict:
    """AWS Strands Agents.

    Schema: Strands Agent with .model, .tools, .system_prompt.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "strands_agent"
    out["model"] = _attr(raw, "model", "") or ""
    out["system_prompt"] = _attr(raw, "system_prompt", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


def _from_google_adk(raw: Any) -> dict:
    """Google Agent Development Kit (ADK).

    Schema: Agent with .name, .model, .instruction, .tools. Distinct
    from Vertex AI Agent Builder; ADK is the lower-level SDK.
    """
    out = dict(_DEFAULTS)
    out["name"] = _attr(raw, "name", "") or "adk_agent"
    out["description"] = _attr(raw, "description", "") or ""
    out["model"] = _attr(raw, "model", "") or ""
    out["system_prompt"] = _attr(raw, "instruction", "") or ""
    out["tools"] = _tools_to_names(_attr(raw, "tools") or [])
    out["agent_key"] = _attr(raw, "agent_key") or out["name"]
    return out


# ── Registry — pluggable, mutable, runtime-extensible ────────────────────

_DISPATCH: dict[str, Callable[[Any], dict]] = {
    "veldt": _from_veldt,
    "langchain": _from_langchain,
    "crewai": _from_crewai,
    "openai": _from_openai,
    "autogen": _from_autogen,
    "semantic_kernel": _from_semantic_kernel,
    "llamaindex": _from_llamaindex,
    "haystack": _from_haystack,
    "mcp": _from_mcp,
    "bedrock": _from_bedrock,
    "vertex": _from_vertex,
    "agents_md": _from_agents_md,
    "skill_manifest": _from_skill_manifest,  # generic skills.yaml / skill.json
    "claude_skill": _from_claude_skill,  # Anthropic-specific alias
    "swarm": _from_swarm,
    "openai_agents": _from_openai_agents,
    "claude_agent": _from_claude_agent,
    "pydantic_ai": _from_pydantic_ai,
    "smol": _from_smol,
    "letta": _from_letta,
    "strands": _from_strands,
    "google_adk": _from_google_adk,
    "generic": _from_generic,
}


def register_adapter(framework: str, fn: Callable[[Any], dict]) -> None:
    """Register a runtime adapter so any third-party framework can plug in.

    The `fn` takes the framework's native object or serialized dict and
    returns a canonical dict consumable by `score_agent`. Re-registering
    a name overwrites the previous adapter. Returns nothing — registration
    is global to the process.

    Recommended pattern for adapter authors:

        def from_my_framework(raw):
            return {
                "name": _attr(raw, "name", ""),
                "tools": [...],
                "human_loop": "none",
                ...
            }
        register_adapter("my_framework", from_my_framework)

    Use this helper alongside `_attr`, `_tools_to_names`, and `_DEFAULTS`
    which are exposed at module level for adapter authors.
    """
    if not framework or not callable(fn):
        raise ValueError("register_adapter requires a non-empty framework name and callable fn")
    _DISPATCH[framework.lower()] = fn


def list_adapters() -> list[str]:
    """Return all registered framework names (sorted alphabetically)."""
    return sorted(_DISPATCH.keys())


def _detect_framework(raw: Any) -> str:
    """Best-effort framework detection from a definition's shape.

    Strict detection — returns 'generic' when uncertain rather than
    guessing wrong (which would lead to misleading factor breakdowns).
    Adapter authors can register their own detectors by overriding
    `detect_framework` via the dispatch table if needed.
    """
    if hasattr(raw, "function_map") or hasattr(raw, "human_input_mode"):
        return "autogen"
    # OpenAI Agents SDK: has tools + handoffs + instructions (production
    # successor to Swarm). Distinguish from Swarm by `tools` vs `functions`.
    if hasattr(raw, "handoffs") and hasattr(raw, "tools") and hasattr(raw, "instructions"):
        return "openai_agents"
    # Swarm (legacy): has functions (raw callables) + instructions, no handoffs
    if hasattr(raw, "functions") and hasattr(raw, "instructions") and not hasattr(raw, "tools"):
        return "swarm"
    # Claude Agent SDK: permission_mode + (max_turns OR allowed_tools).
    # Distinguishes from `mcp` (server-side) and `claude_skill` (manifest).
    if hasattr(raw, "permission_mode") and (
        hasattr(raw, "max_turns") or hasattr(raw, "allowed_tools")
    ):
        return "claude_agent"
    if hasattr(raw, "kernel") or hasattr(raw, "execution_settings"):
        return "semantic_kernel"
    if hasattr(raw, "agent") and hasattr(raw, "tools"):
        return "langchain"
    if hasattr(raw, "role") and hasattr(raw, "goal") and hasattr(raw, "backstory"):
        return "crewai"
    if isinstance(raw, dict):
        if "agentName" in raw and "foundationModel" in raw:
            return "bedrock"
        if "display_name" in raw and "system_instruction" in raw:
            return "vertex"
        if "instructions" in raw and "model" in raw and "tools" in raw:
            return "openai"
        if "server_name" in raw or (
            "tools" in raw
            and isinstance(raw.get("tools"), list)
            and raw["tools"]
            and isinstance(raw["tools"][0], dict)
            and "inputSchema" in raw["tools"][0]
        ):
            return "mcp"
        if "role" in raw and "goal" in raw:
            return "crewai"
    return "generic"


def normalize_agent_def(framework: SupportedFramework, raw_def: Any) -> dict:
    """Normalize a framework-specific agent definition to KYA's canonical
    schema.

    `framework="auto"` runs duck-typed detection and falls back to
    "generic" if no signature matches. Unknown explicit framework names
    also fall back to "generic" with a `framework` audit field that
    preserves the caller's original value.

    The result is always safe to pass to `kya.score_agent()`. The
    `framework` and `raw` fields preserve the original for audit — they
    don't influence the score.
    """
    fw = (framework or "auto").lower()
    if fw == "auto":
        fw = _detect_framework(raw_def)
    # If the requested framework isn't registered, we fall back to the
    # generic adapter. Reflect THAT in the audit trail — don't claim to
    # have parsed something we didn't know how to parse.
    if fw in _DISPATCH:
        adapter = _DISPATCH[fw]
        resolved = fw
    else:
        adapter = _from_generic
        resolved = "generic"
    out = adapter(raw_def)
    out["framework"] = resolved
    # Don't store the raw object if it's a non-serializable Python instance
    if isinstance(raw_def, dict):
        out["raw"] = raw_def
    else:
        out["raw"] = {"_type": type(raw_def).__name__}
    return out
