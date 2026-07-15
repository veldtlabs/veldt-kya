"""
Security capabilities — what *power* an agent has at a system level.

Where data_classes asks "what kind of data does this agent touch?",
security capabilities ask "what system-level actions can it perform?".
An agent with `code_execution` capability is materially more dangerous
than one with ten write tools to a curated business surface — it can,
in principle, do anything the host process can do.

Capability taxonomy
-------------------
    fs_read         — can read arbitrary files                          (5)
    fs_write        — can write arbitrary files                        (15)
    network_egress  — can make outbound HTTP/socket calls              (15)
    prod_database   — can hit production datastores                    (25)
    secret_access   — can read credentials/API keys/PKI material       (20)
    code_execution  — can execute Python / arbitrary code              (30)
    shell_access    — can run shell commands on the host               (35)
    container_exec  — can exec inside other containers                 (40)

Capabilities and data classes COMPOSE. An agent that handles `pii` AND
has `code_execution` is far riskier than either alone — the score adds
both contributions, capped at SENSITIVITY_CAP + CAPABILITY_CAP.

Public API
----------
    SECURITY_CAPS                                  — known names (set)
    CAPABILITY_WEIGHTS                             — name → risk delta
    DEFAULT_TOOL_CAPABILITIES                      — tool → caps
    classify_tool_capabilities(tool) -> list[str]
    infer_capabilities(tools) -> list[str]
    capability_weight(caps) -> int
    set_capability_weights(weights)
    set_tool_capabilities(catalog)
"""

# ── Taxonomy ─────────────────────────────────────────────────────────────

SECURITY_CAPS = {
    "fs_read",
    "fs_write",
    "network_egress",
    "prod_database",
    "secret_access",
    "code_execution",
    "shell_access",
    "container_exec",
}

CAPABILITY_WEIGHTS = {
    "fs_read": 5,
    "fs_write": 15,
    "network_egress": 15,
    "prod_database": 25,
    "secret_access": 20,
    "code_execution": 30,
    "shell_access": 35,
    "container_exec": 40,
}

# Cap on the security contribution — additive to data sensitivity, so a
# truly dangerous agent (code exec + PHI handling) can still rack up
# significant points across both dimensions without dominating one.
CAPABILITY_CAP = 60


# ── Default tool → capabilities mapping (Veldt's tools) ──────────────────

DEFAULT_TOOL_CAPABILITIES: dict[str, list[str]] = {
    # Database connectors hit prod
    "connect_database": ["network_egress", "prod_database"],
    "test_database_connection": ["network_egress"],
    "execute_sql": ["network_egress", "prod_database"],
    "manage_schema_knowledge": ["prod_database"],
    # External connectors
    "connect_email": ["network_egress"],
    "connect_slack": ["network_egress"],
    "connect_nifi": ["network_egress"],
    # Knowledge / RAG calls hit internal services but not production DBs
    "search_documents": [],
    "search_lightrag": [],
    # Anything that fetches a URL or remote API
    "fetch_url": ["network_egress"],
    "web_search": ["network_egress"],
    # Code interpreter / function execution
    "execute_python": ["code_execution"],
    "run_code": ["code_execution"],
    "code_interpreter": ["code_execution"],
    "shell": ["shell_access"],
    "bash": ["shell_access"],
    "run_command": ["shell_access"],
}


# ── Runtime overrides ────────────────────────────────────────────────────


def set_capability_weights(weights: dict) -> None:
    """Replace the capability weight table."""
    CAPABILITY_WEIGHTS.clear()
    CAPABILITY_WEIGHTS.update(weights or {})


def set_tool_capabilities(catalog: dict[str, list[str]]) -> None:
    """Replace the tool→capabilities mapping."""
    DEFAULT_TOOL_CAPABILITIES.clear()
    DEFAULT_TOOL_CAPABILITIES.update(catalog or {})


# ── Helpers ──────────────────────────────────────────────────────────────


def classify_tool_capabilities(tool_name: str) -> list[str]:
    """Return the security capabilities a tool is known to grant."""
    return list(DEFAULT_TOOL_CAPABILITIES.get(tool_name, []))


def infer_capabilities(tools: list[str]) -> list[str]:
    """Union of capabilities across a tool list, sorted by risk DESC."""
    seen: set[str] = set()
    for t in tools or []:
        for c in classify_tool_capabilities(t):
            if c in SECURITY_CAPS:
                seen.add(c)
    return sorted(seen, key=lambda c: -CAPABILITY_WEIGHTS.get(c, 0))


def capability_weight(caps: list[str], weights: dict | None = None) -> int:
    """Compute the total security-capability risk contribution.

    Unlike sensitivity (MAX), capabilities SUM up to the cap — having
    BOTH code_execution AND shell_access really is worse than having
    one. The cap ensures the total can't dominate the whole score.
    """
    if not caps:
        return 0
    weight_source = weights if weights is not None else CAPABILITY_WEIGHTS
    total = sum(weight_source.get(c, 0) for c in set(caps))
    return min(CAPABILITY_CAP, total)
