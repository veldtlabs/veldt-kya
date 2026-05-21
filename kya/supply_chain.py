"""
Supply-chain dependencies (#20) — external APIs, MCP servers, plugins,
package dependencies.

Each external dependency an agent consumes is a supply-chain risk vector.
Log4Shell / xz-utils / event-stream taught the industry that transitive
dependencies kill you. An agent calling 5 MCP servers from 5 different
publishers has 5 attack surfaces.

Taxonomy
--------
We classify each dependency by *publisher trust*:
    first_party       — internal, same tenant                  (0)
    vendor_contracted — vendor with MSA / DPA                  (2)
    open_source       — public OSS package or MCP server       (4)
    marketplace       — paid marketplace / app store           (5)
    third_party       — unknown / unverified third party       (8)
    self_hosted_ext   — external infrastructure not maintained
                         by you (typo squat risk for OSS)     (10)

Weight rule
-----------
For each dependency, add its publisher-trust weight; cap at SUPPLY_CHAIN_CAP.
COUNT also matters: more dependencies = bigger surface, so each dep over
5 adds a small breadth premium.

Public API
----------
    supply_chain_weight(agent_def) -> tuple[int, str]
    parse_dependencies(agent_def) -> list[dict]
"""

_PUBLISHER_WEIGHTS = {
    "first_party": 0,
    "vendor_contracted": 2,
    "open_source": 4,
    "marketplace": 5,
    "third_party": 8,
    "self_hosted_ext": 10,
    "unknown": 6,
}

SUPPLY_CHAIN_CAP = 35


def parse_dependencies(agent_def: dict) -> list[dict]:
    """Return a normalized list of dependencies from the agent_def.

    Accepts EITHER `external_dependencies` (preferred, fully structured)
    OR derives a best-effort list from `mcp_servers`, `external_apis`,
    `plugins`. Each dict has keys: name, kind, publisher.
    """
    explicit = agent_def.get("external_dependencies")
    if isinstance(explicit, list):
        out = []
        for d in explicit:
            if isinstance(d, dict):
                out.append(
                    {
                        "name": d.get("name", "unknown"),
                        "kind": d.get("kind", "unknown"),  # mcp / api / plugin / package
                        "publisher": (d.get("publisher") or "unknown").lower(),
                    }
                )
            elif isinstance(d, str):
                out.append({"name": d, "kind": "unknown", "publisher": "unknown"})
        return out

    out: list[dict] = []
    for name in agent_def.get("mcp_servers") or []:
        if isinstance(name, str):
            out.append({"name": name, "kind": "mcp", "publisher": "unknown"})
    for name in agent_def.get("external_apis") or []:
        if isinstance(name, str):
            out.append({"name": name, "kind": "api", "publisher": "unknown"})
    for name in agent_def.get("plugins") or []:
        if isinstance(name, str):
            out.append({"name": name, "kind": "plugin", "publisher": "unknown"})
    return out


def supply_chain_weight(agent_def: dict) -> tuple[int, str]:
    """Sum publisher-trust weights + breadth premium, capped.

    Returns (delta, label). label names the worst dep so the operator
    can see the riskiest one at a glance.
    """
    deps = parse_dependencies(agent_def)
    if not deps:
        return 0, ""

    weights = [_PUBLISHER_WEIGHTS.get(d["publisher"], _PUBLISHER_WEIGHTS["unknown"]) for d in deps]
    base = sum(weights)

    # Breadth premium — > 5 deps starts adding +1 per extra
    extras = max(0, len(deps) - 5)
    score = min(SUPPLY_CHAIN_CAP, base + extras)

    if score == 0:
        return 0, ""

    # Find the riskiest single dep for the label
    worst_idx = max(range(len(deps)), key=lambda i: weights[i])
    worst = deps[worst_idx]
    label = f"{len(deps)} external dependencies (worst: {worst['name']} from {worst['publisher']})"
    return score, label
