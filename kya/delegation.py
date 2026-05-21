"""
Delegation depth — how many hops of agent-to-agent calls an agent can
trigger before a human is in the loop.

An agent that calls one other agent is one thing. An agent that calls
another that calls another that creates a rule is qualitatively
different — risk compounds through the chain. KYA tracks the MAX
delegation depth reachable from an agent's `can_delegate_to` graph
and weights it into the static risk score.

Cycle handling: BFS with visited set so an A→B→A loop terminates at
depth 1 (counted once). Maximum cap is `_MAX_DEPTH_CAP` to keep risk
contributions bounded.

Public API
----------
    max_delegation_depth(agent_def, all_agents) -> int
    delegation_chain(agent_def, all_agents) -> list[list[str]]
    delegation_weight(depth) -> int
"""

_PER_HOP = 6  # +6 per hop in the chain
_MAX_DEPTH_CAP = 30  # total contribution cap


# Safety caps — protect against pathological graphs supplied by users.
_MAX_TRAVERSAL_NODES = 5000  # visit at most this many nodes
_MAX_CHAIN_DEPTH = 50  # cap depth reported (anything deeper = "very deep")
_MAX_PATHS_RETURNED = 50  # paths returned by delegation_chain


def max_delegation_depth(agent_def: dict, all_agents: dict[str, dict]) -> int:
    """Return the longest delegation chain reachable from this agent.

    Iterative BFS — no recursion → no `RecursionError` on long chains.
    Visited-set + node cap + depth cap prevent unbounded work from
    user-controlled graphs.
    """
    start = agent_def.get("agent_key") or agent_def.get("id")
    if not start and (agent_def.get("can_delegate_to") or []):
        # No key — score from the immediate edges instead. Seed the queue
        # with the children at depth 1.
        seeds = [(t, 1) for t in agent_def["can_delegate_to"] if t]
    elif start:
        seeds = [(start, 0)]
    else:
        return 0

    visited: set[str] = set()
    max_depth = 0
    queue: list[tuple[str, int]] = list(seeds)
    while queue and len(visited) < _MAX_TRAVERSAL_NODES:
        node_key, depth = queue.pop()
        if node_key in visited or depth > _MAX_CHAIN_DEPTH:
            continue
        visited.add(node_key)
        if depth > max_depth:
            max_depth = depth
        node = all_agents.get(node_key) or {}
        for target in node.get("can_delegate_to") or []:
            if isinstance(target, str) and target not in visited:
                queue.append((target, depth + 1))
    return max_depth


def delegation_chain(agent_def: dict, all_agents: dict[str, dict]) -> list[list[str]]:
    """Return delegation paths starting at `agent_def`, capped at
    `_MAX_PATHS_RETURNED` for safety.

    Iterative DFS with explicit stack + path-emit cap. A fan-out tree
    with 5 children at depth 8 would produce 390k paths under the old
    recursive walker; here we stop at 50 and tag the truncation.
    """
    start = agent_def.get("agent_key") or agent_def.get("id")
    if not start:
        return []
    paths: list[list[str]] = []
    stack: list[tuple[str, list[str], set[str]]] = [(start, [start], {start})]
    while stack and len(paths) < _MAX_PATHS_RETURNED:
        node_key, path, seen = stack.pop()
        if len(path) > _MAX_CHAIN_DEPTH:
            paths.append(path + ["(truncated — chain too deep)"])
            continue
        node = all_agents.get(node_key) or {}
        children = node.get("can_delegate_to") or []
        if not children:
            paths.append(path)
            continue
        for child in children:
            if not isinstance(child, str):
                continue
            if child in seen:
                paths.append(path + [child + " (cycle)"])
                continue
            stack.append((child, path + [child], seen | {child}))
    if len(paths) >= _MAX_PATHS_RETURNED:
        paths.append([f"(more paths exist — list truncated at {_MAX_PATHS_RETURNED})"])
    return paths


def delegation_weight(depth: int) -> int:
    """Map a depth integer to a risk-score delta, capped."""
    if depth <= 0:
        return 0
    return min(_MAX_DEPTH_CAP, _PER_HOP * depth)
