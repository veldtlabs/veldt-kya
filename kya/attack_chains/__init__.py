"""
Phase 3c -- Declarative attack-chain rule DSL.

KYA's existing detection is single-event: each signal (rogue_pattern,
oos_tool, etc.) is independent. But many real attacks are multi-step
sequences that only look malicious when correlated -- individual steps
look benign in isolation.

This package adds:
  - YAML rule loader (kya/attack_chains/rules/*.yml + caller-supplied)
  - Match primitives (glob, regex, dotted-path field access, time-window)
  - Partial-match state machine per (tenant, principal_id)
  - Engine hook into record_evidence() -- when a chain fully matches,
    emit record_principal_signal(signal_kind="rogue_*"), which feeds
    Phase 5b RBAC's block surface

Off-by-default. Activated when KYA_ATTACK_CHAIN_RULES_DIR is set
(env-driven, same pattern as KYA_SPIFFE_TRUST_DOMAINS in Phase 4c).

Design contract
---------------
- Each submodule is independently testable. Matchers have no DB, no
  state. The loader has no engine knowledge. The state machine knows
  matchers but nothing about persistence. The engine wires them
  together.
- DRY field access: one dotted-path implementation in _matchers used
  by both loader (for validation) and engine (for matching).
- Reusable: the rule loader accepts file paths OR dicts (programmatic
  rule construction), so an integration test can build rules in-line
  without touching disk.
- Optional dependency: PyYAML (`pip install veldt-kya[attack_chains]`
  pulls it in). Without PyYAML, only programmatic dict-form rules work
  -- file loading is skipped with a debug log, no crash.

What this is NOT
----------------
- Not a streaming framework. Each evidence event is processed
  synchronously inside record_evidence() with a small per-(tenant,
  principal) state. The default ``InMemoryStateStore`` is per-process;
  for multi-worker / multi-agent fleets that need partial-match state
  shared across processes, pass ``ValkeyStateStore`` to
  ``AttackChainEngine(state_store=...)``.
- Not Sigma. Sigma rules don't have time-window semantics; this DSL
  does. They're related but not interchangeable.
- Not pre-deployment chain testing -- that's Garak/PyRIT's territory.
  This is runtime detection.
"""

from __future__ import annotations

from ._engine import (
    AttackChainEngine,
    get_default_engine,
    reset_default_engine,
    resolve_state_store,
)

# Re-export the public API surface. Implementation details (the
# underscore-prefixed modules) are internal and may be refactored
# without breaking callers.
from ._loader import (
    AttackChainRule,
    RuleLoadError,
    load_rule,
    load_rules_from_dir,
)
from ._matchers import (
    MatcherError,
    field_value,
    match_value,
)
from ._state import (
    InMemoryStateStore,
    PartialMatch,
    StateStore,
    ValkeyStateStore,
)
from .delegation_correlation import (
    DEFAULT_MAX_HOPS,
    correlation_id_for_invocation,
)

__all__ = [
    # Rules + loader
    "AttackChainRule",
    "RuleLoadError",
    "load_rule",
    "load_rules_from_dir",
    # Matchers
    "MatcherError",
    "field_value",
    "match_value",
    # State
    "PartialMatch",
    "StateStore",
    "InMemoryStateStore",
    "ValkeyStateStore",
    # Engine
    "AttackChainEngine",
    "get_default_engine",
    "reset_default_engine",
    "resolve_state_store",
    # Cross-agent / delegation-graph correlation helper
    "correlation_id_for_invocation",
    "DEFAULT_MAX_HOPS",
]
