"""
Data classification — what *kind* of data an agent handles.

KYA's static risk score (`risk.py`) factors in the most-sensitive data
class an agent touches. A read-only agent that handles PHI is still a
high-risk agent. A "write" agent that only touches public data is lower
risk than its tool count alone would suggest.

Taxonomy (in order of increasing sensitivity)
---------------------------------------------
    public         — disclosable to anyone, no controls (0)
    internal       — internal-use, not public, but no regulated content (8)
    confidential   — business-sensitive (contracts, strategy, source) (15)
    pii            — personally identifiable info (name + email/dob/etc) (20)
    financial      — transactions, account numbers, balances (25)
    phi            — protected health info (HIPAA scope) (30)
    secret         — credentials, API keys, cryptographic material (40)

The taxonomy is intentionally small and additive — easier to keep clean
than 20 categories nobody remembers. Custom classes can be injected via
`set_class_weights()` for tenants with their own regimes (e.g., DoD CUI,
EU GDPR special categories).

Public API
----------
    DATA_CLASSES                                   — known class names (set)
    CLASS_WEIGHTS                                  — class → risk delta (dict)
    DEFAULT_TOOL_CLASSIFICATIONS                   — tool_name → classes
    classify_tool(tool_name) -> list[str]          — best-effort lookup
    infer_data_classes(tools) -> list[str]         — union across tool list
    sensitivity_weight(classes) -> int             — sum of weights, capped
    set_class_weights(weights: dict)               — runtime override
    set_tool_classifications(catalog: dict)        — runtime override
"""

# ── Taxonomy ─────────────────────────────────────────────────────────────

DATA_CLASSES = {
    # Civilian taxonomy
    "public",
    "internal",
    "confidential",
    "pii",
    "financial",
    "phi",
    "secret",
    # Defense / aerospace / federal — see comments below for sources
    "cui",  # Controlled Unclassified Information (32 CFR 2002)
    "cdi",  # Covered Defense Information (DFARS 252.204-7012)
    "itar",  # Int'l Traffic in Arms Regulations (export-controlled)
    "ear",  # Export Administration Regulations
    "classified",  # generic classified (use specific level when known)
    "us_confidential",  # US CONFIDENTIAL — disambiguated from civilian
    "us_secret",  # US SECRET (specific clearance level)
    "us_top_secret",  # US TOP SECRET
    # NATO
    "nato_restricted",
    "nato_confidential",
    "nato_secret",
    # EU
    "restreint_ue",  # EU RESTRICTED
    "confidentiel_ue",  # EU CONFIDENTIAL
    "secret_ue",  # EU SECRET
}

CLASS_WEIGHTS = {
    # Civilian
    "public": 0,
    "internal": 8,
    "confidential": 15,
    "pii": 20,
    "financial": 25,
    "phi": 30,
    "secret": 40,  # credentials / API keys / crypto material
    # Defense / aerospace / federal — weighted above civilian "secret"
    # because they imply legal export-control / clearance obligations,
    # not just operational risk.
    "cui": 35,
    "cdi": 40,
    "ear": 40,
    "itar": 50,  # ITAR violations can be felonies
    "classified": 50,
    "us_confidential": 45,
    "us_secret": 55,
    "us_top_secret": 60,
    "nato_restricted": 35,
    "nato_confidential": 45,
    "nato_secret": 55,
    "restreint_ue": 35,
    "confidentiel_ue": 45,
    "secret_ue": 55,
}

# Cap on the sensitivity contribution. Bumped to 60 to accommodate the
# higher weights of classified / ITAR / NATO categories — a TOP SECRET
# agent should pin the dimension. The overall risk score is still capped
# at 100 in risk.py so this can't dominate.
SENSITIVITY_CAP = 60


# ── Default tool → data-class mappings (Veldt's tools) ───────────────────

# Conservative defaults — only mark a class when there's strong evidence
# the tool actually returns that data. Most "search_*" / "list_*" tools
# are domain-agnostic and not pre-classified here; tenants who care should
# inject via set_tool_classifications().
DEFAULT_TOOL_CLASSIFICATIONS: dict[str, list[str]] = {
    # Document RAG / search — typically organizational confidential
    "search_documents": ["confidential"],
    "search_lightrag": ["confidential"],
    # Decisions, rules — internal but not regulated by default
    "list_rules": ["internal"],
    "create_rule": ["internal"],
    "delete_rules": ["internal"],
    "override_decision": ["internal"],
    "revert_decision": ["internal"],
    # Entity / graph — depends on the entity domain; treat as confidential
    "manage_relationships": ["confidential"],
    "merge_entities": ["confidential"],
    # Database connectors — caller-supplied schema may contain anything;
    # mark conservatively as confidential to push the risk score up. If a
    # tenant connects only public datasets they can override.
    "connect_database": ["confidential"],
    "test_database_connection": ["confidential"],
    "manage_schema_knowledge": ["confidential"],
    # Email / chat connectors — high PII potential
    "connect_email": ["pii", "confidential"],
    "connect_slack": ["pii", "confidential"],
    # Governance audit data is internal
    "get_traces": ["internal"],
    "list_governance_events": ["internal"],
}


# ── Runtime overrides ────────────────────────────────────────────────────


def set_class_weights(weights: dict, merge: bool = True) -> None:
    """Override the weight table at runtime.

    merge=True (default): additive — preserves built-in defaults, overrides
    only the keys you pass. Add a new class? Also add it to DATA_CLASSES.
    merge=False: replace — clears all defaults first. Use with care.
    """
    if not merge:
        CLASS_WEIGHTS.clear()
    CLASS_WEIGHTS.update(weights or {})


def set_tool_classifications(catalog: dict[str, list[str]], merge: bool = True) -> None:
    """Override the tool→classes mapping.

    merge=True (default): additive. merge=False: replace.
    """
    if not merge:
        DEFAULT_TOOL_CLASSIFICATIONS.clear()
    DEFAULT_TOOL_CLASSIFICATIONS.update(catalog or {})


# ── Helpers ──────────────────────────────────────────────────────────────


def classify_tool(tool_name: str) -> list[str]:
    """Return the data classes a tool is known to handle. Empty if unknown.

    Best-effort and conservative — `[]` means "unclassified", NOT
    "definitely safe". UIs should distinguish the two.
    """
    return list(DEFAULT_TOOL_CLASSIFICATIONS.get(tool_name, []))


def infer_data_classes(tools: list[str]) -> list[str]:
    """Union of data classes across a tool list, sorted by sensitivity DESC.

    Useful when an agent definition doesn't carry an explicit
    `data_classes` field — call this against its `tools` to get a best
    guess.
    """
    seen: set[str] = set()
    for t in tools or []:
        for c in classify_tool(t):
            if c in DATA_CLASSES:
                seen.add(c)
    # Sort by weight descending so callers can take [0] = most sensitive
    return sorted(seen, key=lambda c: -CLASS_WEIGHTS.get(c, 0))


def sensitivity_weight(classes: list[str], weights: dict | None = None) -> int:
    """Compute a single risk delta for a set of data classes.

    Returns the MAX weight (not the sum) — handling PHI is what makes an
    agent high-stakes; touching internal + confidential + PHI doesn't
    triple-count. The cap is applied to keep total risk bounded.

    `weights` (optional, Round 11.1): explicit weight table to use for
    this evaluation. Defaults to the module-level `CLASS_WEIGHTS`. The
    risk scorer passes tenant-resolved weights here when a `tenant_id`
    is in scope.
    """
    if not classes:
        return 0
    table = weights if weights is not None else CLASS_WEIGHTS
    vals = [table.get(c, 0) for c in classes]
    return min(SENSITIVITY_CAP, max(vals))
