"""
Skills — first-class capability bundles.

Where `tools` lists the individual callables an agent can dispatch,
`skills` describes the **bundle-level** abstraction many frameworks use:

- Veldt's own skills.yaml (skill = reusable group of tools)
- Microsoft Semantic Kernel plugins (renamed from "skills")
- Anthropic Claude Skills
- HuggingFace Smol skill manifests
- Custom in-house skill registries

A skill can carry its OWN data classification + security caps that
apply at the bundle level. Three scenarios where this matters:

  1. "The `customer_lookup` skill handles PII as a group, even if
     the individual `query_db` and `redact_pii` tools inside don't."
  2. A tenant imports `weather_skill` v3 from a marketplace — lineage
     and version provenance attach to the SKILL, not each tool.
  3. Security sign-off happens on a skill bundle, not 12 individual
     tools — `review_status` lives at the skill level.

Design rules
------------
- Skills DO NOT replace tools. A skill expands INTO tools at dispatch
  time. KYA preserves the skill abstraction for audit + classification
  but still flattens to `tools` for the actual tool-level checks.
- Classification UNIONS: an agent that calls a `phi_handling` skill
  with tools `[get_record, redact]` is treated as PHI-handling even
  if neither tool name matches the classification catalog.
- Skills can be EITHER strings (just names) OR dicts (full spec).

Canonical Skill shape
---------------------
    {
      "name":           str,          # required — stable identifier
      "description":    str,
      "version":        str,
      "publisher":      str,          # first_party / vendor / marketplace / ...
      "tools":          list[str],    # individual tools this skill bundles
      "data_classes":   list[str],    # data classes the bundle handles
      "security_caps":  list[str],    # security capabilities the bundle grants
      "approved_at":    iso date,     # security signoff timestamp
      "approved_by":    str,
    }

Public API
----------
    normalize_skills(raw)                                  -> list[dict]
    flatten_to_tools(skills)                               -> list[str]
    infer_skill_classifications(skills) -> tuple[list, list]    (classes, caps)
    classify_skill(skill_name) -> tuple[list, list]
    set_skill_classifications(catalog, merge=True)
    DEFAULT_SKILL_CLASSIFICATIONS
"""

from typing import Any

# Default skill→classification catalog. Conservative — only marks
# classifications where there's strong evidence. Tenants extend via
# set_skill_classifications().
DEFAULT_SKILL_CLASSIFICATIONS: dict[str, dict] = {
    # Veldt's built-in skill groups
    "knowledge_search": {
        "data_classes": ["confidential"],
        "security_caps": [],
    },
    "decision_workflow": {
        "data_classes": ["internal"],
        "security_caps": [],
    },
    "schema_inspection": {
        "data_classes": ["confidential"],
        "security_caps": ["prod_database"],
    },
    "rule_authoring": {
        "data_classes": ["internal"],
        "security_caps": [],
    },
    "data_ingestion": {
        "data_classes": ["confidential"],
        "security_caps": ["network_egress", "prod_database"],
    },
    # Common external skill groups
    "customer_lookup": {
        "data_classes": ["pii"],
        "security_caps": ["prod_database"],
    },
    "billing_operations": {
        "data_classes": ["financial", "pii"],
        "security_caps": ["prod_database", "network_egress"],
    },
    "code_interpreter": {
        "data_classes": [],
        "security_caps": ["code_execution"],
    },
    "shell_runner": {
        "data_classes": [],
        "security_caps": ["shell_access"],
    },
    "web_research": {
        "data_classes": [],
        "security_caps": ["network_egress"],
    },
    "phi_handler": {
        "data_classes": ["phi"],
        "security_caps": ["prod_database"],
    },
    # Defense / federal common bundles
    "itar_doc_access": {
        "data_classes": ["itar", "cui"],
        "security_caps": ["prod_database"],
    },
    "classified_research": {
        "data_classes": ["classified"],
        "security_caps": [],
    },
}


def set_skill_classifications(catalog: dict, merge: bool = True) -> None:
    """Inject or replace skill classifications. `merge=True` (default)
    preserves built-in defaults."""
    if not merge:
        DEFAULT_SKILL_CLASSIFICATIONS.clear()
    DEFAULT_SKILL_CLASSIFICATIONS.update(catalog or {})


def normalize_skills(raw: Any) -> list[dict]:
    """Accept skills in either of two shapes and return a list of full dicts.

    Accepts:
      - list[str]              → [{"name": s} for s in raw]
      - list[dict]             → pass-through (with name normalization)
      - dict[name -> spec]     → expanded to list
      - None / empty           → []

    Always returns a list of dicts with `name` set.
    """
    if raw is None:
        return []
    if isinstance(raw, dict):
        # name->spec map
        return [
            (s if isinstance(s, dict) else {"name": k, "value": s}) | {"name": k}
            for k, s in raw.items()
        ]
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for item in raw:
        if isinstance(item, str):
            out.append({"name": item})
        elif isinstance(item, dict):
            if "name" in item:
                out.append(dict(item))
            elif "tool_name" in item:
                d = dict(item)
                d["name"] = d["tool_name"]
                out.append(d)
        else:
            # Object with .name attr (LangChain Skill-ish)
            name = getattr(item, "name", None)
            if name:
                out.append({"name": name})
    return out


def flatten_to_tools(skills: list[dict] | None) -> list[str]:
    """Pull the union of all tool names referenced inside each skill.

    Used by adapters to populate `tools` from `skills` when the caller
    only sent skill-level structure. Idempotent: if a skill has no
    `tools` field, it contributes nothing (the bundle is opaque).
    """
    out: list[str] = []
    seen: set[str] = set()
    for s in skills or []:
        if not isinstance(s, dict):
            continue
        for t in s.get("tools") or []:
            if isinstance(t, str) and t not in seen:
                seen.add(t)
                out.append(t)
            elif isinstance(t, dict):
                name = t.get("name") or t.get("tool_name")
                if name and name not in seen:
                    seen.add(name)
                    out.append(name)
    return out


def classify_skill(skill_name: str) -> tuple[list[str], list[str]]:
    """Return (data_classes, security_caps) declared for a skill name in
    the catalog. Empty lists if unknown."""
    entry = DEFAULT_SKILL_CLASSIFICATIONS.get(skill_name) or {}
    return (
        list(entry.get("data_classes") or []),
        list(entry.get("security_caps") or []),
    )


def infer_skill_classifications(
    skills: list[dict] | None,
) -> tuple[list[str], list[str]]:
    """Union data_classes + security_caps across a skill list.

    Resolution order per skill:
      1. Explicit `data_classes` / `security_caps` on the skill dict
         (caller's intent always wins)
      2. Catalog lookup by `name`
      3. Empty (no contribution)

    Returns deduplicated lists sorted by sensitivity (most-sensitive first
    for data classes — uses CLASS_WEIGHTS) so downstream consumers can
    take `[0]` as the worst.
    """
    classes: set[str] = set()
    caps: set[str] = set()
    for s in skills or []:
        if not isinstance(s, dict):
            continue
        # 1. Explicit on the skill
        for c in s.get("data_classes") or []:
            if isinstance(c, str):
                classes.add(c)
        for cap in s.get("security_caps") or []:
            if isinstance(cap, str):
                caps.add(cap)
        # 2. Catalog lookup
        name = s.get("name")
        if name:
            cat_classes, cat_caps = classify_skill(name)
            classes.update(cat_classes)
            caps.update(cat_caps)

    # Sort data classes by sensitivity DESC (caller wants worst first)
    try:
        from .data_classes import CLASS_WEIGHTS

        sorted_classes = sorted(classes, key=lambda c: -CLASS_WEIGHTS.get(c, 0))
    except ImportError:
        sorted_classes = sorted(classes)

    # Sort caps by weight DESC
    try:
        from .security_caps import CAPABILITY_WEIGHTS

        sorted_caps = sorted(caps, key=lambda c: -CAPABILITY_WEIGHTS.get(c, 0))
    except ImportError:
        sorted_caps = sorted(caps)

    return sorted_classes, sorted_caps
