"""
Agent Risk Scoring — pure function module.

Computes a 0-100 risk score for an agent definition based on:
  - Write-tool count (highest signal — write tools mutate state)
  - Admin-restricted tool count (rule_admin / governance_admin gated tools)
  - Governance mode (none = autonomous = high risk; in_the_loop = low)
  - can_override / can_revert flags
  - access_level (read vs write)
  - Sandbox discount (newly-created agents start lower-risk by default)

No DB / HTTP dependencies — pure function. Reusable from the API layer,
tests, CLI tools, or batch scoring jobs.

Public API
----------
    score_agent(agent_def: dict) -> AgentRiskScore
    bucket_for(score: int) -> str  ("low" | "medium" | "high" | "critical")
    is_write_tool(tool_name: str) -> bool
    is_admin_tool(tool_name: str) -> bool

Score buckets:
    0–29   → low
    30–59  → medium
    60–84  → high
    85–100 → critical
"""

from dataclasses import dataclass, field

from .blast_radius import blast_radius_breakdown
from .cost import cost_burn_weight
from .data_classes import CLASS_WEIGHTS, infer_data_classes, sensitivity_weight
from .delegation import delegation_weight, max_delegation_depth
from .delegation_trust import delegation_trust_weight
from .deployment import deployment_weight
from .input_sources import input_source_weight
from .interactions import interaction_multiplier
from .lifecycle import approval_weight, lifecycle_weight, ownership_weight
from .security_caps import CAPABILITY_WEIGHTS, capability_weight, infer_capabilities
from .skills import infer_skill_classifications
from .supply_chain import supply_chain_weight
from .trust_signals import citation_weight, trust_score_weight

# Provenance — where did this agent come from? Same definition is a
# different risk depending on whether you wrote it, downloaded it from a
# marketplace, or imported it from a partner.
_PROVENANCE_WEIGHTS = {
    "builtin": 0,  # ships with Veldt — audited code-path
    "custom": 5,  # tenant authored — they own it
    "imported": 10,  # imported from a partner / inter-tenant
    "marketplace": 15,  # downloaded from public marketplace
    "third_party": 20,  # explicit untrusted third party
    "unknown": 10,  # default — conservative
}

# Model trust — frontier+hosted vs. self-hosted/unknown is a real risk
# delta. Same prompts on different models = different rate of
# misbehavior. Weights are small because model risk is partly captured
# by hallucination rate in dynamic signals.
_MODEL_TRUST_WEIGHTS = {
    "enterprise": 0,  # MSA, BAA, DPA in place
    "frontier": 3,  # claude / gpt-4 / gemini — known, audited
    "open": 8,  # known open-weight model running on trusted infra
    "self_hosted": 10,  # tenant-controlled inference — opaque to KYA
    "unknown": 10,
}

# Tool catalog — maps tool_name -> required roles. KYA optionally consumes
# Veldt's tool_rbac module so we can flag admin-gated tools accurately.
# When Veldt isn't present (standalone use / pip package), the catalog
# falls back to an empty dict and is_admin_tool returns False — pure
# write/read heuristics still apply.
try:
    from agents.tool_rbac import TOOL_ROLE_REQUIREMENTS as _DEFAULT_CATALOG
except ImportError:
    _DEFAULT_CATALOG: dict = {}

# Public mutable handle — callers can inject their own catalog at runtime
# via `set_tool_catalog()` for full pluggability without re-importing.
TOOL_ROLE_REQUIREMENTS = dict(_DEFAULT_CATALOG)


def set_tool_catalog(catalog: dict) -> None:
    """Replace the in-process tool catalog used by is_admin_tool / scoring.

    Callers in non-Veldt environments should pass their own mapping of
    tool_name -> list[role_name]. KYA only reads it; the catalog is
    advisory (write detection still falls back to name prefixes).
    """
    TOOL_ROLE_REQUIREMENTS.clear()
    TOOL_ROLE_REQUIREMENTS.update(catalog or {})


# ── Tool classification (read vs write, admin vs non-admin) ──────────────

# Name prefixes that imply mutation. Used as a fallback for tools that
# aren't in TOOL_ROLE_REQUIREMENTS (which contains most write tools but
# isn't exhaustive). Read tools (search_, list_, get_, explain_, render_,
# detect_, find_, query_, analyze_, forecast_, predict_, etc.) are
# treated as zero-risk for the write-tool count.
_WRITE_PREFIXES = (
    "create_",
    "delete_",
    "update_",
    "generate_",
    "merge_",
    "override_",
    "revert_",
    "ingest_",
    "execute_",
    "compile_",
    "connect_",
    "test_",
    "record_",
    "manage_",
    "set_",
    "save_",
    "publish_",
    "ack_",
    "acknowledge_",
    "approve_",
    "reject_",
    "deactivate_",
    "suspend_",
    "reactivate_",
    "remove_",
)

# Roles that imply elevated authority — tools requiring these are high
# risk to grant via an agent.
_ADMIN_ROLES = frozenset({"rule_admin", "governance_admin"})


def is_write_tool(tool_name: str) -> bool:
    """True if the tool is a known write/mutation tool.

    Decision order:
      1. Tool is in TOOL_ROLE_REQUIREMENTS → yes (every gated tool is a
         write tool by construction — pure reads aren't gated).
      2. Name has a write-prefix (create_, delete_, etc.) → yes.
      3. Otherwise → no.
    """
    if not tool_name:
        return False
    if tool_name in TOOL_ROLE_REQUIREMENTS:
        return True
    return tool_name.startswith(_WRITE_PREFIXES)


def is_admin_tool(tool_name: str) -> bool:
    """True if the tool requires an admin role (rule_admin or governance_admin)."""
    required = TOOL_ROLE_REQUIREMENTS.get(tool_name, [])
    return any(r in _ADMIN_ROLES for r in required)


# ── Scoring ──────────────────────────────────────────────────────────────

# Score weights — chosen so a "typical" agent (5 tools, hybrid governance,
# no override/revert) lands around 25-40 (low-to-medium), while an
# autonomous agent with several write tools + override authority pushes
# 70+ (high). Tunable via env if needed later; constants for now.
_BASE = 5
_PER_WRITE_TOOL = 4  # +4 per write/mutation tool
_PER_ADMIN_TOOL = 8  # +8 per admin-restricted tool (in addition to write penalty)
_HUMAN_LOOP_WEIGHTS = {
    "none": 30,  # fully autonomous → highest risk
    "on_the_loop": 15,  # acts + notifies → medium
    "hybrid": 10,  # mixed — reads free, writes gated
    "in_the_loop": 0,  # every action gated → lowest
}
_CAN_OVERRIDE = 12  # +12 if can_override=True
_CAN_REVERT = 8  # +8 if can_revert=True
_ACCESS_WRITE = 6  # +6 if access_level="write"


@dataclass
class RiskFactor:
    """A single contributor to the risk score, surfaced in the breakdown."""

    name: str  # e.g. "write_tools" — stable id for UI/audit
    label: str  # human-readable, e.g. "3 write tools"
    delta: int  # signed contribution to the score


@dataclass
class AgentRiskScore:
    score: int  # 0–100 (clamped)
    bucket: str  # "low" | "medium" | "high" | "critical"
    factors: list[RiskFactor] = field(default_factory=list)
    write_tool_count: int = 0
    admin_tool_count: int = 0
    data_classes: list[str] = field(default_factory=list)  # most-sensitive first
    max_sensitivity: str = "public"  # highest class name
    security_caps: list[str] = field(default_factory=list)  # capabilities, most-risky first
    provenance: str = "unknown"  # builtin / custom / imported / ...
    model_trust: str = "unknown"  # enterprise / frontier / open / ...
    delegation_depth: int = 0  # max hops in can_delegate_to chain
    additive_score: int = 0  # score before interaction multipliers
    interaction_multiplier: float = 1.0  # capped product of fired interactions
    interactions: list[dict] = field(default_factory=list)  # which interactions fired
    delegation_trust_evidence: list[dict] = field(
        default_factory=list
    )  # risky delegates (Round 13.3)
    # Two-axis view (PYPI task #9, "Option E" minimum-blast-radius):
    # surface concentration + overrun alongside the existing single
    # 0-100 score so consumers can distinguish "additive at ceiling
    # with strong concentration" from "additive at ceiling, no
    # concentration." score/bucket semantics unchanged.
    concentration: float = 1.0   # alias for interaction_multiplier with clearer semantics
    overrun: int = 0             # how much the 0-100 score clamp suppressed (additive * multiplier - 100, floored at 0)


def bucket_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def score_agent(
    agent_def: dict,
    all_agents: dict[str, dict] | None = None,
    db=None,
    tenant_id: str | None = None,
) -> AgentRiskScore:
    """Score a single agent. Pure function (with optional DB resolution).

    The agent_def dict shape mirrors what skills.yaml + custom_agents
    produce: keys consulted are `tools`, `human_loop`, `can_override`,
    `can_revert`, `access_level`. Missing fields are treated
    conservatively (most-permissive interpretation = highest risk).

    `all_agents` is an optional dict of {agent_key: definition} used
    to compute delegation depth.

    `db` + `tenant_id` (Round 11.1): when both are supplied, the
    sensitivity / capability / source / deployment weight tables are
    resolved with that tenant's overrides layered on top of the
    platform default. Without them, the in-process module defaults
    are used (existing behavior — SDK / standalone callers unchanged).
    """
    # Resolve tenant-scoped weight overrides (Round 11.1)
    _class_weights = None
    _capability_weights = None
    _source_weights = None
    _deployment_weights = None
    if db is not None:
        try:
            from .tenant_weights import get_effective_weights

            _class_weights = get_effective_weights(db, "class_weights", tenant_id)
            _capability_weights = get_effective_weights(db, "capability_weights", tenant_id)
            _source_weights = get_effective_weights(db, "source_weights", tenant_id)
            _deployment_weights = get_effective_weights(db, "deployment_weights", tenant_id)
        except Exception:
            # If the table doesn't exist yet or DB hiccups, fall back to
            # in-process defaults — scoring must never break.
            #
            # CRITICAL: roll back the session so PG doesn't leave us in
            # an aborted-transaction state. Without this, every
            # subsequent DB op in the same session fails with
            # `psycopg2.errors.InFailedSqlTransaction` until manual
            # rollback -- which a caller assembling a regulator pack
            # (score_agent + record_invocation + freeze_snapshot in
            # one Session) has no idea to do.
            try:
                db.rollback()
            except Exception:
                pass
    # Defensive coercion — a caller may pass tools as a string by mistake.
    # Iterate-as-list-of-strings; reject non-iterables.
    raw_tools = agent_def.get("tools") or []
    if isinstance(raw_tools, str):
        # Treat a single string as a one-element list rather than iterating chars.
        raw_tools = [raw_tools]
    try:
        tools: list[str] = [t for t in raw_tools if isinstance(t, str)]
    except TypeError:
        tools = []
    human_loop = (agent_def.get("human_loop") or "none").strip().lower()
    can_override = bool(agent_def.get("can_override", False))
    can_revert = bool(agent_def.get("can_revert", False))
    access_level = (agent_def.get("access_level") or "write").strip().lower()
    # Skills (Round 12) — union skill-level data classes / security caps
    # into the inference so a skill-bundle classification flows through
    # even when individual tool names aren't in the catalog.
    skills_input = agent_def.get("skills") or []
    skill_classes, skill_caps = infer_skill_classifications(skills_input)

    # Data classes — caller can declare explicitly via agent_def["data_classes"];
    # otherwise infer from the tool list AND skill bundles. Explicit
    # declaration wins (allows tenants to override when they know better).
    declared_classes = agent_def.get("data_classes")
    if declared_classes is not None:
        data_classes = list(declared_classes)
    else:
        tool_classes = set(infer_data_classes(list(tools)))
        tool_classes.update(skill_classes)
        # Re-sort by sensitivity DESC
        data_classes = sorted(tool_classes, key=lambda c: -CLASS_WEIGHTS.get(c, 0))

    factors: list[RiskFactor] = []
    score = _BASE
    factors.append(RiskFactor("base", "Base score", _BASE))

    # --- Tool-driven risk -----------------------------------------------
    write_count = sum(1 for t in tools if is_write_tool(t))
    admin_count = sum(1 for t in tools if is_admin_tool(t))
    if write_count:
        d = write_count * _PER_WRITE_TOOL
        score += d
        factors.append(
            RiskFactor(
                "write_tools",
                f"{write_count} write tool{'s' if write_count != 1 else ''}",
                d,
            )
        )
    if admin_count:
        d = admin_count * _PER_ADMIN_TOOL
        score += d
        factors.append(
            RiskFactor(
                "admin_tools",
                f"{admin_count} admin-gated tool{'s' if admin_count != 1 else ''}",
                d,
            )
        )

    # --- Governance mode -------------------------------------------------
    loop_weight = _HUMAN_LOOP_WEIGHTS.get(human_loop, _HUMAN_LOOP_WEIGHTS["none"])
    score += loop_weight
    factors.append(
        RiskFactor(
            "governance_mode",
            f"human_loop={human_loop}",
            loop_weight,
        )
    )

    # --- Override / revert authority -------------------------------------
    if can_override:
        score += _CAN_OVERRIDE
        factors.append(RiskFactor("can_override", "can override decisions", _CAN_OVERRIDE))
    if can_revert:
        score += _CAN_REVERT
        factors.append(RiskFactor("can_revert", "can revert decisions", _CAN_REVERT))

    # --- Access level ----------------------------------------------------
    if access_level == "write":
        score += _ACCESS_WRITE
        factors.append(RiskFactor("access_write", "access_level=write", _ACCESS_WRITE))

    # --- Data sensitivity ------------------------------------------------
    # Take the MAX-weight class as the contribution (not the sum) — see
    # data_classes.sensitivity_weight for rationale.
    sens_delta = sensitivity_weight(data_classes)
    max_class = data_classes[0] if data_classes else "public"
    if sens_delta > 0:
        score += sens_delta
        factors.append(
            RiskFactor(
                "data_sensitivity",
                f"handles {max_class}"
                + (f" (+{len(data_classes) - 1} other class)" if len(data_classes) > 1 else ""),
                sens_delta,
            )
        )

    # --- Security capabilities -------------------------------------------
    # Capabilities SUM up to a cap (code_exec + shell_access really is
    # worse than either alone). Caller can declare via
    # agent_def["security_caps"], else infer from the tool catalog +
    # skill bundles (Round 12).
    declared_caps = agent_def.get("security_caps")
    if declared_caps is not None:
        sec_caps = list(declared_caps)
    else:
        cap_set = set(infer_capabilities(list(tools)))
        cap_set.update(skill_caps)
        sec_caps = sorted(cap_set, key=lambda c: -CAPABILITY_WEIGHTS.get(c, 0))
    cap_delta = capability_weight(sec_caps)
    if cap_delta > 0:
        score += cap_delta
        worst = sec_caps[0] if sec_caps else ""
        factors.append(
            RiskFactor(
                "security_caps",
                f"capabilities: {worst}"
                + (f" + {len(sec_caps) - 1} more" if len(sec_caps) > 1 else ""),
                cap_delta,
            )
        )

    # --- Provenance ------------------------------------------------------
    # The same definition imported from a public marketplace is a higher
    # risk than one a tenant authored locally. Provenance is a free input
    # — KYA doesn't try to verify it cryptographically here (that's
    # attestation's job downstream).
    prov = (agent_def.get("provenance") or "unknown").strip().lower()
    prov_delta = _PROVENANCE_WEIGHTS.get(prov, _PROVENANCE_WEIGHTS["unknown"])
    if prov_delta > 0:
        score += prov_delta
        factors.append(RiskFactor("provenance", f"provenance={prov}", prov_delta))

    # --- Model trust -----------------------------------------------------
    mt = (agent_def.get("model_trust") or "unknown").strip().lower()
    mt_delta = _MODEL_TRUST_WEIGHTS.get(mt, _MODEL_TRUST_WEIGHTS["unknown"])
    if mt_delta > 0:
        score += mt_delta
        factors.append(RiskFactor("model_trust", f"model_trust={mt}", mt_delta))

    # --- Delegation depth -----------------------------------------------
    # Agents that can fan out to other agents compound risk. Depth is
    # capped, and the depth factor only fires when there's an actual chain.
    if all_agents is not None:
        delegation_depth = max_delegation_depth(agent_def, all_agents)
    else:
        delegation_depth = len(agent_def.get("can_delegate_to") or [])
    deleg_delta = delegation_weight(delegation_depth)
    if deleg_delta > 0:
        score += deleg_delta
        factors.append(
            RiskFactor(
                "delegation_depth",
                f"delegation_depth={delegation_depth}",
                deleg_delta,
            )
        )

    # --- Blast radius ---------------------------------------------------
    br = blast_radius_breakdown(agent_def)
    if br.score > 0:
        score += br.score
        # Surface the biggest component as the factor label
        top = br.components[0] if br.components else {"label": "amplified"}
        factors.append(
            RiskFactor(
                "blast_radius",
                f"blast_radius: {top['label']}",
                br.score,
            )
        )

    # --- Input sources --------------------------------------------------
    # WHERE the agent ingests from. Untrusted sources (user uploads,
    # arbitrary web fetches) materially raise prompt-injection + data-
    # poisoning risk. See input_sources.py.
    isources = agent_def.get("input_sources") or []
    isrc_delta = input_source_weight(isources) if isources else 0
    if isrc_delta > 0:
        worst = isources[0] if isources else "unknown"
        factors.append(
            RiskFactor(
                "input_sources",
                f"input_sources: {worst}"
                + (f" + {len(isources) - 1} more" if len(isources) > 1 else ""),
                isrc_delta,
            )
        )
        score += isrc_delta

    # --- Round 13.3: delegation_trust ----------------------------------
    # Penalty for delegating to agents that have low principal trust.
    # Requires a DB session — silently 0 for SDK-only scoring.
    delegation_trust_evidence: list[dict] = []
    if db is not None:
        try:
            dt_delta, dt_label, dt_evidence = delegation_trust_weight(
                db,
                tenant_id or "",
                agent_def,
            )
            if dt_delta > 0:
                score += dt_delta
                factors.append(
                    RiskFactor(
                        "delegation_trust",
                        dt_label,
                        dt_delta,
                    )
                )
                delegation_trust_evidence = dt_evidence
        except Exception:
            pass

    # --- Round 8: lifecycle / supply chain / deployment / trust / cost --
    # Each helper returns (delta, label). Skip the factor when delta == 0.
    # Order matters for readability in the factor breakdown; positive
    # deltas first (risks), then negative (trust reductions).
    for name, fn in (
        ("ownership", ownership_weight),
        ("approval", approval_weight),
        ("lifecycle", lifecycle_weight),
        ("supply_chain", supply_chain_weight),
        ("deployment", deployment_weight),
        ("cost_burn", cost_burn_weight),
        ("citation", citation_weight),  # may be negative
        ("trust_audits", trust_score_weight),  # may be negative
    ):
        try:
            delta, label = fn(agent_def)
        except Exception:
            delta, label = 0, ""
        if delta != 0:
            score += delta
            factors.append(RiskFactor(name, label, delta))

    # Capture the additive score before applying interaction multipliers
    # (Round 11.2). Clamp once at the additive layer, again at the end.
    additive = max(0, min(100, score))

    # --- Round 11.2: interaction multipliers ----------------------------
    # Detect known-dangerous factor combos and multiply the score. Caller
    # can disable for backwards-compat via agent_def["disable_interactions"]=True.
    if not agent_def.get("disable_interactions"):
        mult, fired = interaction_multiplier(
            agent_def,
            factors=[{"name": f.name, "label": f.label, "delta": f.delta} for f in factors],
        )
    else:
        mult, fired = 1.0, []

    raw_with_mult = int(round(additive * mult))
    final_score = max(0, min(100, raw_with_mult))
    # Overrun captures how much the multiplier amplification was
    # absorbed by the 0-100 clamp. For saturated-additive agents
    # (e.g. additive=86, mult=1.95 → raw=168 → score=100), overrun=68
    # tells operators "this agent had concentration that pushed past
    # the ceiling" — invisible at the score/bucket level alone.
    overrun = max(0, raw_with_mult - 100)

    return AgentRiskScore(
        score=final_score,
        bucket=bucket_for(final_score),
        factors=factors,
        write_tool_count=write_count,
        admin_tool_count=admin_count,
        data_classes=data_classes,
        max_sensitivity=max_class,
        security_caps=sec_caps,
        provenance=prov,
        model_trust=mt,
        delegation_depth=delegation_depth,
        additive_score=additive,
        interaction_multiplier=mult,
        interactions=fired,
        delegation_trust_evidence=delegation_trust_evidence,
        concentration=mult,        # two-axis alias for interaction_multiplier
        overrun=overrun,           # suppressed-by-clamp amplification
    )
