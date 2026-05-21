"""
Blast radius — how MUCH damage can an agent do if it goes wrong?

Two agents with identical permissions can have very different blast
radii depending on:
  - Rate limit (10 calls/min vs. 10,000)
  - Cost ceiling (5 / month vs. 50,000)
  - User base size (one engineer vs. 50,000 customers)
  - Tenant count (single-tenant agent vs. multi-tenant platform agent)
  - Geographic scope (single region vs. global)

The product manager / security review should ALWAYS see this — the
right answer to "should this agent be deployed?" is often a function
of blast radius, not just permissions.

Public API
----------
    blast_radius_weight(agent_def) -> int  # 0..30 contribution
    BlastRadiusBreakdown                   # dataclass with explanation
"""

from dataclasses import dataclass, field

# Risk delta thresholds. Calibrated to keep blast radius from
# overpowering the rest of the score — it's an amplifier of existing
# risk, not a standalone signal.
_RATE_THRESHOLDS = [
    (10_000, 10, "rate_limit > 10k/min — fleet-scale"),
    (1_000, 6, "rate_limit > 1k/min — high-volume"),
    (100, 3, "rate_limit > 100/min — production"),
]
_COST_THRESHOLDS = [
    (50_000, 8, "cost_ceiling > $50k/mo — multi-tenant platform"),
    (10_000, 5, "cost_ceiling > $10k/mo — enterprise"),
    (1_000, 3, "cost_ceiling > $1k/mo — production"),
]
_USERBASE_THRESHOLDS = [
    (10_000, 8, "user_base > 10k — public-facing"),
    (1_000, 5, "user_base > 1k — broad internal"),
    (50, 3, "user_base > 50 — team-scale"),
]
_BR_CAP = 30


@dataclass
class BlastRadiusBreakdown:
    score: int = 0
    components: list[dict] = field(default_factory=list)
    rate_limit_per_min: int = 0
    cost_ceiling_usd: int = 0
    user_base_size: int = 0
    multi_tenant: bool = False
    geographic_scope: str = "single_region"

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "components": self.components,
            "rate_limit_per_min": self.rate_limit_per_min,
            "cost_ceiling_usd": self.cost_ceiling_usd,
            "user_base_size": self.user_base_size,
            "multi_tenant": self.multi_tenant,
            "geographic_scope": self.geographic_scope,
        }


def _bucket(value: float, thresholds: list[tuple[int, int, str]]) -> tuple[int, str]:
    """Return (delta, label) for the highest threshold value exceeds."""
    for threshold, delta, label in thresholds:
        if value >= threshold:
            return delta, label
    return 0, ""


def _safe_int(value, default: int = 0) -> int:
    """Coerce to int; non-numeric strings ("unlimited") fall back to default."""
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def blast_radius_breakdown(agent_def: dict) -> BlastRadiusBreakdown:
    """Compute the blast radius contribution.

    All inputs default to 0 (conservative — no amplification). Callers
    should populate from real operational data:
      - `rate_limit_per_min`: API gateway / Anthropic SDK setting
      - `cost_ceiling_usd`:   monthly budget (default 0 = unbounded)
      - `user_base_size`:     active users invoking this agent
      - `multi_tenant`:       True if this agent serves multiple tenants
      - `geographic_scope`:   single_region / multi_region / global

    Robust to type abuse: non-numeric strings ("unlimited") fall back to 0
    rather than raising — KYA must never break the request path.
    """
    br = BlastRadiusBreakdown(
        rate_limit_per_min=_safe_int(agent_def.get("rate_limit_per_min")),
        cost_ceiling_usd=_safe_int(agent_def.get("cost_ceiling_usd")),
        user_base_size=_safe_int(agent_def.get("user_base_size")),
        multi_tenant=bool(agent_def.get("multi_tenant") or False),
        geographic_scope=(agent_def.get("geographic_scope") or "single_region"),
    )

    score = 0
    for value, thresholds, name in [
        (br.rate_limit_per_min, _RATE_THRESHOLDS, "rate_limit"),
        (br.cost_ceiling_usd, _COST_THRESHOLDS, "cost_ceiling"),
        (br.user_base_size, _USERBASE_THRESHOLDS, "user_base"),
    ]:
        delta, label = _bucket(value, thresholds)
        if delta > 0:
            score += delta
            br.components.append({"name": name, "delta": delta, "label": label})

    if br.multi_tenant:
        score += 5
        br.components.append(
            {"name": "multi_tenant", "delta": 5, "label": "serves multiple tenants"}
        )
    if br.geographic_scope == "global":
        score += 4
        br.components.append({"name": "geographic_scope", "delta": 4, "label": "global scope"})
    elif br.geographic_scope == "multi_region":
        score += 2
        br.components.append({"name": "geographic_scope", "delta": 2, "label": "multi-region"})

    br.score = min(_BR_CAP, score)
    return br


def blast_radius_weight(agent_def: dict) -> int:
    """Convenience: just the integer delta for inclusion in risk.score_agent."""
    return blast_radius_breakdown(agent_def).score
