"""
Lifecycle factors — ownership, approval status, time-in-production,
change cadence.

These are HUMAN-process signals that materially affect risk:

- **Ownership / on-call** (#18). Orphan agents are the #1 governance
  failure mode. When something misbehaves at 3 AM, somebody needs to be
  pageable. No owner = high risk by definition.

- **Approval / review status** (#19). SOC 2 CC1.4, ISO 27001 A.5.34,
  EU AI Act Art. 9 all require evidence that a human reviewed the agent.
  An unreviewed agent in production is a finding, not a deployment.

- **Time-in-production / change cadence** (#22). Brand-new agents are
  unknown-quality. Agents changing weekly are unstable. Both are risk
  premiums; the steady middle is the safe zone.

All inputs are FREE on the agent_def — KYA doesn't enforce them; it
weights what callers declare. Tenants who don't populate these will
default to the most conservative (highest-risk) interpretation.

Public API
----------
    ownership_weight(agent_def) -> tuple[int, str]
    approval_weight(agent_def) -> tuple[int, str]
    lifecycle_weight(agent_def) -> tuple[int, str]
    Each returns (delta, label) for inclusion in score_agent's factor list.
"""

from datetime import datetime, timezone

# ── Ownership / on-call (#18) ────────────────────────────────────────────


def _has_owner(agent_def: dict) -> bool:
    """Owner can be declared via any of: owner_user_id, owner_team,
    on_call, escalation_chain. ANY one of these = owned."""
    for k in ("owner_user_id", "owner_team", "on_call", "escalation_chain"):
        if agent_def.get(k):
            return True
    return False


def ownership_weight(agent_def: dict) -> tuple[int, str]:
    """+15 if the agent has NO declared owner. Owners get 0."""
    if _has_owner(agent_def):
        return 0, ""
    return 15, "no_owner: orphan agent (no owner/on_call/escalation declared)"


# ── Approval / review status (#19) ───────────────────────────────────────

# Review states:
#   "approved"       — explicit approval recorded
#   "pending"        — submitted, not yet reviewed
#   "rejected"       — rejected (shouldn't be in prod)
#   "expired"        — was approved but expired (annual re-review pattern)
#   None / "unknown" — never reviewed

_APPROVAL_WEIGHTS = {
    "approved": 0,
    "pending": 10,
    "rejected": 30,  # explicit rejection in prod = critical bug
    "expired": 20,
    "unknown": 15,  # never reviewed
}


def approval_weight(agent_def: dict) -> tuple[int, str]:
    """Weight based on review_status. Also checks review_expires_at to
    auto-expire if past due."""
    status = (agent_def.get("review_status") or "unknown").strip().lower()

    # Auto-expire: approved but past review_expires_at → "expired"
    if status == "approved":
        exp = agent_def.get("review_expires_at")
        if exp:
            try:
                exp_dt = (
                    exp
                    if isinstance(exp, datetime)
                    else datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                )
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < datetime.now(timezone.utc):
                    status = "expired"
            except (ValueError, TypeError):
                pass  # malformed date — leave status alone

    delta = _APPROVAL_WEIGHTS.get(status, _APPROVAL_WEIGHTS["unknown"])
    if delta == 0:
        return 0, ""
    return delta, f"review_status={status}"


# ── Time-in-production + change cadence (#22) ────────────────────────────

# Brand-new agents (<7 days in prod) carry an "unknown quality" premium.
# Agents changing very frequently (>10 changes in last 30 days) are
# unstable. Stable, mature agents (>30 days, low change) score 0.


def lifecycle_weight(agent_def: dict) -> tuple[int, str]:
    """+ premium for new agents AND for high-churn agents. The middle
    band (mature + stable) contributes 0."""
    deltas: list[tuple[int, str]] = []

    # Time-in-production
    deployed = agent_def.get("first_deployed_at") or agent_def.get("created_at")
    if deployed:
        try:
            dt = (
                deployed
                if isinstance(deployed, datetime)
                else datetime.fromisoformat(str(deployed).replace("Z", "+00:00"))
            )
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - dt).days
            if age_days < 7:
                deltas.append((8, f"new_agent ({age_days}d old)"))
            elif age_days < 30:
                deltas.append((3, f"young_agent ({age_days}d old)"))
        except (ValueError, TypeError):
            pass

    # Change cadence
    changes_30d = int(agent_def.get("changes_last_30d") or 0)
    if changes_30d >= 20:
        deltas.append((10, f"high_churn ({changes_30d} changes/30d)"))
    elif changes_30d >= 10:
        deltas.append((5, f"moderate_churn ({changes_30d} changes/30d)"))

    if not deltas:
        return 0, ""
    total = sum(d for d, _ in deltas)
    label = "; ".join(lbl for _, lbl in deltas)
    return total, label
