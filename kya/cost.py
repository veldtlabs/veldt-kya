"""
Cost burn / token budget (#25) — operational risk dimension.

An autonomous agent burning $1k/hr unattended is a real risk — both
financial (runaway cost) and behavioral (something is wrong, it's
looping or chained). Cost is also a leading indicator of misuse:
prompt-injection attacks often trigger expensive long-context bursts.

Inputs on agent_def
-------------------
    cost_last_24h_usd        — observed cost in last 24h (float)
    cost_last_1h_usd         — observed cost in last 1h (float)
    monthly_budget_usd       — declared monthly budget (int)
    token_budget_remaining   — 0..1, % of monthly budget left
    cost_anomaly_factor      — observed/expected ratio (1.0 = normal)

Calibration
-----------
- Bursts: cost_last_1h_usd > monthly_budget/720 (avg hourly burn) by >5×
  → high-risk burst signal (+10)
- Budget exhausted: token_budget_remaining < 0.1 → +6
- Cost anomaly factor: > 3× → +5, > 10× → +12
- No data: +0 (operator hasn't wired metrics, don't punish)

Public API
----------
    cost_burn_weight(agent_def) -> tuple[int, str]
"""

_COST_CAP = 15


def cost_burn_weight(agent_def: dict) -> tuple[int, str]:
    """Returns risk delta from cost-burn signals, capped at _COST_CAP."""
    monthly_budget = float(agent_def.get("monthly_budget_usd") or 0)
    cost_24h = float(agent_def.get("cost_last_24h_usd") or 0)
    cost_1h = float(agent_def.get("cost_last_1h_usd") or 0)
    remaining = agent_def.get("token_budget_remaining")
    anomaly = float(agent_def.get("cost_anomaly_factor") or 1.0)

    delta = 0
    reasons: list[str] = []

    # Hourly burst: observed 1h cost vs. averaged expected hourly cost
    if monthly_budget > 0 and cost_1h > 0:
        expected_hourly = monthly_budget / 720.0  # ~30d months
        if expected_hourly > 0 and cost_1h > 5 * expected_hourly:
            ratio = cost_1h / expected_hourly
            delta += 10
            reasons.append(f"cost_burst ({ratio:.1f}× hourly avg)")

    # Budget near-exhaustion — runaway risk
    if isinstance(remaining, (int, float)) and remaining < 0.1:
        delta += 6
        reasons.append(f"budget_remaining={remaining:.0%}")

    # Anomaly factor — observed/expected from caller's own model
    if anomaly >= 10:
        delta += 12
        reasons.append(f"cost_anomaly={anomaly:.1f}×")
    elif anomaly >= 3:
        delta += 5
        reasons.append(f"cost_anomaly={anomaly:.1f}×")

    # Absolute-spend signal: agents in $10k+/24h territory regardless of budget
    if cost_24h >= 10_000:
        delta += 8
        reasons.append(f"high_absolute_spend (${cost_24h:.0f}/24h)")

    delta = min(_COST_CAP, delta)
    if delta == 0:
        return 0, ""
    return delta, "; ".join(reasons)
