"""
External trust signals — red-team / bias / fairness scores + output
provenance.

These are signals KYA doesn't COMPUTE — they're produced by external
processes (red-team exercises, fairness audits, bias-test suites) and
declared on the agent_def. KYA reads them and weights the score.

#23 — Output provenance / citation
    Does the agent's responses cite sources? Required for EU AI Act
    Art. 13 transparency. Captured by:
        cites_sources       — bool, does the agent emit citations?
        citation_score      — 0..1, % of outputs that include citations
        reproducibility     — "deterministic" | "low_temp" | "stochastic"

#24 — Red-team / bias / fairness scores
    Inputs (all 0..1 where higher = more passed):
        red_team_score       — % of adversarial prompts handled correctly
        bias_score           — % bias tests passed
        fairness_score       — % fairness audits passed
        last_audit_at        — timestamp of latest audit
    Stale audits (>180 days) lose half their weight.

Calibration
-----------
Trust signals REDUCE risk (negative delta) when good — they prove the
agent has been tested. When MISSING they add risk premium because
"untested" is the riskiest state. When bad scores are present, the
premium grows linearly.

Public API
----------
    citation_weight(agent_def) -> tuple[int, str]
    trust_score_weight(agent_def) -> tuple[int, str]
"""

from datetime import datetime, timezone

# ── #23 Output provenance ────────────────────────────────────────────────


def citation_weight(agent_def: dict) -> tuple[int, str]:
    """Reward agents that cite sources; penalize those that don't.

    Returns negative delta (risk reduction) when explicit `cites_sources`
    is True; positive delta when it's False or the agent isn't deterministic.
    """
    cites = agent_def.get("cites_sources")
    cit_score = agent_def.get("citation_score")
    reproducibility = (agent_def.get("reproducibility") or "").strip().lower()

    if cites is True or (isinstance(cit_score, (int, float)) and cit_score >= 0.8):
        # Strong citation hygiene — small risk reduction
        return -3, f"cites_sources={'true' if cites is True else f'{cit_score:.0%}'}"
    if reproducibility == "deterministic":
        # Deterministic output is its own form of provenance
        return -2, "deterministic outputs"
    if cites is False:
        return 5, "cites_sources=false (AI Act Art. 13 transparency gap)"
    return 0, ""


# ── #24 Red-team / bias / fairness ───────────────────────────────────────

# Decay applied to audit scores when the last_audit_at is stale.
_AUDIT_STALE_DAYS = 180


def _audit_freshness_factor(agent_def: dict) -> float:
    """Returns 1.0 for fresh audits, 0.5 for stale (>180 days), 0.0 for
    none. Used to discount old test scores."""
    last = agent_def.get("last_audit_at")
    if not last:
        return 0.0
    try:
        dt = (
            last
            if isinstance(last, datetime)
            else datetime.fromisoformat(str(last).replace("Z", "+00:00"))
        )
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - dt).days
        if age_days <= _AUDIT_STALE_DAYS:
            return 1.0
        return 0.5
    except (ValueError, TypeError):
        return 0.0


def trust_score_weight(agent_def: dict) -> tuple[int, str]:
    """Returns risk delta from red-team + bias + fairness scores.

    Logic:
      - All three scores present + >= 0.8 + fresh audit → -6 (strong trust)
      - Mixed or older results → 0
      - Scores below 0.5 → +5 to +10 (proven failures)
      - No scores declared → +8 (untested)
    """
    rt = agent_def.get("red_team_score")
    bs = agent_def.get("bias_score")
    fs = agent_def.get("fairness_score")
    fresh = _audit_freshness_factor(agent_def)

    # Nothing declared
    if rt is None and bs is None and fs is None:
        return 8, "no red-team / bias / fairness audit results declared"

    # Worst score determines the premium for failed tests
    declared = [s for s in (rt, bs, fs) if isinstance(s, (int, float))]
    if not declared:
        return 8, "no usable audit scores declared"

    worst = min(declared)
    avg = sum(declared) / len(declared)

    # Failed tests
    if worst < 0.5:
        return int(10 * (1 - worst)), f"audit_failure (worst score {worst:.2f})"
    if worst < 0.7:
        return 5, f"audit_marginal (worst score {worst:.2f})"

    # Passing scores get a reduction proportional to freshness
    if avg >= 0.8:
        reduction = int(6 * fresh)
        if reduction == 0:
            return 4, "audits stale (>180d) — trust reduced"
        return -reduction, f"strong_audit_pass (avg {avg:.2f}, freshness {fresh:.0%})"

    return 0, f"audit_pass (avg {avg:.2f})"
