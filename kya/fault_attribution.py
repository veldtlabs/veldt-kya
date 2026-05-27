"""
Fault attribution heuristic — Priority 4.

Closes Gap A from the CrewAI design discussion. When agent B leaks data,
KYA today bumps the user AND the calling agent AND the leaking agent.
But sometimes the user asked something benign — the orchestrator
misinterpreted, or the delegate hallucinated, and the user shouldn't bear
the full penalty.

Computing "was it the user's fault?" is hard. Doing it WELL needs:
  - Embedding similarity between user input and agent output
  - LLM-judge evaluation of whether the action matched the request
  - Goal/plan tracking through multi-agent fan-out

This v1 ships a CONSERVATIVE primitive: a per-agent "intent divergence
rate" derived from existing signals. When the rate is high, KYA surfaces
it as a contextual signal that biases attribution AWAY from the user
when the operator investigates.

The score is observational only — it doesn't change trust deltas
automatically. Going further (LLM-judge, embedding compare) is future
work and lives behind a feature flag.

Heuristic logic
---------------
For each agent over the last N days:
  signal_rate = total_rogue_signals / total_invocations
  refused_rate = refused_outcomes / total_invocations
  blocked_rate = blocked_outcomes / total_invocations

  divergence_score (0..1) = clamp(
      signal_rate * 2 + refused_rate * 1.5 + blocked_rate * 1.5
  )

Interpretation
--------------
divergence_score < 0.1  → "looks intentional" — user-side blame is reasonable
divergence_score 0.1..0.3 → "mixed signals" — investigate both
divergence_score > 0.3  → "likely agent misbehavior" — bias attribution
                          toward the agent regardless of which user invoked

Public API
----------
    agent_divergence_score(db, tenant_id, agent_key, window_days=7) -> dict
"""

import logging
from dataclasses import dataclass

try:
    from sqlalchemy import text as _sa_text

    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False

    def _sa_text(s):
        raise RuntimeError(
            "kya.fault_attribution requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


text = _sa_text

logger = logging.getLogger(__name__)


@dataclass
class DivergenceReport:
    """Per-agent intent-divergence summary."""

    agent_key: str
    tenant_id: str
    window_days: int
    total_invocations: int = 0
    refused_count: int = 0
    blocked_count: int = 0
    error_count: int = 0
    divergence_score: float = 0.0
    classification: str = "insufficient_data"  # one of bucket strings below
    interpretation: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_key": self.agent_key,
            "tenant_id": self.tenant_id,
            "window_days": self.window_days,
            "total_invocations": self.total_invocations,
            "refused_count": self.refused_count,
            "blocked_count": self.blocked_count,
            "error_count": self.error_count,
            "divergence_score": round(self.divergence_score, 3),
            "classification": self.classification,
            "interpretation": self.interpretation,
        }


# Bucket thresholds calibrated to be CONSERVATIVE — easy to fall back on
# "insufficient data" or "looks intentional" when in doubt.
_MIN_SAMPLE_SIZE = 10  # need at least this many invocations to score
_T_LOW = 0.10  # below = looks intentional
_T_MID = 0.30  # mid = mixed signals
# Above _T_MID = likely agent misbehavior


def _classify(score: float, total: int) -> tuple[str, str]:
    if total < _MIN_SAMPLE_SIZE:
        return "insufficient_data", (
            f"Only {total} invocations in window — too few for confident "
            f"divergence classification (need {_MIN_SAMPLE_SIZE}+)."
        )
    if score < _T_LOW:
        return "intentional", (
            "Agent's actions consistently align with invocations — "
            "attribution can reasonably include the user."
        )
    if score < _T_MID:
        return "mixed", (
            "Mixed signals — some invocations diverged, some didn't. "
            "Investigate the specific incident before assigning blame."
        )
    return "agent_misbehavior", (
        "Agent diverges from user intent often. Bias attribution AWAY "
        "from the invoking user — the agent is the likely root cause."
    )


def agent_divergence_score(
    db,
    tenant_id: str,
    agent_key: str,
    window_days: int = 7,
) -> DivergenceReport:
    """Compute the agent's intent-divergence score from its invocation
    record over the last N days. Fail-soft: returns insufficient_data
    when the DB query errors or there's no data."""
    report = DivergenceReport(
        agent_key=agent_key,
        tenant_id=tenant_id,
        window_days=window_days,
    )
    from ._portable import qual_for_raw_sql
    qual = qual_for_raw_sql(db)
    # Dialect-aware query: PG keeps the single-statement FILTER + now()
    # interval. Non-PG uses portable CASE + parameterized cutoff (since
    # FILTER and `now() - interval` syntax are PG-specific).
    bind = db.get_bind() if hasattr(db, "get_bind") else db
    dialect = (bind.dialect.name
               if hasattr(bind, "dialect") else "unknown")
    try:
        if dialect == "postgresql":
            row = db.execute(
                text(f"""
                    SELECT
                        COUNT(*),
                        COUNT(*) FILTER (WHERE outcome = 'refused'),
                        COUNT(*) FILTER (WHERE outcome = 'blocked'),
                        COUNT(*) FILTER (WHERE outcome = 'error')
                    FROM {qual}kya_invocations
                    WHERE tenant_id = :tid AND agent_key = :agent
                      AND started_at >= now() - (:days || ' days')::interval
                """),
                {"tid": tenant_id, "agent": agent_key,
                 "days": str(window_days)},
            ).fetchone()
        else:
            # Portable across SQLite / MySQL / DuckDB: compute the
            # cutoff in Python and use CASE WHEN ... aggregation.
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(
                days=window_days)
            row = db.execute(
                text(f"""
                    SELECT
                        COUNT(*),
                        SUM(CASE WHEN outcome = 'refused' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN outcome = 'blocked' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN outcome = 'error' THEN 1 ELSE 0 END)
                    FROM {qual}kya_invocations
                    WHERE tenant_id = :tid AND agent_key = :agent
                      AND started_at >= :cutoff
                """),
                {"tid": tenant_id, "agent": agent_key,
                 "cutoff": cutoff},
            ).fetchone()
    except Exception as exc:
        logger.debug("[KYA-FAULT] divergence query failed: %s", exc)
        report.classification = "insufficient_data"
        report.interpretation = "DB error or table not yet populated."
        return report
    if not row:
        return report

    total = int(row[0] or 0)
    refused = int(row[1] or 0)
    blocked = int(row[2] or 0)
    errored = int(row[3] or 0)
    report.total_invocations = total
    report.refused_count = refused
    report.blocked_count = blocked
    report.error_count = errored

    if total == 0:
        report.classification = "insufficient_data"
        report.interpretation = "No invocations recorded in this window."
        return report

    # Compute the weighted divergence rate. Refusals and blocks weight
    # higher than errors because they imply governance had to step in —
    # the agent was about to do something it shouldn't.
    signal_component = 0.0  # placeholder for future rogue-signal mix-in
    refused_component = (refused / total) * 1.5
    blocked_component = (blocked / total) * 1.5
    error_component = (errored / total) * 0.5
    score = min(1.0, signal_component + refused_component + blocked_component + error_component)
    report.divergence_score = score

    cls, msg = _classify(score, total)
    report.classification = cls
    report.interpretation = msg
    return report
