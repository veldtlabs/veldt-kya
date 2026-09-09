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
  refused_rate = refused_outcomes / total_invocations
  blocked_rate = blocked_outcomes / total_invocations
  error_rate   = error_outcomes   / total_invocations

  divergence_score (0..1) = min(1.0,
      refused_rate * 1.5 + blocked_rate * 1.5 + error_rate * 0.5
  )

Refusals and blocks weigh more than errors because they mean governance
had to step in. A rogue-signal term is reserved (`signal_component`) and
contributes zero today; mixing it in is future work.

Interpretation
--------------
divergence_score < 0.1    → governance rarely intervened
divergence_score 0.1..0.3 → mixed; some invocations were stopped
divergence_score > 0.3    → governance intervened often; a reason to look
                            at the agent, not a finding about cause

Limitations
-----------
A rate of governance intervention, not an attribution:

  * No delegation lineage. `parent_invocation_id` is on the same rows and
    is not read, so a delegate acting on its own and one carrying out what
    it was asked score the same — and the delegate, being the one refused,
    carries the score wherever the fault began.
  * Rises with enforcement strength. `refused` and `blocked` are outcomes
    of your policy, so tightening it raises every agent's score.
  * Saturates early: blocked on >20% of invocations reaches
    `agent_misbehavior`; 1.0 at 67%.

Separating cause from position in a chain needs a different method, not
different weights.

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
    # Text describes what was measured, not a cause. See Limitations.
    if score < _T_LOW:
        return "intentional", (
            "Governance rarely intervened against this agent; its "
            "invocations mostly completed. Nothing here argues against "
            "including the user in attribution."
        )
    if score < _T_MID:
        return "mixed", (
            "Governance intervened on some of this agent's invocations "
            "and not others. Investigate the specific incident — this "
            "rate does not identify a cause."
        )
    return "agent_misbehavior", (
        "Governance intervened on a large share of this agent's "
        "invocations. That is a reason to examine the agent, not a "
        "finding that it is the root cause: the rate is also raised by "
        "strict policy, and it does not distinguish an agent acting on "
        "its own from one doing what it was asked."
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
    # Windowed on COALESCE(started_at, occurred_at): `started_at` is
    # optional, so filtering on it alone hid every row that omitted it.
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
                      AND COALESCE(started_at, occurred_at)
                          >= now() - (:days || ' days')::interval
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
                      AND COALESCE(started_at, occurred_at) >= :cutoff
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
