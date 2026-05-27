"""
Request-level rollup — Priority 2.

When CrewAI fires three agents in parallel under one user request, today
KYA tracks each agent's invocation individually but offers no "request"
abstraction. SOC analysts want to ask:

    "Which requests in the last hour resulted in at least one critical
     rogue event?"
    "What % of requests this week had a leak somewhere in the fan-out?"
    "Which users initiated the most multi-leak request trees?"

The data is already there in `kya_invocations` (Round 13.4): every
invocation under one logical request shares a `correlation_id`. This
module aggregates by correlation_id to produce per-request summaries.

Public API
----------
    summarize_request(db, tenant_id, correlation_id) -> RequestSummary
    list_recent_requests(db, tenant_id, since=None, worst_outcome_at_least=None, limit=100)
    request_score(summary) -> int          # 0..100, single number per request

Pure SQL — no streaming computation, no maintenance daemon. Each query
walks the rows for one correlation_id (or a windowed slice) and returns
the rolled-up view. The `kya_invocations` table is indexed on
correlation_id (Round 13.4 already added the index).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

try:
    from sqlalchemy import text as _sa_text

    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False

    def _sa_text(s):
        raise RuntimeError(
            "kya.requests requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


text = _sa_text

logger = logging.getLogger(__name__)


# Outcome severity ranking — used to compute "worst_outcome" across the
# fan-out. Higher value = worse outcome. (Mirrors the operator's mental
# model: "blocked" is worse than "error" because it implies an intentional
# bad action that governance had to catch.)
_OUTCOME_SEVERITY = {
    "success": 0,
    "partial": 1,
    "in_progress": 1,
    "error": 2,
    "refused": 3,
    "blocked": 4,
}


@dataclass
class RequestSummary:
    """Rolled-up view of one request tree (all invocations under one
    correlation_id)."""

    correlation_id: str
    tenant_id: str
    total_invocations: int = 0
    unique_agents: list[str] = field(default_factory=list)
    principals: list[dict] = field(default_factory=list)  # [{kind,id}]
    started_at: str | None = None
    ended_at: str | None = None
    total_duration_ms: int = 0
    worst_outcome: str = "success"
    outcomes: dict = field(default_factory=dict)  # outcome → count
    modes: dict = field(default_factory=dict)  # mode → count
    parallel_count: int = 0  # how many top-level siblings
    has_in_progress: bool = False

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "tenant_id": self.tenant_id,
            "total_invocations": self.total_invocations,
            "unique_agents": self.unique_agents,
            "principals": self.principals,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "total_duration_ms": self.total_duration_ms,
            "worst_outcome": self.worst_outcome,
            "outcomes": self.outcomes,
            "modes": self.modes,
            "parallel_count": self.parallel_count,
            "has_in_progress": self.has_in_progress,
        }


def summarize_request(db, tenant_id: str, correlation_id: str) -> RequestSummary:
    """Aggregate all invocations under one correlation_id.

    Returns a RequestSummary with empty defaults if no rows match (caller
    can distinguish via total_invocations == 0).
    """
    from ._portable import qual_for_raw_sql
    qual = qual_for_raw_sql(db)
    rows = db.execute(
        text(f"""
            SELECT id, agent_key, principal_kind, principal_id,
                   mode, outcome, duration_ms,
                   parent_invocation_id,
                   started_at, ended_at
            FROM {qual}kya_invocations
            WHERE tenant_id = :tid AND correlation_id = :cid
            ORDER BY started_at ASC
        """),
        {"tid": tenant_id, "cid": correlation_id},
    ).fetchall()

    summary = RequestSummary(correlation_id=correlation_id, tenant_id=tenant_id)
    if not rows:
        return summary

    agent_set: set[str] = set()
    principal_set: set[tuple[str, str]] = set()
    outcomes: dict = {}
    modes: dict = {}
    worst_severity = -1
    worst_outcome = "success"
    top_level_count = 0

    for r in rows:
        summary.total_invocations += 1
        agent_set.add(r[1])
        if r[2] and r[3]:
            principal_set.add((r[2], r[3]))
        mode = r[4]
        outcome = r[5]
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        modes[mode] = modes.get(mode, 0) + 1
        dur = r[6]
        if dur is not None:
            summary.total_duration_ms += int(dur)
        if r[7] is None:
            top_level_count += 1
        sev = _OUTCOME_SEVERITY.get(outcome, 0)
        if sev > worst_severity:
            worst_severity = sev
            worst_outcome = outcome
        if outcome == "in_progress":
            summary.has_in_progress = True
        # SQLite + MySQL return TIMESTAMP columns as strings; PG
        # returns datetime objects. Normalize via _iso() so both
        # shapes work without per-dialect branching.
        s8 = (r[8].isoformat() if r[8] and hasattr(r[8], "isoformat")
              else (str(r[8]) if r[8] else None))
        s9 = (r[9].isoformat() if r[9] and hasattr(r[9], "isoformat")
              else (str(r[9]) if r[9] else None))
        if s8 and (summary.started_at is None or s8 < summary.started_at):
            summary.started_at = s8
        if s9 and (summary.ended_at is None or s9 > summary.ended_at):
            summary.ended_at = s9

    summary.unique_agents = sorted(agent_set)
    summary.principals = [{"kind": k, "id": i} for (k, i) in sorted(principal_set)]
    summary.outcomes = outcomes
    summary.modes = modes
    summary.worst_outcome = worst_outcome
    summary.parallel_count = top_level_count
    return summary


def list_recent_requests(
    db,
    tenant_id: str,
    since: datetime | None = None,
    worst_outcome_at_least: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Recent requests sorted by start time (newest first).

    `since` defaults to 24 hours ago. `worst_outcome_at_least` filters
    requests whose worst outcome is at LEAST as severe as the given
    outcome — handy for "only show me requests that had a blocked or
    refused outcome anywhere in the tree."
    """
    if since is None:
        since = datetime.now(timezone.utc) - timedelta(hours=24)

    # Pull distinct correlation_ids in the window. This is a small query
    # because correlation_id has an index and we limit results.
    from ._portable import qual_for_raw_sql
    qual = qual_for_raw_sql(db)
    rows = db.execute(
        text(f"""
            SELECT DISTINCT correlation_id
            FROM {qual}kya_invocations
            WHERE tenant_id = :tid
              AND correlation_id IS NOT NULL
              AND started_at >= :since
            ORDER BY correlation_id DESC
            LIMIT :lim
        """),
        {"tid": tenant_id, "since": since, "lim": limit},
    ).fetchall()

    out: list[dict] = []
    min_severity = (
        _OUTCOME_SEVERITY.get(worst_outcome_at_least or "", 0) if worst_outcome_at_least else None
    )
    for r in rows:
        cid = str(r[0]) if r[0] else None
        if not cid:
            continue
        summary = summarize_request(db, tenant_id, cid)
        if min_severity is not None:
            sev = _OUTCOME_SEVERITY.get(summary.worst_outcome, 0)
            if sev < min_severity:
                continue
        out.append(summary.to_dict())
    # Resort by started_at DESC (the DISTINCT query couldn't order by
    # started_at because the GROUP BY wouldn't allow it without aggregation)
    out.sort(key=lambda x: x.get("started_at") or "", reverse=True)
    return out


# ── Request scoring (a single number per request) ────────────────────────

# How much each component contributes. Calibration choices — tunable.
_PER_OUTCOME_DELTA = {
    "success": 0,
    "partial": 2,
    "in_progress": 0,
    "error": 5,
    "refused": 8,
    "blocked": 15,
}
_PER_AGENT_BREADTH = 2  # additional agents amplify (fan-out attack pattern)
_REQUEST_SCORE_CAP = 100


def request_score(summary: RequestSummary | dict) -> int:
    """Compute a 0..100 request-level threat score from the summary.

    The score reflects "how concerning is this request as a whole?"
      * Each non-success outcome contributes weight by severity
      * Fan-out (many agents) amplifies — a leak across 5 agents is
        worse than a leak in one
      * Capped at 100
    """
    if isinstance(summary, RequestSummary):
        summary = summary.to_dict()
    score = 0
    outcomes = summary.get("outcomes") or {}
    for outcome, count in outcomes.items():
        delta = _PER_OUTCOME_DELTA.get(outcome, 0)
        score += delta * int(count)
    # Fan-out premium — only when there's at least one non-success outcome
    agents = len(summary.get("unique_agents") or [])
    has_bad = any(o != "success" for o in outcomes)
    if has_bad and agents > 1:
        score += (agents - 1) * _PER_AGENT_BREADTH
    return min(_REQUEST_SCORE_CAP, score)
