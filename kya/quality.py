"""
Quality signals — hallucination + answer relevance + injection susceptibility.

Where rogue signals capture POLICY violations (RBAC, governance, tenant),
quality signals capture CONTENT problems (the agent confabulated, the
answer missed the question, the input looked like a jailbreak attempt).

Phoenix integration (read-only)
-------------------------------
Phoenix evaluators run async on collected OTel traces. Their outputs are
stored in Phoenix's own datastore. KYA reads them via the Phoenix client
when available, and gracefully falls back to a heuristic Prometheus-only
signal when Phoenix isn't reachable (we keep counters of our own as a
fallback).

Public API
----------
    record_hallucination(agent_key, tenant_id, score=1.0)
    record_qa_irrelevance(agent_key, tenant_id, score=1.0)
    record_injection_attempt(agent_key, tenant_id, technique=None)
    get_quality_signals(agent_key) -> QualityReport
    quality_score(report) -> int   # 0..30 dynamic factor

Designed to feed the same factor-breakdown surface as other risk
dimensions — the card and score formulas don't need to know if it came
from Phoenix or our heuristic.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Counters we own (Phoenix may also exist; we keep our own so the signal
# is available even without Phoenix infrastructure).
_HALL_COUNTER = None
_QA_COUNTER = None
_INJ_COUNTER = None
_AGENT_CALLS = None  # Total agent invocations for rate computation


def _ensure_counters():
    global _HALL_COUNTER, _QA_COUNTER, _INJ_COUNTER, _AGENT_CALLS
    if all([_HALL_COUNTER, _QA_COUNTER, _INJ_COUNTER]):
        return
    try:
        from prometheus_client import REGISTRY, Counter

        def _get_or_create(name: str, desc: str, labels: list[str]):
            try:
                return Counter(name, desc, labels)
            except ValueError:
                return REGISTRY._names_to_collectors.get(name)

        if _HALL_COUNTER is None:
            _HALL_COUNTER = _get_or_create(
                "veldt_agent_hallucination_total",
                "Times an agent's output was flagged as hallucinated by an evaluator",
                ["agent_type", "tenant_id"],
            )
        if _QA_COUNTER is None:
            _QA_COUNTER = _get_or_create(
                "veldt_agent_qa_irrelevance_total",
                "Times an agent's answer was flagged as irrelevant to the question",
                ["agent_type", "tenant_id"],
            )
        if _INJ_COUNTER is None:
            _INJ_COUNTER = _get_or_create(
                "veldt_agent_injection_attempts_total",
                "Times an agent received an input flagged as a prompt-injection attempt",
                ["agent_type", "tenant_id", "technique"],
            )
    except ImportError:
        pass


# ── Recording helpers ────────────────────────────────────────────────────


def record_hallucination(agent_key: str, tenant_id: str = "", score: float = 1.0) -> None:
    """Record a hallucination event. `score` reserved for future weighted
    counts (e.g., partial-hallucination = 0.5)."""
    _ensure_counters()
    if _HALL_COUNTER is None:
        return
    try:
        _HALL_COUNTER.labels(
            agent_type=agent_key or "unknown",
            tenant_id=tenant_id or "unknown",
        ).inc(score)
        logger.warning(
            "[QUALITY] agent=%s hallucination_score=%.2f tenant=%s",
            agent_key,
            score,
            tenant_id,
        )
    except Exception as exc:
        logger.debug("[QUALITY] hall counter inc failed: %s", exc)


def record_qa_irrelevance(agent_key: str, tenant_id: str = "", score: float = 1.0) -> None:
    """Record an irrelevant-answer event."""
    _ensure_counters()
    if _QA_COUNTER is None:
        return
    try:
        _QA_COUNTER.labels(
            agent_type=agent_key or "unknown",
            tenant_id=tenant_id or "unknown",
        ).inc(score)
    except Exception as exc:
        logger.debug("[QUALITY] qa counter inc failed: %s", exc)


def record_injection_attempt(
    agent_key: str, tenant_id: str = "", technique: str | None = None
) -> None:
    """Record a prompt-injection attempt against an agent."""
    _ensure_counters()
    if _INJ_COUNTER is None:
        return
    try:
        _INJ_COUNTER.labels(
            agent_type=agent_key or "unknown",
            tenant_id=tenant_id or "unknown",
            technique=technique or "unknown",
        ).inc()
    except Exception as exc:
        logger.debug("[QUALITY] inj counter inc failed: %s", exc)


# ── Read side ────────────────────────────────────────────────────────────


@dataclass
class QualityReport:
    """Aggregate quality counts for one agent."""

    agent_key: str
    hallucinations: int = 0
    qa_irrelevant: int = 0
    injection_attempts: int = 0
    total_calls: int = 0  # denominator for rate computation
    hallucination_rate: float = 0.0
    qa_irrelevance_rate: float = 0.0

    def to_dict(self) -> dict:
        return {
            "agent_key": self.agent_key,
            "hallucinations": self.hallucinations,
            "qa_irrelevant": self.qa_irrelevant,
            "injection_attempts": self.injection_attempts,
            "total_calls": self.total_calls,
            "hallucination_rate": round(self.hallucination_rate, 4),
            "qa_irrelevance_rate": round(self.qa_irrelevance_rate, 4),
        }


def get_quality_signals(agent_key: str) -> QualityReport:
    """Scrape the Prometheus registry for quality signals for an agent."""
    report = QualityReport(agent_key=agent_key)
    try:
        from prometheus_client import REGISTRY

        for metric in REGISTRY.collect():
            mname = metric.name
            if mname == "veldt_agent_hallucination":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        report.hallucinations += int(s.value)
            elif mname == "veldt_agent_qa_irrelevance":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        report.qa_irrelevant += int(s.value)
            elif mname == "veldt_agent_injection_attempts":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        report.injection_attempts += int(s.value)
            elif mname == "veldt_agent_requests":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        report.total_calls += int(s.value)
    except Exception as exc:
        logger.debug("[QUALITY] scrape failed: %s", exc)

    if report.total_calls > 0:
        report.hallucination_rate = report.hallucinations / report.total_calls
        report.qa_irrelevance_rate = report.qa_irrelevant / report.total_calls
    return report


# ── Score contribution ───────────────────────────────────────────────────

_QUALITY_CAP = 30


def quality_score(report: QualityReport) -> int:
    """Dynamic quality contribution (0..30) — ADDS to risk score.

    Weights chosen so:
      - >10% hallucination rate over 20+ calls adds +10
      - >25% hallucination rate adds +20 (call this agent unreliable)
      - Any injection attempts surface as +5..+15 depending on count
      - Irrelevant-answer rate counts half as much as hallucination
    """
    s = 0
    if report.total_calls >= 20:
        if report.hallucination_rate > 0.25:
            s += 20
        elif report.hallucination_rate > 0.10:
            s += 10
        if report.qa_irrelevance_rate > 0.25:
            s += 10
        elif report.qa_irrelevance_rate > 0.10:
            s += 5
    if report.injection_attempts > 0:
        s += min(15, 3 + report.injection_attempts // 2)
    return min(_QUALITY_CAP, s)
