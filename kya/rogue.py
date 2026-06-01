"""
Rogue Agent Detection — observed-misbehavior signals.

Where KYA's *static* risk score (`agent_risk.py`) measures what an agent
*could* do, the rogue signals here measure what it has *attempted* to do
that it shouldn't have. A read-only agent that has tried to call
`override_decision` ten times is materially more concerning than one
sitting idle, even if their static scores match.

Signal sources (already captured elsewhere — this module just reads them):
  1. TOOL RBAC REFUSAL — Layer 3 blocked a tool call. Counter:
     `veldt_tool_rbac_refusals_total{agent_type, tool}`.
  2. OUT-OF-SCOPE TOOL — Agent invoked a tool not in its sanctioned
     `tools` list. Counter: `veldt_agent_oos_tool_attempts_total`.
     (Instrumented in agents/api.py + agents/streaming.py.)
  3. GOVERNANCE BLOCK — Action gate vetoed the action (PII, content
     safety, policy violation). Counter:
     `veldt_governance_action_gate_total{verdict="block"}`.
  4. CROSS-TENANT — Agent attempted a tool with a tenant_id not its
     own. Counter: `veldt_agent_cross_tenant_attempts_total`.

Public API
----------
    get_rogue_signals(agent_key: str) -> RogueReport
    record_oos_tool_attempt(agent_key: str, tool: str, tenant_id: str)
    record_cross_tenant_attempt(agent_key: str, expected_tid: str, actual_tid: str)
    rogue_score(report: RogueReport) -> int    # 0–100, additive to static risk

The module is read-only with respect to existing state — it never modifies
anything. The two `record_*` helpers are used by call-sites that detect
misbehavior in-line; this module only owns the counters/labels.
"""

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def _safe_label(value) -> str:
    """Strip CR/LF/tab from log fields. Foreign-framework adapters may
    pass attacker-controlled agent names containing newlines that would
    fake log entries downstream."""
    if value is None:
        return ""
    return re.sub(r"[\r\n\t]", "_", str(value))[:200]


# ── Prometheus counters owned by this module ─────────────────────────────

_OOS_COUNTER = None  # veldt_agent_oos_tool_attempts_total
_XTENANT_COUNTER = None  # veldt_agent_cross_tenant_attempts_total
_LEAK_COUNTER = None  # veldt_agent_data_leak_total — agent emitted data
# of a class it isn't sanctioned to expose
_PV_COUNTER = None  # veldt_agent_policy_violations_total — behavioral
# violation (jailbreak / harmful output / refusal fail)


def _ensure_counters():
    """Lazy-init Prometheus counters. Safe to call repeatedly."""
    global _OOS_COUNTER, _XTENANT_COUNTER, _LEAK_COUNTER, _PV_COUNTER
    if (
        _OOS_COUNTER is not None
        and _XTENANT_COUNTER is not None
        and _LEAK_COUNTER is not None
        and _PV_COUNTER is not None
    ):
        return
    try:
        from prometheus_client import Counter

        if _OOS_COUNTER is None:
            try:
                _OOS_COUNTER = Counter(
                    "veldt_agent_oos_tool_attempts",
                    "Tool calls invoked by an agent against tools NOT in its sanctioned tools list",
                    ["agent_type", "tool", "tenant_id"],
                )
            except ValueError:
                # Already registered in another worker / re-import — pull from registry.
                from prometheus_client import REGISTRY

                _OOS_COUNTER = REGISTRY._names_to_collectors.get("veldt_agent_oos_tool_attempts")
        if _XTENANT_COUNTER is None:
            try:
                _XTENANT_COUNTER = Counter(
                    "veldt_agent_cross_tenant_attempts",
                    "Agent tool invocations where the supplied tenant_id did not match the agent's tenant",
                    ["agent_type", "expected_tid", "actual_tid"],
                )
            except ValueError:
                from prometheus_client import REGISTRY

                _XTENANT_COUNTER = REGISTRY._names_to_collectors.get(
                    "veldt_agent_cross_tenant_attempts"
                )
        if _LEAK_COUNTER is None:
            try:
                _LEAK_COUNTER = Counter(
                    "veldt_agent_data_leak",
                    "Agent output contained data of a class it is not sanctioned to handle (e.g., PII from a public-only agent)",
                    ["agent_type", "data_class", "tenant_id"],
                )
            except ValueError:
                from prometheus_client import REGISTRY

                _LEAK_COUNTER = REGISTRY._names_to_collectors.get("veldt_agent_data_leak")
        if _PV_COUNTER is None:
            try:
                _PV_COUNTER = Counter(
                    "veldt_agent_policy_violations",
                    "Agent output or behavior violated a policy (jailbreak, harmful output, refusal failure, prompt injection success)",
                    ["agent_type", "violation_kind", "severity", "source", "tenant_id"],
                )
            except ValueError:
                from prometheus_client import REGISTRY

                _PV_COUNTER = REGISTRY._names_to_collectors.get("veldt_agent_policy_violations")
    except ImportError:
        # prometheus_client absent — record_* becomes a no-op.
        pass


def record_data_leak(
    agent_key: str,
    data_class: str,
    tenant_id: str = "",
    evidence: str | None = None,
    user_id: str | None = None,
    actor_agent_key: str | None = None,
) -> None:
    """Record a data-leakage signal — agent's output contained data of a
    class outside its sanctioned `data_classes` list.

    Call from PII / content-safety guardrails when they detect a hit and
    can attribute it to a specific agent. `evidence` is an optional
    redacted excerpt for audit (don't pass raw PII).

    `user_id` (KYU): when supplied, attributes the leak to the invoking
    user too. -10 KYU trust delta.
    """
    _ensure_counters()
    _emit_otel_event(
        "rogue.data_leak",
        {
            "agent": agent_key,
            "data_class": data_class,
            "tenant_id": tenant_id,
            **({"evidence": evidence} if evidence else {}),
        },
    )
    _emit_realtime(
        tenant_id,
        agent_key,
        "data_leak",
        severity="critical",
        detail={
            "data_class": data_class,
            **({"evidence": evidence} if evidence else {}),
        },
    )
    _emit_user_signal(tenant_id, user_id, "data_leak")
    _emit_actor_agent_signal(tenant_id, actor_agent_key, "data_leak")
    if _LEAK_COUNTER is None:
        return
    try:
        _LEAK_COUNTER.labels(
            agent_type=agent_key or "unknown",
            data_class=data_class or "unknown",
            tenant_id=tenant_id or "unknown",
        ).inc()
        logger.warning(
            "[ROGUE] agent=%s leaked data_class=%s tenant=%s",
            _safe_label(agent_key),
            _safe_label(data_class),
            _safe_label(tenant_id),
        )
    except Exception as exc:
        logger.debug("[ROGUE] leak counter inc failed: %s", exc)


def _emit_otel_event(event_name: str, attributes: dict) -> None:
    """Attach a span event to the current OpenTelemetry span so Phoenix /
    any OTel-aware backend records the rogue signal alongside the regular
    agent trace. No-op if no active span or OTel isn't installed.
    """
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if span and span.is_recording():
            # Span event labels — keep keys simple, OTel will namespace them
            span.add_event(event_name, attributes={k: str(v) for k, v in attributes.items()})
            # Also flag the span so Phoenix dashboards can filter rogue traces
            span.set_attribute("veldt.rogue", True)
            span.set_attribute("veldt.rogue.signal", event_name)
    except Exception:
        pass  # observability is best-effort — never break the request


def _emit_realtime(
    tenant_id: str,
    agent_key: str,
    signal: str,
    severity: str = "warning",
    detail: dict | None = None,
) -> None:
    """Push to Valkey sliding windows + alerts channel. Fail-soft.
    Also forwards to the aggregate-telemetry counter and (if enabled)
    the dual-write sink.
    """
    try:
        from .realtime import record_signal

        record_signal(tenant_id, agent_key, signal, severity=severity, detail=detail)
    except Exception:
        pass  # observability is best-effort
    try:
        from . import _emit, telemetry
        telemetry.record_event("rogue_event", kind=signal)
        if _emit.is_enabled():
            _emit.emit(
                "rogue_signal",
                _emit.safe_row({
                    "tenant_id": tenant_id,
                    "agent_key": agent_key,
                    "signal": signal,
                    "severity": severity,
                    "detail": detail,
                }),
            )
    except Exception:
        pass


def _emit_user_signal(tenant_id: str, user_id: str | None, signal_kind: str) -> None:
    """KYU + KYP mirror — attribute to the invoking human user.
    Writes to BOTH the legacy kya_user_trust table (backwards compat)
    AND the new kya_principal_trust table (Round 13.2 unified view).

    Uses the pluggable session factory (`_session_factory.get_session`)
    so the SDK can inject a sessionmaker that isn't `db.database.SessionLocal`.
    """
    if not user_id:
        return
    try:
        from ._session_factory import get_session
        from .principals import record_principal_signal
        from .users import record_user_signal

        db = get_session()
        if db is None:
            return
        try:
            # Legacy KYU table — preserve existing /kya/users endpoint behavior
            try:
                record_user_signal(db, tenant_id, user_id, signal_kind)
            except Exception as exc:
                logger.debug("[KYU] legacy table write skipped: %s", exc)
            # New unified Principal table — Round 13.2
            record_principal_signal(db, tenant_id, "user", user_id, signal_kind)
        finally:
            try:
                db.close()
            except Exception:
                pass
    except Exception as exc:
        logger.debug("[KYP] user-signal mirror skipped: %s", exc)


def _emit_actor_agent_signal(tenant_id: str, actor_agent_key: str | None, signal_kind: str) -> None:
    """Round 13.2: attribute rogue events to the CALLING agent (when one
    agent drives another's misbehavior in a delegation chain). Writes to
    the kya_principal_trust table with principal_kind="agent".

    Uses the pluggable session factory (`_session_factory.get_session`).
    """
    if not actor_agent_key:
        return
    try:
        from ._session_factory import get_session
        from .principals import record_principal_signal

        db = get_session()
        if db is None:
            return
        try:
            record_principal_signal(db, tenant_id, "agent", actor_agent_key, signal_kind)
        finally:
            try:
                db.close()
            except Exception:
                pass
    except Exception as exc:
        logger.debug("[KYP] actor-agent-signal mirror skipped: %s", exc)


def record_oos_tool_attempt(
    agent_key: str,
    tool: str,
    tenant_id: str = "",
    user_id: str | None = None,
    actor_agent_key: str | None = None,
) -> None:
    """Record an out-of-scope tool attempt — agent called a tool it isn't allowed.

    "Allowed" here means listed in the agent's own `tools` array — distinct
    from RBAC role gating. An agent CAN have role permission to call a tool
    yet not have it in its toolkit; calling it anyway is a rogue signal.

    `user_id` (KYU, Round 11.3): when supplied, the signal ALSO bumps that
    user's KYU trust score downward. The same event becomes a signal at
    both the agent layer (this agent is rogue) and the user layer (this
    user is driving rogue agents).
    """
    _ensure_counters()
    _emit_otel_event(
        "rogue.oos_tool",
        {
            "agent": agent_key,
            "tool": tool,
            "tenant_id": tenant_id,
        },
    )
    _emit_realtime(tenant_id, agent_key, "oos_tool", severity="warning", detail={"tool": tool})
    _emit_user_signal(tenant_id, user_id, "oos_tool")
    _emit_actor_agent_signal(tenant_id, actor_agent_key, "oos_tool")
    if _OOS_COUNTER is None:
        return
    try:
        _OOS_COUNTER.labels(
            agent_type=agent_key or "unknown",
            tool=tool or "unknown",
            tenant_id=tenant_id or "unknown",
        ).inc()
        logger.warning(
            "[ROGUE] agent=%s called out-of-scope tool=%s tenant=%s",
            _safe_label(agent_key),
            _safe_label(tool),
            _safe_label(tenant_id),
        )
    except Exception as exc:
        logger.debug("[ROGUE] OOS counter inc failed: %s", exc)


def record_cross_tenant_attempt(
    agent_key: str,
    expected_tid: str,
    actual_tid: str,
    user_id: str | None = None,
    actor_agent_key: str | None = None,
) -> None:
    """Record a cross-tenant access attempt by an agent.

    `user_id` (KYU): same event also degrades that user's KYU trust by
    -15 — cross-tenant is the heaviest KYU penalty because it's never
    benign in normal operation.
    """
    _ensure_counters()
    _emit_otel_event(
        "rogue.cross_tenant",
        {
            "agent": agent_key,
            "expected_tenant": expected_tid,
            "actual_tenant": actual_tid,
        },
    )
    _emit_realtime(
        expected_tid,
        agent_key,
        "cross_tenant",
        severity="critical",
        detail={"expected_tid": expected_tid, "actual_tid": actual_tid},
    )
    _emit_user_signal(expected_tid, user_id, "cross_tenant")
    _emit_actor_agent_signal(expected_tid, actor_agent_key, "cross_tenant")
    if _XTENANT_COUNTER is None:
        return
    try:
        _XTENANT_COUNTER.labels(
            agent_type=agent_key or "unknown",
            expected_tid=expected_tid or "unknown",
            actual_tid=actual_tid or "unknown",
        ).inc()
        logger.warning(
            "[ROGUE] agent=%s cross-tenant attempt expected=%s actual=%s",
            _safe_label(agent_key),
            _safe_label(expected_tid),
            _safe_label(actual_tid),
        )
    except Exception as exc:
        logger.debug("[ROGUE] cross-tenant counter inc failed: %s", exc)


_VALID_PV_SEVERITIES = ("low", "medium", "high", "critical")


def record_policy_violation(
    agent_key: str,
    violation_kind: str,
    tenant_id: str = "",
    severity: str = "medium",
    evidence: str | None = None,
    user_id: str | None = None,
    actor_agent_key: str | None = None,
    source: str = "observed",
) -> None:
    """Record a behavioral policy violation by an agent.

    Distinct from data_leak (which is about *what data* the agent exposed)
    and oos_tool (which is about *which tool* the agent invoked) —
    policy_violation is about how the agent *behaved*. Examples:
      - violation_kind="jailbreak"        agent complied with a jailbreak prompt
      - violation_kind="harmful_output"   agent produced content a guardrail flagged
      - violation_kind="refusal_failure"  agent failed to refuse a request it should have
      - violation_kind="prompt_injection" injected instructions caused tool/output divergence

    `severity` ∈ {low, medium, high, critical}. Drives anomaly bucketing.
    `source`   ∈ {observed, garak, pyrit, ...} — provenance for the regulator
                  pack. Defaults to "observed" (live traffic). Red-team
                  campaigns pass "pyrit" or "garak" so findings from
                  synthetic attacks can be told apart from real incidents.
    """
    _ensure_counters()
    if severity not in _VALID_PV_SEVERITIES:
        severity = "medium"
    _emit_otel_event(
        "rogue.policy_violation",
        {
            "agent": agent_key,
            "violation_kind": violation_kind,
            "severity": severity,
            "source": source,
            "tenant_id": tenant_id,
            **({"evidence": evidence} if evidence else {}),
        },
    )
    _emit_realtime(
        tenant_id,
        agent_key,
        "policy_violation",
        severity="critical" if severity == "critical" else "warning",
        detail={
            "violation_kind": violation_kind,
            "severity": severity,
            "source": source,
            **({"evidence": evidence} if evidence else {}),
        },
    )
    _emit_user_signal(tenant_id, user_id, "policy_violation")
    _emit_actor_agent_signal(tenant_id, actor_agent_key, "policy_violation")
    if _PV_COUNTER is None:
        return
    try:
        _PV_COUNTER.labels(
            agent_type=agent_key or "unknown",
            violation_kind=violation_kind or "unknown",
            severity=severity,
            source=source or "observed",
            tenant_id=tenant_id or "unknown",
        ).inc()
        logger.warning(
            "[ROGUE] agent=%s policy_violation=%s severity=%s source=%s tenant=%s",
            _safe_label(agent_key),
            _safe_label(violation_kind),
            _safe_label(severity),
            _safe_label(source),
            _safe_label(tenant_id),
        )
    except Exception as exc:
        logger.debug("[ROGUE] policy_violation counter inc failed: %s", exc)


# ── Read-side: build a report for a specific agent ───────────────────────


@dataclass
class RogueReport:
    """All rogue-signal counts observed for a single agent."""

    agent_key: str
    rbac_refusals: int = 0
    oos_tool_attempts: int = 0
    governance_blocks: int = 0
    cross_tenant_attempts: int = 0
    data_leaks: int = 0
    policy_violations: int = 0
    # Tool-level breakdown of the riskiest signal — what was attempted
    top_offending_tools: list[dict] = field(default_factory=list)
    # Per-class leak breakdown — which data classes were emitted
    leaked_classes: dict = field(default_factory=dict)
    # Per-violation-kind breakdown — which behavioral failures fired
    violation_kinds: dict = field(default_factory=dict)

    @property
    def total(self) -> int:
        return (
            self.rbac_refusals
            + self.oos_tool_attempts
            + self.governance_blocks
            + self.cross_tenant_attempts
            + self.data_leaks
            + self.policy_violations
        )

    @property
    def is_rogue(self) -> bool:
        return self.total > 0

    def to_dict(self) -> dict:
        return {
            "agent_key": self.agent_key,
            "rbac_refusals": self.rbac_refusals,
            "oos_tool_attempts": self.oos_tool_attempts,
            "governance_blocks": self.governance_blocks,
            "cross_tenant_attempts": self.cross_tenant_attempts,
            "data_leaks": self.data_leaks,
            "policy_violations": self.policy_violations,
            "leaked_classes": self.leaked_classes,
            "violation_kinds": self.violation_kinds,
            "total": self.total,
            "is_rogue": self.is_rogue,
            "top_offending_tools": self.top_offending_tools,
        }


def get_rogue_signals(agent_key: str, db=None, tenant_id: str | None = None) -> RogueReport:
    """Build a rogue report. Authoritative source is the DB principal
    record (`kya_principal_trust.signal_counts`, in the configured KYA
    schema) — that's cross-worker, persistent, and survives restarts.
    Prometheus counters are also scraped as a *supplemental* live-
    activity feed (for per-tool top-offenders, since the DB stores
    aggregate counts only).

    Read-only and exception-safe — falls back to a zeroed report on any
    failure.
    """
    report = RogueReport(agent_key=agent_key)
    tool_counts: dict[str, int] = {}

    # ── PRIMARY: read merged signal_counts from kya_principal_trust ──
    # This survives container restarts and is the source the migration
    # tool writes to. If a db+tenant are passed, this is authoritative.
    if db is not None and tenant_id:
        try:
            # End the caller's open transaction (if any) before reading.
            # MySQL's default REPEATABLE READ isolation otherwise hides
            # writes that landed via the actor_agent_key/user_id mirror
            # path — those use a separate session, so the caller's
            # snapshot doesn't see them until the snapshot is dropped.
            try:
                db.commit()
            except Exception:
                pass

            # Use ORM Core so the query is portable across the SDK
            # (tenant_id VARCHAR) and vd-app legacy (tenant_id UUID)
            # schema variants. Raw `(:tid)::uuid` cast worked on vd-app
            # but raised "operator does not exist: character varying = uuid"
            # on fresh SDK installs.
            from .principals import _PrincipalRow

            row = db.execute(
                _PrincipalRow.__table__.select()
                .with_only_columns(_PrincipalRow.__table__.c.signal_counts)
                .where(_PrincipalRow.__table__.c.tenant_id == tenant_id)
                .where(_PrincipalRow.__table__.c.principal_id == agent_key)
                .where(_PrincipalRow.__table__.c.principal_kind == "agent")
            ).fetchone()
            if row and row[0]:
                counts = row[0] or {}
                report.rbac_refusals = int(
                    counts.get("rbac_refusal", 0) or counts.get("rbac_refusals", 0)
                )
                report.oos_tool_attempts = int(
                    counts.get("oos_tool", 0) or counts.get("oos_tool_attempts", 0)
                )
                report.governance_blocks = int(
                    counts.get("governance_block", 0) or counts.get("governance_blocks", 0)
                )
                report.cross_tenant_attempts = int(
                    counts.get("cross_tenant", 0) or counts.get("cross_tenant_attempts", 0)
                )
                report.data_leaks = int(counts.get("data_leak", 0) or counts.get("data_leaks", 0))
                report.policy_violations = int(
                    counts.get("policy_violation", 0) or counts.get("policy_violations", 0)
                )
        except Exception as exc:
            logger.debug("[ROGUE] db read failed for %s: %s", agent_key, exc)

    # ── SUPPLEMENTAL: scrape Prometheus for per-tool top-offenders ──
    # Counter values may be stale or restart-zeroed — we use them only
    # for the per-tool breakdown (DB stores aggregate counts only).
    try:
        from prometheus_client import REGISTRY

        for metric in REGISTRY.collect():
            mname = metric.name
            if mname == "veldt_tool_rbac_refusals":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        v = int(s.value)
                        tool = s.labels.get("tool", "?")
                        tool_counts[tool] = tool_counts.get(tool, 0) + v
                        # only add to report totals if DB didn't already populate them
                        if db is None or not tenant_id:
                            report.rbac_refusals += v
            elif mname == "veldt_agent_oos_tool_attempts":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        v = int(s.value)
                        tool = s.labels.get("tool", "?")
                        tool_counts[tool] = tool_counts.get(tool, 0) + v
                        if db is None or not tenant_id:
                            report.oos_tool_attempts += v
            elif mname == "veldt_agent_data_leak":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        v = int(s.value)
                        dc = s.labels.get("data_class", "unknown")
                        report.leaked_classes[dc] = report.leaked_classes.get(dc, 0) + v
                        if db is None or not tenant_id:
                            report.data_leaks += v
            elif mname == "veldt_governance_action_gate":
                for s in metric.samples:
                    if (
                        s.name.endswith("_total")
                        and s.labels.get("verdict") == "block"
                        and s.labels.get("action_type") == agent_key
                    ):
                        if db is None or not tenant_id:
                            report.governance_blocks += int(s.value)
            elif mname == "veldt_agent_cross_tenant_attempts":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        if db is None or not tenant_id:
                            report.cross_tenant_attempts += int(s.value)
            elif mname == "veldt_agent_policy_violations":
                for s in metric.samples:
                    if s.name.endswith("_total") and s.labels.get("agent_type") == agent_key:
                        v = int(s.value)
                        vk = s.labels.get("violation_kind", "unknown")
                        report.violation_kinds[vk] = report.violation_kinds.get(vk, 0) + v
                        if db is None or not tenant_id:
                            report.policy_violations += v
    except Exception as exc:
        logger.debug("[ROGUE] scrape failed: %s", exc)

    report.top_offending_tools = sorted(
        [{"tool": k, "attempts": v} for k, v in tool_counts.items() if v > 0],
        key=lambda x: x["attempts"],
        reverse=True,
    )[:5]
    return report


# ── Rogue score (additive to static risk) ────────────────────────────────

# Weights chosen so observable misbehavior moves the needle but doesn't
# dominate static risk. A clean agent stays at its baseline; a few RBAC
# refusals add a noticeable but bounded delta; cross-tenant attempts
# (much rarer + much worse) push the score hard.
_PER_RBAC_REFUSAL = 2
_PER_OOS_ATTEMPT = 3
_PER_GOV_BLOCK = 1
_PER_XTENANT = 15
_PER_DATA_LEAK = 10  # heavy — leaking regulated data is the worst signal
_PER_POLICY_VIOLATION = 8  # behavioral failure — between gov_block and data_leak
_ROGUE_CAP = 50  # rogue contribution is clamped at this many points


def rogue_score(report: RogueReport) -> int:
    """Compute a 0..50 rogue contribution from observed signals.

    Designed to be ADDED to the static risk score in `agent_risk.py`. The
    cap prevents a single misconfigured agent from pinning the dashboard at
    100 indefinitely while still surfacing severity.
    """
    s = (
        _PER_RBAC_REFUSAL * report.rbac_refusals
        + _PER_OOS_ATTEMPT * report.oos_tool_attempts
        + _PER_GOV_BLOCK * report.governance_blocks
        + _PER_XTENANT * report.cross_tenant_attempts
        + _PER_DATA_LEAK * report.data_leaks
        + _PER_POLICY_VIOLATION * report.policy_violations
    )
    return min(_ROGUE_CAP, s)


# ── Governance integration — read-only summary for the KYA card ──────────


def get_governance_summary(
    db, tenant_id: str, agent_key: str | None = None, window_days: int = 7
) -> dict:
    """Pull tenant-level governance stats for the KYA card.

    Returns verdict counts, open incidents, pending approvals, and the
    last 5 audit-log entries within the window. Per-agent attribution
    isn't reliable from `governance_audit_log` (action_type doesn't carry
    agent_key today) — this is tenant-scoped context the operator can
    cross-reference with the agent's activity.

    Pass agent_key=None to skip the per-agent filter on the recent-events
    list. Exception-safe: returns zeroed/empty dict on any DB failure.
    """
    from sqlalchemy import text

    from ._portable import qual_for_raw_sql_decisions

    out = {
        "window_days": window_days,
        "verdict_counts": {},  # verdict -> count
        "open_incidents": 0,
        "critical_incidents": 0,
        "pending_approvals": 0,
        "recent_events": [],
    }
    try:
        # governance_audit_log / governance_incidents / decision_approvals
        # are veldt-decisions tables, not KYA tables -- use the decisions
        # schema qualifier so split-schema deployments work. Named `dq`
        # for consistency with fleet_metrics.py's split-qualifier code.
        dq = qual_for_raw_sql_decisions(db)
        # Verdict counts within window
        rows = db.execute(
            text(f"""
                SELECT verdict, COUNT(*)
                FROM {dq}governance_audit_log
                WHERE tenant_id = :tid
                  AND created_at >= now() - (:days || ' days')::interval
                GROUP BY verdict
            """),
            {"tid": tenant_id, "days": str(window_days)},
        ).fetchall()
        out["verdict_counts"] = {r[0]: int(r[1]) for r in rows}

        # Open incidents
        row = db.execute(
            text(f"""
                SELECT COUNT(*) FILTER (WHERE resolution_status IN ('open','investigating')),
                       COUNT(*) FILTER (WHERE severity = 'critical'
                                        AND resolution_status IN ('open','investigating'))
                FROM {dq}governance_incidents
                WHERE tenant_id = :tid
            """),
            {"tid": tenant_id},
        ).fetchone()
        if row:
            out["open_incidents"] = int(row[0] or 0)
            out["critical_incidents"] = int(row[1] or 0)

        # Pending approvals
        row = db.execute(
            text(f"""
                SELECT COUNT(*)
                FROM {dq}decision_approvals
                WHERE tenant_id = :tid AND status = 'pending_approval'
            """),
            {"tid": tenant_id},
        ).fetchone()
        if row:
            out["pending_approvals"] = int(row[0] or 0)

        # Most-recent 5 audit entries
        rows = db.execute(
            text(f"""
                SELECT action_type, verdict, risk_level, created_at,
                       policies_failed, model_id
                FROM {dq}governance_audit_log
                WHERE tenant_id = :tid
                  AND created_at >= now() - (:days || ' days')::interval
                ORDER BY created_at DESC
                LIMIT 5
            """),
            {"tid": tenant_id, "days": str(window_days)},
        ).fetchall()
        out["recent_events"] = [
            {
                "action_type": r[0],
                "verdict": r[1],
                "risk_level": r[2],
                "created_at": r[3].isoformat() if r[3] else None,
                "policies_failed": r[4] if isinstance(r[4], list) else [],
                "model_id": r[5],
            }
            for r in rows
        ]
    except Exception as exc:
        logger.debug("[ROGUE] governance summary failed: %s", exc)
    return out


# ── Anomaly detection — simple rules over rogue + activity counters ──────


@dataclass
class Anomaly:
    severity: str  # "info" | "warning" | "critical"
    code: str  # short stable id, e.g. "high_refusal_rate"
    message: str  # human-readable
    detail: dict = field(default_factory=dict)


def get_anomalies(rogue: RogueReport, activity: dict, governance: dict | None = None) -> list[dict]:
    """Return a list of active anomalies for an agent.

    `activity` is the same shape returned by the KYA card's
    `_metrics_for_agent` helper (tool_calls_total, errors_total, etc.).
    `governance` is the dict from `get_governance_summary` (optional —
    used only for tenant-level alerts that surface on the card too).
    """
    out: list[Anomaly] = []
    calls = int(activity.get("tool_calls_total") or 0)
    errors = int(activity.get("errors_total") or 0)
    refusal_rate = (rogue.rbac_refusals / calls) if calls > 0 else 0.0
    error_rate = (errors / calls) if calls > 0 else 0.0

    if rogue.cross_tenant_attempts > 0:
        out.append(
            Anomaly(
                severity="critical",
                code="cross_tenant_attempt",
                message=f"{rogue.cross_tenant_attempts} cross-tenant access attempt(s) detected — this is always a serious signal.",
                detail={"count": rogue.cross_tenant_attempts},
            )
        )
    if rogue.data_leaks > 0:
        worst_classes = sorted(rogue.leaked_classes.items(), key=lambda kv: -kv[1])[:3]
        out.append(
            Anomaly(
                severity="critical",
                code="data_leak",
                message=(
                    f"{rogue.data_leaks} data leak event(s) — agent emitted data "
                    f"of class(es): {', '.join(c for c, _ in worst_classes)}."
                ),
                detail={"count": rogue.data_leaks, "by_class": dict(worst_classes)},
            )
        )
    if rogue.oos_tool_attempts > 0:
        out.append(
            Anomaly(
                severity="warning",
                code="out_of_scope_tools",
                message=f"Agent attempted {rogue.oos_tool_attempts} tool call(s) outside its sanctioned tool list.",
                detail={
                    "count": rogue.oos_tool_attempts,
                    "tools": [t["tool"] for t in rogue.top_offending_tools[:3]],
                },
            )
        )
    if calls >= 10 and refusal_rate > 0.1:
        out.append(
            Anomaly(
                severity="warning",
                code="high_refusal_rate",
                message=f"{refusal_rate * 100:.1f}% of tool calls have been refused by RBAC (>{10}% threshold).",
                detail={
                    "refusals": rogue.rbac_refusals,
                    "calls": calls,
                    "rate": round(refusal_rate, 3),
                },
            )
        )
    if calls >= 10 and error_rate > 0.2:
        out.append(
            Anomaly(
                severity="warning",
                code="high_error_rate",
                message=f"{error_rate * 100:.1f}% error rate over {calls} calls (>20% threshold).",
                detail={"errors": errors, "calls": calls, "rate": round(error_rate, 3)},
            )
        )
    if rogue.governance_blocks >= 5:
        out.append(
            Anomaly(
                severity="warning",
                code="governance_block_burst",
                message=f"{rogue.governance_blocks} actions blocked by governance policies.",
                detail={"count": rogue.governance_blocks},
            )
        )

    # Tenant-level surface (informational on the card)
    if governance and governance.get("critical_incidents", 0) > 0:
        out.append(
            Anomaly(
                severity="critical",
                code="tenant_critical_incident",
                message=f"Tenant has {governance['critical_incidents']} unresolved critical governance incident(s).",
                detail={"count": governance["critical_incidents"]},
            )
        )

    return [
        {
            "severity": a.severity,
            "code": a.code,
            "message": a.message,
            "detail": a.detail,
        }
        for a in out
    ]
