"""Phase 6 — Compliance breach-notification shim.

Periodic job that closes the regulatory loop on `governance_incidents`:

    incident written  →  shim wakes (every 5 min)
                      →  for each open, unnotified incident
                         older than its regime's breach-notify SLA
                      →  emit_event("compliance_breach_notification", ...)
                         in the regime's regulator-grade format
                      →  insert kya_breach_notifications row
                         (UNIQUE on incident_id + regime — idempotent)

Drives off the GovernancePolicy.regulation_tags column for which regime
applies to which incident. A single incident can produce multiple
notifications when its policy is tagged for multiple regimes (e.g., a
PII leak on a GDPR+NYDFS-scoped agent fires TWO breach notifications
with different formats and SLAs).

Per-regime SLA + format come from `kya.compliance.REGIME_BREACH_NOTIFY`.
Outbound delivery is fire-and-forget via `kya.external_emitters.emit_event`
— delivery success is tracked by the existing
`veldt_kya_outbound_webhooks_total` counter.

Idempotency: kya_breach_notifications has UNIQUE(incident_id, regime)
so a hot APScheduler tick (or a re-run of the job after a crash) cannot
double-fire a notification for the same regulator.

Counters:
    veldt_kya_breach_notifications_total{tenant_id, regime, outcome}
        outcome ∈ {sent, already_sent, no_destinations, db_error}
    veldt_kya_breach_notify_lag_seconds{regime}    — gauge
        How far past the SLA the most-recently notified incident was
        when the shim caught it. Useful to alert that the shim
        cadence (or the operator's webhook destination) is lagging.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from .compliance import REGIME_BREACH_NOTIFY
from .external_emitters import emit_event

logger = logging.getLogger(__name__)


# NOTE: DDL is no longer maintained here. The kya_breach_notifications
# table is owned by `kya._legacy_tables` so the schema qualifier and
# dialect-specific types are handled centrally (see
# create_legacy_tables() for the dispatch logic).


def ensure_table(db: Session) -> None:
    """DDL bootstrap — dialect-aware via _legacy_tables.create_legacy_tables."""
    from ._legacy_tables import create_legacy_tables, kya_breach_notifications

    create_legacy_tables(db, [kya_breach_notifications])
    db.commit()


# ── Prometheus counters / gauges ────────────────────────────────────

_COUNTER = None
_LAG_GAUGE = None


def _ensure_metrics():
    global _COUNTER, _LAG_GAUGE
    if _COUNTER is not None:
        return
    try:
        from prometheus_client import REGISTRY, Counter, Gauge

        try:
            _COUNTER = Counter(
                "veldt_kya_breach_notifications",
                "Compliance breach-notification fires by regime + outcome.",
                ["tenant_id", "regime", "outcome"],
            )
        except ValueError:
            _COUNTER = REGISTRY._names_to_collectors.get("veldt_kya_breach_notifications")
        try:
            _LAG_GAUGE = Gauge(
                "veldt_kya_breach_notify_lag_seconds",
                "Most-recent notification's lag past the regime SLA "
                "(positive = past SLA when caught; 0 = on-time).",
                ["regime"],
                multiprocess_mode="max",
            )
        except (ValueError, TypeError):
            _LAG_GAUGE = REGISTRY._names_to_collectors.get("veldt_kya_breach_notify_lag_seconds")
    except ImportError:
        pass


# ── The shim ────────────────────────────────────────────────────────


def _candidate_query(qual: str) -> str:
    """SQL: open incidents that may have crossed at least one regime's SLA.

    Returns the policy's regulation_tags so the caller can decide which
    regimes apply. We DON'T filter by regime here — the cheapest filter
    is "older than the smallest SLA in the matrix", and Python decides
    per-row what to emit.
    """
    return f"""
        SELECT i.id           AS incident_id,
               i.tenant_id    AS tenant_id,
               i.severity     AS severity,
               i.action_taken AS action_taken,
               i.created_at   AS detected_at,
               i.model_id     AS agent_key,
               i.audit_log_id AS audit_log_id,
               p.regulation_tags AS regulation_tags
        FROM {qual}governance_incidents i
        JOIN {qual}governance_policies  p ON p.id = i.policy_id
        WHERE i.resolution_status = 'open'
          AND i.created_at < :cutoff
          AND p.regulation_tags IS NOT NULL
        ORDER BY i.created_at ASC
        LIMIT 200
    """


def _already_notified(db: Session, incident_id: int, regime: str) -> bool:
    from ._portable import qual_for_raw_sql
    qual = qual_for_raw_sql(db)
    row = db.execute(
        text(
            f"SELECT 1 FROM {qual}kya_breach_notifications "
            "WHERE incident_id = :iid AND regime = :reg"
        ),
        {"iid": incident_id, "reg": regime},
    ).first()
    return row is not None


def _record_notification(
    db: Session,
    tenant_id: str,
    incident_id: int,
    regime: str,
    fmt: str,
    destinations: int,
    summary: dict,
) -> bool:
    """Idempotent insert. Returns True if a new row was created."""
    from ._portable import qual_for_raw_sql
    qual = qual_for_raw_sql(db)
    try:
        db.execute(
            text(f"""
            INSERT INTO {qual}kya_breach_notifications
              (tenant_id, incident_id, regime, format, destinations, payload_summary)
            VALUES ((:tid)::uuid, :iid, :reg, :fmt, :dst, CAST(:sum AS jsonb))
            ON CONFLICT (incident_id, regime) DO NOTHING
            RETURNING id
        """),
            {
                "tid": str(tenant_id),
                "iid": incident_id,
                "reg": regime,
                "fmt": fmt,
                "dst": destinations,
                "sum": _json_dumps(summary),
            },
        )
        db.commit()
        return True
    except Exception as exc:
        db.rollback()
        logger.error(
            "[KYA-SHIM] record_notification failed iid=%s regime=%s: %s",
            incident_id,
            regime,
            exc,
        )
        return False


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, default=str)


def run_once(db: Session) -> dict:
    """One shim tick. Designed to be APScheduler-driven, every 5 min.

    Returns a summary dict {scanned, regimes_evaluated, emitted, skipped,
    errors} suitable for /health-style logging.
    """
    from ._portable import qual_for_raw_sql

    _ensure_metrics()
    now = datetime.now(timezone.utc)
    # Cheapest pre-filter: include any incident older than the smallest
    # SLA in the matrix — Python then per-row decides actual eligibility.
    min_window_h = min(v["window_hours"] for v in REGIME_BREACH_NOTIFY.values())
    cutoff = now - timedelta(hours=min_window_h)

    # governance_incidents + governance_policies live in the
    # veldt-decisions schema, NOT the KYA schema -- use the decisions
    # qualifier so customers running KYA and decisions in different
    # schemas don't break.
    from ._portable import qual_for_raw_sql_decisions
    dq = qual_for_raw_sql_decisions(db)
    rows = db.execute(text(_candidate_query(dq)), {"cutoff": cutoff}).mappings().all()
    summary = {
        "scanned": len(rows),
        "regimes_evaluated": 0,
        "emitted": 0,
        "skipped": 0,
        "errors": 0,
    }
    if not rows:
        return summary

    for row in rows:
        try:
            tags = row["regulation_tags"] or []
            if not isinstance(tags, list):
                continue
            # A regulation_tag like "gdpr_art_33" maps back to the
            # regime "gdpr" by prefix match. We also allow exact-name
            # tags ("nydfs_500", "dora") for operator-set policies.
            applicable_regimes = set()
            for tag in tags:
                t = str(tag).lower()
                for regime in REGIME_BREACH_NOTIFY:
                    if t == regime or t.startswith(regime + "_"):
                        applicable_regimes.add(regime)

            if not applicable_regimes:
                continue
            summary["regimes_evaluated"] += len(applicable_regimes)
            for regime in applicable_regimes:
                spec = REGIME_BREACH_NOTIFY[regime]
                window_h = spec["window_hours"]
                fmt = spec["format"]
                detected = row["detected_at"]
                if detected.tzinfo is None:
                    detected = detected.replace(tzinfo=timezone.utc)
                age_h = (now - detected).total_seconds() / 3600
                if age_h < window_h:
                    continue  # not yet past SLA

                if _already_notified(db, row["incident_id"], regime):
                    if _COUNTER is not None:
                        _COUNTER.labels(
                            tenant_id=str(row["tenant_id"]),
                            regime=regime,
                            outcome="already_sent",
                        ).inc()
                    summary["skipped"] += 1
                    continue

                # SLA-lag gauge: how far past SLA we were when caught.
                lag_seconds = (age_h - window_h) * 3600
                if _LAG_GAUGE is not None:
                    try:
                        _LAG_GAUGE.labels(regime=regime).set(lag_seconds)
                    except Exception:
                        pass

                payload = {
                    "tenant_id": str(row["tenant_id"]),
                    "agent_key": row["agent_key"],
                    "incident_id": row["incident_id"],
                    "audit_log_id": row["audit_log_id"],
                    "severity": row["severity"],
                    "violation_kind": row["action_taken"],
                    "attack_category": row["action_taken"],
                    "detected_at": detected.isoformat(),
                    "regime": regime,
                    "sla_window_hours": window_h,
                    "authority": spec["authority"],
                    "lag_seconds_past_sla": int(lag_seconds),
                }
                # Override format per destination → emit in the regime's
                # regulator format. We achieve this by tagging the event
                # type with the regime so a destination configured
                # `events: ["compliance_breach_notification"]` receives
                # it in whatever `format` that destination chose. The
                # regulator-grade adapters (nydfs_breach, esma_dora,
                # edpb_breach, hhs_breach) are wired in external_emitters.
                queued = emit_event(
                    "compliance_breach_notification",
                    payload,
                    tenant_id=str(row["tenant_id"]),
                )
                if queued == 0:
                    if _COUNTER is not None:
                        _COUNTER.labels(
                            tenant_id=str(row["tenant_id"]),
                            regime=regime,
                            outcome="no_destinations",
                        ).inc()
                    # Still record the attempt so we don't loop forever
                    # — operator will see destinations=0 in the row and
                    # know to configure a webhook.

                if _record_notification(
                    db,
                    tenant_id=str(row["tenant_id"]),
                    incident_id=row["incident_id"],
                    regime=regime,
                    fmt=fmt,
                    destinations=queued,
                    summary={
                        "severity": row["severity"],
                        "kind": row["action_taken"],
                        "lag_seconds": int(lag_seconds),
                    },
                ):
                    summary["emitted"] += 1
                    if _COUNTER is not None and queued > 0:
                        _COUNTER.labels(
                            tenant_id=str(row["tenant_id"]),
                            regime=regime,
                            outcome="sent",
                        ).inc()
                else:
                    summary["errors"] += 1
                    if _COUNTER is not None:
                        _COUNTER.labels(
                            tenant_id=str(row["tenant_id"]),
                            regime=regime,
                            outcome="db_error",
                        ).inc()
        except Exception as exc:
            summary["errors"] += 1
            logger.exception("[KYA-SHIM] incident_id=%s failed: %s", row.get("incident_id"), exc)
    return summary


def get_notification_history(
    db: Session,
    tenant_id: str,
    *,
    regime: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Tenant-scoped query for the dashboard: 'What did we tell whom?'"""
    from ._portable import qual_for_raw_sql
    qual = qual_for_raw_sql(db)
    sql = f"""
        SELECT id, incident_id, regime, format, destinations,
               notified_at, payload_summary
        FROM {qual}kya_breach_notifications
        WHERE tenant_id = (:tid)::uuid
    """
    params: dict[str, Any] = {"tid": str(tenant_id)}
    if regime:
        sql += " AND regime = :regime"
        params["regime"] = regime
    sql += " ORDER BY notified_at DESC LIMIT :lim"
    params["lim"] = int(limit)
    rows = db.execute(text(sql), params).mappings().all()
    return [dict(r) for r in rows]
