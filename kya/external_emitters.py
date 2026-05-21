"""Outbound webhook emitters — KYA → external SIEM / GRC / vendor.

Pairs with `external_defenders.py` (which is INBOUND: vendors POST
verdicts INTO KYA). This module emits OUT: when KYA records a
finding or a high-severity signal, fire-and-forget POST to operator-
configured URLs.

Configuration
-------------
JSON in env `KYA_OUTBOUND_WEBHOOK_URLS`:
    [
      {"url": "https://splunk.example.com/hec/event",
       "format": "splunk_hec",
       "auth_header": "Splunk ABC123",
       "events": ["finding", "policy_violation", "data_leak"]},
      {"url": "https://api.datadoghq.com/api/v1/events",
       "format": "datadog_event",
       "auth_header": "DD-API-KEY xxx",
       "events": ["finding"]},
      {"url": "https://customer.example.com/kya-webhook",
       "format": "kya_native",
       "events": ["*"]}
    ]

Per-tenant config (Phase 6.5):
    JSON at env KYA_OUTBOUND_WEBHOOK_URLS_<tenant_id>
    (UUID hyphens replaced with underscores)
Tenant-specific config takes precedence; global is the fallback.

Formats
-------
  kya_native     — KYA's own schema (the finding/signal dict verbatim)
  splunk_hec     — Splunk HTTP Event Collector envelope
  datadog_event  — Datadog Events API envelope
  generic_json   — minimal {timestamp, event_type, severity, agent_key,
                   payload} — useful for custom SIEM ingest
  lakera_signal  — pushes a verdict-shape that Lakera-style consumers
                   recognize (closing the loop with their own dashboard)

Failure semantics: posts are FIRE-AND-FORGET on a background thread,
3-attempt exponential backoff per URL. A failing destination doesn't
block the orchestrator; failures are logged + a counter increments.
"""

from __future__ import annotations

import json as _json
import logging
import os
import threading
import time

try:
    import requests
except ImportError:
    requests = None  # type: ignore

logger = logging.getLogger(__name__)


_GLOBAL_ENV = "KYA_OUTBOUND_WEBHOOK_URLS"
_DISABLE_ENV = "KYA_DISABLE_OUTBOUND_WEBHOOKS"

# Threading: bounded executor so a slow webhook can't pile up
# unbounded background work. Configurable via env.
_MAX_WORKERS = int(os.environ.get("KYA_OUTBOUND_WEBHOOK_WORKERS", "4"))
_EXECUTOR = None
_EXECUTOR_LOCK = threading.Lock()


def _get_executor():
    global _EXECUTOR
    if _EXECUTOR is not None:
        return _EXECUTOR
    with _EXECUTOR_LOCK:
        if _EXECUTOR is None:
            from concurrent.futures import ThreadPoolExecutor

            _EXECUTOR = ThreadPoolExecutor(
                max_workers=_MAX_WORKERS,
                thread_name_prefix="kya-emitter",
            )
    return _EXECUTOR


# Outbound metric counter — lazy-init
_OUT_COUNTER = None


def _ensure_counter():
    global _OUT_COUNTER
    if _OUT_COUNTER is not None:
        return
    try:
        from prometheus_client import Counter

        try:
            _OUT_COUNTER = Counter(
                "veldt_kya_outbound_webhooks",
                "Outbound webhook delivery attempts. outcome ∈ "
                "{success, http_4xx, http_5xx, transport}. format = "
                "destination format.",
                ["format", "outcome"],
            )
        except ValueError:
            from prometheus_client import REGISTRY

            _OUT_COUNTER = REGISTRY._names_to_collectors.get("veldt_kya_outbound_webhooks")
    except ImportError:
        pass


# ── Configuration loading ───────────────────────────────────────────


def _load_config(tenant_id: str | None = None) -> list[dict]:
    """Return the merged list of webhook destinations applicable to
    this tenant. Per-tenant config wins over global; global appended
    for any destination not already covered."""
    out: list[dict] = []
    if os.environ.get(_DISABLE_ENV, "").lower() in ("1", "true", "yes"):
        return out
    # Per-tenant
    if tenant_id:
        env_name = _GLOBAL_ENV + "_" + tenant_id.replace("-", "_")
        raw = os.environ.get(env_name, "").strip()
        if raw:
            try:
                parsed = _json.loads(raw)
                if isinstance(parsed, list):
                    out.extend(parsed)
            except Exception as exc:
                logger.warning("[KYA-EMIT] bad %s: %s", env_name, exc)
    # Global
    raw = os.environ.get(_GLOBAL_ENV, "").strip()
    if raw:
        try:
            parsed = _json.loads(raw)
            if isinstance(parsed, list):
                out.extend(parsed)
        except Exception as exc:
            logger.warning("[KYA-EMIT] bad %s: %s", _GLOBAL_ENV, exc)
    return out


def _event_matches(dest: dict, event_type: str) -> bool:
    events = dest.get("events") or ["*"]
    return "*" in events or event_type in events


# ── Format adapters ─────────────────────────────────────────────────


def _format_payload(fmt: str, event_type: str, payload: dict) -> dict:
    """Adapt KYA's native event into the destination's expected shape."""
    timestamp = (
        payload.get("created_at")
        or payload.get("timestamp")
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    if fmt == "kya_native":
        return {"event_type": event_type, "timestamp": timestamp, **payload}
    if fmt == "splunk_hec":
        return {
            "time": int(time.time()),
            "host": "veldt-kya",
            "source": "kya",
            "sourcetype": "kya:" + event_type,
            "event": {"event_type": event_type, **payload},
        }
    if fmt == "datadog_event":
        return {
            "title": f"KYA {event_type}: {payload.get('severity', 'info')}",
            "text": _json.dumps(payload)[:4000],
            "alert_type": (
                "error"
                if payload.get("severity") == "critical"
                else "warning"
                if payload.get("severity") == "high"
                else "info"
            ),
            "tags": [
                f"event:{event_type}",
                f"severity:{payload.get('severity', 'unknown')}",
                f"agent:{payload.get('agent_key', 'unknown')}",
                f"tenant:{payload.get('tenant_id', 'unknown')}",
            ],
        }
    if fmt == "lakera_signal":
        # Loop-back format: pushes a verdict-shape that other Lakera-
        # style consumers recognize. Schema chosen to match the
        # `category / severity / agent_key` triple their dashboards
        # expect on inbound.
        return {
            "vendor": "veldt-kya",
            "category": payload.get("attack_category") or event_type,
            "severity": payload.get("severity") or "medium",
            "agent_key": payload.get("agent_key"),
            "tenant_id": payload.get("tenant_id"),
            "summary": payload.get("finding_class") or payload.get("violation_kind"),
            "occurred_at": timestamp,
            "evidence_source": payload.get("evidence_source"),
        }
    # Regulator-grade breach-notify formats (Phase 6 compliance pack).
    # These mirror the field names regulators use on their intake forms /
    # APIs. None of them are an official wire format (regulators don't
    # publish one), but they're the canonical field set you'd attach to
    # a webhook → SOAR playbook that fills the regulator's PDF/portal.
    if fmt == "nydfs_breach":
        # 23 NYCRR §500.17 — Notice of Cybersecurity Event to Superintendent
        return {
            "regulation": "23 NYCRR Part 500",
            "section": "§500.17(a)",
            "covered_entity_id": payload.get("tenant_id"),
            "event_type": "cybersecurity_event",
            "detected_at": payload.get("detected_at") or timestamp,
            "notified_at": timestamp,
            "severity": payload.get("severity") or "high",
            "category": payload.get("attack_category") or payload.get("violation_kind"),
            "affected_system": payload.get("agent_key"),
            "summary": payload.get("finding_class") or payload.get("violation_kind"),
            "incident_id": payload.get("incident_id"),
            "audit_log_id": payload.get("audit_log_id"),
            "sla_hours": 72,
            "authority": "NYDFS Superintendent",
        }
    if fmt == "esma_dora":
        # DORA Art. 19 — initial notification of major ICT-related incident.
        # Field names per ESMA's draft RTS on incident classification.
        sev = (payload.get("severity") or "high").lower()
        classification = "major" if sev in ("critical", "high") else "significant"
        return {
            "regulation": "Regulation (EU) 2022/2554 (DORA)",
            "article": "Art. 19",
            "report_type": "initial_notification",
            "entity_id": payload.get("tenant_id"),
            "incident_classification": classification,
            "detection_time": payload.get("detected_at") or timestamp,
            "reported_at": timestamp,
            "affected_service": payload.get("agent_key"),
            "category": payload.get("attack_category") or payload.get("violation_kind"),
            "criticality": sev,
            "summary": payload.get("finding_class") or payload.get("violation_kind"),
            "incident_id": payload.get("incident_id"),
            "sla_hours": 24,
            "authority": "Competent national authority (DORA Art. 19)",
        }
    if fmt == "edpb_breach":
        # GDPR Art. 33 — Notification of a personal data breach to the
        # supervisory authority. Field set per EDPB Guidelines 9/2022.
        return {
            "regulation": "GDPR",
            "article": "Art. 33",
            "data_controller_id": payload.get("tenant_id"),
            "breach_detected_at": payload.get("detected_at") or timestamp,
            "notification_at": timestamp,
            "nature": payload.get("attack_category") or "confidentiality_breach",
            "data_classes": payload.get("data_classes") or [],
            "approx_data_subjects": payload.get("approx_subjects"),
            "summary": payload.get("finding_class") or payload.get("violation_kind"),
            "incident_id": payload.get("incident_id"),
            "sla_hours": 72,
            "authority": "Lead Supervisory Authority",
        }
    if fmt == "hhs_breach":
        # HIPAA breach notification — 45 CFR §164.408.
        return {
            "regulation": "HIPAA Breach Notification Rule",
            "cfr": "45 CFR §164.408",
            "covered_entity_id": payload.get("tenant_id"),
            "breach_discovered_at": payload.get("detected_at") or timestamp,
            "notification_at": timestamp,
            "affected_individuals": payload.get("approx_subjects"),
            "phi_involved": "phi" in (payload.get("data_classes") or []),
            "summary": payload.get("finding_class") or payload.get("violation_kind"),
            "incident_id": payload.get("incident_id"),
            "sla_hours": 24 * 60,
            "authority": "HHS Office for Civil Rights",
        }
    # generic_json (default fallback)
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": payload.get("severity"),
        "agent_key": payload.get("agent_key"),
        "tenant_id": payload.get("tenant_id"),
        "payload": payload,
    }


# ── POST + retry ────────────────────────────────────────────────────

_RETRY_BACKOFF_S = (0.5, 1.5, 4.0)


def _post_one(dest: dict, event_type: str, payload: dict) -> None:
    """POST ONE destination with retry. Runs in the background thread —
    swallows all exceptions but increments the outcome counter."""
    if requests is None:
        return
    _ensure_counter()
    url = dest.get("url")
    fmt = dest.get("format", "kya_native")
    if not url or not _event_matches(dest, event_type):
        return
    body = _format_payload(fmt, event_type, payload)
    headers = {"Content-Type": "application/json"}
    auth = dest.get("auth_header")
    if auth:
        # auth_header is the full Authorization value
        # ("Bearer xxx" / "Splunk xxx" / "DD-API-KEY xxx" / "Basic ...").
        headers["Authorization"] = auth
    last_status: str = "transport"
    for delay in (0.0,) + _RETRY_BACKOFF_S:
        if delay:
            time.sleep(delay)
        try:
            r = requests.post(url, json=body, headers=headers, timeout=10)
            if r.status_code < 400:
                last_status = "success"
                break
            elif r.status_code >= 500:
                last_status = "http_5xx"
                continue  # retry on server error
            else:
                last_status = "http_4xx"
                break  # don't retry client errors
        except requests.RequestException as exc:
            last_status = "transport"
            logger.debug("[KYA-EMIT] %s POST %s: %s", fmt, url, exc)
    if _OUT_COUNTER is not None:
        try:
            _OUT_COUNTER.labels(format=fmt, outcome=last_status).inc()
        except Exception:
            pass


def emit_event(
    event_type: str,
    payload: dict,
    *,
    tenant_id: str | None = None,
) -> int:
    """Fire-and-forget POST to every configured destination matching
    event_type. Returns the count of destinations the work was queued
    against. Safe to call from anywhere — never raises.

    event_type values used in KYA today:
        finding              — kya_redteam_findings row written
        policy_violation     — record_policy_violation fired
        data_leak            — record_data_leak fired
        oos_tool             — record_oos_tool_attempt fired
        cross_tenant         — record_cross_tenant_attempt fired
        rbac_refusal         — Layer 3 blocked
        governance_block     — Layer 2 blocked
        incident_opened      — governance_incidents insert
        compliance_breach_notification — Phase 6 shim, fired by
            kya.compliance_shim when an incident under a regulated
            regime crosses the breach-notify SLA.
    """
    dests = _load_config(tenant_id=tenant_id)
    if not dests:
        return 0
    pool = _get_executor()
    queued = 0
    for dest in dests:
        if not _event_matches(dest, event_type):
            continue
        try:
            pool.submit(_post_one, dest, event_type, payload)
            queued += 1
        except Exception as exc:
            logger.warning("[KYA-EMIT] submit failed: %s", exc)
    return queued


def configuration_status() -> dict:
    """Surface for /external-defenders/emitter-status — diagnostics
    without exposing auth headers."""
    dests = _load_config()
    redacted = []
    for d in dests:
        rd = dict(d)
        if "auth_header" in rd:
            rd["auth_header"] = "<redacted, %d chars>" % len(d.get("auth_header") or "")
        redacted.append(rd)
    return {
        "destinations_global": len(redacted),
        "destinations": redacted,
        "env_var": _GLOBAL_ENV,
        "disabled_via_env": os.environ.get(_DISABLE_ENV, ""),
        "worker_pool_size": _MAX_WORKERS,
    }
