"""KYA fleet-wide Prometheus metrics — assurance, cost, compliance,
reliability, capacity, workflow.

Closes the gap between "observation layer" (already had 23 counters
for what agents did) and the things buyers actually ask about:
  - Cost: $ per tenant per model
  - Compliance: agents under each regulatory regime
  - Reliability: sidecar fallback, heartbeat sweeps, Valkey unavailable
  - Capacity: thread pool depth, queue depth
  - Workflow: incidents open, approvals pending, target verification
  - Trust transitions: bucket movement counts (the alerting signal)
  - Versioning: agent version creates, rollbacks
  - Framework coverage: OTLP spans received per framework

Three patterns:
  - Counters fired at event sites via inc() helpers (no decorator needed)
  - Gauges recomputed on a 30s tick via recompute_fleet_gauges(db)
  - The same multiprocess_mode='mostrecent' fallback used by the
    per-principal trust gauge, so multi-worker docker-compose works

All metric names use the `veldt_kya_` prefix for consistency with the
existing surface.
"""

from __future__ import annotations

import logging

try:
    from sqlalchemy import text
except ImportError:

    def text(s):
        raise RuntimeError("kya.fleet_metrics requires SQLAlchemy")


logger = logging.getLogger(__name__)


# ── Counter / Gauge instances (lazy-init) ───────────────────────────

_INITIALIZED = False

# Counters (event-driven, fire via inc() helpers below)
COST_DOLLARS = None  # cost_dollars_total{tenant, model, kind}
ATTESTATIONS_SIGNED = None  # attestations_signed_total{entity_type}
APPROVALS_SLA_BREACHED = None  # approvals_sla_breached_total
SIDECAR_FALLBACK = None  # redteam_sidecar_fallback_total{reason}
HEARTBEAT_SWEEP = None  # heartbeat_sweep_total{outcome}
VALKEY_UNAVAILABLE = None  # valkey_unavailable_total{operation}
ORCHESTRATOR_ERRORS = None  # orchestrator_errors_total{kind}
FINDINGS_PROMOTED = None  # findings_promoted_total{tenant}
TRUST_BUCKET_TRANSITIONS = None  # trust_bucket_transitions_total{from, to}
AGENT_VERSIONS_CREATED = None  # agent_versions_created_total{tenant}
AGENT_ROLLBACKS = None  # agent_rollbacks_total{tenant}
ATTACK_BLOCKED = None  # attack_blocked_total{layer, kind}
ATTACK_SUCCEEDED = None  # attack_succeeded_total{kind}
OTLP_SPANS_RECEIVED = None  # otlp_spans_received_total{framework}

# Gauges (recomputed periodically OR set at event sites)
AGENTS_UNDER_REGIME = None  # agents_under_regime{tenant, regime}
APPROVALS_PENDING = None  # approvals_pending{tenant}
INCIDENTS_OPEN = None  # incidents_open{severity}
TARGET_VERIFIED_STATUS = None  # target_verified_status{tenant, status}
TENANTS_TOTAL = None  # tenants_total{status}
POOL_ACTIVE = None  # redteam_pool_active{tenant}
POOL_QUEUED = None  # redteam_pool_queued (no label)


def _make_counter(name: str, doc: str, labels: list[str]):
    try:
        from prometheus_client import Counter

        try:
            return Counter(name, doc, labels)
        except ValueError:
            from prometheus_client import REGISTRY

            return REGISTRY._names_to_collectors.get(name)
    except ImportError:
        return None


def _make_gauge(name: str, doc: str, labels: list[str]):
    try:
        from prometheus_client import Gauge

        kw = dict(name=name, documentation=doc, labelnames=labels)
        for mode in ("mostrecent", "max"):
            try:
                return Gauge(**kw, multiprocess_mode=mode)
            except (TypeError, ValueError) as exc:
                if "multiprocess_mode" in str(exc):
                    continue
                if "Duplicated" in str(exc) or "already" in str(exc).lower():
                    from prometheus_client import REGISTRY

                    return REGISTRY._names_to_collectors.get(name)
        try:
            return Gauge(**kw)
        except ValueError:
            from prometheus_client import REGISTRY

            return REGISTRY._names_to_collectors.get(name)
    except ImportError:
        return None


def init_metrics():
    global _INITIALIZED
    if _INITIALIZED:
        return
    global COST_DOLLARS, ATTESTATIONS_SIGNED, APPROVALS_SLA_BREACHED
    global SIDECAR_FALLBACK, HEARTBEAT_SWEEP, VALKEY_UNAVAILABLE
    global ORCHESTRATOR_ERRORS, FINDINGS_PROMOTED, TRUST_BUCKET_TRANSITIONS
    global AGENT_VERSIONS_CREATED, AGENT_ROLLBACKS, ATTACK_BLOCKED
    global ATTACK_SUCCEEDED, OTLP_SPANS_RECEIVED
    global AGENTS_UNDER_REGIME, APPROVALS_PENDING, INCIDENTS_OPEN
    global TARGET_VERIFIED_STATUS, TENANTS_TOTAL, POOL_ACTIVE, POOL_QUEUED

    COST_DOLLARS = _make_counter(
        "veldt_kya_cost_dollars",
        "Estimated LLM cost in USD. kind ∈ {agent, attacker, judge}. "
        "Computed via LiteLLM's completion_cost() where possible; "
        "falls back to a per-model price table.",
        ["tenant_id", "model", "kind"],
    )
    ATTESTATIONS_SIGNED = _make_counter(
        "veldt_kya_attestations_signed",
        "Ed25519 attestations chained into the audit trail.",
        ["tenant_id", "entity_type"],
    )
    APPROVALS_SLA_BREACHED = _make_counter(
        "veldt_kya_approvals_sla_breached",
        "Flag-for-review approvals that timed out past their window.",
        ["tenant_id"],
    )
    SIDECAR_FALLBACK = _make_counter(
        "veldt_kya_redteam_sidecar_fallback",
        "Times /run-async fell back from the sidecar to in-process. "
        "Non-zero rate = sidecar is sick.",
        ["reason"],
    )
    HEARTBEAT_SWEEP = _make_counter(
        "veldt_kya_heartbeat_sweep",
        "Runs reconciled by the heartbeat-timeout sweep (worker crash).",
        ["outcome"],
    )
    VALKEY_UNAVAILABLE = _make_counter(
        "veldt_kya_valkey_unavailable",
        "Valkey-backed gates that fell open because the cache was "
        "unreachable. Non-zero = budget/rate caps were not enforced.",
        ["operation"],
    )
    ORCHESTRATOR_ERRORS = _make_counter(
        "veldt_kya_orchestrator_errors",
        "Internal errors inside the red-team runner: scorer / target / attacker LLM / persistence.",
        ["kind"],
    )
    FINDINGS_PROMOTED = _make_counter(
        "veldt_kya_findings_promoted",
        "Findings manually promoted to governance_incidents via the "
        "POST /findings/{id}/promote endpoint.",
        ["tenant_id"],
    )
    TRUST_BUCKET_TRANSITIONS = _make_counter(
        "veldt_kya_trust_bucket_transitions",
        "Principal trust bucket movements. 'from' and 'to' ∈ "
        "{trusted, neutral, risky, blocked}. The 'X→Y this week' "
        "signal that operators alert on.",
        ["tenant_id", "principal_kind", "from", "to"],
    )
    AGENT_VERSIONS_CREATED = _make_counter(
        "veldt_kya_agent_versions_created",
        "Agent definition snapshots (every create / update writes one).",
        ["tenant_id"],
    )
    AGENT_ROLLBACKS = _make_counter(
        "veldt_kya_agent_rollbacks",
        "Agent definitions rolled back to a prior version.",
        ["tenant_id"],
    )
    ATTACK_BLOCKED = _make_counter(
        "veldt_kya_attack_blocked",
        "Attack attempts the 3-layer gate stopped. layer ∈ {auth, "
        "action_gate, tool_rbac}. kind = attack_category (jailbreak, "
        "oos_tool, cross_tenant, etc.).",
        ["layer", "kind"],
    )
    ATTACK_SUCCEEDED = _make_counter(
        "veldt_kya_attack_succeeded",
        "Attack attempts that got through the gates. Paired with "
        "attack_blocked, gives the defense ratio.",
        ["kind"],
    )
    OTLP_SPANS_RECEIVED = _make_counter(
        "veldt_kya_otlp_spans_received",
        "OTel spans received by the kya_otlp_bridge. framework ∈ "
        "{openinference, openllmetry, openclaw, veldt, generic}.",
        ["framework"],
    )

    # ── Gauges ──
    AGENTS_UNDER_REGIME = _make_gauge(
        "veldt_kya_agents_under_regime",
        "Number of agents subject to each regulatory regime (HIPAA / "
        "GDPR / EU AI Act / SOX / PCI / CCPA / GLBA / FERPA / etc.).",
        ["tenant_id", "regime"],
    )
    APPROVALS_PENDING = _make_gauge(
        "veldt_kya_approvals_pending",
        "Pending flag-for-review approvals per tenant.",
        ["tenant_id"],
    )
    INCIDENTS_OPEN = _make_gauge(
        "veldt_kya_incidents_open",
        "Open governance incidents by severity.",
        ["tenant_id", "severity"],
    )
    TARGET_VERIFIED_STATUS = _make_gauge(
        "veldt_kya_target_verified_status",
        "Red-team targets by verified_status (ok / failing / never).",
        ["tenant_id", "status"],
    )
    TENANTS_TOTAL = _make_gauge(
        "veldt_kya_tenants",
        "Total tenants by status (active / trial / suspended).",
        ["status"],
    )
    POOL_ACTIVE = _make_gauge(
        "veldt_kya_redteam_pool_active",
        "Red-team campaigns currently in 'queued' or 'running' state.",
        ["tenant_id"],
    )
    POOL_QUEUED = _make_gauge(
        "veldt_kya_redteam_pool_queued",
        "Red-team submissions waiting for a worker (sum across tenants).",
        [],
    )
    _INITIALIZED = True


# ── Counter inc helpers ─────────────────────────────────────────────
# Each takes label values + an optional value=N. All exception-safe.


def _inc(counter, *, by: float = 1.0, **labels):
    """Tiny shim so call sites don't need try/except around each .inc().
    Initializes the metric registry lazily on first call."""
    init_metrics()
    if counter is None:
        return
    try:
        counter.labels(**labels).inc(by)
    except Exception as exc:
        logger.debug("[KYA-METRICS] counter inc failed: %s", exc)


def inc_cost_dollars(tenant_id: str, model: str, kind: str, dollars: float):
    """kind ∈ {agent, attacker, judge}. Pass dollars as a float; we
    accumulate to a Counter so it monotonically increases over the
    tenant's billing period."""
    if dollars <= 0:
        return
    _inc(
        COST_DOLLARS,
        by=float(dollars),
        tenant_id=tenant_id or "unknown",
        model=model or "unknown",
        kind=kind or "unknown",
    )


def inc_attestation_signed(tenant_id: str, entity_type: str):
    _inc(
        ATTESTATIONS_SIGNED,
        tenant_id=tenant_id or "unknown",
        entity_type=entity_type or "unknown",
    )


def inc_approval_sla_breached(tenant_id: str):
    _inc(APPROVALS_SLA_BREACHED, tenant_id=tenant_id or "unknown")


def inc_sidecar_fallback(reason: str):
    _inc(SIDECAR_FALLBACK, reason=reason or "unknown")


def inc_heartbeat_sweep(outcome: str):
    _inc(HEARTBEAT_SWEEP, outcome=outcome or "unknown")


def inc_valkey_unavailable(operation: str):
    _inc(VALKEY_UNAVAILABLE, operation=operation or "unknown")


def inc_orchestrator_error(kind: str):
    _inc(ORCHESTRATOR_ERRORS, kind=kind or "unknown")


def inc_finding_promoted(tenant_id: str):
    _inc(FINDINGS_PROMOTED, tenant_id=tenant_id or "unknown")


def inc_trust_bucket_transition(
    tenant_id: str, principal_kind: str, from_bucket: str, to_bucket: str
):
    if from_bucket == to_bucket:
        return
    _inc(
        TRUST_BUCKET_TRANSITIONS,
        tenant_id=tenant_id or "unknown",
        principal_kind=principal_kind or "unknown",
        **{"from": from_bucket, "to": to_bucket},
    )


def inc_agent_version_created(tenant_id: str):
    _inc(AGENT_VERSIONS_CREATED, tenant_id=tenant_id or "unknown")


def inc_agent_rollback(tenant_id: str):
    _inc(AGENT_ROLLBACKS, tenant_id=tenant_id or "unknown")


def inc_attack_blocked(layer: str, kind: str):
    _inc(ATTACK_BLOCKED, layer=layer or "unknown", kind=kind or "unknown")


def inc_attack_succeeded(kind: str):
    _inc(ATTACK_SUCCEEDED, kind=kind or "unknown")


def inc_otlp_span(framework: str):
    _inc(OTLP_SPANS_RECEIVED, framework=framework or "generic")


# ── Periodic gauge recompute ────────────────────────────────────────


def recompute_fleet_gauges(db) -> dict:
    """One pass over Postgres that refreshes every gauge in this module.
    Called on the 30s APScheduler tick (alongside the per-principal
    trust gauge recompute in kya/principals.py). Returns a summary dict.

    Safe to call from any worker; the metric library handles cross-
    worker convergence via multiprocess_mode='mostrecent'.
    """
    from ._portable import qual_for_raw_sql, qual_for_raw_sql_decisions

    init_metrics()
    summary = {"ok": True}
    # `qual` for KYA tables (kya_redteam_*); `dq` for decisions
    # tables (tenants, decision_approvals, governance_incidents,
    # custom_agents) which live in the veldt-decisions schema.
    qual = qual_for_raw_sql(db)
    dq = qual_for_raw_sql_decisions(db)

    # tenants_total{status}
    if TENANTS_TOTAL is not None:
        try:
            rows = db.execute(
                text(
                    f"SELECT tenant_status, COUNT(*) FROM {dq}tenants GROUP BY tenant_status"
                )
            ).fetchall()
            for status, n in rows:
                try:
                    TENANTS_TOTAL.labels(status=str(status or "unknown")).set(int(n))
                except Exception:
                    pass
            summary["tenants_groups"] = len(rows)
        except Exception as exc:
            logger.debug("[KYA-METRICS] tenants gauge: %s", exc)

    # approvals_pending{tenant_id}
    if APPROVALS_PENDING is not None:
        try:
            rows = db.execute(
                text(
                    "SELECT tenant_id, COUNT(*) "
                    f"FROM {dq}decision_approvals "
                    "WHERE status = 'pending_approval' "
                    "GROUP BY tenant_id"
                )
            ).fetchall()
            for tid, n in rows:
                try:
                    APPROVALS_PENDING.labels(tenant_id=str(tid)).set(int(n))
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("[KYA-METRICS] approvals_pending gauge: %s", exc)

    # incidents_open{tenant_id, severity}
    if INCIDENTS_OPEN is not None:
        try:
            rows = db.execute(
                text(
                    "SELECT tenant_id, severity, COUNT(*) "
                    f"FROM {dq}governance_incidents "
                    "WHERE resolution_status IN ('open', 'investigating') "
                    "GROUP BY tenant_id, severity"
                )
            ).fetchall()
            for tid, sev, n in rows:
                try:
                    INCIDENTS_OPEN.labels(
                        tenant_id=str(tid),
                        severity=str(sev or "unknown"),
                    ).set(int(n))
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("[KYA-METRICS] incidents_open gauge: %s", exc)

    # target_verified_status{tenant_id, status}
    if TARGET_VERIFIED_STATUS is not None:
        try:
            rows = db.execute(
                text(
                    "SELECT tenant_id, verified_status, COUNT(*) "
                    f"FROM {qual}kya_redteam_targets "
                    "GROUP BY tenant_id, verified_status"
                )
            ).fetchall()
            for tid, status, n in rows:
                try:
                    TARGET_VERIFIED_STATUS.labels(
                        tenant_id=str(tid),
                        status=str(status or "never"),
                    ).set(int(n))
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("[KYA-METRICS] target_verified gauge: %s", exc)

    # pool_active{tenant_id}: count campaigns currently in queued/running
    if POOL_ACTIVE is not None:
        try:
            rows = db.execute(
                text(
                    "SELECT tenant_id, COUNT(*) "
                    f"FROM {qual}kya_redteam_runs "
                    "WHERE status IN ('queued', 'running') "
                    "GROUP BY tenant_id"
                )
            ).fetchall()
            # Zero out tenants that are no longer in flight by NOT touching
            # their series — mostrecent mode keeps the last value, which
            # is fine if the value's older than the campaign cleanup
            # window. For strict accuracy we'd track tenant set and
            # explicitly set 0; defer.
            total_queued = 0
            for tid, n in rows:
                try:
                    POOL_ACTIVE.labels(tenant_id=str(tid)).set(int(n))
                except Exception:
                    pass
                total_queued += int(n)
            if POOL_QUEUED is not None:
                try:
                    # Queue depth = runs in 'queued' state (not yet picked up).
                    queued_row = db.execute(
                        text(
                            f"SELECT COUNT(*) FROM {qual}kya_redteam_runs "
                            "WHERE status = 'queued'"
                        )
                    ).fetchone()
                    POOL_QUEUED.set(int(queued_row[0]) if queued_row else 0)
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("[KYA-METRICS] pool gauge: %s", exc)

    # agents_under_regime{tenant_id, regime}: requires reading compliance
    # scope from agent definitions. Expensive — we approximate by reading
    # the `compliance_scope` field if present on custom agents.
    if AGENTS_UNDER_REGIME is not None:
        try:
            rows = db.execute(
                text(
                    "SELECT tenant_id, "
                    "       jsonb_array_elements_text(COALESCE(definition->'compliance_scope', '[]'::jsonb)) AS regime, "
                    "       COUNT(*) "
                    f"FROM {dq}custom_agents "
                    "WHERE definition IS NOT NULL "
                    "GROUP BY tenant_id, regime"
                )
            ).fetchall()
            for tid, regime, n in rows:
                if not regime:
                    continue
                try:
                    AGENTS_UNDER_REGIME.labels(
                        tenant_id=str(tid),
                        regime=str(regime),
                    ).set(int(n))
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("[KYA-METRICS] regime gauge: %s", exc)

    return summary
