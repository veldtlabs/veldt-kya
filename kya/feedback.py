"""
Incident feedback loop — propose weight adjustments from resolved
governance incidents.

When a `governance_incident` is resolved with `severity=critical`, this
module analyzes WHICH factors fired against the agent that produced the
incident and proposes weight bumps for factors that SHOULD have caught
it earlier (or contributed to it being missed). Suggestions are stored
in `prov_schema.kya_weight_suggestions` for platform-admin review.

Closed-loop intent
------------------
    1. Incident fires → SOC resolves
    2. KYA proposes which weights would have caught this sooner
    3. Platform admin reviews + approves OR rejects
    4. Approved suggestion lands via the Round 11.1 weight-override API
    5. Future incidents are caught at lower score thresholds

Crucial design rule: **never auto-tune.** Suggestions surface for a
human to review. Auto-applying weights based on incidents creates a
feedback loop where one false-positive incident silently weakens the
governance model. Human-in-the-loop is non-negotiable here.

Storage
-------
prov_schema.kya_weight_suggestions:
    id, tenant_id, incident_id, agent_key, scope, key,
    current_value, suggested_value, suggested_delta,
    rationale (text), evidence (jsonb), status, suggested_at,
    decided_at, decided_by, decision_notes

`status` ∈ {pending, approved, rejected, applied, superseded}

Public API
----------
    ensure_suggestions_table(db)
    propose_from_incident(db, incident_row) -> list[dict]
    list_suggestions(db, tenant_id=None, status=None, limit=100)
    approve_suggestion(db, suggestion_id, approved_by, notes=None) -> dict
    reject_suggestion(db, suggestion_id, rejected_by, notes=None) -> dict
"""

import logging

# Lazy SQLAlchemy import for SDK pluggability
try:
    from sqlalchemy import text as _sa_text

    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False

    def _sa_text(s):
        raise RuntimeError(
            "kya.feedback requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


text = _sa_text

logger = logging.getLogger(__name__)


_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_weight_suggestions (
    id                SERIAL PRIMARY KEY,
    tenant_id         UUID,                       -- NULL = platform-level suggestion
    incident_id       INTEGER,                    -- FK to governance_incidents.id
    agent_key         VARCHAR(100),
    scope             VARCHAR(50) NOT NULL,
    key               VARCHAR(100) NOT NULL,
    current_value     INTEGER,
    suggested_value   INTEGER NOT NULL,
    suggested_delta   INTEGER NOT NULL,
    rationale         TEXT,
    evidence          JSONB NOT NULL DEFAULT '{}'::jsonb,
    status            VARCHAR(20) NOT NULL DEFAULT 'pending',
    suggested_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at        TIMESTAMPTZ,
    decided_by        UUID,
    decision_notes    TEXT
);
"""
_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS idx_kya_suggestions_tenant_status
    ON prov_schema.kya_weight_suggestions (tenant_id, status, suggested_at DESC);
"""


def ensure_suggestions_table(db) -> None:
    """Idempotent — dialect-aware via _legacy_tables.create_legacy_tables."""
    from ._legacy_tables import create_legacy_tables, kya_weight_suggestions

    create_legacy_tables(db, [kya_weight_suggestions])
    db.commit()


# ── Proposal logic ───────────────────────────────────────────────────────

# Heuristic mapping: when an incident type fires, which factor categories
# are the candidates for tightening? This is a STARTING POINT — the human
# reviewer decides the final action. Format: incident_signature -> list of
# (scope, key, suggested_delta, rationale_template).
_INCIDENT_TO_FACTORS = {
    "pii_detection": [
        (
            "class_weights",
            "pii",
            +5,
            "PII leak incident — bump 'pii' sensitivity weight so similar "
            "agents would score higher before deploying.",
        ),
        (
            "class_weights",
            "phi",
            +3,
            "Most PII-leak incidents share root causes with PHI handling — "
            "co-bump as a precaution.",
        ),
    ],
    # Alias — production policies use `pii_protection`; same intent.
    "pii_protection": [
        (
            "class_weights",
            "pii",
            +5,
            "PII protection incident — bump 'pii' sensitivity weight so similar "
            "agents would score higher before deploying.",
        ),
        (
            "class_weights",
            "phi",
            +3,
            "Most PII incidents share root causes with PHI handling — "
            "co-bump as a precaution.",
        ),
    ],
    "content_safety": [
        (
            "class_weights",
            "confidential",
            +3,
            "Content-safety incident often indicates an agent crossed a "
            "boundary on internal/confidential data.",
        ),
    ],
    "cross_tenant": [
        (
            "class_weights",
            "confidential",
            +5,
            "Cross-tenant incident — confidentiality boundary breach. "
            "Bump confidential weight + tighten tenant isolation policies.",
        ),
    ],
}


def propose_from_incident(db, incident_row: dict) -> list[dict]:
    """Generate weight-tightening suggestions from a resolved incident.

    `incident_row` is the dict-shape of a `prov_schema.governance_incidents`
    row including resolution context. Returns the list of suggestion dicts
    persisted to `kya_weight_suggestions` (status='pending').

    Caller should invoke this on every incident resolution with
    severity=critical. Suggestions don't auto-apply — they wait for
    platform-admin review.
    """
    ensure_suggestions_table(db)

    # Identify the incident "type" — typically the policy_type from
    # governance_incidents OR a guardrail name inside the metadata.
    incident_id = incident_row.get("id")
    tenant_id = incident_row.get("tenant_id")
    severity = (incident_row.get("severity") or "").lower()
    if severity != "critical":
        return []  # only propose tightening from critical incidents

    incident_type = (
        incident_row.get("policy_type") or incident_row.get("incident_type") or "unknown"
    ).lower()

    # Look up the factor candidates for this incident type
    candidates = _INCIDENT_TO_FACTORS.get(incident_type, [])
    if not candidates:
        logger.info(
            "[KYA_FEEDBACK] no factor candidates registered for incident_type=%s — skipping",
            incident_type,
        )
        return []

    # For each candidate, look up the current weight (platform-level) and
    # propose the bumped value.
    from .tenant_weights import get_effective_weights

    suggestions = []
    for scope, key, delta, rationale_template in candidates:
        try:
            current_weights = get_effective_weights(db, scope, tenant_id=None)
        except Exception as exc:
            logger.debug("[KYA_FEEDBACK] weight lookup failed: %s", exc)
            continue
        current = int(current_weights.get(key, 0))
        suggested = current + delta

        # Don't propose duplicate pending suggestions for the same key.
        # SA Core (not raw text) so it works cross-dialect — the raw
        # version used PG-specific `::uuid` casts and `prov_schema.`
        # prefix that don't translate on SQLite/MySQL.
        from sqlalchemy import and_
        from sqlalchemy import select as sa_select

        from ._legacy_tables import kya_weight_suggestions as _WS
        tid_clause = (
            _WS.c.tenant_id.is_(None) if tenant_id is None
            else _WS.c.tenant_id == tenant_id
        )
        existing = db.execute(
            sa_select(_WS.c.id).where(
                and_(
                    _WS.c.scope == scope,
                    _WS.c.key == key,
                    _WS.c.status == "pending",
                    tid_clause,
                )
            )
        ).fetchone()
        if existing:
            logger.info(
                "[KYA_FEEDBACK] pending suggestion already exists for %s.%s — skipping",
                scope,
                key,
            )
            continue

        evidence = {
            "incident_id": incident_id,
            "incident_type": incident_type,
            "agent_key": incident_row.get("model_id"),
            "policy_id": incident_row.get("policy_id"),
            "resolved_at": str(incident_row.get("resolved_at") or ""),
        }
        # Use SA Core insert (not raw text()) so the autoinc_id Sequence
        # default fires Python-side. Raw text INSERT on PG fails with
        # NotNullViolation on the id column because SA 2.x doesn't emit
        # DEFAULT nextval() in the CREATE TABLE DDL when Sequence is
        # only a positional Column arg — the sequence value is supplied
        # by SA at insert time when using table.insert(). The text()
        # path bypassed that. (PYPI task #12, May 2026.)
        from ._legacy_tables import kya_weight_suggestions
        result = db.execute(
            kya_weight_suggestions.insert().values(
                tenant_id=tenant_id,
                incident_id=incident_id,
                agent_key=incident_row.get("model_id"),
                scope=scope,
                key=key,
                current_value=current,
                suggested_value=suggested,
                suggested_delta=delta,
                rationale=rationale_template,
                evidence=evidence,  # json_or_jsonb() type handles dialect
                status="pending",
            ).returning(kya_weight_suggestions.c.id)
        ).fetchone()
        sid = int(result[0])
        suggestions.append(
            {
                "id": sid,
                "scope": scope,
                "key": key,
                "current_value": current,
                "suggested_value": suggested,
                "suggested_delta": delta,
                "rationale": rationale_template,
                "status": "pending",
            }
        )
        logger.info(
            "[KYA_FEEDBACK] proposed %s.%s %d -> %d from incident_id=%s",
            scope,
            key,
            current,
            suggested,
            incident_id,
        )
    db.commit()
    return suggestions


# ── Read side ────────────────────────────────────────────────────────────


def list_suggestions(
    db,
    tenant_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """List suggestions, optionally filtered. Default returns 100 most-
    recent across all statuses. SA Core for cross-dialect portability."""
    ensure_suggestions_table(db)
    from sqlalchemy import select as sa_select

    from ._legacy_tables import kya_weight_suggestions as _WS
    stmt = sa_select(
        _WS.c.id, _WS.c.tenant_id, _WS.c.incident_id, _WS.c.agent_key,
        _WS.c.scope, _WS.c.key,
        _WS.c.current_value, _WS.c.suggested_value, _WS.c.suggested_delta,
        _WS.c.rationale, _WS.c.evidence, _WS.c.status,
        _WS.c.suggested_at, _WS.c.decided_at, _WS.c.decided_by,
        _WS.c.decision_notes,
    )
    if tenant_id is not None:
        stmt = stmt.where(_WS.c.tenant_id == tenant_id)
    if status is not None:
        stmt = stmt.where(_WS.c.status == status)
    stmt = stmt.order_by(_WS.c.suggested_at.desc()).limit(int(limit))
    rows = db.execute(stmt).fetchall()
    return [
        {
            "id": int(r[0]),
            "tenant_id": str(r[1]) if r[1] else None,
            "incident_id": int(r[2]) if r[2] is not None else None,
            "agent_key": r[3],
            "scope": r[4],
            "key": r[5],
            "current_value": int(r[6]) if r[6] is not None else None,
            "suggested_value": int(r[7]),
            "suggested_delta": int(r[8]),
            "rationale": r[9],
            "evidence": r[10] if isinstance(r[10], dict) else {},
            "status": r[11],
            "suggested_at": r[12].isoformat() if r[12] else None,
            "decided_at": r[13].isoformat() if r[13] else None,
            "decided_by": str(r[14]) if r[14] else None,
            "decision_notes": r[15],
        }
        for r in rows
    ]


# ── Decision side ────────────────────────────────────────────────────────


def _set_decision(
    db,
    suggestion_id: int,
    new_status: str,
    decided_by: str | None,
    notes: str | None,
) -> dict:
    """SA Core update with RETURNING — cross-dialect (raw text would
    fail on SQLite because of the prov_schema. prefix)."""
    from datetime import datetime, timezone

    from sqlalchemy import update as sa_update

    from ._legacy_tables import kya_weight_suggestions as _WS
    row = db.execute(
        sa_update(_WS)
        .where(_WS.c.id == suggestion_id)
        .where(_WS.c.status == "pending")
        .values(
            status=new_status,
            decided_at=datetime.now(timezone.utc),
            decided_by=decided_by,
            decision_notes=notes,
        )
        .returning(
            _WS.c.id, _WS.c.tenant_id, _WS.c.scope, _WS.c.key,
            _WS.c.suggested_value, _WS.c.status,
        )
    ).fetchone()
    db.commit()
    if not row:
        raise ValueError(f"suggestion {suggestion_id} not found or not pending")
    return {
        "id": int(row[0]),
        "tenant_id": str(row[1]) if row[1] else None,
        "scope": row[2],
        "key": row[3],
        "suggested_value": int(row[4]),
        "status": row[5],
    }


def approve_suggestion(
    db,
    suggestion_id: int,
    approved_by: str | None = None,
    notes: str | None = None,
) -> dict:
    """Approve a pending suggestion AND apply it via the Round 11.1
    weight-override API. After this returns, the new weight is live.

    If the apply step fails, the suggestion is marked 'approved' but NOT
    'applied' — caller can retry. Race-safe: only pending suggestions
    can be approved.
    """
    ensure_suggestions_table(db)
    decision = _set_decision(db, suggestion_id, "approved", approved_by, notes)
    # Apply the weight via the same path the REST API uses
    try:
        from .tenant_weights import set_override

        set_override(
            db,
            scope=decision["scope"],
            key=decision["key"],
            value=decision["suggested_value"],
            tenant_id=decision["tenant_id"],
            changed_by=approved_by,
            reason=f"applied from kya_weight_suggestion id={suggestion_id}",
            # Operator approval IS the gate — if they approved a
            # platform-level decrease, honor it.
            allow_platform_decrease=True,
        )
        # Mark as applied. SA Core for cross-dialect.
        from sqlalchemy import update as sa_update

        from ._legacy_tables import kya_weight_suggestions as _WS
        db.execute(
            sa_update(_WS).where(_WS.c.id == suggestion_id).values(status="applied")
        )
        db.commit()
        decision["status"] = "applied"
    except Exception as exc:
        logger.warning(
            "[KYA_FEEDBACK] approve succeeded but apply failed for id=%s: %s",
            suggestion_id,
            exc,
        )
        decision["apply_error"] = str(exc)
    return decision


def reject_suggestion(
    db,
    suggestion_id: int,
    rejected_by: str | None = None,
    notes: str | None = None,
) -> dict:
    """Reject a pending suggestion. Audit trail preserves who/when/why."""
    return _set_decision(db, suggestion_id, "rejected", rejected_by, notes)
