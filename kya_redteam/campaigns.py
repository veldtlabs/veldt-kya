"""Campaign + finding tables for KYA red-team.

Follows the kya_agent_aliases pattern: idempotent DDL via ensure_tables,
additive evolution via _MIGRATIONS, all queries parameterized + tenant-
scoped.

Three tables:
  - kya_redteam_campaigns       campaign definitions (per agent_key)
  - kya_redteam_findings        per-run findings persistence
  - kya_redteam_tenant_policy   tenant-level ceilings + tier entitlement
"""
from __future__ import annotations

import json as _json
import logging
import uuid
from typing import Any, Optional

try:
    from sqlalchemy import text
except ImportError:
    def text(s):  # type: ignore
        raise RuntimeError("kya_redteam.campaigns requires SQLAlchemy")

# _migrations lives in agents/kya — reuse it rather than duplicating
from kya._migrations import apply_migrations

logger = logging.getLogger(__name__)


# ── Enum-like value sets (validated at write time) ──────────────────

VALID_ORCHESTRATORS = (
    # Free tier — single-shot probes, no attacker LLM needed
    "prompt_sending",
    "garak_probes",                   # Garak-style curated probes
    # Standard tier — multi-turn, requires attacker LLM
    "red_teaming",
    "xpia",
    # Premium tier — advanced orchestrators
    "crescendo",
    "tree_of_attacks_with_pruning",
)

VALID_SCORERS = (
    # Native scorers (Phase 2/3 — no LLM judge needed):
    "sub_string",
    "regex",
    "data_leak_scanner",
    "refusal_failure",
    "tool_hijack",
    # LLM-judge scorers (Phase 3 onward — needs attacker LLM):
    "self_ask_true_false",
    # Reserved for PyRIT runtime (Phase 3.5+):
    "self_ask_likert",
    "azure_content_filter",
)

VALID_TIERS = ("free", "standard", "premium")

VALID_AUTO_INCIDENT_MODES = ("never", "critical_only", "always")

VALID_SEVERITIES = ("low", "medium", "high", "critical")

# Which tier each orchestrator requires. The tier check at run-time
# rejects a campaign whose tenant tier is below this floor.
_ORCHESTRATOR_MIN_TIER = {
    "prompt_sending":               "free",
    "garak_probes":                 "free",
    "red_teaming":                  "standard",
    "xpia":                         "standard",
    "crescendo":                    "premium",
    "tree_of_attacks_with_pruning": "premium",
}

_TIER_RANK = {"free": 0, "standard": 1, "premium": 2}


def tier_allows_orchestrator(tenant_tier: str, orchestrator_kind: str) -> bool:
    """Return True if the tenant's entitlement tier covers the orchestrator's
    minimum tier. Unknown orchestrator -> False (fail closed)."""
    floor = _ORCHESTRATOR_MIN_TIER.get(orchestrator_kind)
    if floor is None:
        return False
    return _TIER_RANK.get(tenant_tier, -1) >= _TIER_RANK.get(floor, 99)


# ── DDL ─────────────────────────────────────────────────────────────

_CAMPAIGNS_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_redteam_campaigns (
    id                  SERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    agent_key           VARCHAR(50) NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT,
    orchestrator_kind   TEXT NOT NULL,
    scorer_kind         TEXT NOT NULL,
    dataset             TEXT,
    attacker_llm        TEXT,
    converters          JSONB,
    schedule_cron       TEXT,
    budget_max_prompts  INT  NOT NULL DEFAULT 100,
    threshold           NUMERIC(3,2) NOT NULL DEFAULT 0.5,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    tier_required       TEXT NOT NULL DEFAULT 'free',
    auto_incident_mode  TEXT NOT NULL DEFAULT 'never',
    last_run_at         TIMESTAMPTZ,
    last_run_status     TEXT,
    last_run_finding_count INT,
    next_run_at         TIMESTAMPTZ,
    created_by          UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

_CAMPAIGNS_IDX = """
CREATE INDEX IF NOT EXISTS idx_kya_redteam_campaigns_tenant_agent
    ON prov_schema.kya_redteam_campaigns (tenant_id, agent_key);
"""

_FINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_redteam_findings (
    id                  SERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    campaign_id         INT REFERENCES prov_schema.kya_redteam_campaigns(id) ON DELETE SET NULL,
    run_id              UUID NOT NULL,
    agent_key           VARCHAR(50) NOT NULL,
    orchestrator        TEXT,
    attack_category     TEXT,
    finding_class       TEXT,
    severity            TEXT,
    score               NUMERIC(3,2),
    prompt_redacted     TEXT,
    response_redacted   TEXT,
    conversation_redacted JSONB,
    pyrit_memory_id     TEXT,
    evidence_source     TEXT NOT NULL DEFAULT 'pyrit',
    posted_event_id     INT,
    promoted_incident_id INT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

_FINDINGS_IDX = """
CREATE INDEX IF NOT EXISTS idx_kya_redteam_findings_run
    ON prov_schema.kya_redteam_findings (tenant_id, agent_key, run_id);
CREATE INDEX IF NOT EXISTS idx_kya_redteam_findings_severity
    ON prov_schema.kya_redteam_findings (tenant_id, severity);
"""

_TENANT_POLICY_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_redteam_tenant_policy (
    tenant_id              UUID PRIMARY KEY,
    max_auto_incident_mode TEXT NOT NULL DEFAULT 'never',
    budget_monthly_prompts INT  NOT NULL DEFAULT 10000,
    redteam_tier           TEXT NOT NULL DEFAULT 'free',
    attacker_llm_model     TEXT,
    attacker_tokens_monthly_cap BIGINT,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by             UUID
);
"""

_MIGRATIONS_CAMPAIGNS: list = []
_MIGRATIONS_FINDINGS: list = []
_MIGRATIONS_POLICY = [
    # Phase 3.5.A — tenant-level attacker-LLM override + token cap.
    # Both nullable so missing values fall back to env defaults.
    "ALTER TABLE prov_schema.kya_redteam_tenant_policy "
    "  ADD COLUMN IF NOT EXISTS attacker_llm_model TEXT;",
    "ALTER TABLE prov_schema.kya_redteam_tenant_policy "
    "  ADD COLUMN IF NOT EXISTS attacker_tokens_monthly_cap BIGINT;",
]

_ENSURED_ENGINES: set[int] = set()


def ensure_tables(db) -> None:
    """Idempotent — runs once per engine. Dialect-aware via _legacy_tables.
    Same portable Table objects used on PG/SQLite/DuckDB/MySQL."""
    try:
        bind = db.get_bind()
        engine_key = id(bind.engine if hasattr(bind, "engine") else bind)
    except Exception:
        engine_key = -1

    if engine_key in _ENSURED_ENGINES:
        return
    try:
        from kya._legacy_tables import (
            create_legacy_tables,
            kya_redteam_campaigns,
            kya_redteam_findings,
            kya_redteam_tenant_policy,
        )

        create_legacy_tables(
            db,
            [
                kya_redteam_campaigns,
                kya_redteam_findings,
                kya_redteam_tenant_policy,
            ],
        )
        apply_migrations(db, "kya_redteam_campaigns", _MIGRATIONS_CAMPAIGNS)
        apply_migrations(db, "kya_redteam_findings", _MIGRATIONS_FINDINGS)
        apply_migrations(db, "kya_redteam_tenant_policy", _MIGRATIONS_POLICY)
        db.commit()
        _ENSURED_ENGINES.add(engine_key)
    except Exception as exc:
        logger.warning("[KYA-REDTEAM] ensure_tables failed: %s", exc)
        db.rollback()


# ── Validation helpers ──────────────────────────────────────────────

def _validate_enum(value: str, valid: tuple, field: str) -> None:
    if value not in valid:
        raise ValueError(f"{field} must be one of {valid}, got '{value}'")


# ── Campaign CRUD ───────────────────────────────────────────────────

def create_campaign(
    db, tenant_id: str, agent_key: str, name: str,
    *,
    orchestrator_kind: str,
    scorer_kind: str,
    description: Optional[str] = None,
    dataset: Optional[str] = None,
    attacker_llm: Optional[str] = None,
    converters: Optional[list] = None,
    schedule_cron: Optional[str] = None,
    budget_max_prompts: int = 100,
    threshold: float = 0.5,
    enabled: bool = True,
    tier_required: str = "free",
    auto_incident_mode: str = "never",
    created_by: Optional[str] = None,
) -> dict:
    """Create a red-team campaign. Returns the inserted row."""
    _validate_enum(orchestrator_kind, VALID_ORCHESTRATORS, "orchestrator_kind")
    _validate_enum(scorer_kind, VALID_SCORERS, "scorer_kind")
    _validate_enum(tier_required, VALID_TIERS, "tier_required")
    _validate_enum(auto_incident_mode, VALID_AUTO_INCIDENT_MODES, "auto_incident_mode")
    # The campaign's declared tier must be sufficient for its orchestrator.
    # We enforce this at write-time so a misconfigured campaign can't sit
    # in the DB waiting to fail at run-time.
    floor = _ORCHESTRATOR_MIN_TIER.get(orchestrator_kind, "free")
    if _TIER_RANK[tier_required] < _TIER_RANK[floor]:
        raise ValueError(
            f"orchestrator '{orchestrator_kind}' requires tier '{floor}' or higher; "
            f"got tier_required='{tier_required}'"
        )
    ensure_tables(db)
    from datetime import datetime, timezone
    from kya._dialect_helpers import insert_returning_id
    from kya._legacy_tables import kya_redteam_campaigns

    now_utc = datetime.now(timezone.utc)
    values = {
        "tenant_id": tenant_id, "agent_key": agent_key, "name": name,
        "description": description,
        "orchestrator_kind": orchestrator_kind, "scorer_kind": scorer_kind,
        "dataset": dataset, "attacker_llm": attacker_llm,
        "converters": converters or [],
        "schedule_cron": schedule_cron,
        "budget_max_prompts": budget_max_prompts,
        "threshold": threshold,
        "enabled": enabled,
        "tier_required": tier_required,
        "auto_incident_mode": auto_incident_mode,
        "created_by": created_by,
        "created_at": now_utc,
        "updated_at": now_utc,
    }
    new_id = insert_returning_id(db, kya_redteam_campaigns, values)
    db.commit()
    return {
        "id": new_id,
        "tenant_id": tenant_id,
        "agent_key": agent_key,
        "name": name,
        "description": description,
        "orchestrator_kind": orchestrator_kind,
        "scorer_kind": scorer_kind,
        "dataset": dataset,
        "attacker_llm": attacker_llm,
        "converters": converters or [],
        "schedule_cron": schedule_cron,
        "budget_max_prompts": budget_max_prompts,
        "threshold": threshold,
        "enabled": enabled,
        "tier_required": tier_required,
        "auto_incident_mode": auto_incident_mode,
        "created_at": now_utc,
    }


def _row_to_campaign(r) -> dict:
    return {
        "id": r[0],
        "tenant_id": str(r[1]),
        "agent_key": r[2],
        "name": r[3],
        "description": r[4],
        "orchestrator_kind": r[5],
        "scorer_kind": r[6],
        "dataset": r[7],
        "attacker_llm": r[8],
        "converters": r[9] or [],
        "schedule_cron": r[10],
        "budget_max_prompts": r[11],
        "threshold": float(r[12]) if r[12] is not None else None,
        "enabled": r[13],
        "tier_required": r[14],
        "auto_incident_mode": r[15],
        "last_run_at": r[16],
        "last_run_status": r[17],
        "last_run_finding_count": r[18],
        "next_run_at": r[19],
        "created_by": str(r[20]) if r[20] else None,
        "created_at": r[21],
        "updated_at": r[22],
    }


_SELECT_CAMPAIGN_COLS = (
    "id, tenant_id, agent_key, name, description, "
    "orchestrator_kind, scorer_kind, dataset, attacker_llm, converters, "
    "schedule_cron, budget_max_prompts, threshold, enabled, tier_required, "
    "auto_incident_mode, last_run_at, last_run_status, last_run_finding_count, "
    "next_run_at, created_by, created_at, updated_at"
)


def list_campaigns(db, tenant_id: str, agent_key: Optional[str] = None) -> list[dict]:
    ensure_tables(db)
    if agent_key:
        rows = db.execute(
            text(
                f"SELECT {_SELECT_CAMPAIGN_COLS} "
                "FROM prov_schema.kya_redteam_campaigns "
                "WHERE tenant_id = (:tid)::uuid AND agent_key = :ak "
                "ORDER BY id DESC"
            ),
            {"tid": tenant_id, "ak": agent_key},
        ).fetchall()
    else:
        rows = db.execute(
            text(
                f"SELECT {_SELECT_CAMPAIGN_COLS} "
                "FROM prov_schema.kya_redteam_campaigns "
                "WHERE tenant_id = (:tid)::uuid "
                "ORDER BY id DESC"
            ),
            {"tid": tenant_id},
        ).fetchall()
    return [_row_to_campaign(r) for r in rows]


def get_campaign(db, tenant_id: str, campaign_id: int) -> Optional[dict]:
    ensure_tables(db)
    row = db.execute(
        text(
            f"SELECT {_SELECT_CAMPAIGN_COLS} "
            "FROM prov_schema.kya_redteam_campaigns "
            "WHERE tenant_id = (:tid)::uuid AND id = :cid"
        ),
        {"tid": tenant_id, "cid": campaign_id},
    ).fetchone()
    return _row_to_campaign(row) if row else None


_MUTABLE_FIELDS = {
    "name", "description", "dataset", "attacker_llm", "converters",
    "schedule_cron", "budget_max_prompts", "threshold", "enabled",
    "auto_incident_mode", "last_run_at", "last_run_status",
    "last_run_finding_count", "next_run_at",
}


def update_campaign(db, tenant_id: str, campaign_id: int, **patch) -> Optional[dict]:
    """Patch-update mutable fields. Returns the updated row or None if
    no campaign matched. orchestrator_kind / scorer_kind / tier_required
    are immutable post-create — create a new campaign instead."""
    ensure_tables(db)
    if not patch:
        return get_campaign(db, tenant_id, campaign_id)
    if "auto_incident_mode" in patch:
        _validate_enum(patch["auto_incident_mode"], VALID_AUTO_INCIDENT_MODES,
                       "auto_incident_mode")
    set_clauses = []
    params: dict[str, Any] = {"tid": tenant_id, "cid": campaign_id}
    for k, v in patch.items():
        if k not in _MUTABLE_FIELDS:
            continue
        if k == "converters":
            set_clauses.append(f"{k} = CAST(:{k} AS JSONB)")
            params[k] = _json.dumps(v or [])
        else:
            set_clauses.append(f"{k} = :{k}")
            params[k] = v
    if not set_clauses:
        return get_campaign(db, tenant_id, campaign_id)
    set_clauses.append("updated_at = now()")
    db.execute(
        text(
            "UPDATE prov_schema.kya_redteam_campaigns "
            f"SET {', '.join(set_clauses)} "
            "WHERE tenant_id = (:tid)::uuid AND id = :cid"
        ),
        params,
    )
    db.commit()
    return get_campaign(db, tenant_id, campaign_id)


def delete_campaign(db, tenant_id: str, campaign_id: int) -> bool:
    """Delete a campaign. Findings rows have ON DELETE SET NULL on
    campaign_id so historical findings survive (a regulator pulling an
    evidence pack later still sees the finding, just without its
    originating campaign definition).
    """
    ensure_tables(db)
    result = db.execute(
        text(
            "DELETE FROM prov_schema.kya_redteam_campaigns "
            "WHERE tenant_id = (:tid)::uuid AND id = :cid"
        ),
        {"tid": tenant_id, "cid": campaign_id},
    )
    db.commit()
    return (result.rowcount or 0) > 0


# ── Findings ────────────────────────────────────────────────────────

_FINDINGS_COUNTER = None


def _ensure_findings_counter():
    global _FINDINGS_COUNTER
    if _FINDINGS_COUNTER is not None:
        return
    try:
        from prometheus_client import Counter
        try:
            _FINDINGS_COUNTER = Counter(
                "veldt_kya_redteam_findings",
                "Red-team findings persisted. The campaign-runs counter "
                "tells you how often we tested; this tells you how many "
                "times the defender lost.",
                ["tenant_id", "agent_key", "severity",
                 "attack_category", "evidence_source"],
            )
        except ValueError:
            from prometheus_client import REGISTRY
            _FINDINGS_COUNTER = REGISTRY._names_to_collectors.get(
                "veldt_kya_redteam_findings"
            )
    except ImportError:
        pass


def record_finding(
    db, tenant_id: str,
    *,
    campaign_id: Optional[int],
    run_id: str,
    agent_key: str,
    orchestrator: Optional[str] = None,
    attack_category: Optional[str] = None,
    finding_class: Optional[str] = None,
    severity: str = "medium",
    score: Optional[float] = None,
    prompt_redacted: Optional[str] = None,
    response_redacted: Optional[str] = None,
    conversation_redacted: Optional[list] = None,
    pyrit_memory_id: Optional[str] = None,
    evidence_source: str = "pyrit",
    posted_event_id: Optional[int] = None,
) -> int:
    """Persist a single finding. Returns the new finding id.

    Also fires the veldt_kya_redteam_findings counter so Grafana can
    chart finding rate by (severity, attack_category, evidence_source)
    without joining against the postgres findings table.
    """
    _validate_enum(severity, VALID_SEVERITIES, "severity")
    ensure_tables(db)
    _ensure_findings_counter()
    from kya._dialect_helpers import insert_returning_id
    from kya._legacy_tables import kya_redteam_findings
    new_id = insert_returning_id(db, kya_redteam_findings, {
        "tenant_id": tenant_id,
        "campaign_id": campaign_id,
        "run_id": run_id,
        "agent_key": agent_key,
        "orchestrator": orchestrator,
        "attack_category": attack_category,
        "finding_class": finding_class,
        "severity": severity,
        "score": score,
        "prompt_redacted": prompt_redacted,
        "response_redacted": response_redacted,
        "conversation_redacted": conversation_redacted or [],
        "pyrit_memory_id": pyrit_memory_id,
        "evidence_source": evidence_source,
        "posted_event_id": posted_event_id,
    })
    row = (new_id,)  # back-compat for the existing tail emit code
    db.commit()
    # Fire the findings counter AFTER commit so the metric reflects
    # durably-written state, not in-flight INSERTs.
    if _FINDINGS_COUNTER is not None:
        try:
            _FINDINGS_COUNTER.labels(
                tenant_id=tenant_id or "unknown",
                agent_key=agent_key or "unknown",
                severity=severity or "medium",
                attack_category=attack_category or "unknown",
                evidence_source=evidence_source or "unknown",
            ).inc()
        except Exception as exc:
            logger.debug("[REDTEAM-METRICS] findings counter inc failed: %s", exc)
    # Outbound webhook emit — fire-and-forget to operator-configured
    # SIEM / Lakera / Datadog / Splunk / custom destinations.
    try:
        from kya.external_emitters import emit_event
        emit_event("finding", {
            "id": int(row[0]),
            "tenant_id": tenant_id,
            "campaign_id": campaign_id,
            "run_id": run_id,
            "agent_key": agent_key,
            "orchestrator": orchestrator,
            "attack_category": attack_category,
            "finding_class": finding_class,
            "severity": severity,
            "score": float(score) if score is not None else None,
            "evidence_source": evidence_source,
            "prompt_redacted": (prompt_redacted or "")[:1000],
            "response_redacted": (response_redacted or "")[:1000],
        }, tenant_id=tenant_id)
    except Exception as exc:
        logger.debug("[REDTEAM-EMIT] outbound emit skipped: %s", exc)
    return int(row[0])


_SELECT_FINDING_COLS = (
    "id, tenant_id, campaign_id, run_id, agent_key, orchestrator, "
    "attack_category, finding_class, severity, score, "
    "prompt_redacted, response_redacted, conversation_redacted, "
    "pyrit_memory_id, evidence_source, posted_event_id, "
    "promoted_incident_id, created_at"
)


def _row_to_finding(r) -> dict:
    return {
        "id": r[0],
        "tenant_id": str(r[1]),
        "campaign_id": r[2],
        "run_id": str(r[3]) if r[3] else None,
        "agent_key": r[4],
        "orchestrator": r[5],
        "attack_category": r[6],
        "finding_class": r[7],
        "severity": r[8],
        "score": float(r[9]) if r[9] is not None else None,
        "prompt_redacted": r[10],
        "response_redacted": r[11],
        "conversation_redacted": r[12] or [],
        "pyrit_memory_id": r[13],
        "evidence_source": r[14],
        "posted_event_id": r[15],
        "promoted_incident_id": r[16],
        "created_at": r[17],
    }


def get_finding(db, tenant_id: str, finding_id: int) -> Optional[dict]:
    ensure_tables(db)
    row = db.execute(
        text(
            f"SELECT {_SELECT_FINDING_COLS} "
            "FROM prov_schema.kya_redteam_findings "
            "WHERE tenant_id = (:tid)::uuid AND id = :fid"
        ),
        {"tid": tenant_id, "fid": finding_id},
    ).fetchone()
    return _row_to_finding(row) if row else None


def list_findings(
    db, tenant_id: str,
    *,
    campaign_id: Optional[int] = None,
    run_id: Optional[str] = None,
    agent_key: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    ensure_tables(db)
    clauses = ["tenant_id = (:tid)::uuid"]
    params: dict[str, Any] = {"tid": tenant_id, "lim": min(max(limit, 1), 500)}
    if campaign_id is not None:
        clauses.append("campaign_id = :cid")
        params["cid"] = campaign_id
    if run_id:
        clauses.append("run_id = (:rid)::uuid")
        params["rid"] = run_id
    if agent_key:
        clauses.append("agent_key = :ak")
        params["ak"] = agent_key
    if severity:
        clauses.append("severity = :sev")
        params["sev"] = severity
    rows = db.execute(
        text(
            f"SELECT {_SELECT_FINDING_COLS} "
            "FROM prov_schema.kya_redteam_findings "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY id DESC LIMIT :lim"
        ),
        params,
    ).fetchall()
    return [_row_to_finding(r) for r in rows]


# ── Tenant policy ───────────────────────────────────────────────────

def get_tenant_policy(db, tenant_id: str) -> dict:
    """Return the tenant's policy row, creating defaults if missing."""
    ensure_tables(db)
    from sqlalchemy import select
    from kya._legacy_tables import kya_redteam_tenant_policy as tbl
    row = db.execute(
        select(
            tbl.c.max_auto_incident_mode, tbl.c.budget_monthly_prompts,
            tbl.c.redteam_tier, tbl.c.attacker_llm_model,
            tbl.c.attacker_tokens_monthly_cap, tbl.c.updated_at,
        ).where(tbl.c.tenant_id == tenant_id)
    ).fetchone()
    if not row:
        return {
            "tenant_id": tenant_id,
            "max_auto_incident_mode": "never",
            "budget_monthly_prompts": 10000,
            "redteam_tier": "free",
            "attacker_llm_model": None,
            "attacker_tokens_monthly_cap": None,
            "updated_at": None,
        }
    return {
        "tenant_id": tenant_id,
        "max_auto_incident_mode": row[0],
        "budget_monthly_prompts": int(row[1]),
        "redteam_tier": row[2],
        "attacker_llm_model": row[3],
        "attacker_tokens_monthly_cap": int(row[4]) if row[4] is not None else None,
        "updated_at": row[5],
    }


def set_tenant_policy(
    db, tenant_id: str,
    *,
    max_auto_incident_mode: Optional[str] = None,
    budget_monthly_prompts: Optional[int] = None,
    redteam_tier: Optional[str] = None,
    attacker_llm_model: Optional[str] = None,
    attacker_tokens_monthly_cap: Optional[int] = None,
    updated_by: Optional[str] = None,
) -> dict:
    """Upsert the tenant's policy. Only non-None fields are written.

    `attacker_llm_model` (Phase 3.5.A): per-tenant override for the
    LLM that drives multi-turn campaigns. Format is LiteLLM's
    `provider/model` (e.g. `anthropic/claude-sonnet-4-6`). When set,
    multi_turn.run_multi_turn picks this over the env defaults — letting
    a BYOK Premium tenant use their own model without changing the
    container env.

    `attacker_tokens_monthly_cap`: per-tenant override for the monthly
    attacker+judge token cap. None = use platform default
    (KYA_REDTEAM_ATTACKER_TOKENS_MONTHLY_CAP_DEFAULT).
    """
    if max_auto_incident_mode is not None:
        _validate_enum(max_auto_incident_mode, VALID_AUTO_INCIDENT_MODES,
                       "max_auto_incident_mode")
    if redteam_tier is not None:
        _validate_enum(redteam_tier, VALID_TIERS, "redteam_tier")
    ensure_tables(db)
    current = get_tenant_policy(db, tenant_id)
    # Allow explicit empty-string to CLEAR the override; None means leave alone.
    if attacker_llm_model is not None and attacker_llm_model == "":
        new_attacker_llm = None
    elif attacker_llm_model is not None:
        new_attacker_llm = attacker_llm_model
    else:
        new_attacker_llm = current.get("attacker_llm_model")
    new = {
        "max_auto_incident_mode": max_auto_incident_mode or current["max_auto_incident_mode"],
        "budget_monthly_prompts": budget_monthly_prompts if budget_monthly_prompts is not None else current["budget_monthly_prompts"],
        "redteam_tier": redteam_tier or current["redteam_tier"],
        "attacker_llm_model": new_attacker_llm,
        "attacker_tokens_monthly_cap": (
            attacker_tokens_monthly_cap if attacker_tokens_monthly_cap is not None
            else current.get("attacker_tokens_monthly_cap")
        ),
    }
    from datetime import datetime, timezone
    from kya._dialect_helpers import portable_upsert
    from kya._legacy_tables import kya_redteam_tenant_policy
    now_utc = datetime.now(timezone.utc)
    portable_upsert(
        db,
        kya_redteam_tenant_policy,
        {
            "tenant_id": tenant_id,
            "max_auto_incident_mode": new["max_auto_incident_mode"],
            "budget_monthly_prompts": new["budget_monthly_prompts"],
            "redteam_tier": new["redteam_tier"],
            "attacker_llm_model": new["attacker_llm_model"],
            "attacker_tokens_monthly_cap": new["attacker_tokens_monthly_cap"],
            "updated_by": updated_by,
            "updated_at": now_utc,
        },
        conflict_cols=("tenant_id",),
        update_cols=(
            "max_auto_incident_mode", "budget_monthly_prompts", "redteam_tier",
            "attacker_llm_model", "attacker_tokens_monthly_cap",
            "updated_by", "updated_at",
        ),
    )
    db.commit()
    return {"tenant_id": tenant_id, **new}


def effective_auto_incident_mode(campaign_mode: str, tenant_policy: dict) -> str:
    """Resolve the effective auto-incident mode for a finding.

    The tenant policy `max_auto_incident_mode` is a CEILING: the campaign's
    own setting can be more conservative (`never` when ceiling is `always`)
    but cannot promote beyond the ceiling. This prevents an over-eager
    team from flooding the incident system on a tenant where the admin
    has explicitly capped auto-promotion.
    """
    ceiling = tenant_policy.get("max_auto_incident_mode", "never")
    rank = {"never": 0, "critical_only": 1, "always": 2}
    cr, mr = rank.get(ceiling, 0), rank.get(campaign_mode, 0)
    return campaign_mode if mr <= cr else ceiling
