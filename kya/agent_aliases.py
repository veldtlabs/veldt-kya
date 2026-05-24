"""Agent alias table — explicit name-mapping for KYA principals.

WHY THIS EXISTS
---------------
The bridge mapper's `normalize_agent_key` handles the *common* case
(hyphens / dots / mixed case → underscored lowercase). That's automatic
and covers ~80% of OTel emitters.

This table handles the rest:
  - Semantic renames: `legacy-bot-2023` → `analyst_v4` (no regex can
    derive that mapping)
  - Version collapsing: `agent-v1`, `agent-v2`, `agent-v3` → `agent`
  - Cross-system imports: a customer's internal agent id `bot_abc_123`
    in their SIEM mapping to KYA's `customer_service_bot`
  - Multi-source unification: same logical agent emits OTel from two
    different services (`legacy-frontend-bot`, `new-backend-bot`),
    both should roll up to one trust score

CONTRACT
--------
- Unique per tenant on (alias) — one alias maps to one canonical.
- Canonical agent_key doesn't have to exist yet — forward mapping OK.
- Aliases are bidirectional in the dashboard view (the card for
  canonical_agent_key shows all aliases pointing to it).
- Resolution is done at KYA HTTP-event ingest time; the alias is rewritten
  to canonical BEFORE write, so storage stays normalized.
"""

from __future__ import annotations

import json as _json
import logging

try:
    from sqlalchemy import text
except ImportError:

    def text(s):  # type: ignore
        raise RuntimeError("kya.agent_aliases requires SQLAlchemy")


from ._migrations import apply_migrations

logger = logging.getLogger(__name__)


_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_agent_aliases (
    id                   SERIAL PRIMARY KEY,
    tenant_id            UUID NOT NULL,
    alias                TEXT NOT NULL,
    canonical_agent_key  VARCHAR(50) NOT NULL,
    note                 TEXT,
    created_by           UUID,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, alias)
);
"""

_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS idx_kya_agent_aliases_canonical
    ON prov_schema.kya_agent_aliases (tenant_id, canonical_agent_key);
"""

_MIGRATIONS = [
    # additive evolution slot
]

_ENSURED_ENGINES: set[int] = set()


def ensure_table(db) -> None:
    """Idempotent — runs once per engine. Dialect-aware via _legacy_tables.

    Per-engine memoization (not process-global) lets a single process
    safely run init_storage against multiple distinct engines (different
    backends, fresh test databases) without the second engine being
    silently skipped if the first one succeeded.
    """
    try:
        bind = db.get_bind()
        engine_key = id(bind.engine if hasattr(bind, "engine") else bind)
    except Exception:
        engine_key = -1

    if engine_key in _ENSURED_ENGINES:
        return
    try:
        from ._legacy_tables import create_legacy_tables, kya_agent_aliases

        create_legacy_tables(db, [kya_agent_aliases])
        apply_migrations(db, "kya_agent_aliases", _MIGRATIONS)
        db.commit()
        _ENSURED_ENGINES.add(engine_key)
    except Exception as exc:
        logger.warning("[KYA-ALIAS] ensure_table failed: %s", exc)
        db.rollback()


def resolve_alias(db, tenant_id: str, alias: str) -> str | None:
    """Look up an alias and return the canonical agent_key, or None if no
    alias is registered. Falls back gracefully on DB error."""
    if not alias:
        return None
    try:
        ensure_table(db)
        # SA Core for cross-dialect (raw text with prov_schema. + ::uuid
        # is PG-only).
        from sqlalchemy import and_
        from sqlalchemy import select as sa_select

        from ._legacy_tables import kya_agent_aliases as _AL
        row = db.execute(
            sa_select(_AL.c.canonical_agent_key).where(
                and_(_AL.c.tenant_id == tenant_id, _AL.c.alias == alias)
            )
        ).fetchone()
        return row[0] if row else None
    except Exception as exc:
        logger.warning("[KYA-ALIAS] resolve failed (alias=%s): %s", alias, exc)
        return None


def add_alias(
    db,
    tenant_id: str,
    alias: str,
    canonical_agent_key: str,
    note: str | None = None,
    user_id: str | None = None,
) -> dict:
    """Create or update an alias. Returns the stored row.

    Cross-backend: portable_upsert dispatches to the right ON CONFLICT
    syntax for PG / SQLite / DuckDB / MySQL.
    """
    from ._dialect_helpers import portable_upsert
    from ._legacy_tables import kya_agent_aliases

    ensure_table(db)
    portable_upsert(
        db,
        kya_agent_aliases,
        {
            "tenant_id": tenant_id,
            "alias": alias,
            "canonical_agent_key": canonical_agent_key,
            "note": note,
            "created_by": user_id,
        },
        conflict_cols=("tenant_id", "alias"),
        update_cols=("canonical_agent_key", "note"),
    )
    db.commit()
    return {
        "alias": alias,
        "canonical_agent_key": canonical_agent_key,
        "note": note,
    }


def list_aliases(db, tenant_id: str, canonical_agent_key: str) -> list[dict]:
    """All aliases pointing at this canonical_agent_key. For the card UI.
    SA Core for cross-dialect portability."""
    ensure_table(db)
    from sqlalchemy import and_
    from sqlalchemy import select as sa_select

    from ._legacy_tables import kya_agent_aliases as _AL
    rows = db.execute(
        sa_select(_AL.c.id, _AL.c.alias, _AL.c.note, _AL.c.created_at).where(
            and_(_AL.c.tenant_id == tenant_id, _AL.c.canonical_agent_key == canonical_agent_key)
        ).order_by(_AL.c.created_at.desc())
    ).fetchall()
    return [{"id": r[0], "alias": r[1], "note": r[2], "created_at": r[3]} for r in rows]


def migrate_principals_for_aliases(db, tenant_id: str) -> dict:
    """One-shot data migration: rewrite historical principal rows that
    were stored under alias keys to their canonical agent_key.

    Why: the bridge's `/events/rogue` resolver rewrites *new* events
    from alias->canonical, but principal rows written *before* the
    alias existed are stuck under the alias key. This walks every
    registered alias and merges the historical rows into the canonical
    principal.

    Merge semantics:
      - signal_counts: additive merge ({oos_tool: 5} + {oos_tool: 2} = {oos_tool: 7})
      - trust_score: keep the LOWER (more conservative — rogue history shouldn't
        recover just because of a rename)
      - last_signal_at: keep the MAX
    Then deletes the alias-keyed row.

    Idempotent — safe to re-run.
    """
    ensure_table(db)
    aliases = db.execute(
        text(
            "SELECT alias, canonical_agent_key FROM prov_schema.kya_agent_aliases "
            "WHERE tenant_id = (:tid)::uuid"
        ),
        {"tid": tenant_id},
    ).fetchall()

    report = {"checked": 0, "migrated": 0, "details": []}
    for alias, canonical in aliases:
        report["checked"] += 1
        # Look up source row (alias-keyed)
        src = db.execute(
            text(
                "SELECT trust_score, signal_counts, last_signal_at, principal_kind "
                "FROM prov_schema.kya_principal_trust "
                "WHERE tenant_id = (:tid)::uuid AND principal_id = :pid"
            ),
            {"tid": tenant_id, "pid": alias},
        ).fetchone()
        if not src:
            continue
        # Look up canonical row
        dst = db.execute(
            text(
                "SELECT trust_score, signal_counts, last_signal_at "
                "FROM prov_schema.kya_principal_trust "
                "WHERE tenant_id = (:tid)::uuid AND principal_id = :pid"
            ),
            {"tid": tenant_id, "pid": canonical},
        ).fetchone()
        # Merge signal_counts (additive)
        src_counts = src[1] or {}
        dst_counts = (dst[1] if dst else {}) or {}
        merged = dict(dst_counts)
        for k, v in src_counts.items():
            merged[k] = (merged.get(k) or 0) + (v or 0)
        # Lower trust wins
        merged_trust = min(
            src[0] if src[0] is not None else 50,
            (dst[0] if dst and dst[0] is not None else 50),
        )
        # Latest signal time wins
        merged_last = src[2]
        if dst and dst[2]:
            merged_last = max(merged_last or dst[2], dst[2])

        if dst:
            db.execute(
                text(
                    "UPDATE prov_schema.kya_principal_trust "
                    "SET trust_score = :ts, signal_counts = (:sc)::jsonb, "
                    "    last_signal_at = :ls, updated_at = now() "
                    "WHERE tenant_id = (:tid)::uuid AND principal_id = :pid"
                ),
                {
                    "tid": tenant_id,
                    "pid": canonical,
                    "ts": merged_trust,
                    "sc": _json.dumps(merged),
                    "ls": merged_last,
                },
            )
        else:
            db.execute(
                text(
                    "INSERT INTO prov_schema.kya_principal_trust "
                    "  (tenant_id, principal_kind, principal_id, trust_score, "
                    "   signal_counts, last_signal_at) "
                    "VALUES ((:tid)::uuid, :kind, :pid, :ts, (:sc)::jsonb, :ls)"
                ),
                {
                    "tid": tenant_id,
                    "kind": src[3] or "agent",
                    "pid": canonical,
                    "ts": merged_trust,
                    "sc": _json.dumps(merged),
                    "ls": merged_last,
                },
            )
        # Drop the alias-keyed row
        db.execute(
            text(
                "DELETE FROM prov_schema.kya_principal_trust "
                "WHERE tenant_id = (:tid)::uuid AND principal_id = :pid"
            ),
            {"tid": tenant_id, "pid": alias},
        )
        db.commit()
        report["migrated"] += 1
        report["details"].append(
            {
                "from": alias,
                "to": canonical,
                "merged_signal_counts": merged,
                "merged_trust": merged_trust,
            }
        )
    return report


def delete_alias(db, tenant_id: str, alias_id: int) -> bool:
    """Remove an alias by id. Returns True if a row was deleted.
    SA Core for cross-dialect portability."""
    ensure_table(db)
    from sqlalchemy import and_
    from sqlalchemy import delete as sa_delete

    from ._legacy_tables import kya_agent_aliases as _AL
    result = db.execute(
        sa_delete(_AL).where(
            and_(_AL.c.id == alias_id, _AL.c.tenant_id == tenant_id)
        )
    )
    db.commit()
    return (result.rowcount or 0) > 0
