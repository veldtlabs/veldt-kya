"""
Agent Versioning — snapshot history + rollback.

Every create/update on a custom agent records an immutable snapshot in
`agent_versions`. Used by the KYA card to surface change history and by
the UI to support rollback.

The table is intentionally append-only — rollback creates a NEW version
that copies an older one, rather than mutating history.

Backend portability
-------------------
ORM-driven DDL — SQLAlchemy emits dialect-correct types automatically:
    PostgreSQL → JSONB (indexable), schema=KYA_VERSIONS_SCHEMA (default
                 'prov_schema' for Veldt deployments)
    SQLite     → JSON (text), default schema
    MySQL      → JSON, default schema
    Oracle     → NCLOB, default schema

SDK consumers running on non-PG backends leave KYA_VERSIONS_SCHEMA unset
and get the table in their default namespace. Veldt's existing PG table
in prov_schema continues to work because create_all is idempotent.

Public API
----------
    ensure_table(db)
    snapshot_agent(db, tenant_id, agent_key, definition, created_by, note=None) -> int
    list_versions(db, tenant_id, agent_key, limit=50) -> list[dict]
    get_version(db, tenant_id, agent_key, version_no) -> dict | None
    rollback_to(db, tenant_id, agent_key, version_no, created_by) -> dict
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

# SQLAlchemy is OPTIONAL — `from kya import score_agent` works without it
# in standalone SDK installs. Versioning functions raise on first call if
# the dependency is missing.
try:
    from sqlalchemy import (
        JSON,
        DateTime,
        Index,
        Integer,
        String,
        Text,
        func,
        select,
    )
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    _HAS_SQLALCHEMY = True
except ImportError:  # pragma: no cover
    _HAS_SQLALCHEMY = False


logger = logging.getLogger(__name__)


# Schema qualifier — PG only. Empty/unset means default namespace (SQLite,
# MySQL, Oracle, or PG installs that don't use a dedicated schema).
_PG_SCHEMA = os.getenv("KYA_VERSIONS_SCHEMA", "prov_schema") or None


def _require_sqlalchemy() -> None:
    if not _HAS_SQLALCHEMY:
        raise RuntimeError(
            "kya.versioning requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


if _HAS_SQLALCHEMY:
    # JSON column → JSONB on PostgreSQL (indexable + queryable),
    # plain JSON on every other dialect. SQLA's variant system swaps the
    # type at DDL emission and bind time — application code is unchanged.
    _JsonType = JSON().with_variant(JSONB(), "postgresql")

    class _Base(DeclarativeBase):
        pass

    class AgentVersion(_Base):
        __tablename__ = "agent_versions"

        # Natural composite primary key — (tenant_id, agent_key, version_no)
        # is already unique by construction. No surrogate `id` column means
        # no dialect-specific autoincrement (SERIAL on PG, AUTOINCREMENT on
        # SQLite, IDENTITY on DuckDB) — the schema is portable as-is.
        tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
        agent_key: Mapped[str] = mapped_column(String(50), primary_key=True)
        version_no: Mapped[int] = mapped_column(Integer, primary_key=True)
        definition: Mapped[dict] = mapped_column(_JsonType, nullable=False)
        note: Mapped[str | None] = mapped_column(Text, nullable=True)
        created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)

        # Event time — when the agent definition was actually edited in the
        # source system (caller's clock). Optional: defaults to ingest time
        # if not supplied. For symmetry with kya_invocations.
        occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

        # Ingest time — when KYA's storage clock saw the row. Always
        # server-set. Named `created_at` for backward-compat with Veldt's
        # existing PG table; surfaced as `ingested_at` in return dicts so
        # new SDK consumers see the more accurate name.
        created_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        )

        __table_args__ = (
            # Lookup index — composite PK already covers (tenant, agent, ver)
            # but an explicit index documents the dominant access pattern
            # and lets PG plan the (tenant, agent) range scan cheaply.
            Index(
                "idx_agent_versions_tenant_key",
                "tenant_id",
                "agent_key",
                "version_no",
            ),
        )


def _bind_schema(bind) -> None:
    """Align the table's schema with the bound dialect. PG → _PG_SCHEMA;
    everything else → default. Mutating ``Table.schema`` is the documented
    way to retarget a declarative table at create-all time."""
    table = AgentVersion.__table__
    target = _PG_SCHEMA if bind.dialect.name == "postgresql" else None
    if table.schema != target:
        table.schema = target


def ensure_table(db) -> None:
    """Create the versions table + index if absent. Idempotent.

    Dialect-aware: PostgreSQL deployments land in `prov_schema` (override
    via KYA_VERSIONS_SCHEMA env); SQLite/MySQL/Oracle/DuckDB get the table
    in the default namespace.

    Uses the session's connection (not a fresh engine connection) so DDL
    participates in the same transaction — required by backends like
    DuckDB that disallow nested transactions.
    """
    _require_sqlalchemy()
    conn = db.connection()
    _bind_schema(conn.engine)
    _Base.metadata.create_all(bind=conn, tables=[AgentVersion.__table__])


def _next_version_no(db, tenant_id: str, agent_key: str) -> int:
    stmt = (
        select(func.coalesce(func.max(AgentVersion.version_no), 0) + 1)
        .where(AgentVersion.tenant_id == tenant_id)
        .where(AgentVersion.agent_key == agent_key)
    )
    return int(db.execute(stmt).scalar() or 1)


def snapshot_agent(
    db,
    tenant_id: str,
    agent_key: str,
    definition: dict,
    created_by: str | None = None,
    note: str | None = None,
    occurred_at: datetime | None = None,
) -> int:
    """Append a new immutable snapshot. Returns the assigned version_no.

    `occurred_at` — optional event time (when the edit actually happened
    in the source system). If absent, the snapshot row records ingest
    time only via `created_at`/`ingested_at`. Supply when replaying
    historical edits or when the source system has its own timestamp.
    """
    _require_sqlalchemy()
    ensure_table(db)

    # Concurrent snapshot writers all SELECT the same MAX(version_no)
    # and race to INSERT with the same version_no, hitting the UNIQUE
    # constraint on (tenant_id, agent_key, version_no). Retry with
    # backoff so high-throughput agent fleets don't silently lose
    # versions under contention. The race window per attempt is small
    # so a handful of retries lands the write.
    from sqlalchemy.exc import IntegrityError
    import random
    import time as _time

    last_exc: Exception | None = None
    version_no: int = 1
    for attempt in range(30):
        version_no = _next_version_no(db, tenant_id, agent_key)
        db.add(
            AgentVersion(
                tenant_id=tenant_id,
                agent_key=agent_key,
                version_no=version_no,
                definition=definition,
                note=note,
                created_by=created_by,
                occurred_at=occurred_at,
            )
        )
        try:
            db.commit()
            break
        except IntegrityError as exc:
            last_exc = exc
            db.rollback()
            if attempt == 29:
                raise
            # Cap backoff at ~50ms so retries don't take forever under
            # heavy contention; jitter so workers don't synchronize.
            _time.sleep(min(0.050, 0.001 * (2 ** attempt))
                        + random.uniform(0, 0.002))
    logger.info(
        "[AGENT_VERSION] tenant=%s key=%s v%d (%s)",
        tenant_id,
        agent_key,
        version_no,
        note or "no note",
    )
    try:
        from . import _emit, telemetry
        telemetry.record_event("snapshot_agent")
        if _emit.is_enabled():
            _emit.emit(
                "agent_versions",
                _emit.safe_row({
                    "tenant_id": tenant_id,
                    "agent_key": agent_key,
                    "version_no": version_no,
                    "definition": definition,
                    "note": note,
                    "created_by": created_by,
                    "occurred_at": occurred_at,
                }),
            )
    except Exception:
        pass
    return version_no


def list_versions(db, tenant_id: str, agent_key: str, limit: int = 50) -> list[dict]:
    """Return versions newest-first, capped at `limit`."""
    _require_sqlalchemy()
    _bind_schema(db.get_bind())
    stmt = (
        select(
            AgentVersion.version_no,
            AgentVersion.note,
            AgentVersion.created_by,
            AgentVersion.occurred_at,
            AgentVersion.created_at,
        )
        .where(AgentVersion.tenant_id == tenant_id)
        .where(AgentVersion.agent_key == agent_key)
        .order_by(AgentVersion.version_no.desc())
        .limit(limit)
    )
    return [
        {
            "version_no": row.version_no,
            "note": row.note,
            "created_by": str(row.created_by) if row.created_by else None,
            "occurred_at": _to_iso(row.occurred_at),
            "ingested_at": _to_iso(row.created_at),
            "created_at": _to_iso(row.created_at),  # legacy alias
            "ingest_lag_ms": _lag_ms(row.occurred_at, row.created_at),
        }
        for row in db.execute(stmt).all()
    ]


def get_version(db, tenant_id: str, agent_key: str, version_no: int) -> dict | None:
    """Return the snapshot of a specific version (full definition included)."""
    _require_sqlalchemy()
    _bind_schema(db.get_bind())
    stmt = (
        select(AgentVersion)
        .where(AgentVersion.tenant_id == tenant_id)
        .where(AgentVersion.agent_key == agent_key)
        .where(AgentVersion.version_no == version_no)
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        return None
    return {
        "version_no": row.version_no,
        "definition": _coerce_definition(row.definition),
        "note": row.note,
        "created_by": str(row.created_by) if row.created_by else None,
        "occurred_at": _to_iso(row.occurred_at),
        "ingested_at": _to_iso(row.created_at),
        "created_at": _to_iso(row.created_at),  # legacy alias
        "ingest_lag_ms": _lag_ms(row.occurred_at, row.created_at),
    }


def rollback_to(
    db,
    tenant_id: str,
    agent_key: str,
    version_no: int,
    created_by: str | None = None,
) -> dict:
    """Restore an older version's definition as a NEW snapshot.

    History stays append-only — rolling back from v5 to v3 creates v6 whose
    definition matches v3, with note="rolled back from v3". Callers MUST
    also apply the restored definition to the live custom_agents row
    (this helper only handles the version table).
    """
    _require_sqlalchemy()
    target = get_version(db, tenant_id, agent_key, version_no)
    if not target:
        raise ValueError(f"version {version_no} not found for {agent_key}")
    new_vno = snapshot_agent(
        db=db,
        tenant_id=tenant_id,
        agent_key=agent_key,
        definition=target["definition"],
        created_by=created_by,
        note=f"rolled back from v{version_no}",
    )
    return {
        "version_no": new_vno,
        "definition": target["definition"],
        "note": f"rolled back from v{version_no}",
    }


def _coerce_definition(raw: Any) -> dict:
    """JSON column returns dict (JSONB / SQLA-decoded JSON) or str (some
    drivers return raw text). Normalize to dict."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


def _to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        # SQLite stores tz-naive even when column declares timezone=True.
        # Treat naive timestamps from the server clock as UTC.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _lag_ms(occurred_at: datetime | None, ingested_at: datetime | None) -> int | None:
    """Compute ingested_at - occurred_at in milliseconds. Returns None if
    occurred_at was not supplied (caller didn't record event time)."""
    if occurred_at is None or ingested_at is None:
        return None
    occ = occurred_at if occurred_at.tzinfo else occurred_at.replace(tzinfo=timezone.utc)
    ing = ingested_at if ingested_at.tzinfo else ingested_at.replace(tzinfo=timezone.utc)
    return int((ing - occ).total_seconds() * 1000)
