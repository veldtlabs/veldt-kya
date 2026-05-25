"""
Invocation tracking — per-call mode + outcome + event/ingest timeline.

Captures the per-call mode that was actually exercised plus the outcome.
Solves three problems:

1. CONFIG vs ACTUAL gap — an agent configured `human_loop="hybrid"` might
   actually run autonomous 90% of the time. EU AI Act Art. 14 wants
   evidence of EXERCISED oversight, not just declared mode.

2. PARALLEL multi-agent visibility — `parent_invocation_id` + `correlation_id`
   let an operator reconstruct the call tree across simultaneous agents.

3. EVENT-TIME vs INGEST-TIME separation — `occurred_at` is when the agent
   says the invocation happened (caller wall-clock); `ingested_at` is when
   KYA's storage captured it (server wall-clock). The delta
   `ingested_at - occurred_at` exposes pipeline lag, clock skew, or — with
   independent OTel span correlation — tampering. Without two timestamps
   you lose the audit signal.

Storage
-------
kya_invocations:
    id, tenant_id, agent_key, principal_kind, principal_id,
    mode, outcome, duration_ms,
    parent_invocation_id, correlation_id,
    occurred_at,   -- caller-supplied event time
    ingested_at,   -- server-side now() at INSERT (always)
    started_at,    -- optional fine-grained agent-runtime start
    ended_at       -- optional fine-grained agent-runtime end

Portable across PostgreSQL, SQLite, DuckDB, MySQL via SQLAlchemy ORM.
"""

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from sqlalchemy import (
        BigInteger,
        DateTime,
        Index,
        Integer,
        Sequence,
        String,
        Text,
        func,
        select,
    )
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    _HAS_SQLALCHEMY = True
except ImportError:  # pragma: no cover
    _HAS_SQLALCHEMY = False


logger = logging.getLogger(__name__)


VALID_MODES = {
    "none",
    "in_the_loop",
    "hybrid",
    "on_the_loop",
    "autonomous",
    "observed",
}

VALID_OUTCOMES = {
    "success",
    "refused",
    "blocked",
    "error",
    "partial",
    "in_progress",
}


def _require_sqlalchemy() -> None:
    if not _HAS_SQLALCHEMY:
        raise RuntimeError(
            "kya.invocations requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


# Schema qualifier — PG only; SDK consumers on SQLite/MySQL/DuckDB get the
# default namespace.
_PG_SCHEMA = os.getenv("KYA_VERSIONS_SCHEMA", "prov_schema") or None


if _HAS_SQLALCHEMY:

    class _Base(DeclarativeBase):
        pass

    # Portable autoincrement via explicit Sequence + dialect-variant id type:
    #   PG       — Sequence becomes BIGSERIAL behavior (idempotent)
    #   SQLite   — Sequence is ignored; INTEGER PRIMARY KEY autoincrements
    #              via rowid alias (needs Integer, not BigInteger)
    #   MySQL    — Sequence is ignored; BIGINT AUTO_INCREMENT
    #   DuckDB   — Sequence becomes CREATE SEQUENCE + nextval() default
    #              (avoids the BIGSERIAL keyword duckdb-engine emits by
    #              default, which DuckDB rejects)
    _INV_SEQ = Sequence("kya_invocations_id_seq")

    class Invocation(_Base):
        __tablename__ = "kya_invocations"

        id: Mapped[int] = mapped_column(
            BigInteger().with_variant(Integer(), "sqlite"),
            _INV_SEQ,
            primary_key=True,
            autoincrement=True,
        )

        tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
        agent_key: Mapped[str] = mapped_column(String(100), nullable=False)
        principal_kind: Mapped[str | None] = mapped_column(String(20), nullable=True)
        principal_id: Mapped[str | None] = mapped_column(Text, nullable=True)

        mode: Mapped[str] = mapped_column(String(20), nullable=False)
        outcome: Mapped[str] = mapped_column(String(20), nullable=False)
        duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

        parent_invocation_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
        correlation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

        # Event time — caller-supplied wall-clock from the agent runtime.
        # If absent, the caller's record-time is used (still useful as a
        # lower bound on when the event happened).
        occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
        # Ingest time — KYA's storage clock at INSERT. Always server-set.
        # Delta `ingested_at - occurred_at` = pipeline-lag audit signal.
        ingested_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        )

        # Optional fine-grained timestamps from agent runtime.
        started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
        ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

        __table_args__ = (
            Index(
                "idx_kya_inv_tenant_agent_occurred",
                "tenant_id",
                "agent_key",
                "occurred_at",
            ),
            Index("idx_kya_inv_correlation", "correlation_id"),
            Index("idx_kya_inv_parent", "parent_invocation_id"),
        )


def _bind_schema(bind) -> None:
    table = Invocation.__table__
    target = _PG_SCHEMA if bind.dialect.name == "postgresql" else None
    if table.schema != target:
        table.schema = target


def ensure_invocations_table(db) -> None:
    """Create kya_invocations + indexes if absent. Idempotent.

    Schema selection is dialect-aware: PostgreSQL deployments land in
    `prov_schema` (override via KYA_VERSIONS_SCHEMA env); SQLite/MySQL/
    DuckDB get the table in the default namespace.
    """
    _require_sqlalchemy()
    conn = db.connection()
    _bind_schema(conn.engine)
    _Base.metadata.create_all(bind=conn, tables=[Invocation.__table__])


def record_invocation(
    db,
    tenant_id: str,
    agent_key: str,
    principal_kind: str | None = None,
    principal_id: str | None = None,
    mode: str = "observed",
    outcome: str = "success",
    duration_ms: int | None = None,
    parent_invocation_id: int | None = None,
    correlation_id: str | None = None,
    occurred_at: datetime | None = None,
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
) -> int:
    """Record one invocation row. Returns the new invocation id.

    Event-time semantics:
        `occurred_at`  — when the invocation actually happened in the agent's
                         clock. If you have it (OTel span start, runtime
                         hook), supply it. Defaults to UTC now (record time).
        `ingested_at`  — always server-side `now()` at INSERT.
        `started_at` / `ended_at` — optional fine-grained runtime timestamps
                         (e.g., for long-running calls where you want both
                         the configured start AND the agent-reported start).

    Multi-agent parallel pattern:
        correlation_id = same UUID across all agents in one request tree
        parent_invocation_id = the agent that delegated to this one

    For long-running calls, write `outcome="in_progress"` first then UPDATE.
    """
    if mode not in VALID_MODES:
        logger.debug("[KYA-INV] unknown mode=%s -> 'observed'", mode)
        mode = "observed"
    if outcome not in VALID_OUTCOMES:
        logger.debug("[KYA-INV] unknown outcome=%s -> 'success'", outcome)
        outcome = "success"

    _require_sqlalchemy()
    ensure_invocations_table(db)

    if occurred_at is None:
        occurred_at = datetime.now(timezone.utc)

    # If the caller supplied ended_at but not duration_ms, derive duration.
    if duration_ms is None and started_at and ended_at:
        duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    # If outcome is terminal and ended_at not provided, default to occurred_at
    # for legacy callers (matches the prior `now()` semantics).
    effective_ended_at = ended_at
    if outcome != "in_progress" and effective_ended_at is None:
        effective_ended_at = occurred_at

    row = Invocation(
        tenant_id=tenant_id,
        agent_key=agent_key,
        principal_kind=principal_kind,
        principal_id=principal_id,
        mode=mode,
        outcome=outcome,
        duration_ms=duration_ms,
        parent_invocation_id=parent_invocation_id,
        correlation_id=correlation_id,
        occurred_at=occurred_at,
        started_at=started_at,
        ended_at=effective_ended_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    sub_invocation_id = int(row.id)

    # Delegation-policy enforcement — only fires when the immediate
    # caller is an agent (principal_kind=="agent"); otherwise no parent
    # capabilities exist to compare against. Fail-soft on every
    # internal path EXCEPT "block" mode + genuine violation, which
    # propagates DelegationPolicyError after persisting the audit row.
    if principal_kind == "agent" and principal_id:
        try:
            from .delegation_policy import (
                DelegationPolicyError,
                _current_mode,
                enforce_delegation_policy,
            )
            current_mode = _current_mode()
            violations = enforce_delegation_policy(
                db,
                tenant_id=tenant_id,
                sub_invocation_id=sub_invocation_id,
                parent_invocation_id=parent_invocation_id,
                parent_agent_key=principal_id,
                sub_agent_key=agent_key,
                mode=current_mode,
            )
        except DelegationPolicyError:
            # Mark the invocation as blocked so the audit row reflects
            # the rejected attempt, then re-raise so the caller can
            # short-circuit the actual delegation.
            try:
                row.outcome = "blocked"
                db.commit()
            except Exception:
                try: db.rollback()
                except Exception: pass
            raise
        except Exception as exc:
            logger.debug(
                "[KYA-INV] delegation policy check raised non-policy "
                "exception (ignored): %s", exc)

    try:
        from . import _emit, telemetry
        telemetry.record_event("record_invocation", kind=outcome)
        if _emit.is_enabled():
            _emit.emit(
                "kya_invocations",
                _emit.safe_row({
                    "id": sub_invocation_id,
                    "tenant_id": tenant_id,
                    "agent_key": agent_key,
                    "principal_kind": principal_kind,
                    "principal_id": principal_id,
                    "mode": mode,
                    "outcome": outcome,
                    "duration_ms": duration_ms,
                    "parent_invocation_id": parent_invocation_id,
                    "correlation_id": correlation_id,
                    "occurred_at": occurred_at,
                    "started_at": started_at,
                    "ended_at": effective_ended_at,
                }),
            )
    except Exception:
        pass
    return sub_invocation_id


def _row_to_dict(row: Invocation) -> dict[str, Any]:
    return {
        "id": int(row.id),
        "agent_key": row.agent_key,
        "principal_kind": row.principal_kind,
        "principal_id": row.principal_id,
        "mode": row.mode,
        "outcome": row.outcome,
        "duration_ms": int(row.duration_ms) if row.duration_ms is not None else None,
        "parent_invocation_id": (
            int(row.parent_invocation_id) if row.parent_invocation_id is not None else None
        ),
        "correlation_id": str(row.correlation_id) if row.correlation_id else None,
        "occurred_at": _to_iso(row.occurred_at),
        "ingested_at": _to_iso(row.ingested_at),
        "started_at": _to_iso(row.started_at),
        "ended_at": _to_iso(row.ended_at),
        "ingest_lag_ms": _ingest_lag_ms(row.occurred_at, row.ingested_at),
    }


def list_invocations(
    db,
    tenant_id: str,
    agent_key: str | None = None,
    principal_id: str | None = None,
    correlation_id: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Most-recent first (by occurred_at). Filterable by any of agent_key /
    principal_id / correlation_id."""
    _require_sqlalchemy()
    ensure_invocations_table(db)

    stmt = select(Invocation).where(Invocation.tenant_id == tenant_id)
    if agent_key:
        stmt = stmt.where(Invocation.agent_key == agent_key)
    if principal_id:
        stmt = stmt.where(Invocation.principal_id == principal_id)
    if correlation_id:
        stmt = stmt.where(Invocation.correlation_id == correlation_id)
    stmt = stmt.order_by(Invocation.occurred_at.desc()).limit(limit)

    return [_row_to_dict(row) for row in db.execute(stmt).scalars().all()]


def mode_distribution(db, tenant_id: str, agent_key: str, window_days: int = 7) -> dict:
    """Return the observed distribution of `mode` for an agent over the
    last N days (window applied to `occurred_at`, the event clock — NOT
    `ingested_at`, which would bias against backfills/replays).
    """
    _require_sqlalchemy()
    ensure_invocations_table(db)
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

    stmt = (
        select(Invocation.mode, func.count(Invocation.id))
        .where(Invocation.tenant_id == tenant_id)
        .where(Invocation.agent_key == agent_key)
        .where(Invocation.occurred_at >= cutoff)
        .group_by(Invocation.mode)
    )
    rows = db.execute(stmt).all()
    total = sum(int(r[1]) for r in rows)
    return {
        "window_days": window_days,
        "total": total,
        "by_mode": {r[0]: int(r[1]) for r in rows},
        "percentages": {r[0]: round(int(r[1]) / total, 3) if total else 0 for r in rows},
    }


def active_parallel_invocations(db, tenant_id: str) -> list[dict]:
    """Return invocations currently `in_progress` for the tenant — the
    forensic snapshot of "what's running RIGHT NOW across all agents."
    """
    _require_sqlalchemy()
    ensure_invocations_table(db)
    stmt = (
        select(Invocation)
        .where(Invocation.tenant_id == tenant_id)
        .where(Invocation.outcome == "in_progress")
        .order_by(Invocation.occurred_at.asc())
    )
    return [_row_to_dict(row) for row in db.execute(stmt).scalars().all()]


def ingest_lag_stats(
    db, tenant_id: str, agent_key: str | None = None, window_days: int = 7
) -> dict:
    """Return ingest-lag distribution over the recent window. The lag is
    `ingested_at - occurred_at` in milliseconds. Surfaces pipeline health
    + (combined with OTel span correlation) potential tampering.

    Returns:
        {
            "samples": N,
            "p50_ms": int, "p95_ms": int, "p99_ms": int,
            "max_ms": int,
        }
    """
    _require_sqlalchemy()
    ensure_invocations_table(db)
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

    stmt = select(Invocation.occurred_at, Invocation.ingested_at).where(
        Invocation.tenant_id == tenant_id
    )
    if agent_key:
        stmt = stmt.where(Invocation.agent_key == agent_key)
    stmt = stmt.where(Invocation.occurred_at >= cutoff)

    lags_ms: list[int] = []
    for occ, ing in db.execute(stmt).all():
        lag = _ingest_lag_ms(occ, ing)
        if lag is not None:
            lags_ms.append(lag)

    if not lags_ms:
        return {"samples": 0, "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "max_ms": 0}

    lags_ms.sort()
    n = len(lags_ms)

    def _percentile(p):
        idx = max(0, min(n - 1, int(round(p * (n - 1)))))
        return int(lags_ms[idx])

    return {
        "samples": n,
        "p50_ms": _percentile(0.50),
        "p95_ms": _percentile(0.95),
        "p99_ms": _percentile(0.99),
        "max_ms": int(lags_ms[-1]),
    }


def new_correlation_id() -> str:
    """Generate a fresh correlation id for a new request tree."""
    return str(uuid.uuid4())


def _to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _ingest_lag_ms(occurred_at: datetime | None, ingested_at: datetime | None) -> int | None:
    if occurred_at is None or ingested_at is None:
        return None
    # Normalize both to tz-aware for the subtraction
    occ = occurred_at if occurred_at.tzinfo else occurred_at.replace(tzinfo=timezone.utc)
    ing = ingested_at if ingested_at.tzinfo else ingested_at.replace(tzinfo=timezone.utc)
    return int((ing - occ).total_seconds() * 1000)
