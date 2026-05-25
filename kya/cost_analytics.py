"""
Cost-events analytics — instant-business-value query layer.

Sits on top of ``kya_cost_events`` (defined in ``_legacy_tables``,
written by ``tenant_budget.record_cost_event``) and exposes the
queries every cost dashboard wants without the embedding layer
writing SQL:

    * Cost by provider / cost-center / business-unit / environment
    * Cost over time (hourly / daily / weekly buckets)
    * Top-N cost agents (FinOps prioritization)
    * Cost-of-failure (money spent on outcomes != success)
    * Cache efficiency (cached_tokens / total_tokens)
    * Cost per invocation (cost-tied-to-audit-trail)
    * One-shot attribution summary (everything in one round trip)

All functions are dialect-portable (PG / MySQL / SQLite / DuckDB)
via SQLAlchemy Core; no raw text() strings. Date-bucket truncation
uses ``func.date_trunc`` on PG and a portable substring trick on
the others (date strings group correctly under string comparison).

Public API
----------
    cost_by_dimension(db, dimension, *, tenant_id, ...) -> dict
    cost_over_time(db, *, tenant_id, bucket="hour", ...) -> list[dict]
    top_cost_agents(db, *, tenant_id, limit=10, ...) -> list[dict]
    cost_of_failure(db, *, tenant_id, ...) -> dict
    cache_efficiency(db, *, tenant_id, ...) -> dict
    cost_per_invocation(db, *, tenant_id, invocation_id) -> dict | None
    attribution_summary(db, *, tenant_id, ...) -> dict
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterable

try:
    from sqlalchemy import and_, func, select
    _SA_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SA_AVAILABLE = False
    and_ = func = select = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# Closed-set dimension names. Each maps to a real column on
# ``kya_cost_events``. Callers pass strings, never SQLAlchemy column
# objects, so injection is impossible.
_DIMENSION_COLUMNS = frozenset({
    "provider", "cost_center", "business_unit", "environment",
    "agent_key", "principal_kind", "model_used", "outcome",
})

_BUCKETS = frozenset({"hour", "day", "week", "month"})


def _events_table():
    """Lazy import — keeps module-load free of SQLAlchemy at the
    cross-backend layer."""
    from ._legacy_tables import kya_cost_events
    return kya_cost_events


def _time_filter(col, start_ts: datetime | None, end_ts: datetime | None):
    """Compose an inclusive timestamp range filter."""
    clauses = []
    if start_ts is not None:
        clauses.append(col >= start_ts)
    if end_ts is not None:
        clauses.append(col <= end_ts)
    return and_(*clauses) if clauses else True


def _bucket_expr(dialect: str, col, bucket: str):
    """Dialect-portable timestamp truncation."""
    if dialect == "postgresql":
        return func.date_trunc(bucket, col)
    if dialect == "duckdb":
        return func.date_trunc(bucket, col)
    # MySQL / SQLite — use string-prefix grouping (works for hour/day/week)
    if bucket == "hour":
        fmt = "%Y-%m-%d %H:00:00"
    elif bucket == "day":
        fmt = "%Y-%m-%d"
    elif bucket == "week":
        # ISO week — fallback to day-truncation for SQLite/MySQL since
        # week semantics differ; callers wanting strict ISO weeks should
        # use PG.
        fmt = "%Y-%m-%d"
    else:  # month
        fmt = "%Y-%m"
    if dialect == "sqlite":
        return func.strftime(fmt, col)
    if dialect == "mysql":
        return func.date_format(col, fmt)
    return func.strftime(fmt, col)  # safe default


def _dialect_of(db) -> str:
    try:
        return db.get_bind().dialect.name
    except Exception:  # pragma: no cover
        return "unknown"


# ── Dimension rollups ───────────────────────────────────────────────


def cost_by_dimension(
    db,
    dimension: str,
    *,
    tenant_id: str,
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
    limit: int = 100,
) -> dict[str, dict[str, float | int]]:
    """Total USD, event count, and average per-event cost grouped by
    one of the closed-set analytics dimensions. One round trip.

    Returns:
        {
            "<dimension_value>": {"usd": 12.34, "events": 100, "avg_usd": 0.1234},
            ...
        }
    """
    if not _SA_AVAILABLE or db is None:
        return {}
    if dimension not in _DIMENSION_COLUMNS:
        raise ValueError(
            f"dimension must be one of {sorted(_DIMENSION_COLUMNS)}"
        )
    t = _events_table()
    col = getattr(t.c, dimension)
    stmt = (
        select(
            col,
            func.sum(t.c.usd_amount).label("usd"),
            func.count(t.c.id).label("events"),
        )
        .where(
            t.c.tenant_id == tenant_id,
            _time_filter(t.c.recorded_at, start_ts, end_ts),
        )
        .group_by(col)
        .order_by(func.sum(t.c.usd_amount).desc())
        .limit(limit)
    )
    out: dict[str, dict[str, float | int]] = {}
    for row in db.execute(stmt).fetchall():
        key = row[0] if row[0] is not None else "(unset)"
        usd = float(row[1] or 0)
        events = int(row[2] or 0)
        out[str(key)] = {
            "usd": round(usd, 6),
            "events": events,
            "avg_usd": round(usd / events, 6) if events else 0.0,
        }
    return out


def cost_over_time(
    db,
    *,
    tenant_id: str,
    bucket: str = "hour",
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
    dimension: str | None = None,
) -> list[dict[str, Any]]:
    """Time-bucketed cost series. ``dimension`` (optional) adds an
    extra group-by axis for stacked-bar / area charts.

    Returns sorted-ascending by bucket timestamp.
    """
    if not _SA_AVAILABLE or db is None:
        return []
    if bucket not in _BUCKETS:
        raise ValueError(f"bucket must be one of {sorted(_BUCKETS)}")
    if dimension is not None and dimension not in _DIMENSION_COLUMNS:
        raise ValueError(
            f"dimension must be one of {sorted(_DIMENSION_COLUMNS)}"
        )

    t = _events_table()
    dialect = _dialect_of(db)
    bucket_col = _bucket_expr(dialect, t.c.recorded_at, bucket).label("bucket")

    selected = [
        bucket_col,
        func.sum(t.c.usd_amount).label("usd"),
        func.count(t.c.id).label("events"),
    ]
    group_cols = [bucket_col]
    if dimension:
        dim_col = getattr(t.c, dimension)
        selected.insert(1, dim_col.label(dimension))
        group_cols.append(dim_col)

    stmt = (
        select(*selected)
        .where(
            t.c.tenant_id == tenant_id,
            _time_filter(t.c.recorded_at, start_ts, end_ts),
        )
        .group_by(*group_cols)
        .order_by(bucket_col)
    )
    rows = db.execute(stmt).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        rec: dict[str, Any] = {"bucket": row[0]}
        if dimension:
            rec[dimension] = row[1]
            rec["usd"] = round(float(row[2] or 0), 6)
            rec["events"] = int(row[3] or 0)
        else:
            rec["usd"] = round(float(row[1] or 0), 6)
            rec["events"] = int(row[2] or 0)
        out.append(rec)
    return out


# ── Specialised dashboards ──────────────────────────────────────────


def top_cost_agents(
    db,
    *,
    tenant_id: str,
    limit: int = 10,
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
) -> list[dict[str, Any]]:
    """Top-N agents by total spend. FinOps prioritization view."""
    rollup = cost_by_dimension(
        db, "agent_key",
        tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts, limit=limit,
    )
    return [
        {"agent_key": k, **v}
        for k, v in rollup.items()
    ]


def cost_of_failure(
    db,
    *,
    tenant_id: str,
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
) -> dict[str, Any]:
    """Money spent on non-success outcomes. Critical for boards and
    cost-justification conversations."""
    rollup = cost_by_dimension(
        db, "outcome",
        tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts,
    )
    total_usd = sum(v["usd"] for v in rollup.values())
    waste_buckets = ("failure", "refused", "unknown")
    wasted_usd = sum(
        v["usd"] for k, v in rollup.items() if k in waste_buckets
    )
    return {
        "by_outcome": rollup,
        "total_usd": round(total_usd, 6),
        "wasted_usd": round(wasted_usd, 6),
        "waste_ratio": round(wasted_usd / total_usd, 4) if total_usd else 0.0,
    }


def cache_efficiency(
    db,
    *,
    tenant_id: str,
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
) -> dict[str, Any]:
    """Aggregate caching efficiency. Higher ratio = more reuse =
    cheaper deployment.

    Returns:
        {
            "cached_tokens":  int,
            "input_tokens":   int,
            "output_tokens":  int,
            "total_tokens":   int,
            "cache_ratio":    float  (cached / (cached + input)),
        }
    """
    if not _SA_AVAILABLE or db is None:
        return {}
    t = _events_table()
    stmt = select(
        func.coalesce(func.sum(t.c.cached_tokens), 0).label("cached"),
        func.coalesce(func.sum(t.c.input_tokens), 0).label("input_"),
        func.coalesce(func.sum(t.c.output_tokens), 0).label("output"),
    ).where(
        t.c.tenant_id == tenant_id,
        _time_filter(t.c.recorded_at, start_ts, end_ts),
    )
    row = db.execute(stmt).first()
    if not row:
        return {"cached_tokens": 0, "input_tokens": 0, "output_tokens": 0,
                "total_tokens": 0, "cache_ratio": 0.0}
    cached = int(row[0] or 0)
    inp = int(row[1] or 0)
    outp = int(row[2] or 0)
    denom = cached + inp
    ratio = round(cached / denom, 4) if denom else 0.0
    return {
        "cached_tokens": cached,
        "input_tokens": inp,
        "output_tokens": outp,
        "total_tokens": cached + inp + outp,
        "cache_ratio": ratio,
    }


def cost_per_invocation(
    db,
    *,
    tenant_id: str,
    invocation_id: int,
) -> dict[str, Any] | None:
    """Roll up all cost events linked to a single invocation. Closes
    the cost ↔ audit-chain loop: every dollar tied to a specific
    HMAC-chained business event."""
    if not _SA_AVAILABLE or db is None:
        return None
    t = _events_table()
    stmt = select(
        func.sum(t.c.usd_amount).label("usd"),
        func.count(t.c.id).label("events"),
        func.sum(t.c.input_tokens).label("input_tokens"),
        func.sum(t.c.output_tokens).label("output_tokens"),
        func.sum(t.c.cached_tokens).label("cached_tokens"),
        func.sum(t.c.latency_ms).label("latency_ms"),
    ).where(
        t.c.tenant_id == tenant_id,
        t.c.invocation_id == invocation_id,
    )
    row = db.execute(stmt).first()
    if not row or row[1] == 0 or row[1] is None:
        return None
    return {
        "invocation_id": invocation_id,
        "usd_amount": round(float(row[0] or 0), 6),
        "events": int(row[1] or 0),
        "input_tokens": int(row[2] or 0),
        "output_tokens": int(row[3] or 0),
        "cached_tokens": int(row[4] or 0),
        "latency_ms_total": int(row[5] or 0),
    }


def attribution_summary(
    db,
    *,
    tenant_id: str,
    start_ts: datetime | None = None,
    end_ts: datetime | None = None,
) -> dict[str, Any]:
    """One-shot dashboard summary. Aggregates every analytics axis the
    board / FinOps team typically asks for in a single payload."""
    if not _SA_AVAILABLE or db is None:
        return {}
    return {
        "tenant_id": tenant_id,
        "window": {"start": start_ts, "end": end_ts},
        "by_provider": cost_by_dimension(
            db, "provider",
            tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts,
        ),
        "by_cost_center": cost_by_dimension(
            db, "cost_center",
            tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts,
        ),
        "by_business_unit": cost_by_dimension(
            db, "business_unit",
            tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts,
        ),
        "by_environment": cost_by_dimension(
            db, "environment",
            tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts,
        ),
        "top_agents": top_cost_agents(
            db, tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts, limit=10,
        ),
        "outcomes": cost_of_failure(
            db, tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts,
        ),
        "cache": cache_efficiency(
            db, tenant_id=tenant_id, start_ts=start_ts, end_ts=end_ts,
        ),
    }
