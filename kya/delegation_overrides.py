"""
Per-scope delegation-policy mode overrides.

The global env var `KYA_DELEGATION_POLICY` sets a single mode
(observe/flag/block) for everything. At production scale (100s-1000s
of agents) operators need finer control — `block` for known-bad
orchestrators, `observe` everywhere else, `flag` for new agents
under review. This module supplies that without changing the global
default.

Scope model
-----------
An override targets a 3-tuple (parent_agent_key, sub_agent_key,
violation_kind). Any field can be NULL to mean "wildcard / any value
matches". NULLs cascade — a row with parent=None sub=None kind=None
is the tenant-default override, equivalent to setting the env var
for just that tenant.

Resolution
----------
At enforcement time, KYA's `enforce_delegation_policy` calls
`resolve_effective_mode(...)` for each violation. The resolver:

  1. Pulls every override matching the scope (NULL = wildcard).
  2. Filters to ACTIVE: effective_at <= now AND (expires_at IS NULL
     OR expires_at > now).
  3. Ranks by specificity = count of non-NULL match fields.
     - 3-non-NULL > 2-non-NULL > 1-non-NULL > 0-non-NULL
     - Ties at the same level broken by `created_at DESC` (most
       recent row wins — last-write-wins on equal specificity).
  4. Returns the winner's mode. If no override matches, falls
     through to the global env var.

The resolver also returns a `source` string explaining WHY a mode
was picked — for the readiness report's rationale + for operator
debugging.

Audit semantics
---------------
Rows are append-only. To change a scope's mode, INSERT a new row;
the resolver picks it up automatically (most-recent + most-specific
wins). To soft-delete an override, set its `expires_at` to NOW().
History is preserved.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from .delegation_policy import DELEGATION_POLICY_MODES

logger = logging.getLogger(__name__)


# ── Public errors ──────────────────────────────────────────────────


class InvalidOverrideError(ValueError):
    """Raised when set_delegation_override is given bad arguments."""


# ── Provisioning ───────────────────────────────────────────────────


def ensure_delegation_overrides_table(db) -> None:
    """Idempotent create_all of kya_delegation_policy_overrides.
    Shares MetaData with the other legacy tables for cross-backend
    schema_translate_map handling."""
    from ._legacy_tables import (
        create_legacy_tables,
        kya_delegation_policy_overrides,
    )
    create_legacy_tables(db, [kya_delegation_policy_overrides])


def _schema_prefix(db) -> str:
    try:
        from ._portable import qual_for_raw_sql
        return qual_for_raw_sql(db)
    except Exception:
        return ""


# ── CRUD API ───────────────────────────────────────────────────────


def set_delegation_override(
    db, *,
    tenant_id: str,
    mode: str,
    parent_agent_key: str | None = None,
    sub_agent_key: str | None = None,
    violation_kind: str | None = None,
    reason: str | None = None,
    changed_by: str | None = None,
    effective_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> int:
    """Insert a new override row. Returns the new id.

    Validates `mode` against DELEGATION_POLICY_MODES; an invalid
    value raises InvalidOverrideError. NULLs in scope fields mean
    "wildcard" — to set a tenant-wide override, leave parent/sub/
    kind all None.

    Multiple inserts for the same scope are allowed and form an
    audit trail; the resolver picks the most-recent active one.
    """
    if not tenant_id:
        raise InvalidOverrideError("tenant_id is required")
    norm_mode = (mode or "").lower().strip()
    if norm_mode not in DELEGATION_POLICY_MODES:
        raise InvalidOverrideError(
            f"Unknown mode {mode!r}; must be one of "
            f"{sorted(DELEGATION_POLICY_MODES)}")
    if (expires_at is not None and effective_at is not None
            and expires_at <= effective_at):
        raise InvalidOverrideError(
            "expires_at must be > effective_at")

    ensure_delegation_overrides_table(db)

    # Use the Table object's insert() so SQLAlchemy emits the dialect-
    # correct autoincrement behavior (PG nextval('seq'), MySQL
    # AUTO_INCREMENT, SQLite rowid, DuckDB sequence default). Raw
    # text() INSERTs would force us to inject nextval() per backend.
    from ._legacy_tables import kya_delegation_policy_overrides as _T

    values = {
        "tenant_id": tenant_id,
        "parent_agent_key": parent_agent_key,
        "sub_agent_key": sub_agent_key,
        "violation_kind": violation_kind,
        "mode": norm_mode,
        "reason": reason,
        "changed_by": changed_by,
    }
    if effective_at is not None:
        values["effective_at"] = effective_at
    if expires_at is not None:
        values["expires_at"] = expires_at

    try:
        conn = db.connection()
        stmt = _T.insert().values(**values)
        result = conn.execute(stmt)
        db.commit()
        # SQLAlchemy normalizes inserted_primary_key across backends —
        # works on PG (RETURNING), MySQL (last_insert_id), SQLite
        # (last_insert_rowid), DuckDB (sequence currval).
        inserted_id = (result.inserted_primary_key[0]
                        if result.inserted_primary_key else None)
        if inserted_id is not None:
            return int(inserted_id)
    except Exception:
        db.rollback()
        raise

    # Fallback if the driver didn't return inserted_primary_key —
    # query the most recent matching row. Single-session race
    # window only; acceptable for admin workflows.
    schema = _schema_prefix(db)
    row = db.execute(text(
        f"SELECT id FROM {schema}kya_delegation_policy_overrides "
        f"WHERE tenant_id = :t "
        f"  AND mode = :m "
        f"  AND ((parent_agent_key IS NULL AND :p IS NULL) "
        f"       OR parent_agent_key = :p) "
        f"  AND ((sub_agent_key IS NULL AND :s IS NULL) "
        f"       OR sub_agent_key = :s) "
        f"  AND ((violation_kind IS NULL AND :k IS NULL) "
        f"       OR violation_kind = :k) "
        f"ORDER BY id DESC LIMIT 1"
    ), {"t": tenant_id, "m": norm_mode,
        "p": parent_agent_key, "s": sub_agent_key,
        "k": violation_kind}).first()
    return int(row[0]) if row else 0


def delete_delegation_override(
    db, *,
    override_id: int,
    reason: str | None = None,
) -> bool:
    """Soft-delete by setting expires_at to a moment SLIGHTLY in the
    past (NOW - 1 second). Using exactly NOW() races with backends
    that store DATETIME at second precision (MySQL default): both the
    write and the next resolver call can round to the same second, so
    `expires_at > NOW()` evaluates true and the override appears
    still-active. Subtracting 1 second guarantees the row reads as
    expired on any backend regardless of clock precision.

    Audit history preserved. Returns True if the row's expires_at
    is non-NULL after the update."""
    from datetime import timedelta
    schema = _schema_prefix(db)
    try:
        expires_marker = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.execute(text(
            f"UPDATE {schema}kya_delegation_policy_overrides "
            f"SET expires_at = :n "
            f"WHERE id = :i AND (expires_at IS NULL OR expires_at > :n)"
        ), {"n": expires_marker, "i": override_id})
        db.commit()
        # Verify by reading back. We just need expires_at to be
        # non-NULL — the value itself doesn't matter for the
        # "is the row now expired?" question, since the resolver
        # will compare it against NOW at lookup time.
        row = db.execute(text(
            f"SELECT expires_at FROM {schema}"
            f"kya_delegation_policy_overrides WHERE id = :i"
        ), {"i": override_id}).first()
        return row is not None and row[0] is not None
    except Exception:
        db.rollback()
        return False


def list_delegation_overrides(
    db, *,
    tenant_id: str,
    include_inactive: bool = False,
    parent_agent_key: str | None = None,
    sub_agent_key: str | None = None,
    violation_kind: str | None = None,
) -> list[dict]:
    """List overrides for a tenant. Scope filters narrow to specific
    parent/sub/kind values (None = no filter)."""
    schema = _schema_prefix(db)
    sql = (
        f"SELECT id, parent_agent_key, sub_agent_key, violation_kind, "
        f"       mode, reason, changed_by, effective_at, expires_at, "
        f"       created_at "
        f"FROM {schema}kya_delegation_policy_overrides "
        f"WHERE tenant_id = :t"
    )
    params: dict[str, Any] = {"t": tenant_id}
    if not include_inactive:
        sql += (" AND effective_at <= :n "
                 "AND (expires_at IS NULL OR expires_at > :n)")
        params["n"] = datetime.now(timezone.utc)
    if parent_agent_key is not None:
        sql += " AND parent_agent_key = :p"
        params["p"] = parent_agent_key
    if sub_agent_key is not None:
        sql += " AND sub_agent_key = :s"
        params["s"] = sub_agent_key
    if violation_kind is not None:
        sql += " AND violation_kind = :k"
        params["k"] = violation_kind
    sql += " ORDER BY id DESC"

    try:
        rows = db.execute(text(sql), params).fetchall()
    except Exception as exc:
        logger.debug("[KYA-DELEG-OVR] list query failed: %s", exc)
        return []

    return [{
        "id": r[0],
        "parent_agent_key": r[1],
        "sub_agent_key": r[2],
        "violation_kind": r[3],
        "mode": r[4],
        "reason": r[5],
        "changed_by": str(r[6]) if r[6] is not None else None,
        "effective_at": _iso(r[7]),
        "expires_at": _iso(r[8]),
        "created_at": _iso(r[9]),
    } for r in rows]


# ── Resolution ─────────────────────────────────────────────────────


def resolve_effective_mode(
    db, *,
    tenant_id: str,
    parent_agent_key: str | None = None,
    sub_agent_key: str | None = None,
    violation_kind: str | None = None,
) -> tuple[str, str]:
    """Pick the effective mode for this scope.

    Specificity ordering (most → least specific):
        (P, S, K) > (P, S, *) ~ (P, *, K) ~ (*, S, K)
                  > (P, *, *) ~ (*, S, *) ~ (*, *, K)
                  > (*, *, *)

    Within the same specificity tier, the most recently created row
    wins (last-write-wins).

    Returns:
        (mode, source) — `mode` is one of DELEGATION_POLICY_MODES;
        `source` is a human-readable explanation of why this mode
        was picked. If no override matches, falls back to the global
        env var with source="global_env".
    """
    if not tenant_id:
        from .delegation_policy import _current_mode
        return _current_mode(), "global_env(no_tenant_id)"

    schema = _schema_prefix(db)
    try:
        rows = db.execute(text(
            f"SELECT id, parent_agent_key, sub_agent_key, "
            f"       violation_kind, mode, created_at "
            f"FROM {schema}kya_delegation_policy_overrides "
            f"WHERE tenant_id = :t "
            f"  AND effective_at <= :n "
            f"  AND (expires_at IS NULL OR expires_at > :n) "
            f"  AND (parent_agent_key IS NULL "
            f"       OR parent_agent_key = :p) "
            f"  AND (sub_agent_key IS NULL "
            f"       OR sub_agent_key = :s) "
            f"  AND (violation_kind IS NULL "
            f"       OR violation_kind = :k)"
        ), {"t": tenant_id,
            "n": datetime.now(timezone.utc),
            "p": parent_agent_key,
            "s": sub_agent_key,
            "k": violation_kind}).fetchall()
    except Exception as exc:
        logger.debug("[KYA-DELEG-OVR] resolve query failed: %s", exc)
        rows = []

    if not rows:
        from .delegation_policy import _current_mode
        return _current_mode(), "global_env"

    # Specificity = number of non-NULL scope fields on the row.
    # Tie-break by id DESC (last-write-wins). Using id instead of
    # created_at avoids the 1-second clock-resolution problem on
    # SQLite/MySQL where two same-second inserts share a timestamp.
    def _specificity_score(r) -> tuple[int, int]:
        score = sum(1 for x in (r[1], r[2], r[3]) if x is not None)
        return (score, int(r[0]))  # higher score + later id win

    rows_sorted = sorted(rows, key=_specificity_score, reverse=True)
    winner = rows_sorted[0]
    scope_str = (
        f"parent={winner[1] or '*'}/"
        f"sub={winner[2] or '*'}/"
        f"kind={winner[3] or '*'}"
    )
    source = f"override#{winner[0]} ({scope_str})"
    return winner[4], source


def _iso(dt) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
