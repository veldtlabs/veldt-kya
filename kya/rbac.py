"""
Phase 5b — KYA-semantic RBAC.

The reverse proxy can do coarse routing (can this caller hit
/admin or not). It cannot decide "can principal X call set_budget
for cost_center=ops?" — that's a KYA-domain decision tied to a
specific action + scope. This module owns those checks.

Model
-----
Direct (principal → action) grants per tenant. No role-name layer
in v1 — operators who want roles fan out to multiple grant rows
via a wrapper. Single-table design keeps the resolver to two
index-backed equality lookups.

A grant row carries:
  - (tenant_id, principal_kind, principal_id, action) — composite uniq
  - granted_by, reason — audit
  - effective_at, expires_at — time-bounded grants supported

Wildcard support
----------------
A single wildcard: `kya.*` matches any KYA action for that
principal. No deeper wildcards (no `kya.budget.*`) — keeps the
resolver SQL to two equality checks instead of LIKE scans.

Off-by-default enforcement
--------------------------
`KYA_RBAC_ENFORCEMENT` env (or `configure_rbac(mode=...)`):
  - "off" (default) — `require_action` always returns True. No
    grant lookups, no overhead. KYA stays plug-and-play for
    consumers that haven't set up RBAC.
  - "flag" — check + log WARNING on denial, return True. Lets
    operators see what WOULD be denied before flipping to block.
  - "block" — check + raise `AccessDeniedError` on denial.

Closed action set
-----------------
ACTIONS frozenset prevents typos in grants and decorators. Adding
a new action requires extending the set explicitly — operators
can't grant ghost actions that nothing checks.

Public API
----------
  grant_action(db, tenant, kind, principal_id, action, ...) -> int
  revoke_action(db, tenant, kind, principal_id, action) -> bool
  list_grants(db, tenant, kind=None, principal_id=None) -> list[dict]
  has_action(db, tenant, kind, principal_id, action) -> bool
  require_action(db, tenant, kind, principal_id, action,
                  mode=None) -> bool
  configure_rbac(mode) -> str
  active_rbac_mode() -> str
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)


# ── Public errors ──────────────────────────────────────────────────


class AccessDeniedError(PermissionError):
    """Raised in `block` mode when a principal lacks the required
    KYA action. Carries structured context (tenant, principal,
    action) so HTTP layers can emit 403 with detail."""

    def __init__(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        action: str,
    ):
        self.tenant_id = tenant_id
        self.principal_kind = principal_kind
        self.principal_id = principal_id
        self.action = action
        super().__init__(
            f"Access denied: principal {principal_kind}:{principal_id} "
            f"in tenant {tenant_id} cannot perform '{action}'")


class InvalidActionError(ValueError):
    """Raised by grant_action when the action string isn't in the
    closed ACTIONS set. Loud-by-design — typos in grants are
    security bugs."""


class InvalidRbacModeError(ValueError):
    """Raised by configure_rbac for unknown mode strings."""


# ── Closed action set ──────────────────────────────────────────────


# Adding a new action: append here AND wire require_action() into
# the relevant primitive. Both are required for a new permission
# to become enforceable.
ACTIONS: frozenset[str] = frozenset({
    # Cost / budget
    "kya.budget.write",
    "kya.budget.read",
    "kya.cost.read",
    # Delegation policy
    "kya.delegation.override.set",
    "kya.delegation.override.delete",
    "kya.delegation.policy.read",
    # Principal identity
    "kya.principal.bind",
    "kya.principal.trust.read",
    # Evidence / audit
    "kya.evidence.read",
    "kya.evidence.export",
    "kya.audit.signed_export",
    # Versioning
    "kya.version.snapshot",
    "kya.version.rollback",
    "kya.version.read",
    # Signals / rogue
    "kya.signal.record",
    "kya.signal.read",
    # Wildcard — super-user
    "kya.*",
})


RBAC_MODES: frozenset[str] = frozenset({"off", "flag", "block"})


# ── Mode resolution ────────────────────────────────────────────────


_ENV_KEY = "KYA_RBAC_ENFORCEMENT"
DEFAULT_RBAC_MODE = "off"


def configure_rbac(mode: str = DEFAULT_RBAC_MODE,
                    *, log: bool = True) -> str:
    """Set the active RBAC enforcement mode for this process. Same
    contract as configure_delegation_policy — validates the mode,
    persists to env so subsequent require_action calls pick it up,
    logs once at INFO for operator visibility.

    Raises InvalidRbacModeError on unknown mode."""
    normalized = (mode or "").lower().strip()
    if normalized not in RBAC_MODES:
        raise InvalidRbacModeError(
            f"Unknown RBAC mode: {mode!r}. "
            f"Must be one of: {sorted(RBAC_MODES)}")
    os.environ[_ENV_KEY] = normalized
    if log:
        logger.info(
            "[KYA-RBAC] enforcement mode active: '%s'", normalized)
    return normalized


def active_rbac_mode() -> str:
    """Return the currently-active mode (defaults to 'off' when
    env unset or invalid)."""
    raw = (os.environ.get(_ENV_KEY) or DEFAULT_RBAC_MODE).lower()
    if raw not in RBAC_MODES:
        return DEFAULT_RBAC_MODE
    return raw


# ── Helpers ────────────────────────────────────────────────────────


def _schema_prefix(db) -> str:
    try:
        return ("prov_schema."
                if db.get_bind().dialect.name == "postgresql"
                else "")
    except Exception:
        return ""


def ensure_rbac_table(db) -> None:
    """Idempotent CREATE for kya_role_grants. Shares MetaData
    with the rest of the legacy tables for the schema_translate_map
    cross-backend flow."""
    from ._legacy_tables import create_legacy_tables, kya_role_grants
    create_legacy_tables(db, [kya_role_grants])


# ── CRUD ───────────────────────────────────────────────────────────


def grant_action(
    db, *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    action: str,
    granted_by: str | None = None,
    reason: str | None = None,
    expires_at: datetime | None = None,
) -> int:
    """Grant `principal` the named action in this tenant.

    Idempotent — re-granting the same (tenant, kind, id, action)
    is a no-op (returns the existing id). Distinct rows for the
    same scope are NOT allowed by UNIQUE constraint; updates to
    granted_by / reason / expires_at on an existing grant should
    revoke + re-grant.

    Validates `action` against the ACTIONS closed set; unknown
    actions raise InvalidActionError (typos in grants are
    security bugs — fail loud).
    """
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not principal_id:
        raise ValueError("principal_id is required")
    if action not in ACTIONS:
        raise InvalidActionError(
            f"Unknown action {action!r}; must be in "
            f"kya.rbac.ACTIONS")

    ensure_rbac_table(db)
    from ._legacy_tables import kya_role_grants as _T

    schema = _schema_prefix(db)

    # SELECT-first: idempotent return if grant already exists.
    # Avoids ON CONFLICT DO NOTHING because SQLAlchemy's SQLite
    # dialect rejects empty SET dicts; PG and MySQL portable_upsert
    # paths have the same constraint. SELECT-first is simpler and
    # works on every backend.
    existing = db.execute(text(
        f"SELECT id FROM {schema}kya_role_grants "
        f"WHERE tenant_id = :t AND principal_kind = :pk "
        f"  AND principal_id = :pid AND action = :a"
    ), {"t": tenant_id, "pk": principal_kind,
        "pid": principal_id, "a": action}).first()
    if existing:
        return int(existing[0])

    values = {
        "tenant_id": tenant_id,
        "principal_kind": principal_kind,
        "principal_id": principal_id,
        "action": action,
        "granted_by": granted_by,
        "reason": reason,
    }
    if expires_at is not None:
        values["expires_at"] = expires_at

    from sqlalchemy.exc import IntegrityError
    try:
        conn = db.connection()
        result = conn.execute(_T.insert().values(**values))
        db.commit()
        inserted_id = (result.inserted_primary_key[0]
                        if result.inserted_primary_key else None)
        if inserted_id is not None:
            return int(inserted_id)
    except IntegrityError:
        # Race condition: between our SELECT and INSERT, another
        # caller inserted the same (tenant, kind, id, action). The
        # UNIQUE constraint fired. Roll back and re-SELECT the
        # winner's row — idempotent contract preserved.
        db.rollback()
    except Exception:
        db.rollback()
        raise

    # Fallback: read it back (also the path after IntegrityError).
    row = db.execute(text(
        f"SELECT id FROM {schema}kya_role_grants "
        f"WHERE tenant_id = :t AND principal_kind = :pk "
        f"  AND principal_id = :pid AND action = :a"
    ), {"t": tenant_id, "pk": principal_kind,
        "pid": principal_id, "a": action}).first()
    if row is None:
        # Both INSERT and re-SELECT missed — should be impossible
        # unless the table itself vanished. Loud rather than 0.
        raise RuntimeError(
            f"grant_action: INSERT silently dropped and "
            f"row not found on re-SELECT (tenant={tenant_id}, "
            f"action={action})")
    return int(row[0])


def revoke_action(
    db, *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    action: str,
) -> bool:
    """Revoke a previously-granted action. Returns True if a row
    was deleted, False if no matching grant existed.

    Hard delete — RBAC grants are operator-managed; we don't keep
    soft-deleted rows here (the same audit chain captures the
    revoke event via the security-event log).

    Authorization contract
    ----------------------
    `revoke_action` does NOT self-gate via require_action. KYA
    primitives consistently trust their callers; the platform layer
    above KYA is expected to enforce admin authorization before
    calling here. This matches the pattern of set_budget,
    set_delegation_override, etc. — KYA is the substrate, not the
    perimeter.

    Operators who want in-app authorization on the revoke endpoint
    should wrap it themselves:

        require_action(db, tenant_id=tenant,
                       principal_kind=actor_kind,
                       principal_id=actor_id,
                       action="kya.rbac.write")  # or similar
        revoke_action(db, tenant_id=tenant, ...)
    """
    if not tenant_id or not principal_id or not action:
        raise ValueError(
            "tenant_id, principal_id, action all required")
    schema = _schema_prefix(db)
    try:
        existed = db.execute(text(
            f"SELECT id FROM {schema}kya_role_grants "
            f"WHERE tenant_id = :t AND principal_kind = :pk "
            f"  AND principal_id = :pid AND action = :a"
        ), {"t": tenant_id, "pk": principal_kind,
            "pid": principal_id, "a": action}).first()
        if not existed:
            return False
        db.execute(text(
            f"DELETE FROM {schema}kya_role_grants "
            f"WHERE id = :i"
        ), {"i": existed[0]})
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


def list_grants(
    db, *,
    tenant_id: str,
    principal_kind: str | None = None,
    principal_id: str | None = None,
    include_expired: bool = False,
) -> list[dict]:
    """List grants for a tenant (optionally narrowed by principal).
    Returns active grants by default; pass include_expired=True
    to see historical / expired entries."""
    if not tenant_id:
        raise ValueError("tenant_id is required")
    schema = _schema_prefix(db)
    sql = (f"SELECT id, principal_kind, principal_id, action, "
           f"       granted_by, reason, "
           f"       effective_at, expires_at, created_at "
           f"FROM {schema}kya_role_grants "
           f"WHERE tenant_id = :t")
    params: dict[str, Any] = {"t": tenant_id}
    if not include_expired:
        sql += (" AND effective_at <= :n "
                 "AND (expires_at IS NULL OR expires_at > :n)")
        params["n"] = datetime.now(timezone.utc)
    if principal_kind is not None:
        sql += " AND principal_kind = :pk"
        params["pk"] = principal_kind
    if principal_id is not None:
        sql += " AND principal_id = :pid"
        params["pid"] = principal_id
    sql += " ORDER BY id"

    try:
        rows = db.execute(text(sql), params).fetchall()
    except Exception as exc:
        logger.debug("[KYA-RBAC] list_grants failed: %s", exc)
        return []
    return [{
        "id": r[0], "principal_kind": r[1],
        "principal_id": r[2], "action": r[3],
        "granted_by": str(r[4]) if r[4] is not None else None,
        "reason": r[5],
        "effective_at": _iso(r[6]),
        "expires_at": _iso(r[7]),
        "created_at": _iso(r[8]),
    } for r in rows]


# ── Resolution ─────────────────────────────────────────────────────


def has_action(
    db, *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    action: str,
) -> bool:
    """Returns True iff the principal has an ACTIVE grant for the
    action OR the wildcard `kya.*` for this tenant.

    "Active" = effective_at <= now AND (expires_at IS NULL OR
    expires_at > now). Pure read — does not raise on DB errors;
    fail-soft returns False (default-deny posture).
    """
    if not tenant_id or not principal_id or not action:
        return False
    schema = _schema_prefix(db)
    try:
        row = db.execute(text(
            f"SELECT 1 FROM {schema}kya_role_grants "
            f"WHERE tenant_id = :t "
            f"  AND principal_kind = :pk "
            f"  AND principal_id = :pid "
            f"  AND action IN (:exact, :wild) "
            f"  AND effective_at <= :n "
            f"  AND (expires_at IS NULL OR expires_at > :n) "
            f"LIMIT 1"
        ), {"t": tenant_id, "pk": principal_kind,
            "pid": principal_id,
            "exact": action, "wild": "kya.*",
            "n": datetime.now(timezone.utc)}).first()
        return row is not None
    except Exception as exc:
        logger.debug("[KYA-RBAC] has_action query failed: %s", exc)
        return False  # default-deny on DB error


def require_action(
    db, *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    action: str,
    mode: str | None = None,
) -> bool:
    """Enforce an action check at the entry of a KYA primitive.

    Three modes (defaults to env KYA_RBAC_ENFORCEMENT or "off"):
      - "off"   → returns True; no check. Plug-and-play for
                  consumers that haven't set up RBAC.
      - "flag"  → check + log WARNING on denial, return True.
                  Lets operators see what WOULD be denied.
      - "block" → check + raise AccessDeniedError on denial.

    Validation errors (unknown mode, unknown action) raise
    InvalidRbacModeError / InvalidActionError immediately (loud).
    """
    # Validate action FIRST, before any mode-based short-circuits.
    # Without this, mode="off" would silently accept typos like
    # `action="kya.budet.write"` (note typo). Validation belongs
    # ahead of the decision branch — operators want loud failures
    # on misspelled grants, off-mode or not.
    if action not in ACTIONS:
        raise InvalidActionError(
            f"Unknown action {action!r} — typo? "
            f"Action must be in kya.rbac.ACTIONS")
    effective_mode = mode if mode is not None else active_rbac_mode()
    if effective_mode == "off":
        return True
    if effective_mode not in RBAC_MODES:
        raise InvalidRbacModeError(
            f"Unknown RBAC mode: {effective_mode!r}")

    granted = has_action(
        db, tenant_id=tenant_id,
        principal_kind=principal_kind,
        principal_id=principal_id,
        action=action)
    if granted:
        return True

    # Denial — emit a security event (DRY: same emitter used by
    # rate_limit, payload_caps, replay_protection)
    try:
        from ._security_events import emit_security_event
        emit_security_event(
            "rbac_refusal",
            tenant_id=tenant_id, primitive="require_action",
            principal_kind=principal_kind,
            principal_id=principal_id, db=db,
            detail={"action": action, "mode": effective_mode})
    except Exception as exc:
        logger.debug(
            "[KYA-RBAC] security-event emit failed: %s", exc)

    if effective_mode == "flag":
        logger.warning(
            "[KYA-RBAC] (flag) denied %s:%s for %s in tenant %s — "
            "no grant; would block in 'block' mode",
            principal_kind, principal_id, action, tenant_id)
        return True
    # block mode
    raise AccessDeniedError(
        tenant_id, principal_kind, principal_id, action)


# ── Internal ───────────────────────────────────────────────────────


def _iso(dt) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
