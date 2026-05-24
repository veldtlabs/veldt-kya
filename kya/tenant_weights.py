"""
Tenant-scoped weight overrides — RBAC-gated, audit-logged, DB-persisted.

Why this exists
---------------
`set_class_weights()`, `set_capability_weights()`, etc. are mutable
process-globals. Convenient for a Python REPL — dangerous if exposed.
A caller with shell access could `set_class_weights({"phi": 0})` and
silently make every PHI-handling agent look benign.

This module replaces "process-global mutation" with "per-tenant DB
overrides resolved at scoring time." The mutation surface (`set_*`)
remains for SDK / library users who manage their own catalogs, but
the production scoring path uses this module.

Resolution order at score time
------------------------------
    1. Caller-provided weights (if explicit `weights=` kwarg)
    2. Tenant override row in `prov_schema.kya_weight_overrides`
    3. Platform default override row (tenant_id = NULL)
    4. Module-level default constants (CLASS_WEIGHTS, CAPABILITY_WEIGHTS, …)

"Only-tighten" constraint
-------------------------
Mirrors `agents/tool_rbac_overrides.py`: a tenant override is rejected
if it would LOWER the effective risk weight below the platform default.
Tenants can raise their own bar; they can't lower it.

Audit
-----
Every successful weight change writes a row to `prov_schema.kya_weight_changes`
with old_value / new_value / changed_by / reason / scope-context.

Public API
----------
    ensure_tables(db)
    get_effective_weights(db, scope, tenant_id=None) -> dict
    set_override(db, scope, key, value, tenant_id, changed_by, reason)
    delete_override(db, scope, key, tenant_id, changed_by, reason)
    list_overrides(db, tenant_id=None) -> list[dict]

`scope` is one of: "class_weights", "capability_weights", "source_weights",
"deployment_weights" — any weight table this module manages.
"""

import logging

# SQLAlchemy is OPTIONAL. Core KYA (scoring, adapter, format normalization)
# has zero hard dependencies — importing this module never fails. Functions
# that actually need a DB session raise a clear message at call time when
# the dep isn't installed. SDK users who don't use persistence pay nothing.
try:
    from sqlalchemy import text as _sa_text

    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False

    def _sa_text(s):
        raise RuntimeError(
            "kya.tenant_weights requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


# Public alias preserved for callers + readability inside this module
text = _sa_text

logger = logging.getLogger(__name__)


_TABLE_OVERRIDES_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_weight_overrides (
    id          SERIAL PRIMARY KEY,
    tenant_id   UUID,                          -- NULL = platform default override
    scope       VARCHAR(50)  NOT NULL,         -- class_weights / capability_weights / ...
    key         VARCHAR(100) NOT NULL,         -- e.g. "pii", "code_execution"
    value       INTEGER      NOT NULL,
    created_by  UUID,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, scope, key)
);
"""

_TABLE_CHANGES_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_weight_changes (
    id          SERIAL PRIMARY KEY,
    tenant_id   UUID,                          -- NULL = platform-level change
    scope       VARCHAR(50)  NOT NULL,
    key         VARCHAR(100) NOT NULL,
    old_value   INTEGER,
    new_value   INTEGER,
    action      VARCHAR(20)  NOT NULL,         -- "set" | "delete"
    changed_by  UUID,
    reason      TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
"""

_INDEX_OVERRIDES_DDL = """
CREATE INDEX IF NOT EXISTS idx_kya_weight_overrides_tenant_scope
    ON prov_schema.kya_weight_overrides (tenant_id, scope);
"""

_INDEX_CHANGES_DDL = """
CREATE INDEX IF NOT EXISTS idx_kya_weight_changes_tenant_created
    ON prov_schema.kya_weight_changes (tenant_id, created_at DESC);
"""


# Scopes this module manages. Each maps to a module-level dict that holds
# the in-process default. Resolution merges DB overrides on top.
_SCOPE_REGISTRY: dict[str, dict] = {}


def register_scope(scope: str, default_dict: dict) -> None:
    """Register a weight scope managed by this module. Called by each
    factor module at import time (data_classes, security_caps, etc.)."""
    _SCOPE_REGISTRY[scope] = default_dict


def known_scopes() -> list[str]:
    return sorted(_SCOPE_REGISTRY.keys())


def ensure_tables(db) -> None:
    """Idempotent — dialect-aware via _legacy_tables.create_legacy_tables."""
    from ._legacy_tables import (
        create_legacy_tables,
        kya_weight_changes,
        kya_weight_overrides,
    )

    create_legacy_tables(db, [kya_weight_overrides, kya_weight_changes])
    db.commit()


# ── Read-side ────────────────────────────────────────────────────────────


def get_effective_weights(db, scope: str, tenant_id: str | None = None) -> dict:
    """Return the resolved weight table for a scope.

    Resolution: platform-default overrides ∘ tenant overrides applied
    on top of the in-process default. If `tenant_id` is None, returns
    platform-effective (no tenant layer).
    """
    if scope not in _SCOPE_REGISTRY:
        raise ValueError(f"unknown weight scope: {scope}")
    weights = dict(_SCOPE_REGISTRY[scope])  # start with in-process default

    # Platform-level overrides (tenant_id IS NULL)
    rows = db.execute(
        text("""
            SELECT key, value FROM prov_schema.kya_weight_overrides
            WHERE tenant_id IS NULL AND scope = :scope
        """),
        {"scope": scope},
    ).fetchall()
    for k, v in rows:
        weights[k] = int(v)

    # Tenant-level overrides — only-tighten enforced at set time, not here
    if tenant_id:
        rows = db.execute(
            text("""
                SELECT key, value FROM prov_schema.kya_weight_overrides
                WHERE tenant_id = :tid AND scope = :scope
            """),
            {"tid": tenant_id, "scope": scope},
        ).fetchall()
        for k, v in rows:
            weights[k] = int(v)

    return weights


# ── Write-side ───────────────────────────────────────────────────────────


class OverrideLoosensError(ValueError):
    """Raised when a tenant tries to LOWER a weight below the platform default.

    Mirrors `agents.tool_rbac_overrides.OverrideLoosensError` semantics —
    tenants can only tighten (raise risk), not loosen (reduce risk)."""


def _check_only_tighten(
    db,
    scope: str,
    key: str,
    new_value: int,
    tenant_id: str | None,
    *,
    allow_platform_decrease: bool = False,
) -> None:
    """Reject the override if `new_value` < the effective platform weight.

    Defense-in-depth: both tenant-level AND platform-level writes
    default to only-tighten now. Previously, platform-level writes
    (tenant_id=None) skipped the check entirely, which left a path for
    a compromised collector signing key to silently lower the platform
    default through the inbound apply pipeline. Per-tenant overrides
    survive that scenario (tenant W_t >= W_0 at write time), but any
    NEW tenant inheriting the lowered default would be exposed.

    Platform admins that *intentionally* lower a default must pass
    ``allow_platform_decrease=True`` explicitly. The inbound apply
    path keeps that flag False so signed-recommendation decreases are
    blocked unless an operator explicitly chooses to apply them through
    a path that opts in.
    """
    if scope not in _SCOPE_REGISTRY:
        raise ValueError(f"unknown weight scope: {scope}")

    from sqlalchemy import and_, select

    from ._legacy_tables import kya_weight_overrides
    platform_eff = dict(_SCOPE_REGISTRY[scope])

    if tenant_id:
        # Tenant write: reject if below the platform default. Unchanged
        # behavior — the historical only-tighten guarantee.
        row = db.execute(
            select(kya_weight_overrides.c.value).where(
                and_(
                    kya_weight_overrides.c.tenant_id.is_(None),
                    kya_weight_overrides.c.scope == scope,
                    kya_weight_overrides.c.key == key,
                )
            )
        ).fetchone()
        platform_value = int(row[0]) if row else platform_eff.get(key, 0)
        if new_value < platform_value:
            raise OverrideLoosensError(
                f"tenant override for {scope}.{key} (value={new_value}) is "
                f"below the platform default ({platform_value}). Tenants can "
                f"only tighten, not loosen."
            )
        return

    # Platform write (tenant_id is None). Defense-in-depth check vs the
    # CURRENT platform value (or in-process default if no override
    # exists yet). Skipped only if the caller explicitly opts in.
    if allow_platform_decrease:
        return
    row = db.execute(
        select(kya_weight_overrides.c.value).where(
            and_(
                kya_weight_overrides.c.tenant_id.is_(None),
                kya_weight_overrides.c.scope == scope,
                kya_weight_overrides.c.key == key,
            )
        )
    ).fetchone()
    current_platform_value = int(row[0]) if row else platform_eff.get(key, 0)
    if new_value < current_platform_value:
        raise OverrideLoosensError(
            f"platform write for {scope}.{key} (value={new_value}) is "
            f"below the current platform value ({current_platform_value}). "
            f"Platform decreases require explicit opt-in via "
            f"set_override(..., allow_platform_decrease=True)."
        )


def _current_value(db, scope: str, key: str, tenant_id: str | None) -> int | None:
    from sqlalchemy import and_, select

    from ._legacy_tables import kya_weight_overrides
    if tenant_id is None:
        clause = and_(
            kya_weight_overrides.c.tenant_id.is_(None),
            kya_weight_overrides.c.scope == scope,
            kya_weight_overrides.c.key == key,
        )
    else:
        clause = and_(
            kya_weight_overrides.c.tenant_id == tenant_id,
            kya_weight_overrides.c.scope == scope,
            kya_weight_overrides.c.key == key,
        )
    row = db.execute(select(kya_weight_overrides.c.value).where(clause)).fetchone()
    return int(row[0]) if row else None


def _audit(
    db,
    scope: str,
    key: str,
    old_value: int | None,
    new_value: int | None,
    action: str,
    tenant_id: str | None,
    changed_by: str | None,
    reason: str | None,
) -> None:
    from ._legacy_tables import kya_weight_changes
    db.execute(kya_weight_changes.insert().values(
        tenant_id=tenant_id, scope=scope, key=key,
        old_value=old_value, new_value=new_value,
        action=action, changed_by=changed_by, reason=reason,
    ))


def set_override(
    db,
    scope: str,
    key: str,
    value: int,
    tenant_id: str | None = None,
    changed_by: str | None = None,
    reason: str | None = None,
    *,
    allow_platform_decrease: bool = False,
) -> dict:
    """Set or update a weight override. Validates only-tighten for both
    tenant overrides AND platform writes. Audits the change. Returns
    the new row.

    ``allow_platform_decrease=True`` opts out of the platform-level
    only-tighten check (added 2026-05). Tenant-level writes ignore the
    flag — they're always only-tighten relative to the platform default.

    Cross-backend via portable_upsert (tenant-level) or via direct
    UPDATE-or-INSERT (platform-level — partial unique index on
    ``(scope, key) WHERE tenant_id IS NULL`` does not have a portable
    on-conflict target).
    """
    from datetime import datetime, timezone

    from ._dialect_helpers import portable_upsert
    from ._legacy_tables import kya_weight_overrides

    ensure_tables(db)
    if scope not in _SCOPE_REGISTRY:
        raise ValueError(f"unknown weight scope: {scope}")
    if not isinstance(value, int):
        raise ValueError("value must be an integer")
    _check_only_tighten(
        db, scope, key, value, tenant_id,
        allow_platform_decrease=allow_platform_decrease,
    )

    old = _current_value(db, scope, key, tenant_id)
    now_utc = datetime.now(timezone.utc)
    if tenant_id is None:
        # Platform-level write: portable_upsert's ON CONFLICT
        # (tenant_id, scope, key) target does NOT fire because PG +
        # SQLite default-treat NULL as DISTINCT, so a second INSERT
        # would create a duplicate. We added a partial unique index
        # (uq_kya_weight_overrides_platform_scope_key) to catch that
        # at the storage layer, which means portable_upsert would now
        # raise IntegrityError on the second platform-level write.
        # Application-level update-or-insert keeps the call portable
        # without needing a partial-index-aware on_conflict target.
        from sqlalchemy import and_, select
        from sqlalchemy import update as sa_update
        existing = db.execute(
            select(kya_weight_overrides.c.id).where(
                and_(
                    kya_weight_overrides.c.tenant_id.is_(None),
                    kya_weight_overrides.c.scope == scope,
                    kya_weight_overrides.c.key == key,
                )
            )
        ).scalar()
        if existing is not None:
            db.execute(
                sa_update(kya_weight_overrides)
                .where(kya_weight_overrides.c.id == existing)
                .values(value=value, updated_at=now_utc)
            )
        else:
            db.execute(
                kya_weight_overrides.insert().values(
                    tenant_id=None, scope=scope, key=key, value=value,
                    created_by=changed_by, updated_at=now_utc,
                )
            )
    else:
        portable_upsert(
            db,
            kya_weight_overrides,
            {
                "tenant_id": tenant_id,
                "scope": scope,
                "key": key,
                "value": value,
                "created_by": changed_by,
                "updated_at": now_utc,
            },
            conflict_cols=("tenant_id", "scope", "key"),
            update_cols=("value", "updated_at"),
        )
    _audit(db, scope, key, old, value, "set", tenant_id, changed_by, reason)
    db.commit()
    logger.info(
        "[KYA_WEIGHTS] %s.%s tenant=%s %s -> %s by=%s",
        scope,
        key,
        tenant_id or "platform",
        old,
        value,
        changed_by or "unknown",
    )
    return {
        "scope": scope,
        "key": key,
        "value": value,
        "tenant_id": tenant_id,
        "old_value": old,
    }


def delete_override(
    db,
    scope: str,
    key: str,
    tenant_id: str | None = None,
    changed_by: str | None = None,
    reason: str | None = None,
) -> bool:
    """Revert to the layer below (tenant→platform, or platform→default)."""
    ensure_tables(db)
    old = _current_value(db, scope, key, tenant_id)
    if old is None:
        return False
    db.execute(
        text("""
            DELETE FROM prov_schema.kya_weight_overrides
            WHERE scope = :scope AND key = :key
              AND ((:tid)::uuid IS NULL AND tenant_id IS NULL
                   OR tenant_id = (:tid)::uuid)
        """),
        {"scope": scope, "key": key, "tid": tenant_id},
    )
    _audit(db, scope, key, old, None, "delete", tenant_id, changed_by, reason)
    db.commit()
    return True


def list_overrides(db, tenant_id: str | None = None) -> list[dict]:
    """List overrides. tenant_id=None returns platform-level; otherwise
    returns both platform AND that tenant's overrides for visibility."""
    ensure_tables(db)
    if tenant_id is None:
        rows = db.execute(
            text("""
                SELECT tenant_id, scope, key, value, created_by, updated_at
                FROM prov_schema.kya_weight_overrides
                WHERE tenant_id IS NULL
                ORDER BY scope, key
            """),
        ).fetchall()
    else:
        rows = db.execute(
            text("""
                SELECT tenant_id, scope, key, value, created_by, updated_at
                FROM prov_schema.kya_weight_overrides
                WHERE tenant_id IS NULL OR tenant_id = :tid
                ORDER BY (tenant_id IS NULL) DESC, scope, key
            """),
            {"tid": tenant_id},
        ).fetchall()
    return [
        {
            "tenant_id": str(r[0]) if r[0] else None,
            "scope": r[1],
            "key": r[2],
            "value": int(r[3]),
            "created_by": str(r[4]) if r[4] else None,
            "updated_at": r[5].isoformat() if r[5] else None,
        }
        for r in rows
    ]


def list_recent_changes(db, tenant_id: str | None = None, limit: int = 100) -> list[dict]:
    """Recent audit-log entries for change visibility."""
    ensure_tables(db)
    if tenant_id is None:
        rows = db.execute(
            text("""
                SELECT tenant_id, scope, key, old_value, new_value, action,
                       changed_by, reason, created_at
                FROM prov_schema.kya_weight_changes
                ORDER BY created_at DESC LIMIT :lim
            """),
            {"lim": limit},
        ).fetchall()
    else:
        rows = db.execute(
            text("""
                SELECT tenant_id, scope, key, old_value, new_value, action,
                       changed_by, reason, created_at
                FROM prov_schema.kya_weight_changes
                WHERE tenant_id = :tid OR tenant_id IS NULL
                ORDER BY created_at DESC LIMIT :lim
            """),
            {"tid": tenant_id, "lim": limit},
        ).fetchall()
    return [
        {
            "tenant_id": str(r[0]) if r[0] else None,
            "scope": r[1],
            "key": r[2],
            "old_value": int(r[3]) if r[3] is not None else None,
            "new_value": int(r[4]) if r[4] is not None else None,
            "action": r[5],
            "changed_by": str(r[6]) if r[6] else None,
            "reason": r[7],
            "created_at": r[8].isoformat() if r[8] else None,
        }
        for r in rows
    ]
