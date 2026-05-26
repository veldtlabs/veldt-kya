"""
External-ID binding for principals and users — Phase 4b.

KYA tracks principals (users, agents, service_accounts) by an internal
opaque `principal_id` string. In federated environments, that string
is rarely the same as the upstream Identity Provider's identifier.
This module adds a structured binding from KYA's principal_id to:

    idp_subject  — the IdP's `sub` claim (Okta, Auth0, Keycloak,
                   Google, Azure, AWS Cognito all emit this in their
                   JWTs / userinfo responses)
    idp_issuer   — the `iss` claim (the IdP's URL), e.g.
                   "https://acme.okta.com" or "https://login.windows.net"
    idp_kind     — closed-set identifier of the IdP vendor / pattern:
                   "okta" | "auth0" | "keycloak" | "google" |
                   "microsoft" | "aws_cognito" | "spiffe" |
                   "internal" | "custom"
    federated_id — opaque canonical form for cross-tenant queries,
                   typically "{idp_kind}|{idp_issuer}|{idp_subject}"

The columns are NULLABLE — callers who don't need IdP binding (e.g.,
single-tenant deployments using KYA-internal IDs) leave them empty
and nothing changes.

Phase 4a (JWT introspection) will provide a path that auto-populates
these fields from a decoded bearer token. Phase 4b ships the storage
+ lookup primitive standalone so:

  - Apps that already decode JWTs at the API gateway can populate
    the fields directly (caller provides the claims).
  - Dashboards can pivot from "trust score" → "Okta user record"
    without parsing the `attributes` JSON blob.
  - Phase 4c (SPIFFE) reuses the same columns for workload identity.

NULL fields are NOT enforced. KYA's role is to record what the caller
declares, not to enforce that every principal has an IdP binding.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import text

logger = logging.getLogger(__name__)


# Closed set of IdP kind identifiers. Keep this short and canonical;
# operators with custom IdP integrations use "custom" + populate
# idp_issuer to distinguish.
IDP_KINDS: frozenset[str] = frozenset({
    "okta",
    "auth0",
    "keycloak",
    "google",       # Google Workspace / Google Identity
    "microsoft",    # Entra ID (formerly Azure AD)
    "aws_cognito",
    "spiffe",       # SPIFFE workload identity (Phase 4c)
    "internal",     # KYA-internal / self-hosted; no external IdP
    "custom",       # any other / per-tenant special case
})


class InvalidIdpKindError(ValueError):
    """Raised when an unknown idp_kind is supplied."""


def _schema_prefix(db) -> str:
    try:
        return ("prov_schema."
                if db.get_bind().dialect.name == "postgresql"
                else "")
    except Exception:
        return ""


def _canonical_federated_id(
    *,
    idp_kind: str | None,
    idp_issuer: str | None,
    idp_subject: str,
) -> str:
    """Default canonical form. Callers can override by passing
    federated_id= explicitly to the bind functions."""
    parts = [idp_kind or "unknown",
             idp_issuer or "",
             idp_subject]
    return "|".join(parts)


def _validate(
    *,
    tenant_id: str,
    idp_subject: str,
    idp_kind: str | None,
) -> None:
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not idp_subject:
        raise ValueError("idp_subject is required")
    if idp_kind is not None and idp_kind not in IDP_KINDS:
        raise InvalidIdpKindError(
            f"Unknown idp_kind {idp_kind!r}; must be one of "
            f"{sorted(IDP_KINDS)}")


# ── Principal binding (kya_principal_trust) ───────────────────────


def bind_principal_to_idp(
    db, *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    idp_subject: str,
    idp_issuer: str | None = None,
    idp_kind: str | None = None,
    federated_id: str | None = None,
) -> bool:
    """Bind an existing principal_trust row to an IdP identifier.

    The principal row must already exist (created by
    record_principal_signal or record_principal_clean). If it doesn't,
    this returns False — we never create rows from this path because
    a principal without trust signals is meaningless.

    Idempotent: re-binding the same principal to the same idp_subject
    is a no-op. Re-binding to a DIFFERENT idp_subject overwrites
    (last-write-wins) — KYA assumes the most recent binding is
    authoritative.

    Returns True if a row was updated, False if the principal row
    doesn't exist or the write failed. Fail-soft on DB errors.

    Implementation note: uses the ORM (select → mutate → commit)
    rather than raw text() UPDATE. DuckDB has a documented quirk
    where raw UPDATE on tables with composite primary keys fires a
    "Duplicate key violates primary key constraint" error (see
    https://duckdb.org/docs/sql/indexes — known index limitations).
    The ORM emits a different SQL shape that DuckDB handles
    correctly. Same code runs on PG/SQLite/MySQL.
    """
    _validate(tenant_id=tenant_id, idp_subject=idp_subject,
              idp_kind=idp_kind)
    fed = federated_id or _canonical_federated_id(
        idp_kind=idp_kind, idp_issuer=idp_issuer,
        idp_subject=idp_subject)
    try:
        from sqlalchemy import select

        from ._dialect_helpers import portable_upsert
        from .principals import _bind_schema, _PrincipalRow
        _bind_schema(db.get_bind())
        # SELECT-first: enforce "no row, no bind" — never create
        # a principal_trust row from this path. Existence verified
        # before the upsert.
        existing = db.execute(
            select(_PrincipalRow)
            .where(_PrincipalRow.tenant_id == tenant_id)
            .where(_PrincipalRow.principal_kind == principal_kind)
            .where(_PrincipalRow.principal_id == principal_id)
        ).scalar_one_or_none()
        if existing is None:
            return False
        # ON CONFLICT DO UPDATE — the row exists (just verified), so
        # the INSERT branch never fires; only the UPDATE branch is
        # exercised. This works around the DuckDB quirk where a raw
        # UPDATE on a table with a composite primary key fires a
        # bogus duplicate-key error.
        portable_upsert(
            db,
            table=_PrincipalRow.__table__,
            values={
                "tenant_id": tenant_id,
                "principal_kind": principal_kind,
                "principal_id": principal_id,
                "idp_subject": idp_subject,
                "idp_issuer": idp_issuer,
                "idp_kind": idp_kind,
                "federated_id": fed,
                "updated_at": datetime.now(timezone.utc),
                # Existing values supplied for the INSERT branch only
                # (never reached because row exists). Required because
                # portable_upsert builds a single INSERT...ON CONFLICT
                # statement with all columns; the SET clause on the
                # ON CONFLICT side picks only the IdP columns to update.
                "trust_score": existing.trust_score,
                "signal_counts": existing.signal_counts or {},
                "attributes": existing.attributes or {},
            },
            conflict_cols=("tenant_id", "principal_kind",
                            "principal_id"),
            update_cols=("idp_subject", "idp_issuer", "idp_kind",
                          "federated_id", "updated_at"),
        )
        db.commit()
        return True
    except Exception as exc:
        logger.warning("[KYA-IDP] bind_principal failed: %s", exc)
        try: db.rollback()
        except Exception: pass
        return False


def lookup_principal_by_idp(
    db, *,
    tenant_id: str,
    idp_subject: str,
) -> dict | None:
    """Find a principal_trust row by IdP subject. Returns None if no
    binding exists (NOT an error). Index-backed: (tenant_id,
    idp_subject) hits the idx_kya_principal_trust_tenant_idp_subject
    index — sub-millisecond on any indexed backend."""
    if not tenant_id or not idp_subject:
        return None
    schema = _schema_prefix(db)
    try:
        row = db.execute(text(
            f"SELECT tenant_id, principal_kind, principal_id, "
            f"       trust_score, idp_subject, idp_issuer, "
            f"       idp_kind, federated_id "
            f"FROM {schema}kya_principal_trust "
            f"WHERE tenant_id = :t AND idp_subject = :sub"
        ), {"t": tenant_id, "sub": idp_subject}).first()
    except Exception as exc:
        logger.debug("[KYA-IDP] lookup_principal failed: %s", exc)
        return None
    if row is None:
        return None
    return {
        "tenant_id": str(row[0]) if row[0] is not None else None,
        "principal_kind": row[1],
        "principal_id": row[2],
        "trust_score": row[3],
        "idp_subject": row[4],
        "idp_issuer": row[5],
        "idp_kind": row[6],
        "federated_id": row[7],
    }


def list_principals_by_idp_kind(
    db, *,
    tenant_id: str,
    idp_kind: str,
    limit: int = 1000,
) -> list[dict]:
    """List all principals bound to a specific IdP. Useful for
    dashboards that want to view all Okta-bound users vs all Auth0-
    bound users vs all SPIFFE-bound service_accounts in one tenant."""
    if idp_kind not in IDP_KINDS:
        raise InvalidIdpKindError(
            f"Unknown idp_kind {idp_kind!r}; "
            f"must be one of {sorted(IDP_KINDS)}")
    schema = _schema_prefix(db)
    try:
        rows = db.execute(text(
            f"SELECT tenant_id, principal_kind, principal_id, "
            f"       trust_score, idp_subject, idp_issuer, "
            f"       idp_kind, federated_id "
            f"FROM {schema}kya_principal_trust "
            f"WHERE tenant_id = :t AND idp_kind = :kind "
            f"ORDER BY principal_id "
            f"LIMIT :lim"
        ), {"t": tenant_id, "kind": idp_kind, "lim": int(limit)}).fetchall()
    except Exception as exc:
        logger.debug("[KYA-IDP] list_principals failed: %s", exc)
        return []
    return [{
        "tenant_id": str(r[0]) if r[0] is not None else None,
        "principal_kind": r[1],
        "principal_id": r[2],
        "trust_score": r[3],
        "idp_subject": r[4],
        "idp_issuer": r[5],
        "idp_kind": r[6],
        "federated_id": r[7],
    } for r in rows]


# ── User binding (kya_user_trust) ─────────────────────────────────


def bind_user_to_idp(
    db, *,
    tenant_id: str,
    user_id: str,
    idp_subject: str,
    idp_issuer: str | None = None,
    idp_kind: str | None = None,
    federated_id: str | None = None,
) -> bool:
    """Bind a KYU user_trust row to an IdP identifier. Same contract
    as bind_principal_to_idp but on the user_trust table.

    Uses the same SELECT-first + ON CONFLICT DO UPDATE pattern as
    bind_principal_to_idp — the user_trust row must already exist
    (created by record_user_signal or record_user_clean); we never
    create rows from this path. The ON CONFLICT pattern is the
    DuckDB-compatible alternative to a raw UPDATE on a unique-keyed
    row.
    """
    _validate(tenant_id=tenant_id, idp_subject=idp_subject,
              idp_kind=idp_kind)
    fed = federated_id or _canonical_federated_id(
        idp_kind=idp_kind, idp_issuer=idp_issuer,
        idp_subject=idp_subject)
    schema = _schema_prefix(db)
    try:
        from ._dialect_helpers import portable_upsert
        from ._legacy_tables import kya_user_trust
        existing = db.execute(text(
            f"SELECT id, trust_score, signal_counts "
            f"FROM {schema}kya_user_trust "
            f"WHERE tenant_id = :t AND user_id = :uid"
        ), {"t": tenant_id, "uid": user_id}).first()
        if existing is None:
            return False
        portable_upsert(
            db,
            table=kya_user_trust,
            values={
                "tenant_id": tenant_id,
                "user_id": user_id,
                "idp_subject": idp_subject,
                "idp_issuer": idp_issuer,
                "idp_kind": idp_kind,
                "federated_id": fed,
                "updated_at": datetime.now(timezone.utc),
                # Existing values for the INSERT branch (unreached).
                "trust_score": existing[1],
                "signal_counts": existing[2] or {},
            },
            conflict_cols=("tenant_id", "user_id"),
            update_cols=("idp_subject", "idp_issuer", "idp_kind",
                          "federated_id", "updated_at"),
        )
        db.commit()
        return True
    except Exception as exc:
        logger.warning("[KYA-IDP] bind_user failed: %s", exc)
        try: db.rollback()
        except Exception: pass
        return False


def lookup_user_by_idp(
    db, *,
    tenant_id: str,
    idp_subject: str,
) -> dict | None:
    """Find a user_trust row by IdP subject. Returns None if no
    binding exists."""
    if not tenant_id or not idp_subject:
        return None
    schema = _schema_prefix(db)
    try:
        row = db.execute(text(
            f"SELECT tenant_id, user_id, trust_score, "
            f"       idp_subject, idp_issuer, idp_kind, federated_id "
            f"FROM {schema}kya_user_trust "
            f"WHERE tenant_id = :t AND idp_subject = :sub"
        ), {"t": tenant_id, "sub": idp_subject}).first()
    except Exception as exc:
        logger.debug("[KYA-IDP] lookup_user failed: %s", exc)
        return None
    if row is None:
        return None
    return {
        "tenant_id": str(row[0]) if row[0] is not None else None,
        "user_id": str(row[1]) if row[1] is not None else None,
        "trust_score": row[2],
        "idp_subject": row[3],
        "idp_issuer": row[4],
        "idp_kind": row[5],
        "federated_id": row[6],
    }
