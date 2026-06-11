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
# Top-level JWT claims preserved verbatim from a verified VC. Anything
# outside this set is dropped — issuers cannot smuggle policy-relevant
# fields ("kya_override", "shell_cmd", etc.) through a signed VC.
_ALLOWED_TOP_LEVEL_CLAIMS: frozenset[str] = frozenset({
    "iss", "sub", "iat", "exp", "nbf", "aud", "jti",
})

# W3C VC data-model fields preserved under `vc.*`. Issuer-defined claims
# live under `vc.credentialSubject`, which we keep — but only inside the
# enumerated vc.* container shape.
_ALLOWED_VC_FIELDS: frozenset[str] = frozenset({
    "@context", "type", "id", "issuer", "issuanceDate", "expirationDate",
    "credentialSubject", "credentialStatus", "credentialSchema",
    "termsOfUse", "evidence", "refreshService",
})

# Cap the sanitized claim set (serialized) to keep DB rows small and to
# bound the memory cost of a single principal's attribute blob.
_MAX_VC_CLAIMS_BYTES: int = 8 * 1024


def _sanitize_vc_claims(raw: dict) -> dict:
    """Drop non-allowlisted top-level / vc.* fields from a verified VC's claims.

    The VC verifier has already proven the issuer signed everything in
    ``raw``. But "the issuer signed it" does not mean "downstream policy
    should honor it as a directive." We keep the spec-shaped fields and
    drop the rest before persisting to principal.attributes.
    """
    out: dict = {}
    for key, value in raw.items():
        if key not in _ALLOWED_TOP_LEVEL_CLAIMS and key != "vc":
            continue
        if key == "vc":
            if not isinstance(value, dict):
                continue
            vc_clean: dict = {}
            for vk, vv in value.items():
                if vk in _ALLOWED_VC_FIELDS:
                    vc_clean[vk] = vv
            out["vc"] = vc_clean
        else:
            out[key] = value
    return out


IDP_KINDS: frozenset[str] = frozenset({
    "okta",
    "auth0",
    "keycloak",
    "google",       # Google Workspace / Google Identity
    "microsoft",    # Entra ID (formerly Azure AD)
    "aws_cognito",
    "spiffe",       # SPIFFE workload identity (Phase 4c)
    "did",          # W3C Decentralized Identifier (Phase 3d)
    "internal",     # KYA-internal / self-hosted; no external IdP
    "custom",       # any other / per-tenant special case
})


class InvalidIdpKindError(ValueError):
    """Raised when an unknown idp_kind is supplied."""


def _schema_prefix(db) -> str:
    try:
        from ._portable import qual_for_raw_sql
        return qual_for_raw_sql(db)
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
    rather than raw text() UPDATE so the same code path runs across
    PG, MySQL, SQLite, and DuckDB. DuckDB's index handling treats
    raw UPDATE on composite-primary-key tables as a constraint
    violation; the ORM emits the shape DuckDB handles.
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


# ─────────────────────────────────────────────────────────────────────
# Phase 3d — DID-bound principals.
#
# `bind_did_principal` is a thin wrapper around `bind_principal_to_idp`
# that uses idp_kind="did" and, optionally, verifies a Verifiable
# Credential before performing the bind. Keeping it as a separate
# function (rather than overloading bind_principal_to_idp) makes the
# DID call site self-explanatory and means callers who don't have DID
# dependencies installed don't import kya.did transitively.
# ─────────────────────────────────────────────────────────────────────


# Phase 5h — DID-aware segment matcher for `auto_approve_patterns`.
# `fnmatch`'s `*` crosses `:` boundaries (security defect 5h-DOC-02).
# This matcher treats `:` as a path separator: `*` matches exactly
# one segment, never multiple.
#
# Per DID Core §3.1 + RFC 3986 — per-segment grammar is
#   idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
#   pct-encoded = "%" HEXDIG HEXDIG
# Round-3 NEW-2 — `%` MUST be followed by two hex digits.
import re as _re

_SEGMENT_RE = r"(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+"
_PATTERN_RE = _re.compile(
    rf"^did:[a-z0-9]+(:{_SEGMENT_RE})+(:\*)?$",
)


def _did_segment_match(did: str, pattern: str) -> bool:
    """Match a DID URI against a single-segment-wildcard pattern.

    Pattern semantics (5h-DOC-02):
      - exact match if pattern has no trailing `:*`
      - `did:web:fleet-a:*` matches `did:web:fleet-a:drone-1234`
      - `did:web:fleet-a:*` does NOT match `did:web:fleet-a-evil:drone`
        (different second-segment)
      - `did:web:fleet-a:*` does NOT match `did:web:fleet-a:evil:drone`
        (`*` matches one segment, never multiple)

    5h-10 — both `did` and `pattern` are normalized via
    ``normalize_admin_did`` first so an operator pasting a mixed-case
    did:web hostname into ``auto_approve_patterns`` matches the
    canonical lowercase form. Without this, an attacker registering
    a case-variant DID could evade an allowlist.
    """
    nd = normalize_admin_did(did)
    np = normalize_admin_did(pattern)
    if not np.endswith(":*"):
        return nd == np
    prefix = np[:-1]   # strip the "*", keep the trailing ":"
    if not nd.startswith(prefix):
        return False
    tail = nd[len(prefix):]
    # Non-empty, no further ':' — i.e., exactly one segment.
    return bool(tail) and ":" not in tail


# Phase 5h — DID method-aware admin principal_id normalization
# (5h-DOC-03; round-3 NEW-3). The dual-admin equality check compares
# normalized principal_ids; the normalization rule MUST be
# DID-method-specific to avoid:
#   - false equality on byte-different multibase encodings (did:key)
#   - real self-approval bypass via hostname case (did:web)
#
# Closed-set rule; unknown methods fall through to byte-exact.
# NOTE: defined BEFORE _did_segment_match because the matcher calls it.
def normalize_admin_did(did: str) -> str:
    """Return a canonical form of a DID for admin equality checks.

    did:web — hostname case-folded (RFC 3986 §3.2.2); path byte-exact.
    did:key — byte-exact (multibase is case-sensitive).
    did:jwk — byte-exact (base64url is case-sensitive).
    other  — byte-exact by default.
    """
    if not isinstance(did, str) or not did.startswith("did:"):
        return did
    parts = did.split(":", 3)   # ["did", method, host_or_id, rest?]
    if len(parts) < 3:
        return did
    method = parts[1]
    if method == "web":
        host = parts[2].lower()
        if len(parts) == 4:
            return f"did:web:{host}:{parts[3]}"
        return f"did:web:{host}"
    return did   # did:key, did:jwk, future methods → byte-exact


def check_vc_scope_against_issuer(
    parent_def: dict,
    vc_claims: dict,
) -> list[dict]:
    """Phase 5g #6 — run the VC's `credentialSubject` scope claims
    through KYA's delegation policy as if the subject were a sub-agent
    of the issuer.

    `parent_def` is the issuer's agent definition (the ceiling).
    `vc_claims` is the verified VC claim set (the parent.attributes
    blob KYA persisted after VC verification).

    Returns the violation list (empty == within ceiling). Read-only —
    no DB writes. Callers (gateway, bind_did_principal) decide what to
    do with the violations: log, emit security event, raise, or all.

    5g-B-02 — VC claims may use either ``human_loop`` (KYA-native) or
    ``human_in_loop`` (VC-spec-friendly); both are translated to the
    key the delegation_policy module reads.
    5g-B-12 — fail-CLOSED when delegation_policy can't be imported:
    return a synthetic violation so the caller treats this as a
    rejected scope, not a passed one.
    """
    cred_subject = (
        ((vc_claims.get("vc") or {}).get("credentialSubject") or {})
        if isinstance(vc_claims, dict) else {}
    )
    if not isinstance(cred_subject, dict):
        return []
    # Synthesize a sub_def from the VC's claimed scope so the existing
    # check_delegation policy primitives apply unchanged.
    sub_def: dict = {}
    if "access_level" in cred_subject:
        sub_def["access_level"] = cred_subject["access_level"]
    if "data_classes" in cred_subject:
        sub_def["data_classes"] = cred_subject["data_classes"]
    if "tools" in cred_subject:
        sub_def["tools"] = list(cred_subject["tools"] or [])
    # Accept both the KYA-internal ``human_loop`` and the VC-data-model
    # phrasing ``human_in_loop``. Without this the most safety-critical
    # dimension would silently widen through a VC scope claim.
    if "human_loop" in cred_subject:
        sub_def["human_loop"] = cred_subject["human_loop"]
    elif "human_in_loop" in cred_subject:
        sub_def["human_loop"] = cred_subject["human_in_loop"]
    if not sub_def:
        return []
    try:
        from .delegation_policy import check_delegation
    except ImportError:
        # Fail-CLOSED: a security check that can't run should reject,
        # not silently pass.
        return [{
            "violation_kind": "scope_check_unavailable",
            "detail": "kya.delegation_policy could not be imported",
        }]
    return check_delegation(parent_def, sub_def)


def issuer_tenant_id_from_did(issuer_did: str) -> str:
    """Phase 5g #8 — derive a stable UUID-shaped tenant_id from an
    issuer DID. Same DID → same UUID; different DIDs → different.

    Lets multi-issuer pro deployments isolate their audit + invocation
    rows in `kya_*` tables that expect UUID-length tenant_ids, instead
    of every issuer-API writing under the same `"kya-pro-issuer"` bucket.

    5g-B-09 — uses ``NAMESPACE_URL`` (not ``NAMESPACE_OID``) because
    DIDs are URIs per DID Core §3.1. This is the obvious choice an
    interoperating system will compute, so the same DID produces the
    same tenant_id across deployments.
    """
    import uuid
    if not issuer_did:
        raise ValueError("issuer_did must be non-empty")
    return str(uuid.uuid5(uuid.NAMESPACE_URL, issuer_did))


def _lookup_agent_def(db, tenant_id: str, principal_id: str) -> dict | None:
    """Read the latest agent definition snapshot for a principal_id.

    Returns None if no snapshot exists (cross-org issuer, fresh tenant,
    etc.). Tests may monkey-patch.
    """
    try:
        from .delegation_policy import _latest_snapshot
        # delegation_policy uses agent_key; we use principal_id as the key.
        return _latest_snapshot(db, tenant_id, principal_id)
    except Exception:
        return None


def _lookup_principal_by_did(
    db, tenant_id: str, did: str,
) -> tuple[str, str] | None:
    """Find the KYA principal (kind, id) whose binding matches a given DID.

    5g-B-03 — returns BOTH ``principal_kind`` and ``principal_id`` so
    the auto-link writes edges at the correct composite key, not at a
    hardcoded ``parent_kind="agent"``.
    5g-B-08 — orders by ``updated_at DESC`` so a transient duplicate
    during a re-bind doesn't fail the lookup; logs a WARNING when more
    than one row matches.
    """
    try:
        from sqlalchemy import select, desc
        from .principals import _PrincipalRow, _bind_schema
        _bind_schema(db.get_bind())
        rows = db.execute(
            select(_PrincipalRow.principal_kind, _PrincipalRow.principal_id)
            .where(_PrincipalRow.tenant_id == tenant_id)
            .where(_PrincipalRow.idp_kind == "did")
            .where(_PrincipalRow.idp_subject == did)
            .order_by(desc(_PrincipalRow.updated_at))
            .limit(2)
        ).all()
        if not rows:
            return None
        if len(rows) > 1:
            logger.warning(
                "[KYA-DID] multiple principals bound to %s in tenant=%s — "
                "using most recent; rows=%s",
                did, tenant_id, rows,
            )
        return (str(rows[0][0]), str(rows[0][1]))
    except Exception as exc:
        logger.debug("[KYA-DID] _lookup_principal_by_did failed: %s", exc)
        return None


def link_vc_issuer_to_child(
    db,
    *,
    tenant_id: str,
    issuer_did: str,
    issuer_principal_id: str | None,
    issuer_principal_kind: str = "agent",
    child_principal_kind: str,
    child_principal_id: str,
) -> bool:
    """Phase 5g #5 — link a VC's issuer DID to its subject as a
    delegation-graph edge when the issuer is a KYA-known principal.

    Called by ``bind_did_principal`` (and the gateway, after a successful
    VC verification) so the delegation graph reflects "issuer -> subject"
    relationships without callers having to scan the principal
    attributes blob.

    5g-B-03 — the issuer's ``principal_kind`` must be passed explicitly
    (default "agent" preserved for back-compat callers that only had the
    id). Without this, a service_account issuer would produce a ghost
    edge pointing at a non-existent ``(agent, issuer_principal_id)``.

    Returns True if an edge was written, False when the issuer is not a
    known principal in this tenant (no-op, no ghost edges).
    """
    if not issuer_principal_id or not issuer_did:
        return False
    try:
        from .principal_edges import add_principal_edge
        add_principal_edge(
            db,
            tenant_id=tenant_id,
            parent_kind=issuer_principal_kind,
            parent_id=issuer_principal_id,
            child_kind=child_principal_kind,
            child_id=child_principal_id,
            edge_kind="vc_issued",
            attributes={"issuer_did": issuer_did},
        )
        return True
    except Exception as exc:
        logger.warning("[KYA-DID] link_vc_issuer_to_child failed: %s", exc)
        return False


def bind_did_principal(
    db,
    *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    did: str,
    vc: str | None = None,
    audience: str | None = None,
    trusted_issuers: set[str] | None = None,
) -> bool:
    """Bind a principal to a W3C DID, optionally with a Verifiable Credential.

    The function:
        1. Validates the DID by resolving it (raises if the resolver is
           disabled or the DID is malformed).
        2. If ``vc`` is provided, verifies the JWT-VC against the issuer's
           DID and records the VC's claim set on the principal's
           ``attributes.did_vc_claims``. The bind succeeds only when the
           VC verifies and (if specified) its ``sub`` matches ``did``.
        3. Calls :func:`bind_principal_to_idp` with ``idp_kind="did"``.

    Args:
        db: A KYA session.
        tenant_id: KYA tenant.
        principal_kind / principal_id: Identifies which existing principal
            row to bind. The row must already exist (per the contract of
            ``bind_principal_to_idp``).
        did: The DID URI to bind (e.g., ``"did:web:bank.example:user42"``).
        vc: Optional JWT-VC string. When present, KYA verifies it and stores
            the issuer DID as the IdP issuer.
        audience: Forwarded to VC verification (``aud`` claim check).
        trusted_issuers: Optional explicit allowlist. Passing ``None``
            (the default) falls back to the ``KYA_DID_TRUSTED_ISSUERS``
            env var (comma-separated); when that's also empty, the
            auto-link is permissive (links any verified VC's issuer
            to a known principal). Passing an empty set explicitly
            means "trust no issuer" — denies all auto-links even
            for verified VCs.

    Returns:
        True if the bind was recorded, False if the principal row doesn't
        exist or the DB write failed (matching the parent function's
        semantics).

    Raises:
        DIDError / VCError: When the DID can't be resolved or the VC
            doesn't verify. The bind never proceeds in those cases.
    """
    # Lazy-import so kya.did and kya.vc are not required by callers
    # that don't use DID. Keeps the cold-import surface small.
    import json as _json
    from kya.did import DIDError, resolve_did
    from kya.vc import VCError, verify_vc

    if not did or not isinstance(did, str) or not did.startswith("did:"):
        raise ValueError(f"did must be a DID URI starting with 'did:', got {did!r}")

    # Step 1 — resolve the DID. This raises if the method is not enabled
    # or the DID document is malformed. We don't catch — let the error
    # propagate to the caller so the failure mode is explicit.
    resolve_did(did)

    issuer_for_idp = did  # Default: DID is self-issued.
    vc_claims_sanitized: dict | None = None

    # Step 2 — verify VC if provided.
    if vc is not None:
        verified = verify_vc(vc, audience=audience, trusted=trusted_issuers)
        # Strict subject check — a VC without sub (or with sub ≠ did) must
        # NOT bind. Otherwise a trusted issuer's sub-less attestation
        # becomes a universal binding token.
        if verified.subject_did != did:
            raise VCError(
                f"VC subject {verified.subject_did!r} does not match bound "
                f"DID {did!r} (sub-less VCs are rejected as universal-binding)"
            )
        issuer_for_idp = verified.issuer_did
        vc_claims_sanitized = _sanitize_vc_claims(dict(verified.claims))
        # Reject before any DB work if the (sanitized) blob would exceed
        # the cap. This is the only check that gates an oversized VC.
        serialized = _json.dumps(vc_claims_sanitized, separators=(",", ":"))
        if len(serialized) > _MAX_VC_CLAIMS_BYTES:
            raise VCError(
                f"VC claims (sanitized) {len(serialized)} bytes exceeds "
                f"cap of {_MAX_VC_CLAIMS_BYTES}"
            )

    # Step 3 — atomic bind + attribute write in a single transaction.
    # We do this directly (rather than calling bind_principal_to_idp +
    # a follow-up SET) because the two-phase approach allowed the bind
    # to succeed while the attributes write silently failed.
    try:
        from sqlalchemy import select
        from ._dialect_helpers import portable_upsert
        from .principals import _bind_schema, _PrincipalRow
        from datetime import datetime, timezone
        _bind_schema(db.get_bind())
        existing = db.execute(
            select(_PrincipalRow)
            .where(_PrincipalRow.tenant_id == tenant_id)
            .where(_PrincipalRow.principal_kind == principal_kind)
            .where(_PrincipalRow.principal_id == principal_id)
        ).scalar_one_or_none()
        if existing is None:
            return False

        fed = _canonical_federated_id(
            idp_kind="did", idp_issuer=issuer_for_idp, idp_subject=did,
        )
        merged_attrs = dict(existing.attributes or {})
        update_cols = ["idp_subject", "idp_issuer", "idp_kind",
                       "federated_id", "updated_at"]
        if vc_claims_sanitized is not None:
            merged_attrs["did_vc_claims"] = vc_claims_sanitized
            update_cols.append("attributes")
        portable_upsert(
            db,
            table=_PrincipalRow.__table__,
            values={
                "tenant_id": tenant_id,
                "principal_kind": principal_kind,
                "principal_id": principal_id,
                "idp_subject": did,
                "idp_issuer": issuer_for_idp,
                "idp_kind": "did",
                "federated_id": fed,
                "updated_at": datetime.now(timezone.utc),
                "trust_score": existing.trust_score,
                "signal_counts": existing.signal_counts or {},
                "attributes": merged_attrs,
            },
            conflict_cols=("tenant_id", "principal_kind", "principal_id"),
            update_cols=tuple(update_cols),
        )
        # 5g-B-04 round-3 — honest semantics. The bind upsert is the
        # AUTHORITATIVE outcome of this call; we commit it first.
        # The auto-link + scope-check are BEST-EFFORT enrichments —
        # `add_principal_edge` and `record_principal_signal` commit
        # internally (their concurrency guarantees rely on it), so a
        # truly atomic bind+link+event is structurally impossible
        # without refactoring those helpers' commit semantics.
        # Failures here are logged at WARNING so operators can detect
        # missing edges from the trust graph; the bind is preserved.
        db.commit()

        link_ok = True

        if vc is not None and issuer_for_idp and issuer_for_idp != did:
            # 5g-B-07 / N-2 — auto-link only fires when:
            #   - explicit allowlist passed AND issuer is in it, OR
            #   - explicit allowlist NOT passed AND env-var allowlist
            #     `KYA_DID_TRUSTED_ISSUERS` is empty (allow-all default)
            # Empty-set (not None) MEANS "deny all" — closes N-2 by
            # making the permissive default explicit only when no
            # constraint is supplied.
            effective_trusted = trusted_issuers
            if effective_trusted is None:
                # N-3 — actual env-var fallback the docstring promises.
                import os as _os
                env_raw = _os.getenv("KYA_DID_TRUSTED_ISSUERS", "").strip()
                if env_raw:
                    effective_trusted = {
                        i.strip() for i in env_raw.split(",") if i.strip()
                    }
            if effective_trusted is None:
                allow_link = True   # no allowlist configured → allow
            elif len(effective_trusted) == 0:
                allow_link = False  # caller explicitly trusts nobody
            else:
                allow_link = issuer_for_idp in effective_trusted
            if allow_link:
                try:
                    issuer_lookup = _lookup_principal_by_did(
                        db, tenant_id, issuer_for_idp,
                    )
                    if issuer_lookup:
                        issuer_kind, issuer_pid = issuer_lookup
                        link_vc_issuer_to_child(
                            db,
                            tenant_id=tenant_id,
                            issuer_did=issuer_for_idp,
                            issuer_principal_id=issuer_pid,
                            issuer_principal_kind=issuer_kind,
                            child_principal_kind=principal_kind,
                            child_principal_id=principal_id,
                        )
                        # Phase 5g #6 — VC scope check against the
                        # issuer's stored agent_def. Surfaces a
                        # security event + log; never raises.
                        try:
                            issuer_def = _lookup_agent_def(
                                db, tenant_id, issuer_pid,
                            )
                            if issuer_def and vc_claims_sanitized:
                                violations = check_vc_scope_against_issuer(
                                    issuer_def, vc_claims_sanitized,
                                )
                                if violations:
                                    try:
                                        from ._security_events import (
                                            emit_security_event,
                                        )
                                        emit_security_event(
                                            "rbac_refusal",
                                            tenant_id=tenant_id,
                                            primitive="vc_scope_check",
                                            principal_kind=principal_kind,
                                            principal_id=principal_id,
                                            detail={
                                                "issuer_did": issuer_for_idp,
                                                "violations": violations,
                                            },
                                            db=db,
                                        )
                                    except Exception as ev_exc:
                                        # N-5 — surface event-emission
                                        # failure; previously silenced.
                                        logger.warning(
                                            "[KYA-DID] vc_scope_check "
                                            "security event emit failed: %s",
                                            ev_exc,
                                        )
                                    logger.warning(
                                        "[KYA-DID] VC scope widens issuer "
                                        "ceiling — %d violation(s) for %s/%s",
                                        len(violations),
                                        principal_kind, principal_id,
                                    )
                        except Exception as exc:
                            # N-4 — scope-check failure is a security
                            # signal, not noise. WARN instead of DEBUG.
                            logger.warning(
                                "[KYA-DID] VC scope check failed: %s", exc,
                            )
                except Exception as exc:
                    link_ok = False
                    logger.warning(
                        "[KYA-DID] auto vc-issuer link failed: %s", exc,
                    )

        if not link_ok:
            logger.warning(
                "[KYA-DID] bind for %s/%s committed without vc-issuer "
                "edge — trust graph may be incomplete",
                principal_kind, principal_id,
            )

        return True
    except Exception as exc:
        logger.warning("[KYA-DID] bind_did_principal failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass
        return False
