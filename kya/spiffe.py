"""
Phase 4c -- SPIFFE/OIDC workload identity for service_accounts.

SPIFFE (Secure Production Identity Framework For Everyone) is the
emerging cross-platform standard for workload identity. Where Phase
4a/4b cover human-identity federation (Okta, Auth0, Keycloak, etc.),
Phase 4c covers SERVICE-to-service identity:

    spiffe://<trust-domain>/<workload-path>

Examples (real SPIFFE IDs):
    spiffe://example.org/ns/prod/sa/inference-service
    spiffe://acme.aws/eks/cluster-1/ns/payments/sa/billing

What Phase 4c provides
----------------------
  - parse_spiffe_id()           - validate + split spiffe://td/path
  - verify_jwt_svid()           - verify a JWT-SVID using Phase 4a's
                                   verify_jwt; checks the embedded
                                   SPIFFE ID is well-formed and (if
                                   configured) in the trust-domain
                                   allowlist
  - bind_spiffe_id_to_principal - bind a known SPIFFE ID to an
                                   existing service_account principal
  - bind_principal_from_svid    - one-call: verify SVID + bind
  - lookup_principal_by_spiffe_id - reverse lookup

What this is NOT
----------------
  - NOT a SPIFFE issuer. SPIRE Server / Istio / Linkerd issue SVIDs.
    KYA only consumes them.
  - NOT X.509-SVID verification (yet). JWT-SVID only in this module.
    X.509-SVID requires cryptography's X.509 stack and a different
    verification chain; can be added as a follow-up without breaking
    the JWT-SVID API.
  - NOT a trust-bundle manager. Caller provides the JWKS endpoint or
    URL; KYA does not fetch/cache trust bundles separately from the
    Phase 4a JWKS cache.

Design contract
---------------
  - Reuses Phase 4a verify_jwt() entirely. No duplicate JWT logic.
  - Stores bindings via Phase 4b bind_principal_to_idp with
    idp_kind="spiffe". One canonical column set, two consumers.
  - Off-by-default: no verification or binding happens unless the
    caller explicitly invokes these functions.
  - Trust-domain allowlist resolution:
        per-call kwarg > KYA_SPIFFE_TRUST_DOMAINS env > unrestricted
    The "unrestricted" default is intentional - KYA cannot know the
    customer's trust domains a priori. Operators MUST configure the
    allowlist for any production deployment.
  - Fail-soft: invalid SVIDs return None from verify; bind returns
    False. Programmer errors (missing tenant_id, etc.) raise
    ValueError.

Optional dependency
-------------------
Same as Phase 4a: PyJWT >= 2.0 + requests (for JWKS fetch). No
additional packages required.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ── Errors ─────────────────────────────────────────────────────────


class SpiffeIdFormatError(ValueError):
    """Raised when a SPIFFE ID string does not conform to the spec."""


class SpiffeVerificationError(RuntimeError):
    """Raised by hard-mode verify paths when an SVID is invalid.
    Soft-mode paths return None / False instead."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"SPIFFE SVID verification failed: {reason}")


# ── SPIFFE ID parsing ──────────────────────────────────────────────


# SPIFFE ID grammar (per spec):
#   spiffe://<trust-domain>[/<path>]
#   trust-domain: lowercase alphanumeric, dots and hyphens; <= 255 chars
#   path: zero or more segments separated by '/'; each segment is
#         non-empty, no "." or ".." segments allowed
# Total SPIFFE ID <= 2048 chars.
_MAX_SPIFFE_ID_LEN = 2048
_MAX_TRUST_DOMAIN_LEN = 255


def parse_spiffe_id(uri: str) -> tuple[str, str]:
    """Validate and parse a SPIFFE ID.

    Args
    ----
    uri : str
        e.g. "spiffe://example.org/ns/prod/sa/inference"

    Returns
    -------
    (trust_domain, path) tuple. trust_domain never empty; path may
    be "" (for trust-domain-only IDs like "spiffe://example.org").

    Raises
    ------
    SpiffeIdFormatError on any malformation.
    """
    if not isinstance(uri, str):
        raise SpiffeIdFormatError(
            f"spiffe id must be str, got {type(uri).__name__}")
    if len(uri) == 0:
        raise SpiffeIdFormatError("spiffe id is empty")
    if len(uri) > _MAX_SPIFFE_ID_LEN:
        raise SpiffeIdFormatError(
            f"spiffe id exceeds {_MAX_SPIFFE_ID_LEN} chars")
    if not uri.startswith("spiffe://"):
        raise SpiffeIdFormatError(
            f"spiffe id must start with 'spiffe://', got {uri[:32]!r}")
    # Use urlparse for structured parse, then validate.
    try:
        parsed = urlparse(uri)
    except Exception as exc:
        raise SpiffeIdFormatError(
            f"spiffe id is unparseable: {exc}") from exc
    if parsed.scheme != "spiffe":
        raise SpiffeIdFormatError(
            f"spiffe id scheme must be 'spiffe', got {parsed.scheme!r}")
    trust_domain = parsed.netloc
    if not trust_domain:
        raise SpiffeIdFormatError(
            "spiffe id has empty trust domain")
    if len(trust_domain) > _MAX_TRUST_DOMAIN_LEN:
        raise SpiffeIdFormatError(
            f"trust domain exceeds {_MAX_TRUST_DOMAIN_LEN} chars")
    # Trust domain: lowercase, alphanumeric + dots + hyphens
    for ch in trust_domain:
        if not (ch.islower() or ch.isdigit() or ch in ".-"):
            raise SpiffeIdFormatError(
                f"trust domain contains invalid char {ch!r}; "
                f"must be lowercase alphanumeric, '.', or '-'")
    # Path validation per spec
    path = parsed.path or ""
    if path:
        if not path.startswith("/"):
            raise SpiffeIdFormatError(
                "spiffe id path must start with '/'")
        # Reject empty segments, ".", "..", and any char outside the
        # SPIFFE spec's path char class [a-zA-Z0-9._-]. Note we do NOT
        # decode percent-encoding -- urlparse leaves `%2f` as literal
        # text, and accepting it here would let two textually distinct
        # SPIFFE IDs map to the same logical workload, opening a
        # normalization gap.
        segments = path[1:].split("/")  # skip leading '/'
        for seg in segments:
            if seg == "":
                raise SpiffeIdFormatError(
                    "spiffe id path has empty segment")
            if seg in (".", ".."):
                raise SpiffeIdFormatError(
                    f"spiffe id path segment {seg!r} not allowed")
            for ch in seg:
                if not (ch.isalnum() or ch in "._-"):
                    raise SpiffeIdFormatError(
                        f"spiffe id path segment {seg!r} contains "
                        f"invalid char {ch!r}; per spec must be "
                        f"[a-zA-Z0-9._-]")
    if parsed.query or parsed.fragment:
        raise SpiffeIdFormatError(
            "spiffe id must not contain query or fragment")
    return trust_domain, path


def is_valid_spiffe_id(uri: str) -> bool:
    """Boolean predicate version of parse_spiffe_id."""
    try:
        parse_spiffe_id(uri)
        return True
    except SpiffeIdFormatError:
        return False


# ── Trust-domain allowlist ─────────────────────────────────────────


def _resolve_trust_domain_allowlist(
    explicit: list[str] | None,
) -> set[str] | None:
    """Resolve allowed trust domains.

    Resolution order:
        explicit arg > KYA_SPIFFE_TRUST_DOMAINS env > None (unrestricted)

    Returns None when no allowlist is configured (caller must decide
    whether to allow or reject in that case).
    """
    if explicit is not None:
        return {td.strip() for td in explicit if td.strip()}
    env = os.environ.get("KYA_SPIFFE_TRUST_DOMAINS", "").strip()
    if not env:
        return None
    return {td.strip() for td in env.split(",") if td.strip()}


_UNRESTRICTED_WARNED = False


def is_allowed_trust_domain(
    trust_domain: str,
    *,
    allowed: list[str] | None = None,
) -> bool:
    """Return True if `trust_domain` is in the configured allowlist
    OR no allowlist is configured (unrestricted mode).

    Unrestricted-mode is OFF-BY-DEFAULT secure in the sense that no
    verification fires unless the caller explicitly invokes verify_*;
    but for production, configure KYA_SPIFFE_TRUST_DOMAINS. Emits a
    one-time WARNING when accepting under unrestricted mode so an
    operator who forgot to set the env var sees a loud signal in
    the logs.
    """
    global _UNRESTRICTED_WARNED
    resolved = _resolve_trust_domain_allowlist(allowed)
    if resolved is None:
        if not _UNRESTRICTED_WARNED:
            logger.warning(
                "[KYA-SPIFFE] no trust-domain allowlist configured -- "
                "ALL trust domains will be accepted. Set "
                "KYA_SPIFFE_TRUST_DOMAINS (comma-separated) or pass "
                "allowed_trust_domains=[...] per call. This warning "
                "fires once per process.")
            _UNRESTRICTED_WARNED = True
        return True  # unrestricted
    return trust_domain in resolved


def _reset_spiffe_warned_state() -> None:
    """Test helper: clear the one-time-warning latch so each test
    can observe the warning behavior independently."""
    global _UNRESTRICTED_WARNED
    _UNRESTRICTED_WARNED = False


# ── JWT-SVID verification (reuses Phase 4a) ────────────────────────


def verify_jwt_svid(
    svid: str,
    *,
    jwks_url: str | None = None,
    expected_audience: str | None = None,
    allowed_trust_domains: list[str] | None = None,
    algorithms: list[str] | None = None,
    leeway_seconds: int | None = None,
) -> dict[str, Any] | None:
    """Verify a JWT-SVID and extract SPIFFE-specific claims.

    JWT-SVID only -- X.509-SVID is a future addition and would live in
    a sibling function (`verify_x509_svid`) once added.

    A JWT-SVID is a JWT issued by a SPIRE Server / SPIFFE-compatible
    issuer where:
      - The `sub` claim is the workload's SPIFFE ID
      - The `iss` claim identifies the trust domain
      - The signature is verifiable via the trust domain's JWKS

    This function:
      1. Verifies the JWT via Phase 4a verify_jwt (signature, exp,
         nbf, aud, iss, alg whitelist)
      2. Extracts `sub` and validates it as a SPIFFE ID
      3. Cross-checks `iss` trust domain against `sub` trust domain
         (rejects on mismatch -- defends against cross-trust-domain
         confusion attacks)
      4. Checks the SPIFFE ID's trust domain against the allowlist
         (KYA_SPIFFE_TRUST_DOMAINS env or `allowed_trust_domains`)

    Config resolution order (most specific wins):
      jwks_url:      kwarg > KYA_SPIFFE_JWKS_URL > KYA_JWT_JWKS_URL > None
      audience:      kwarg > KYA_SPIFFE_AUDIENCE > KYA_JWT_AUDIENCE > None
      trust_domains: kwarg > KYA_SPIFFE_TRUST_DOMAINS > unrestricted

    Args
    ----
    svid : str
        The JWT-SVID string (header.payload.signature, base64url).
    jwks_url : str | None
        JWKS endpoint for the trust domain's signing keys. Falls
        back to KYA_SPIFFE_JWKS_URL then KYA_JWT_JWKS_URL.
    expected_audience : str | None
        The aud claim KYA expects to see. Falls back to
        KYA_SPIFFE_AUDIENCE then KYA_JWT_AUDIENCE.
    allowed_trust_domains : list[str] | None
        Trust-domain allowlist override. Defaults to env.
    algorithms : list[str] | None
        Override JWT alg whitelist. Defaults to Phase 4a default.
    leeway_seconds : int | None
        Clock-skew leeway. Defaults to Phase 4a default.

    Returns
    -------
    dict with keys:
        spiffe_id      : the verified SPIFFE ID
        trust_domain   : extracted trust domain
        path           : extracted workload path
        claims         : full JWT claims dict
        idp_issuer     : "spiffe://<trust-domain>" (canonical issuer)
    OR None on any verification failure (fail-soft).
    """
    if not isinstance(svid, str) or not svid:
        logger.debug(
            "[KYA-SPIFFE] verify_jwt_svid called with empty/non-str "
            "svid -- returning None")
        return None

    # Resolve config from kwargs or env (SPIFFE-specific takes
    # priority over generic JWT env).
    if jwks_url is None:
        jwks_url = (os.environ.get("KYA_SPIFFE_JWKS_URL")
                    or os.environ.get("KYA_JWT_JWKS_URL"))
    if expected_audience is None:
        expected_audience = (os.environ.get("KYA_SPIFFE_AUDIENCE")
                             or os.environ.get("KYA_JWT_AUDIENCE"))
    if not jwks_url:
        logger.debug(
            "[KYA-SPIFFE] no JWKS URL configured -- cannot verify SVID")
        return None

    # Delegate JWT verification to Phase 4a -- DRY.
    # Lazy import is REQUIRED for test mocking — tests patch
    # `kya.auth.verify_jwt` at the module attribute and rely on
    # this call-site lookup to hit the patched object. Do NOT
    # hoist to a top-of-file import.
    try:
        from kya.auth import verify_jwt
    except ImportError as exc:
        logger.debug(
            "[KYA-SPIFFE] kya.auth.verify_jwt unavailable: %s", exc)
        return None

    # Defensive fail-soft: any exception in the JWT layer (programmer
    # errors, new failure modes added to Phase 4a) is converted to a
    # soft None so the SPIFFE-level "fail-soft" contract holds.
    try:
        claims = verify_jwt(
            svid,
            jwks_url=jwks_url,
            audience=expected_audience,
            algorithms=algorithms,
            leeway_seconds=leeway_seconds)
    except Exception as exc:
        logger.debug(
            "[KYA-SPIFFE] verify_jwt raised %s: %s",
            type(exc).__name__, exc)
        return None
    if claims is None:
        return None  # signature/exp/aud/iss already failed in Phase 4a

    sub = claims.get("sub")
    if not sub:
        logger.debug(
            "[KYA-SPIFFE] svid `sub` is missing -- not a JWT-SVID")
        return None

    try:
        trust_domain, path = parse_spiffe_id(sub)
    except SpiffeIdFormatError as exc:
        logger.debug(
            "[KYA-SPIFFE] svid `sub` is not a valid SPIFFE ID: %s",
            exc)
        return None

    # SPIFFE JWT-SVID spec requires iss parity with sub's trust domain.
    # A misconfigured (or attacker-controlled) JWKS could otherwise let
    # issuer A sign tokens whose sub claims trust domain B. Reject any
    # mismatch defensively. `iss` is OPTIONAL in the JWT-SVID spec, so
    # only enforce when present.
    iss = claims.get("iss")
    if iss:
        try:
            iss_td, _ = parse_spiffe_id(iss)
        except SpiffeIdFormatError:
            logger.warning(
                "[KYA-SPIFFE] iss %r is not a valid SPIFFE ID -- "
                "rejecting", iss)
            return None
        if iss_td != trust_domain:
            logger.warning(
                "[KYA-SPIFFE] iss trust-domain %r != sub trust-domain "
                "%r -- rejecting (cross-trust-domain confusion attack)",
                iss_td, trust_domain)
            return None

    if not is_allowed_trust_domain(
            trust_domain, allowed=allowed_trust_domains):
        logger.warning(
            "[KYA-SPIFFE] trust domain %r not in allowlist -- "
            "rejecting", trust_domain)
        return None

    return {
        "spiffe_id": sub,
        "trust_domain": trust_domain,
        "path": path,
        "claims": claims,
        "idp_issuer": f"spiffe://{trust_domain}",
    }


# ── Binding helpers (delegate to Phase 4b) ─────────────────────────


def bind_spiffe_id_to_principal(
    db, *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    spiffe_id: str,
    allowed_trust_domains: list[str] | None = None,
) -> bool:
    """Bind a (pre-verified) SPIFFE ID to an existing principal_trust
    row.

    Validates the SPIFFE ID format and trust-domain allowlist before
    writing. Returns False if the principal row doesn't exist (same
    semantics as Phase 4b bind_principal_to_idp).

    This is the "I already verified the SVID elsewhere" entry point.
    For the one-call verify+bind path, use bind_principal_from_svid.

    **principal_kind**: typically "service_account" -- SPIFFE is the
    workload-identity layer. The function does NOT enforce this so
    operators can attach SPIFFE IDs to other principal kinds (e.g.,
    "agent" for an agent that authenticates to KYA via SPIRE),
    but the design intent is service_account.

    **Re-binding semantics**: last-write-wins. Calling this twice for
    the same (tenant_id, principal_kind, principal_id) with different
    spiffe_ids will replace the prior binding -- the old SPIFFE ID
    becomes unfindable via lookup. This matches Phase 4b's
    bind_principal_to_idp contract and is the right behavior when a
    workload moves trust domains, but callers depending on
    stable bindings should bind once and use a different principal_id
    for replacements.
    """
    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not principal_id:
        raise ValueError("principal_id is required")
    try:
        trust_domain, _path = parse_spiffe_id(spiffe_id)
    except SpiffeIdFormatError:
        return False
    if not is_allowed_trust_domain(
            trust_domain, allowed=allowed_trust_domains):
        logger.warning(
            "[KYA-SPIFFE] refusing to bind: trust domain %r not in "
            "allowlist", trust_domain)
        return False

    # Delegate storage to Phase 4b -- single canonical column set.
    # `federated_id` is intentionally NOT passed: Phase 4b's
    # _canonical_federated_id produces "{idp_kind}|{idp_issuer}|
    # {idp_subject}" -> "spiffe|spiffe://<td>|<spiffe_id>", and we
    # want that exact shape so cross-tenant pivots match what other
    # callers of bind_principal_to_idp emit.
    from kya.external_id import bind_principal_to_idp
    return bind_principal_to_idp(
        db,
        tenant_id=tenant_id,
        principal_kind=principal_kind,
        principal_id=principal_id,
        idp_subject=spiffe_id,
        idp_issuer=f"spiffe://{trust_domain}",
        idp_kind="spiffe")


def bind_principal_from_svid(
    db, *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    svid: str,
    jwks_url: str | None = None,
    expected_audience: str | None = None,
    allowed_trust_domains: list[str] | None = None,
) -> bool:
    """One-call: verify the JWT-SVID, then bind to the principal.

    Returns True iff verification succeeds AND the bind succeeds.
    Otherwise False (no partial state -- bind is skipped if verify
    fails)."""
    result = verify_jwt_svid(
        svid,
        jwks_url=jwks_url,
        expected_audience=expected_audience,
        allowed_trust_domains=allowed_trust_domains)
    if result is None:
        return False
    return bind_spiffe_id_to_principal(
        db,
        tenant_id=tenant_id,
        principal_kind=principal_kind,
        principal_id=principal_id,
        spiffe_id=result["spiffe_id"],
        allowed_trust_domains=allowed_trust_domains)


def lookup_principal_by_spiffe_id(
    db, *,
    tenant_id: str,
    spiffe_id: str,
) -> dict[str, Any] | None:
    """Reverse-lookup: SPIFFE ID -> principal row.

    Validates the SPIFFE ID format before querying. Returns None
    if no binding exists or the SPIFFE ID is malformed."""
    if not tenant_id:
        raise ValueError("tenant_id is required")
    try:
        parse_spiffe_id(spiffe_id)
    except SpiffeIdFormatError:
        return None
    from kya.external_id import lookup_principal_by_idp
    row = lookup_principal_by_idp(
        db,
        tenant_id=tenant_id,
        idp_subject=spiffe_id)
    # Defense-in-depth: confirm the bound row is actually a SPIFFE
    # binding. The full "spiffe://..." string is astronomically
    # unlikely to collide with an Okta/Auth0 sub, but if a sloppy
    # caller stored one via bind_principal_to_idp(idp_kind="okta",
    # idp_subject="spiffe://..."), we don't want to return it here.
    if row is not None and row.get("idp_kind") != "spiffe":
        return None
    return row
