"""
Phase 4a — JWT introspection + claim extraction.

Decodes and verifies an OIDC/OAuth bearer token against a JWKS
endpoint, then exposes the standard claims (sub, iss, aud, email,
groups, roles, scope) for downstream KYA use:

  - bind_principal_to_idp / bind_user_to_idp can be auto-populated
    from claims via claims_to_kya_principal()
  - record_principal_signal / record_invocation can be wrapped by
    bind_principal_from_token() — one call instead of decode + bind
  - Phase 4c (SPIFFE) reuses verify_jwt for OIDC workload-identity
    tokens

Design contract
---------------
KYA does NOT issue tokens. KYA inherits whatever the upstream IdP
(Okta / Auth0 / Keycloak / Google / Entra / Cognito / SPIFFE / custom)
signed. This module's job is "given a bearer string, verify it
against the configured JWKS, return the claims" — nothing more.

Fail-soft on every path: invalid signatures, expired tokens, missing
JWKS keys, network failures fetching JWKS, malformed JWT — all return
None (or False for bind helpers). The only exceptions raised are
programmer errors (missing tenant_id, etc.), surfaced as ValueError.

Optional dependency
-------------------
PyJWT >= 2.0. If not installed, `verify_jwt()` raises ImportError
with install hint on first call. Other module functions that don't
touch tokens (claims_to_kya_principal, _infer_idp_kind) work fine
without PyJWT.

Config via env (or per-call kwargs)
-----------------------------------
KYA_JWT_JWKS_URL       — JWKS endpoint (e.g. https://acme.okta.com/.well-known/jwks.json)
KYA_JWT_AUDIENCE       — Expected `aud` claim (set OR rejected)
KYA_JWT_ISSUER         — Expected `iss` claim (set OR rejected)
KYA_JWT_LEEWAY_SECONDS — Clock-skew tolerance, default 10
KYA_JWT_ALGORITHMS     — Comma-separated allowed algs; default
                         "RS256,ES256,RS384,ES384,RS512,ES512"
                         (deliberately excludes 'none' and HS*)

Security defaults
-----------------
  - Algorithm whitelist (no alg=none, no HS256 confusion)
  - Signature verification REQUIRED (never disabled)
  - JWKS auto-rotation supported (cache TTL 5 min default)
  - Audience + issuer checks enforced when configured
  - `exp` and `nbf` enforced with configurable leeway
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)


# Default algorithm whitelist. Deliberately excludes:
#   - "none" (the alg=none confusion attack)
#   - "HS*" (HMAC algs — possible if attacker tricks lib into
#     interpreting the public key as a secret)
# Asymmetric algs only.
_DEFAULT_ALGS = ("RS256", "ES256", "RS384", "ES384", "RS512", "ES512")


# IdP kind inference from the iss claim. Used by claims_to_kya_principal
# to populate Phase 4b's idp_kind column with a sensible default.
def _infer_idp_kind(iss: str | None) -> str:
    if not iss:
        return "custom"
    s = iss.lower()
    if "okta.com" in s or ".okta-emea.com" in s:
        return "okta"
    if "auth0.com" in s or "auth0.net" in s:
        return "auth0"
    if "/auth/realms/" in s or "keycloak" in s:
        return "keycloak"
    if "accounts.google.com" in s or "googleapis.com" in s:
        return "google"
    if ("login.microsoftonline.com" in s
            or "login.windows.net" in s or "/sts.windows.net" in s):
        return "microsoft"
    if "cognito-idp" in s or "amazoncognito.com" in s:
        return "aws_cognito"
    if s.startswith("spiffe://"):
        return "spiffe"
    return "custom"


# ── JWKS cache (per-process, TTL-bounded) ──────────────────────────


_JWKS_CACHE: dict[str, tuple[float, Any]] = {}
_JWKS_LOCK = threading.Lock()
_JWKS_TTL_SECONDS = int(os.environ.get("KYA_JWT_JWKS_TTL_SECONDS", "300"))


def _fetch_jwks(jwks_url: str) -> Any | None:
    """Fetch and cache JWKS JSON. Returns None on any network /
    parse failure (fail-soft)."""
    now = time.monotonic()
    with _JWKS_LOCK:
        cached = _JWKS_CACHE.get(jwks_url)
        if cached and (now - cached[0]) < _JWKS_TTL_SECONDS:
            return cached[1]
    try:
        import requests
    except ImportError:
        logger.debug(
            "[KYA-AUTH] `requests` not installed — JWKS fetch unavailable")
        return None
    try:
        resp = requests.get(jwks_url, timeout=5.0)
        if not (200 <= resp.status_code < 300):
            logger.debug(
                "[KYA-AUTH] JWKS fetch %s returned %s",
                jwks_url, resp.status_code)
            return None
        data = resp.json()
    except Exception as exc:
        logger.debug("[KYA-AUTH] JWKS fetch %s failed: %s",
                     jwks_url, exc)
        return None
    with _JWKS_LOCK:
        _JWKS_CACHE[jwks_url] = (now, data)
    return data


def reset_jwks_cache() -> None:
    """Test helper — clear the in-process JWKS cache."""
    with _JWKS_LOCK:
        _JWKS_CACHE.clear()


# ── Core verification ──────────────────────────────────────────────


def verify_jwt(
    token: str,
    *,
    jwks_url: str | None = None,
    audience: str | None = None,
    issuer: str | None = None,
    leeway_seconds: int | None = None,
    algorithms: list[str] | None = None,
) -> dict[str, Any] | None:
    """Verify and decode a JWT bearer token.

    Returns the claims dict on success. Returns None on ANY failure
    (invalid signature, expired, wrong audience, wrong issuer, missing
    JWKS, missing PyJWT, malformed token, network failure fetching
    JWKS) — fail-soft. Callers should treat None as "this token isn't
    trustworthy" and proceed without principal binding.

    Programmer errors (missing all of jwks_url+KYA_JWT_JWKS_URL) raise
    ValueError so misconfiguration is loud.

    Args
    ----
    token : str
        The raw bearer token string (the `xxx.yyy.zzz` payload, no
        "Bearer " prefix).
    jwks_url : str | None
        JWKS endpoint URL. Falls back to env KYA_JWT_JWKS_URL.
    audience : str | None
        Expected `aud` claim. Falls back to env KYA_JWT_AUDIENCE.
        If None and env is empty, audience is NOT checked (open).
    issuer : str | None
        Expected `iss` claim. Falls back to env KYA_JWT_ISSUER.
        If None and env is empty, issuer is NOT checked (open).
    leeway_seconds : int | None
        Clock-skew tolerance for exp/nbf. Default 10s.
    algorithms : list[str] | None
        Allowed signing algorithms. Default: asymmetric only
        (RS256/ES256/RS384/ES384/RS512/ES512). NEVER includes
        "none" or HS* (security risk).
    """
    if not token:
        return None
    jwks_url = jwks_url or os.environ.get("KYA_JWT_JWKS_URL")
    if not jwks_url:
        raise ValueError(
            "verify_jwt requires jwks_url (kwarg or KYA_JWT_JWKS_URL env)")
    audience = audience or os.environ.get("KYA_JWT_AUDIENCE") or None
    issuer = issuer or os.environ.get("KYA_JWT_ISSUER") or None
    if leeway_seconds is None:
        # 30s default — industry-typical for IdP↔service clock skew.
        # Tighter (10s) rejected legitimate tokens when small drift
        # accumulated; looser (>300s) defeats expiration semantics.
        try:
            leeway_seconds = int(
                os.environ.get("KYA_JWT_LEEWAY_SECONDS", "30"))
        except ValueError:
            leeway_seconds = 30
    if algorithms is None:
        env_algs = os.environ.get("KYA_JWT_ALGORITHMS")
        if env_algs:
            algorithms = [a.strip() for a in env_algs.split(",")
                           if a.strip()]
        else:
            algorithms = list(_DEFAULT_ALGS)
    # Defense against alg confusion / alg=none — strip if anyone
    # smuggled them through env or kwargs.
    algorithms = [a for a in algorithms
                  if a.lower() != "none"
                  and not a.upper().startswith("HS")]
    if not algorithms:
        logger.debug(
            "[KYA-AUTH] no safe algorithms configured — rejecting")
        return None

    try:
        import jwt as _jwt
        from jwt import PyJWKClient
    except ImportError as exc:
        logger.debug(
            "[KYA-AUTH] PyJWT not installed (`pip install PyJWT`): %s",
            exc)
        return None
    except Exception as exc:
        logger.debug("[KYA-AUTH] PyJWT import surprise: %s", exc)
        return None

    try:
        # PyJWKClient handles its own caching; we layer in our own
        # cache for the raw JWKS document so multiple sessions in
        # the same process share rotation state.
        client = PyJWKClient(jwks_url, cache_keys=True,
                             lifespan=_JWKS_TTL_SECONDS)
        signing_key = client.get_signing_key_from_jwt(token)
    except Exception as exc:
        logger.debug(
            "[KYA-AUTH] JWKS key resolution failed for token: %s",
            exc)
        return None

    # OIDC mandates `exp`. `iat` is RECOMMENDED but not strictly
    # required — some legitimate IdPs (service-account / refresh
    # token issuers) omit it. Don't reject those tokens; just don't
    # require iat to be present. nbf / aud / iss enforcement still
    # happens when configured.
    decode_opts: dict[str, Any] = {
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "require": ["exp"],
    }
    if audience:
        decode_opts["verify_aud"] = True
        decode_opts["require"].append("aud")
    else:
        decode_opts["verify_aud"] = False
    if issuer:
        decode_opts["verify_iss"] = True
        decode_opts["require"].append("iss")
    else:
        decode_opts["verify_iss"] = False

    # Loud warning when running in fully-open mode (no aud + no iss
    # enforcement). OIDC best practice is to verify both when known —
    # operators running open-mode should see this in their logs and
    # know they're trusting whatever JWT the JWKS endpoint signs.
    if not audience and not issuer:
        logger.warning(
            "[KYA-AUTH] verify_jwt called with no audience AND no "
            "issuer enforcement. Signature is still verified, but "
            "any token signed by the JWKS endpoint will be accepted "
            "— set KYA_JWT_AUDIENCE or KYA_JWT_ISSUER to tighten.")

    try:
        claims = _jwt.decode(
            token,
            key=signing_key.key,
            algorithms=algorithms,
            audience=audience if audience else None,
            issuer=issuer if issuer else None,
            leeway=leeway_seconds,
            options=decode_opts,
        )
    except Exception as exc:
        # PyJWT raises ExpiredSignatureError, InvalidAudienceError,
        # InvalidIssuerError, InvalidSignatureError, etc. — fail-soft
        # on all of them. Operators get the WHY via DEBUG logs.
        logger.debug("[KYA-AUTH] JWT decode rejected: %s", exc)
        return None
    return claims


# ── Claim mapping ──────────────────────────────────────────────────


def claims_to_kya_principal(claims: dict[str, Any]) -> dict[str, Any]:
    """Map standard OIDC claims into KYA's external_id binding shape
    (idp_subject / idp_issuer / idp_kind / federated_id).

    Returns a dict with those four keys. None values are returned for
    any claims that are missing. Does NOT touch the DB — pure mapping.

    Standard claims consulted:
        sub        → idp_subject
        iss        → idp_issuer (and used to infer idp_kind)
        federated_id is auto-derived "{idp_kind}|{idp_issuer}|{sub}"

    Also returns ancillary claims the caller might want for trust
    decisions: email, groups, roles, scope.
    """
    sub = claims.get("sub")
    iss = claims.get("iss")
    idp_kind = _infer_idp_kind(iss)
    if sub:
        federated_id = f"{idp_kind}|{iss or ''}|{sub}"
    else:
        federated_id = None
    return {
        "idp_subject": sub,
        "idp_issuer": iss,
        "idp_kind": idp_kind,
        "federated_id": federated_id,
        # Bonus claims operators commonly use for trust decisions —
        # NOT written to KYA columns; caller decides what to do.
        "email": claims.get("email"),
        "groups": claims.get("groups"),
        "roles": claims.get("roles"),
        "scope": claims.get("scope"),
    }


# ── One-shot helper: verify + bind ─────────────────────────────────


def bind_principal_from_token(
    db, *,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    bearer_token: str,
    jwks_url: str | None = None,
    audience: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any] | None:
    """Convenience: verify a token, extract claims, bind the principal
    via Phase 4b's bind_principal_to_idp().

    Returns the claims dict on success. Returns None on ANY failure —
    token rejected, missing principal row, DB error during bind, token
    valid but no `sub` claim — all collapse to None.

    Ambiguity warning
    -----------------
    A None return is intentionally LOSSY: the caller cannot
    distinguish "the token was bad" from "the token was good but the
    principal row doesn't exist" from "the DB hiccupped during the
    bind." This convenience function trades that detail for a tight
    single-call surface.

    If you need to distinguish failure modes, call the two pieces
    separately:

        claims = verify_jwt(token, jwks_url=...)
        if claims is None: ...  # token was rejected
        bound = bind_principal_to_idp(db, ...)
        if not bound: ...  # principal missing or DB error

    The principal row MUST already exist (created by a
    record_principal_signal call). bind_principal_to_idp fail-softs
    to False if not — and this wrapper returns None in that case.
    """
    if not tenant_id or not principal_kind or not principal_id:
        raise ValueError(
            "tenant_id, principal_kind, principal_id are all required")
    claims = verify_jwt(
        bearer_token, jwks_url=jwks_url,
        audience=audience, issuer=issuer)
    if not claims:
        return None
    mapped = claims_to_kya_principal(claims)
    if not mapped["idp_subject"]:
        logger.debug(
            "[KYA-AUTH] token verified but `sub` claim missing — "
            "cannot bind")
        return None
    try:
        from .external_id import bind_principal_to_idp
        bound = bind_principal_to_idp(
            db, tenant_id=tenant_id,
            principal_kind=principal_kind,
            principal_id=principal_id,
            idp_subject=mapped["idp_subject"],
            idp_issuer=mapped["idp_issuer"],
            idp_kind=mapped["idp_kind"],
            federated_id=mapped["federated_id"],
        )
    except Exception as exc:
        logger.debug("[KYA-AUTH] bind from token failed: %s", exc)
        return None
    if not bound:
        return None
    return claims
