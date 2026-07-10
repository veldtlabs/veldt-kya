"""JWKS-backed OIDC token verifier.

A generic verifier for JWTs signed by a third-party OpenID Connect
provider (Keycloak, Auth0, Okta, AWS Cognito, ...). The function is
identity-blind: it verifies the signature, audience, and standard
claims, then returns the decoded claim set. Callers decide what the
claims authorize.

Relationship to ``kya.auth.verify_jwt``
---------------------------------------
``kya.auth.verify_jwt`` already exists for workload-identity tokens
(the gateway path). It's **fail-soft** (returns ``None`` on any
failure) and takes a single ``jwks_url``. That posture is correct
for the gateway: a bad workload JWT just means "treat the request as
anonymous and let the policy engine decide."

This module's ``verify_oidc_token`` is the **strict** counterpart for
admin / privileged-action use cases. Differences:

- **Multi-issuer allowlist**: takes ``trusted_issuers`` mapping
  ``iss -> jwks_uri``. An admin deployment may federate with several
  IdPs (Keycloak realm A, B; plus Auth0); each is a strict
  pre-authorised entry. ``verify_jwt`` is single-issuer.
- **Raise-on-failure**: callers need to know *why* a token was
  rejected (so they can 401 with a known reason and not silently
  pretend a request was anonymous). ``verify_jwt`` returns ``None``.
- **JTI + nbf required**: required claims include ``jti`` for the
  replay-cache contract; ``nbf`` is enforced. ``verify_jwt`` requires
  only ``exp``.
- **Audience never optional**: open-mode (no audience check) is
  refused at the verifier level. ``verify_jwt`` warns but allows it.
- **JWK-derived alg allowlist**: the algorithm set is derived from
  the JWK's ``kty``/``crv`` (with the JWK's explicit ``alg`` winning
  when present). Defeats alg-confusion attacks where an attacker
  swaps a token signed under HS256 for a JWK published as RSA.

After successful verification, callers commonly compose with helpers
in ``kya.auth`` and ``kya.external_id`` to create a durable binding:

    from kya.oidc import verify_oidc_token
    from kya.auth import claims_to_kya_principal
    from kya.external_id import bind_principal_to_idp

    claims = verify_oidc_token(
        token=token, audience=AUD,
        trusted_issuers={ISS: JWKS_URI},
        jti_cache=jti_cache,
    )
    mapped = claims_to_kya_principal(claims)
    bind_principal_to_idp(db, tenant_id=TID, principal_kind="admin",
                          principal_id=mapped["federated_id"],
                          **{k: mapped[k] for k in (
                              "idp_subject", "idp_issuer",
                              "idp_kind", "federated_id",
                          )})

Consumers in this repo
----------------------
- ``kya_pro.issuer_api`` (proprietary issuer-API) wires this verifier
  into its admin-auth dispatcher as the OIDC token path, alongside
  HMAC bearer + DID-signed JWT paths.

- (Reserved) ``kya_gateway`` may consume this for workload-identity
  tokens that need strict verification (e.g., when an AI agent / NHI
  presents an IdP-issued token and the gateway must 401 rather than
  proceed anonymously on a bad signature).

Design contract
---------------
- Strictly trusted-issuer-only. A token can only authenticate if its
  ``iss`` claim matches an entry in the operator-configured
  allowlist. A captured token from an arbitrary Keycloak / Auth0
  tenant can't authenticate just because its signature happens to
  verify against a fetched JWKS.

- JWKS fetched lazily on first use, cached per-issuer with an
  operator-configurable TTL (default 5 min). Each fetch goes
  through ``urllib`` with a short timeout; failures raise
  ``OIDCJWKSFetchError`` and the verifier rejects until cache
  refresh succeeds. **No fail-open.**

- Honours an optional JTI replay cache so a captured access token
  can't be replayed within its TTL. The cache is passed in by the
  caller (the issuer-API shares its cache across HMAC/DID/OIDC).

- Required claims: ``iss``, ``aud``, ``iat``, ``exp``, ``nbf``,
  ``jti``. Keycloak issues ``jti`` by default; other providers may
  need a client-side claim mapper.

- Required audience match. Tokens with a different ``aud`` are
  rejected after signature verification.

- Algorithm allowlist driven by what the JWK advertises. Tokens
  whose header ``alg`` doesn't match an algorithm derivable from
  the JWK ``kty``/``crv`` are rejected. Defeats ``alg=none`` and
  HS256-against-an-RSA-key alg-confusion attacks. RSA-PSS variants
  (PS256/PS384/PS512) are included alongside RS* because modern
  Keycloak (>= 18) and Auth0 increasingly default new realms to
  PS256.

The verifier never logs or returns the failed token's contents --
operators who need to debug a rejection get the exception message,
which carries the structural reason without exposing key material.
Callers that surface ``OIDCAuthError`` as an HTTP body should
genericise the message to avoid leaking trust-config state to
unauthenticated callers (e.g., which kids are known to the JWKS
cache for a given issuer).
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any

# ``pyjwt`` is imported lazily inside ``verify_oidc_token`` rather
# than at module load (mirrors ``kya.auth.verify_jwt``'s pattern).
# This keeps the bare ``pip install veldt-kya`` lean -- consumers
# who don't call the verifier don't pay the pyjwt import cost and,
# more importantly, can still reference ``OIDCAuthError`` /
# ``OIDCJWKSFetchError`` for exception handling without installing
# pyjwt themselves. Install the ``[did]`` extra (or any of the
# higher-level extras like ``[all]``) to get pyjwt bundled.

logger = logging.getLogger(__name__)


class OIDCAuthError(Exception):
    """OIDC token verification failed.

    Caller maps this to whatever its protocol uses for "rejected"
    (HTTP 401, gRPC UNAUTHENTICATED, ...). The message is
    operator-visible in logs but should NOT be returned verbatim to
    unauthenticated callers -- it can leak trust-config state.
    """


class OIDCJWKSFetchError(OIDCAuthError):
    """JWKS URL was unreachable or returned a malformed document.

    Distinct subclass so a startup preflight can distinguish "OIDC
    config is wrong" from "the token was bad."
    """


# ─── JWKS cache ────────────────────────────────────────────────────


class _JWKSCache:
    """Per-issuer JWKS cache with TTL.

    ``get(issuer, jwks_uri, kid)`` returns the JWK dict for the
    requested kid, fetching + caching the full JWKS the first time
    or whenever the TTL has elapsed. Thread-safe (the cache lock is
    held for the duration of the fetch so concurrent kid lookups
    don't trigger N parallel HTTP requests on first miss).
    """

    def __init__(self, ttl_seconds: int = 300, fetch_timeout_seconds: int = 5):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if fetch_timeout_seconds <= 0:
            raise ValueError("fetch_timeout_seconds must be > 0")
        self._ttl = ttl_seconds
        self._timeout = fetch_timeout_seconds
        # issuer -> (expires_at_epoch, {kid: jwk_dict})
        self._cache: dict[str, tuple[float, dict[str, dict]]] = {}
        self._lock = threading.Lock()

    def get(self, issuer: str, jwks_uri: str, kid: str) -> dict:
        """Return the JWK dict for kid, refreshing the JWKS if stale.

        Raises ``OIDCJWKSFetchError`` on network / parse failure.
        Raises ``OIDCAuthError`` if kid is not present in the
        successfully-fetched JWKS.
        """
        now = time.time()
        with self._lock:
            entry = self._cache.get(issuer)
            if entry is not None:
                expires_at, jwks_map = entry
                if now < expires_at and kid in jwks_map:
                    return jwks_map[kid]
            # Either no cache, expired, or kid missing -- refresh.
            jwks_map = self._fetch(jwks_uri)
            self._cache[issuer] = (now + self._ttl, jwks_map)
        jwk = jwks_map.get(kid)
        if jwk is None:
            raise OIDCAuthError(
                f"kid {kid!r} not present in JWKS for issuer {issuer!r}"
            )
        return jwk

    def _fetch(self, jwks_uri: str) -> dict[str, dict]:
        """Fetch JWKS and return ``{kid: jwk_dict}``.

        Raises ``OIDCJWKSFetchError`` on any failure. Caller owns
        the cache lock during this call so concurrent kid lookups
        don't fire parallel HTTP requests.
        """
        try:
            with urllib.request.urlopen(jwks_uri, timeout=self._timeout) as resp:
                if resp.status != 200:
                    raise OIDCJWKSFetchError(
                        f"JWKS endpoint {jwks_uri!r} returned HTTP "
                        f"{resp.status}"
                    )
                body = resp.read()
        except urllib.error.URLError as exc:
            raise OIDCJWKSFetchError(
                f"JWKS endpoint {jwks_uri!r} unreachable: {exc.reason!r}"
            ) from exc
        except (OSError, ValueError) as exc:
            # Narrow rather than bare ``Exception`` so a
            # KeyboardInterrupt or system-level exit propagates.
            raise OIDCJWKSFetchError(
                f"JWKS endpoint {jwks_uri!r} fetch failed: {exc}"
            ) from exc
        try:
            doc = json.loads(body)
        except json.JSONDecodeError as exc:
            raise OIDCJWKSFetchError(
                f"JWKS endpoint {jwks_uri!r} returned non-JSON body: {exc}"
            ) from exc
        keys = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(keys, list):
            raise OIDCJWKSFetchError(
                f"JWKS endpoint {jwks_uri!r} response missing `keys` array"
            )
        out: dict[str, dict] = {}
        for jwk in keys:
            if not isinstance(jwk, dict):
                continue
            kid = jwk.get("kid")
            if isinstance(kid, str):
                out[kid] = jwk
        if not out:
            raise OIDCJWKSFetchError(
                f"JWKS endpoint {jwks_uri!r} had no usable kid-bearing keys"
            )
        return out


# Module-level singleton so repeated calls share the JWKS cache
# across the process. Created lazily so importing kya.oidc doesn't
# bring in a thread or socket eagerly.
_JWKS_CACHE: _JWKSCache | None = None
_JWKS_CACHE_LOCK = threading.Lock()


def _resolve_cache(ttl_seconds: int, fetch_timeout_seconds: int) -> _JWKSCache:
    global _JWKS_CACHE
    with _JWKS_CACHE_LOCK:
        if _JWKS_CACHE is None:
            _JWKS_CACHE = _JWKSCache(
                ttl_seconds=ttl_seconds,
                fetch_timeout_seconds=fetch_timeout_seconds,
            )
        return _JWKS_CACHE


def reset_jwks_cache_for_tests() -> None:
    """Drop the JWKS cache singleton. Tests use this; production
    deployments do not."""
    global _JWKS_CACHE
    with _JWKS_CACHE_LOCK:
        _JWKS_CACHE = None


# ─── Token verifier ───────────────────────────────────────────────


def verify_oidc_token(
    *,
    token: str,
    audience: str,
    trusted_issuers: dict[str, str],
    jti_cache: Any | None = None,
    ttl_seconds: int = 300,
    fetch_timeout_seconds: int = 5,
    require_jti: bool = True,
) -> dict:
    """Verify an OIDC JWT against the configured trusted-issuer JWKS.

    ``trusted_issuers`` is a mapping from issuer URL (the ``iss``
    claim) to the JWKS URI. An issuer absent from the map is rejected
    BEFORE any signature work -- a captured token from an arbitrary
    Keycloak / Auth0 tenant can't authenticate just because the
    signature happens to verify.

    Required claims: ``iss``, ``aud``, ``iat``, ``exp``. ``jti`` is
    ALSO required by default (needed for the replay-cache contract on
    admin-auth flows), but can be relaxed via ``require_jti=False``
    for providers whose default id_token flow may omit ``jti`` — this
    includes Google's id_token, Microsoft Entra's default v2 flow,
    and some Auth0 pipelines (behavior varies by tenant and by
    custom-actions configuration). If your provider does emit ``jti``,
    keep ``require_jti=True`` — the default is safer.

    Callers who disable ``jti`` MUST have their own replay protection
    (e.g., single-use OAuth ``state`` + PKCE ``code_verifier`` bound
    at authorize time) or accept the exposure. This is why the safe
    default is ``True``.

    Returns the decoded claim set on success. Raises ``OIDCAuthError``
    (or subclass) on any failure. The verifier is identity-blind:
    callers decide what the verified claims authorize.
    """
    if not trusted_issuers:
        raise OIDCAuthError("no OIDC trusted issuers configured")

    try:
        import jwt as pyjwt
    except ImportError as exc:
        raise OIDCAuthError(
            "pyjwt is required for OIDC token verification. Install "
            "with `pip install veldt-kya[did]` (or any extra that "
            "includes pyjwt)."
        ) from exc

    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.InvalidTokenError as exc:
        raise OIDCAuthError(f"OIDC token header invalid: {exc}") from exc
    try:
        unverified = pyjwt.decode(
            token, options={"verify_signature": False}
        )
    except pyjwt.InvalidTokenError as exc:
        raise OIDCAuthError(f"OIDC token body invalid: {exc}") from exc

    iss = unverified.get("iss")
    if not isinstance(iss, str) or iss not in trusted_issuers:
        raise OIDCAuthError(
            f"OIDC issuer {iss!r} not in trusted_issuers allowlist"
        )
    jwks_uri = trusted_issuers[iss]

    kid = header.get("kid") if isinstance(header, dict) else None
    if not isinstance(kid, str) or not kid:
        raise OIDCAuthError("OIDC token missing `kid` header")
    alg = header.get("alg") if isinstance(header, dict) else None
    if not isinstance(alg, str) or alg == "none":
        raise OIDCAuthError(
            f"OIDC token alg {alg!r} forbidden (must be an asymmetric "
            "signature algorithm; 'none' is never accepted)"
        )

    cache = _resolve_cache(ttl_seconds, fetch_timeout_seconds)
    jwk = cache.get(iss, jwks_uri, kid)

    # Derive the allowed algorithm from the JWK to defeat
    # alg-confusion attacks (e.g., HS256-against-RSA-key). The JWK's
    # `alg` claim wins if present; else fall back to the kty/crv map.
    jwk_alg = jwk.get("alg") if isinstance(jwk, dict) else None
    allowed_algorithms = (
        [jwk_alg] if isinstance(jwk_alg, str)
        else _algorithms_for_jwk(jwk)
    )
    if alg not in allowed_algorithms:
        raise OIDCAuthError(
            f"OIDC token alg {alg!r} not in JWK-derived allowlist "
            f"{allowed_algorithms!r}"
        )

    required_claims = ["iss", "aud", "iat", "exp"]
    if require_jti:
        required_claims.append("jti")
    try:
        claims = pyjwt.decode(
            token,
            key=pyjwt.PyJWK(jwk).key,
            algorithms=allowed_algorithms,
            audience=audience,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_aud": True,
                "require": required_claims,
            },
        )
    except pyjwt.InvalidTokenError as exc:
        raise OIDCAuthError(f"OIDC token signature/claims invalid: {exc}") from exc

    if jti_cache is not None and "jti" in claims:
        # A downstream replay-cache fault (Valkey outage, OOM, etc.)
        # must not poison a token that already passed signature +
        # claims verification. The cache exists to prevent replay;
        # failing closed here would convert an infrastructure flake
        # into a fleet-wide auth lockout. Log loudly; the next
        # request from the same JTI will still be caught once the
        # cache is healthy again.
        #
        # Guarded on "jti" in claims because require_jti=False callers
        # (Auth0 hosted-login, Google id_token) legitimately omit it.
        try:
            jti_cache.observe(claims["jti"], exp_at=claims.get("exp"))
        except Exception as exc:
            logger.warning(
                "OIDC jti_cache.observe failed for jti=%s (token "
                "accepted): %s",
                claims["jti"], exc, exc_info=True,
            )
    return claims


def _algorithms_for_jwk(jwk: dict) -> list[str]:
    """Derive an algorithm allowlist from a JWK's kty/crv shape.

    Mirrors the subset of pyjwt-supported algorithms most OIDC
    providers actually use:

      - kty=RSA              -> RS256/RS384/RS512 + PS256/PS384/PS512
      - kty=EC,  crv=P-256   -> ES256
      - kty=EC,  crv=P-384   -> ES384
      - kty=EC,  crv=P-521   -> ES512
      - kty=OKP, crv=Ed25519 -> EdDSA

    RSA-PSS variants are included because modern Keycloak (>= 18)
    and Auth0 increasingly default new realms to PS256, often
    omitting the ``alg`` claim on the JWK itself. Without PS* the
    JWK-derived allowlist would silently refuse a valid token.

    Returns an empty list when the JWK shape is unrecognised; the
    caller treats that as a hard failure.
    """
    kty = jwk.get("kty") if isinstance(jwk, dict) else None
    crv = jwk.get("crv") if isinstance(jwk, dict) else None
    if kty == "RSA":
        return ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
    if kty == "EC":
        if crv == "P-256":
            return ["ES256"]
        if crv == "P-384":
            return ["ES384"]
        if crv == "P-521":
            return ["ES512"]
    if kty == "OKP" and crv == "Ed25519":
        return ["EdDSA"]
    return []
