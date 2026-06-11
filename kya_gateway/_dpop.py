"""DPoP (RFC 9449) proof verification for /v1/principals/me.

A DPoP JWT carries per-request claims that bind the proof to:
* the HTTP method (``htm``)
* the request URI (``htu``)
* a recent timestamp (``iat``)
* the bound principal's DID (``iss``)

Signed by a key in the DID document's ``authentication`` set. Replaying
the proof requires the private key — the endpoint stops being a free
credential-validation oracle.

This module is OSS-only and has no pro dependency.
"""
from __future__ import annotations

import time
from typing import Optional

try:
    import jwt as pyjwt
except ImportError as exc:   # pragma: no cover
    raise RuntimeError(
        "kya_gateway requires pyjwt — install veldt-kya[gateway]"
    ) from exc

from kya_gateway.errors import IdentityCredentialInvalid


class DPoPError(IdentityCredentialInvalid):
    """A DPoP proof was missing or failed verification.

    Phase 5g-B-01 — carries a typed ``code`` so the security-event
    dispatcher classifies the failure WITHOUT reading the message
    string (which interpolates attacker-controlled JWS fields like
    ``kid`` and ``htu``). Recognized codes:

      missing          — header absent
      malformed        — header not a JWT / not JSON / bad shape
      kid_unknown      — kid not in the DID's authentication set
      signature        — JWS signature verification failed
      iss_mismatch     — iss claim does not match bound DID
      htm_mismatch     — htm claim does not match the request method
      htu_mismatch     — htu claim does not match the request URI
      iat_future       — iat is in the future past leeway
      iat_too_old      — iat older than the replay window
      iat_invalid      — iat missing or not numeric
    """

    def __init__(self, message: str, *, code: str = "malformed"):
        super().__init__(message)
        self.code = code


def verify_dpop(
    dpop_header: Optional[str],
    *,
    expected_htm: str,
    expected_htu: str,
    doc,
    leeway_seconds: int = 30,
) -> dict:
    """Verify a DPoP proof against the bound principal's DID document.

    Args:
        dpop_header: The raw value of the ``DPoP`` request header.
        expected_htm: HTTP method the proof must bind to (uppercase).
        expected_htu: HTTP URI the proof must bind to (scheme + authority
            + path; no query). Must equal the proof's ``htu`` claim
            exactly after normalization.
        doc: The resolved DID document (kya.did_document.DIDDocument).
        leeway_seconds: Clock skew tolerance for the ``iat`` check.

    Returns:
        The verified claim set (dict) on success.

    Raises:
        DPoPError: when the proof is missing, malformed, signed by the
            wrong key, has the wrong htm/htu, or is too old / future-dated.
    """
    if not dpop_header:
        raise DPoPError("missing DPoP header", code="missing")
    if not isinstance(dpop_header, str):
        raise DPoPError(
            f"DPoP header must be a string, got {type(dpop_header).__name__}",
            code="malformed",
        )
    if dpop_header.count(".") != 2:
        raise DPoPError(
            "DPoP value is not a JWT (need 3 base64url segments)",
            code="malformed",
        )

    # Step 1 — read JWS header for kid + typ
    try:
        header = pyjwt.get_unverified_header(dpop_header)
    except pyjwt.InvalidTokenError as exc:
        raise DPoPError(f"DPoP header invalid: {exc}", code="malformed") from exc
    if not isinstance(header, dict):
        raise DPoPError("DPoP header is not a JSON object", code="malformed")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise DPoPError(
            "DPoP JWS header must include a 'kid' string", code="malformed",
        )

    # Step 2 — look up the kid in the DID doc's authentication set
    auth_ids = set(doc.authentication or [])
    if not auth_ids:
        raise DPoPError(
            f"DID {doc.id!r} document declares no `authentication` keys — "
            f"refusing DPoP",
            code="kid_unknown",
        )
    vm = doc.find_key(kid)
    if vm is None:
        raise DPoPError(
            f"DPoP kid={kid!r} not in DID document for {doc.id!r}",
            code="kid_unknown",
        )
    if vm.id not in auth_ids:
        raise DPoPError(
            f"DPoP kid={kid!r} resolves to VM {vm.id!r} which is not in "
            f"the DID's authentication set",
            code="kid_unknown",
        )

    # Step 3 — single-alg verify (no family acceptance)
    from kya.vc import _algorithms_for_jwk   # type: ignore[attr-defined]
    algorithms = _algorithms_for_jwk(vm.public_key_jwk, doc.id)

    try:
        claims = pyjwt.decode(
            dpop_header,
            key=pyjwt.PyJWK(vm.public_key_jwk).key,
            algorithms=algorithms,
            leeway=leeway_seconds,
            options={
                "verify_signature": True,
                "verify_iat": True,
                "require": ["iss", "iat", "htm", "htu"],
                # No exp required — iat-bound window does the work.
                # Cap is checked manually below to bound replay.
            },
        )
    except pyjwt.InvalidTokenError as exc:
        raise DPoPError(
            f"DPoP signature verification failed: {exc}", code="signature",
        ) from exc

    # Step 4 — htm / htu binding (case-insensitive on method, exact on URI)
    if claims.get("iss") != doc.id:
        raise DPoPError(
            f"DPoP iss={claims.get('iss')!r} does not match bound DID {doc.id!r}",
            code="iss_mismatch",
        )

    htm = claims.get("htm")
    if not isinstance(htm, str) or htm.upper() != expected_htm.upper():
        raise DPoPError(
            f"DPoP htm={htm!r} does not match request method {expected_htm!r}",
            code="htm_mismatch",
        )

    htu = claims.get("htu")
    if not isinstance(htu, str) or _normalize_htu(htu) != _normalize_htu(expected_htu):
        raise DPoPError(
            f"DPoP htu={htu!r} does not match request URI {expected_htu!r}",
            code="htu_mismatch",
        )

    # Step 5 — iat freshness: reject future-iat past leeway,
    # and reject iat older than 5x leeway as a soft replay window.
    iat = claims.get("iat")
    now = int(time.time())
    if not isinstance(iat, (int, float)):
        raise DPoPError("DPoP iat missing or not numeric", code="iat_invalid")
    if iat > now + leeway_seconds:
        raise DPoPError(
            f"DPoP iat={iat} is in the future (now={now})", code="iat_future",
        )
    # Cap replay window: with 30s leeway, max age is 5*30=150s.
    if now - iat > leeway_seconds * 5:
        raise DPoPError(
            f"DPoP iat={iat} too old (max age {leeway_seconds*5}s)",
            code="iat_too_old",
        )

    return claims


def _normalize_htu(url: str) -> str:
    """Normalize for case-insensitive scheme + host, strict path.

    * Strip query + fragment + trailing slash
    * Lowercase scheme and host (DNS is case-insensitive; RFC 3986 §3.2.2)
    * Keep path case-sensitive

    Without this, `https://Foo.example.com/me` and `https://foo.example.com/me`
    would falsely mismatch — a client behind a proxy that lowercases the
    Host header would see spurious 401s. Path stays case-sensitive
    because filesystem-style URIs are.
    """
    from urllib.parse import urlsplit, urlunsplit
    base = url.split("#", 1)[0].split("?", 1)[0]
    try:
        parts = urlsplit(base)
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()
        # Strip default ports — `https://x:443/me` and `https://x/me` are
        # the same endpoint; without this, a client that adds the
        # default port mismatches a config that omits it.
        if scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[: -len(":443")]
        elif scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[: -len(":80")]
        path = parts.path.rstrip("/")
        return urlunsplit((scheme, netloc, path, "", ""))
    except Exception:
        return base.rstrip("/")
