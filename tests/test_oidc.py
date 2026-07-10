"""Tests for ``kya.oidc`` — the JWKS-backed OIDC token verifier.

Covers:
  - Trusted-issuer-only allowlist (untrusted iss refused BEFORE
    any signature work, so an attacker who controls a JWKS endpoint
    can't grind against the verifier).
  - Algorithm-confusion CVE class (alg=none, HS256-against-RSA).
  - Audience enforcement (single + array forms).
  - Required claims: iss / aud / iat / exp / nbf / jti.
  - JWKS cache TTL + refresh + malformed body handling.
  - JTI replay-cache observation + downstream-fault fail-open
    (cache outage must not poison a verified token).
  - PS256/Ed25519 interop (Keycloak >= 18 defaults; common Auth0
    rotation shapes).
  - Composition with ``kya.auth.claims_to_kya_principal`` +
    ``kya.external_id.bind_principal_to_idp`` -- the OSS pieces
    consumers compose for durable IdP binding after verification.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ─── Stub OIDC issuer fixtures ────────────────────────────────────


def _rsa_keypair():
    """Return ``(private_key_pem, public_jwk)`` for an RS-family issuer."""
    sk = generate_private_key(public_exponent=65537, key_size=2048)
    pk = sk.public_key()
    n = pk.public_numbers().n
    e = pk.public_numbers().e
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": "stub-rsa-kid",
        "n": _b64url(n_bytes),
        "e": _b64url(e_bytes),
    }
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem, jwk


def _mint_token(
    *, sk_pem: bytes, kid: str, iss: str,
    aud, sub: str = "alice@example.com",
    extra_claims: dict | None = None,
    alg: str = "RS256",
    iat_offset: int = -5, exp_offset: int = 300,
) -> str:
    now = int(time.time())
    claims = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": now + iat_offset,
        "nbf": now + iat_offset,
        "exp": now + exp_offset,
        "jti": uuid.uuid4().hex,
        **(extra_claims or {}),
    }
    return pyjwt.encode(
        claims, sk_pem, algorithm=alg,
        headers={"kid": kid, "alg": alg, "typ": "JWT"},
    )


class _JWKSServer:
    """Tiny in-process HTTP server serving a JWKS document.
    Used so the verifier exercises the real ``urllib`` fetch path."""

    def __init__(self, jwks: dict):
        self.jwks = jwks
        self.handler_class = self._build_handler()
        self.server = HTTPServer(("127.0.0.1", 0), self.handler_class)
        self.port = self.server.server_address[1]
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _build_handler(self):
        jwks_body = json.dumps(self.jwks).encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(jwks_body)))
                self.end_headers()
                self.wfile.write(jwks_body)

            def log_message(self, *args, **kwargs):
                pass

        return Handler

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/.well-known/jwks"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def reset_jwks_cache():
    """Each test starts with a fresh JWKS cache so prior fetches
    don't leak. Pairs with the module-level singleton in ``kya.oidc``."""
    from kya.oidc import reset_jwks_cache_for_tests
    reset_jwks_cache_for_tests()
    yield
    reset_jwks_cache_for_tests()


@pytest.fixture
def jwks_server():
    """RS256 issuer + JWKS server. Yields a dict the test can use to
    mint tokens against."""
    sk_pem, jwk = _rsa_keypair()
    jwks = {"keys": [jwk]}
    server = _JWKSServer(jwks)
    try:
        iss = f"http://127.0.0.1:{server.port}/"
        yield {
            "sk_pem": sk_pem, "jwk": jwk, "kid": jwk["kid"],
            "iss": iss,
            "jwks_uri": server.url,
        }
    finally:
        server.stop()


# ─── Happy path ───────────────────────────────────────────────────


def test_verify_oidc_token_trusted_issuer_accepted(
    reset_jwks_cache, jwks_server,
):
    """Token signed by the trusted JWKS, matching audience, verifies."""
    from kya.oidc import verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
    )
    claims = verify_oidc_token(
        token=token, audience="kya-oss-verifier",
        trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
    )
    assert claims["iss"] == jwks_server["iss"]
    assert claims["sub"] == "alice@example.com"


# ─── Trust boundary ───────────────────────────────────────────────


def test_untrusted_issuer_refused_before_signature(
    reset_jwks_cache, jwks_server,
):
    """Untrusted issuer must be refused BEFORE the JWKS fetch.
    Otherwise an attacker controlling a JWKS endpoint can grind
    against the verifier."""
    from kya.oidc import OIDCAuthError, verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss="https://evil.example/",
        aud="kya-oss-verifier",
    )
    with pytest.raises(OIDCAuthError, match="not in trusted_issuers"):
        verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={
                jwks_server["iss"]: jwks_server["jwks_uri"],
            },
        )


def test_empty_trusted_issuers_refused(reset_jwks_cache, jwks_server):
    from kya.oidc import OIDCAuthError, verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
    )
    with pytest.raises(OIDCAuthError, match="no OIDC trusted issuers"):
        verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={},
        )


# ─── Algorithm-confusion defense ──────────────────────────────────


def test_alg_none_refused(reset_jwks_cache, jwks_server):
    """``alg=none`` MUST be refused even from a trusted issuer."""
    from kya.oidc import OIDCAuthError, verify_oidc_token
    now = int(time.time())
    unsigned = pyjwt.encode(
        {
            "iss": jwks_server["iss"], "aud": "kya-oss-verifier",
            "iat": now, "nbf": now, "exp": now + 300,
            "jti": uuid.uuid4().hex,
        },
        key="", algorithm="none",
        headers={"kid": jwks_server["kid"], "alg": "none"},
    )
    with pytest.raises(OIDCAuthError, match="alg.*forbidden|alg.*not in"):
        verify_oidc_token(
            token=unsigned, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        )


def test_hs256_against_rsa_jwk_refused(reset_jwks_cache, jwks_server):
    """### CVE-class: HS256-against-RSA-public-key.

    Classic OIDC verifier CVE -- attacker uses the JWKS-published RSA
    public PEM as the HMAC secret and mints a self-signed token. KYA's
    JWK-derived alg allowlist must reject it BEFORE pyjwt's decode
    gets to misinterpret the PEM bytes.

    pyjwt.encode() refuses to use a PEM key as an HMAC secret
    (post-CVE-2018-1000531), so the token is constructed manually --
    we want defense in depth: KYA must reject regardless of whether
    the upstream library would.
    """
    from kya.oidc import OIDCAuthError, verify_oidc_token

    pk = serialization.load_pem_private_key(
        jwks_server["sk_pem"], password=None,
    ).public_key()
    pub_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    now = int(time.time())
    header = {"alg": "HS256", "kid": jwks_server["kid"], "typ": "JWT"}
    payload = {
        "iss": jwks_server["iss"], "sub": "attacker",
        "aud": "kya-oss-verifier",
        "iat": now, "nbf": now, "exp": now + 300,
        "jti": uuid.uuid4().hex,
    }
    h_enc = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_enc = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_enc}.{p_enc}".encode()
    sig = hmac.new(pub_pem, signing_input, hashlib.sha256).digest()
    sig_enc = _b64url(sig)
    forged = f"{h_enc}.{p_enc}.{sig_enc}"

    with pytest.raises(OIDCAuthError, match="alg.*not in"):
        verify_oidc_token(
            token=forged, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        )


def test_alg_in_header_not_in_jwk_refused(reset_jwks_cache, jwks_server):
    """### JWT header alg must be in the JWK-derived allowlist.

    A token claiming ES256 but signed against an RSA JWK must be
    refused at the allowlist check, not silently misverified.
    """
    from kya.oidc import OIDCAuthError, verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
    )
    # Tamper alg in the header.
    head_b64, payload_b64, sig_b64 = token.split(".")
    head = json.loads(base64.urlsafe_b64decode(head_b64 + "=="))
    head["alg"] = "ES256"
    new_head_b64 = _b64url(json.dumps(head, separators=(",", ":")).encode())
    tampered = f"{new_head_b64}.{payload_b64}.{sig_b64}"
    with pytest.raises(OIDCAuthError):
        verify_oidc_token(
            token=tampered, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        )


def test_kid_not_in_jwks_refused(reset_jwks_cache, jwks_server):
    """Token claiming a kid the JWKS doesn't advertise must be refused
    (no fallthrough to other keys)."""
    from kya.oidc import OIDCAuthError, verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid="some-other-kid",
        iss=jwks_server["iss"], aud="kya-oss-verifier",
    )
    with pytest.raises(OIDCAuthError, match="kid.*not present"):
        verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        )


# ─── Audience enforcement ─────────────────────────────────────────


def test_wrong_audience_refused(reset_jwks_cache, jwks_server):
    from kya.oidc import OIDCAuthError, verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="some-other-app",
    )
    with pytest.raises(OIDCAuthError):
        verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        )


def test_audience_array_with_match_accepted(reset_jwks_cache, jwks_server):
    """Keycloak issues ``aud`` as an array. Verifier must accept the
    target audience anywhere in the array."""
    from kya.oidc import verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"],
        aud=["account", "kya-oss-verifier"],
    )
    claims = verify_oidc_token(
        token=token, audience="kya-oss-verifier",
        trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
    )
    aud = claims["aud"]
    assert "kya-oss-verifier" in (aud if isinstance(aud, list) else [aud])


# ─── Required claims ──────────────────────────────────────────────


def test_missing_jti_refused(reset_jwks_cache, jwks_server):
    """``jti`` is required so the replay cache can do its job."""
    from kya.oidc import OIDCAuthError, verify_oidc_token
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": jwks_server["iss"], "sub": "x",
            "aud": "kya-oss-verifier",
            "iat": now, "nbf": now, "exp": now + 300,
        },
        jwks_server["sk_pem"], algorithm="RS256",
        headers={"kid": jwks_server["kid"], "alg": "RS256"},
    )
    with pytest.raises(OIDCAuthError):
        verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        )


def test_missing_jti_accepted_when_require_jti_false(
    reset_jwks_cache, jwks_server,
):
    """`require_jti=False` opt-out lets a jti-less id_token through.

    Used for one-shot OAuth code-exchange flows (Auth0 hosted-login,
    Google id_token, Microsoft Entra without id_token_jti_required)
    where replay protection comes from PKCE + `state` binding at
    /authorize, not from jti tracking.
    """
    from kya.oidc import verify_oidc_token
    now = int(time.time())
    # Mint a token WITHOUT a jti claim — the shape Auth0 / Google emit
    # on id_tokens from the /authorize code-exchange flow.
    token = pyjwt.encode(
        {
            "iss": jwks_server["iss"], "sub": "user-123",
            "aud": "kya-oss-verifier",
            "iat": now, "nbf": now, "exp": now + 300,
            "email": "kola@veldtlabs.ai", "email_verified": True,
        },
        jwks_server["sk_pem"], algorithm="RS256",
        headers={"kid": jwks_server["kid"], "alg": "RS256"},
    )
    claims = verify_oidc_token(
        token=token, audience="kya-oss-verifier",
        trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        require_jti=False,
    )
    # Signature + audience + issuer + expiry are still enforced —
    # only the jti presence requirement is relaxed.
    assert claims["iss"] == jwks_server["iss"]
    assert claims["aud"] == "kya-oss-verifier"
    assert claims["email"] == "kola@veldtlabs.ai"
    assert "jti" not in claims


def test_jti_cache_skipped_when_token_has_no_jti(
    reset_jwks_cache, jwks_server,
):
    """`jti_cache.observe()` MUST NOT be called for jti-less tokens.

    Guards the `if jti_cache is not None and "jti" in claims:` line
    — without it, a jti-less token would KeyError on `claims["jti"]`
    inside the cache-observe branch.
    """
    from kya.oidc import verify_oidc_token

    observed: list[str] = []

    class SpyCache:
        def observe(self, jti, exp_at):
            observed.append(jti)

    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": jwks_server["iss"], "sub": "x",
            "aud": "kya-oss-verifier",
            "iat": now, "nbf": now, "exp": now + 300,
        },
        jwks_server["sk_pem"], algorithm="RS256",
        headers={"kid": jwks_server["kid"], "alg": "RS256"},
    )
    verify_oidc_token(
        token=token, audience="kya-oss-verifier",
        trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        jti_cache=SpyCache(),
        require_jti=False,
    )
    assert observed == [], "cache.observe was called for a jti-less token"


def test_jti_cache_still_observed_when_require_jti_false_but_token_has_jti(
    reset_jwks_cache, jwks_server,
):
    """Mixed environment: opt-out is set, but a jti-bearing token
    arrives → cache MUST still observe it.

    Guards against a future refactor that inverts the `and "jti" in
    claims` guard to key off `require_jti` instead. If that regressed,
    an operator running mixed flows (opt-out for Auth0 SSO + jti-
    tracking for admin API) would silently lose replay protection on
    the admin path the moment they enabled the SSO one.
    """
    from kya.oidc import verify_oidc_token

    observed: list[str] = []

    class SpyCache:
        def observe(self, jti, exp_at):
            observed.append(jti)

    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
    )
    verify_oidc_token(
        token=token, audience="kya-oss-verifier",
        trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        jti_cache=SpyCache(),
        require_jti=False,  # opt-out set, but token still has a jti
    )
    assert len(observed) == 1
    assert isinstance(observed[0], str) and observed[0], (
        "jti-bearing token was NOT observed by cache — replay tracking "
        "would silently break on the admin path"
    )


def test_require_jti_default_is_true_backward_compat(
    reset_jwks_cache, jwks_server,
):
    """Default `require_jti=True` preserves the pre-0.4 behavior.

    A caller that omits the new kwarg keeps the strict jti requirement
    that admin-auth callers depend on. Locks in backward compatibility.
    """
    from kya.oidc import OIDCAuthError, verify_oidc_token
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": jwks_server["iss"], "sub": "x",
            "aud": "kya-oss-verifier",
            "iat": now, "nbf": now, "exp": now + 300,
        },
        jwks_server["sk_pem"], algorithm="RS256",
        headers={"kid": jwks_server["kid"], "alg": "RS256"},
    )
    # Same call as test_missing_jti_refused — proves default hasn't
    # changed and no downstream caller silently loses jti enforcement.
    with pytest.raises(OIDCAuthError):
        verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        )


def test_expired_refused(reset_jwks_cache, jwks_server):
    from kya.oidc import OIDCAuthError, verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
        iat_offset=-3600, exp_offset=-1800,
    )
    with pytest.raises(OIDCAuthError):
        verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        )


# ─── JWKS fetch failure modes ─────────────────────────────────────


def test_unreachable_jwks_refused(reset_jwks_cache, jwks_server):
    from kya.oidc import OIDCJWKSFetchError, verify_oidc_token
    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
    )
    with pytest.raises(OIDCJWKSFetchError):
        verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: "http://127.0.0.1:1/jwks"},
            fetch_timeout_seconds=1,
        )


def test_malformed_jwks_json_refused(reset_jwks_cache):
    """### Malformed JWKS body raises OIDCJWKSFetchError, not fail-open."""
    from kya.oidc import OIDCJWKSFetchError, verify_oidc_token

    class GarbageHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"this is not json {{{"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args, **kwargs):
            pass

    server = HTTPServer(("127.0.0.1", 0), GarbageHandler)
    port = server.server_address[1]
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        iss = f"http://127.0.0.1:{port}/"
        sk_pem, jwk = _rsa_keypair()
        token = _mint_token(
            sk_pem=sk_pem, kid=jwk["kid"], iss=iss,
            aud="kya-oss-verifier",
        )
        with pytest.raises(OIDCJWKSFetchError, match="non-JSON|JSON"):
            verify_oidc_token(
                token=token, audience="kya-oss-verifier",
                trusted_issuers={iss: f"http://127.0.0.1:{port}/jwks"},
                fetch_timeout_seconds=2,
            )
    finally:
        server.shutdown()
        server.server_close()


def test_jwks_keys_array_missing_refused(reset_jwks_cache):
    """### JWKS doc with no ``keys`` array raises OIDCJWKSFetchError."""
    from kya.oidc import OIDCJWKSFetchError, verify_oidc_token

    class NoKeysHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = json.dumps({"error": "misconfigured"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args, **kwargs):
            pass

    server = HTTPServer(("127.0.0.1", 0), NoKeysHandler)
    port = server.server_address[1]
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        iss = f"http://127.0.0.1:{port}/"
        sk_pem, jwk = _rsa_keypair()
        token = _mint_token(
            sk_pem=sk_pem, kid=jwk["kid"], iss=iss,
            aud="kya-oss-verifier",
        )
        with pytest.raises(OIDCJWKSFetchError, match="keys"):
            verify_oidc_token(
                token=token, audience="kya-oss-verifier",
                trusted_issuers={iss: f"http://127.0.0.1:{port}/jwks"},
                fetch_timeout_seconds=2,
            )
    finally:
        server.shutdown()
        server.server_close()


# ─── JTI replay cache ─────────────────────────────────────────────


def test_jti_observed_in_replay_cache(reset_jwks_cache, jwks_server):
    """Successful verify records the jti so a replay can be detected."""
    from kya.oidc import verify_oidc_token

    seen: list[tuple[str, Any]] = []

    class StubCache:
        def observe(self, jti, exp_at):
            seen.append((jti, exp_at))

    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
    )
    verify_oidc_token(
        token=token, audience="kya-oss-verifier",
        trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
        jti_cache=StubCache(),
    )
    assert len(seen) == 1
    jti, exp_at = seen[0]
    assert isinstance(jti, str) and jti
    assert isinstance(exp_at, int) and exp_at > time.time()


def test_jti_cache_observe_failure_does_not_reject_token(
    reset_jwks_cache, jwks_server, caplog,
):
    """### Replay-cache fault must NOT poison an already-verified token.

    A Valkey outage / OOM mid-flight would otherwise convert
    infrastructure flake into a fleet-wide auth lockout. Verifier
    accepts the token (it's already signature- and claims-verified)
    and logs WARNING for operator follow-up.
    """
    import logging
    from kya.oidc import verify_oidc_token

    class BrokenCache:
        def observe(self, jti, exp_at=None):
            raise RuntimeError("simulated cache outage")

    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
    )
    with caplog.at_level(logging.WARNING, logger="kya.oidc"):
        claims = verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
            jti_cache=BrokenCache(),
        )
    assert claims["sub"] == "alice@example.com"
    assert any(
        "jti_cache.observe failed" in r.message for r in caplog.records
    ), f"expected WARNING; got {[r.message for r in caplog.records]}"


# ─── JWKS cache TTL refresh ───────────────────────────────────────


def test_jwks_cache_refreshes_after_ttl(reset_jwks_cache):
    """### Cache TTL contract — IdP key rotation propagates within bounded time."""
    from kya import oidc

    sk_pem, jwk = _rsa_keypair()
    server = _JWKSServer({"keys": [jwk]})
    try:
        iss = f"http://127.0.0.1:{server.port}/"
        token = _mint_token(
            sk_pem=sk_pem, kid=jwk["kid"], iss=iss,
            aud="kya-oss-verifier",
        )
        oidc.verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={iss: server.url}, ttl_seconds=1,
        )
        assert oidc._JWKS_CACHE is not None
        with oidc._JWKS_CACHE._lock:
            _, jwks_map = oidc._JWKS_CACHE._cache[iss]
        # Force expiry.
        oidc._JWKS_CACHE._cache[iss] = (time.time() - 1, jwks_map)

        token2 = _mint_token(
            sk_pem=sk_pem, kid=jwk["kid"], iss=iss,
            aud="kya-oss-verifier",
        )
        oidc.verify_oidc_token(
            token=token2, audience="kya-oss-verifier",
            trusted_issuers={iss: server.url}, ttl_seconds=1,
        )
        new_expiry, _ = oidc._JWKS_CACHE._cache[iss]
        assert new_expiry > time.time()
    finally:
        server.stop()


# ─── EdDSA + PS256 interop ────────────────────────────────────────


def test_ed25519_jwk_accepted(reset_jwks_cache):
    """### Ed25519 OIDC interop (some IdPs use OKP keys)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from kya.oidc import verify_oidc_token

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pk_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {
        "kty": "OKP", "crv": "Ed25519",
        "use": "sig", "kid": "ed-kid-1",
        "x": _b64url(pk_raw),
    }
    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    server = _JWKSServer({"keys": [jwk]})
    try:
        iss = f"http://127.0.0.1:{server.port}/"
        token = _mint_token(
            sk_pem=sk_pem, kid=jwk["kid"], iss=iss,
            aud="kya-oss-verifier", alg="EdDSA",
        )
        claims = verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={iss: server.url},
        )
        assert claims["sub"] == "alice@example.com"
    finally:
        server.stop()


def test_ps256_keycloak_default_accepted(reset_jwks_cache):
    """### Modern Keycloak (>= 18) defaults new realms to PS256
    and may publish JWKs WITHOUT an explicit ``alg`` claim. The
    JWK-derived allowlist must include PS* for kty=RSA."""
    from kya.oidc import verify_oidc_token

    sk_pem, jwk = _rsa_keypair()
    jwk_no_alg = {k: v for k, v in jwk.items() if k != "alg"}
    server = _JWKSServer({"keys": [jwk_no_alg]})
    try:
        iss = f"http://127.0.0.1:{server.port}/"
        token = _mint_token(
            sk_pem=sk_pem, kid=jwk_no_alg["kid"], iss=iss,
            aud="kya-oss-verifier", alg="PS256",
        )
        claims = verify_oidc_token(
            token=token, audience="kya-oss-verifier",
            trusted_issuers={iss: server.url},
        )
        assert claims["sub"] == "alice@example.com"
    finally:
        server.stop()


# ═════════════════════════════════════════════════════════════════
# Composition with kya.auth + kya.external_id
# ═════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("principal_kind", ["user", "service_account", "admin"])
def test_composition_verify_then_map_then_bind_creates_durable_record(
    reset_jwks_cache, jwks_server, principal_kind,
):
    """### End-to-end: ``verify_oidc_token`` → ``claims_to_kya_principal``
    → ``bind_principal_to_idp`` creates a durable ``kya_principal_trust``
    row, for whichever principal_kind the consumer chooses.

    This is the composition pattern documented in ``kya/oidc.py``.
    OSS is identity-blind: a workload-identity caller (gateway path)
    might bind as ``user`` or ``service_account``; an admin-auth
    caller (pro issuer-API) binds as ``admin``. The verifier doesn't
    care which.
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    from kya.oidc import verify_oidc_token
    from kya.auth import claims_to_kya_principal
    from kya.external_id import bind_principal_to_idp
    from kya import record_principal_signal

    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    db = Session()
    pid = f"oidc-test|{principal_kind}|alice"
    # The principal row MUST already exist (per
    # bind_principal_to_idp's contract). Create it first via a benign
    # signal so the trust row is materialised.
    record_principal_signal(
        db, tenant_id="t1",
        principal_kind=principal_kind, principal_id=pid,
        signal_kind="rogue_login_anomaly",
        attributes={"source": "test"},
    )
    db.commit()

    token = _mint_token(
        sk_pem=jwks_server["sk_pem"], kid=jwks_server["kid"],
        iss=jwks_server["iss"], aud="kya-oss-verifier",
        sub="alice@example.com",
    )
    claims = verify_oidc_token(
        token=token, audience="kya-oss-verifier",
        trusted_issuers={jwks_server["iss"]: jwks_server["jwks_uri"]},
    )
    mapped = claims_to_kya_principal(claims)
    assert mapped["idp_subject"] == "alice@example.com"
    assert mapped["idp_issuer"] == jwks_server["iss"]
    bound = bind_principal_to_idp(
        db, tenant_id="t1",
        principal_kind=principal_kind, principal_id=pid,
        idp_subject=mapped["idp_subject"],
        idp_issuer=mapped["idp_issuer"],
        idp_kind=mapped["idp_kind"],
        federated_id=mapped["federated_id"],
    )
    db.commit()
    assert bound, "bind_principal_to_idp returned False — principal row missing?"

    rows = db.execute(
        text(
            "SELECT idp_subject, idp_issuer, federated_id "
            "FROM kya_principal_trust "
            "WHERE tenant_id='t1' AND principal_kind=:k AND principal_id=:p"
        ),
        {"k": principal_kind, "p": pid},
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "alice@example.com"
    assert rows[0][1] == jwks_server["iss"]
    assert rows[0][2] == mapped["federated_id"]
    db.close()


def test_all_canonical_kinds_accepted_by_binding():
    """### Sanity: the kinds the OSS gateway might bind workload
    identity to (``user``, ``service_account``, ``agent``) are all
    registered, so calling ``bind_principal_to_idp`` with any of
    them never trips kind validation.

    The verifier itself is identity-blind; this test pins the OSS
    contract that the natural consumer-side kinds are usable without
    requiring ``register_principal_kind()`` first.
    """
    from kya.principals import is_valid_principal_kind
    for k in ("user", "service_account", "agent", "admin"):
        assert is_valid_principal_kind(k), f"{k!r} not canonical in OSS"


def test_kya_oidc_importable_without_pyjwt(monkeypatch):
    """### Lean-install contract: importing ``kya.oidc`` (and its
    exception classes) must NOT require pyjwt at module load.

    Bare ``pip install veldt-kya`` (no extras) doesn't pull pyjwt.
    Consumers handling ``OIDCAuthError`` from a downstream module
    must still be able to import the class. pyjwt is only needed
    when actually calling ``verify_oidc_token``.

    Pin by blocking the ``jwt`` module on import and ensuring
    ``from kya.oidc import OIDCAuthError, OIDCJWKSFetchError`` works.
    """
    import importlib
    import sys
    # Block ``jwt`` at import time.
    monkeypatch.setitem(sys.modules, "jwt", None)
    # Force a fresh import of kya.oidc so the top-level executes
    # without pyjwt available.
    sys.modules.pop("kya.oidc", None)
    mod = importlib.import_module("kya.oidc")
    assert hasattr(mod, "OIDCAuthError")
    assert hasattr(mod, "OIDCJWKSFetchError")
    assert hasattr(mod, "verify_oidc_token")
    # Calling the verifier without pyjwt must raise OIDCAuthError
    # (not bare ImportError -- helps callers map to 401).
    with pytest.raises(mod.OIDCAuthError, match="pyjwt is required"):
        mod.verify_oidc_token(
            token="x.y.z", audience="a",
            trusted_issuers={"https://i/": "https://i/jwks"},
        )
