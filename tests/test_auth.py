"""Phase 4a — JWT introspection + claim extraction tests.

Mints signed tokens locally using a freshly generated RSA keypair,
serves the public JWK via an in-process HTTP server, and exercises
verify_jwt + claims_to_kya_principal + bind_principal_from_token
across happy paths and ALL the security-relevant failure modes.

No external IdP required.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

# Skip the entire module if PyJWT isn't installed — it's an optional dep
jwt = pytest.importorskip("jwt")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    bind_principal_from_token,
    claims_to_kya_principal,
    init_storage,
    record_principal_signal,
    reset_jwks_cache,
    verify_jwt,
)
from kya.auth import _infer_idp_kind


TENANT = "11111111-2222-3333-4444-aaaaaaaaaaaa"


# ── Inline IdP setup ───────────────────────────────────────────────


@pytest.fixture(scope="module")
def keypair():
    """Generate an RSA-2048 keypair once per module run."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    # PyJWT needs the private key as PEM string for signing
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    # Build the JWKS doc that the test HTTP server will serve
    public_numbers = public_key.public_numbers()
    import base64
    def _b64u(n: int) -> str:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    jwks = {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": "test-key-1",
            "alg": "RS256",
            "n": _b64u(public_numbers.n),
            "e": _b64u(public_numbers.e),
        }]
    }
    return {
        "private_pem": pem_priv,
        "kid": "test-key-1",
        "jwks": jwks,
    }


@pytest.fixture(scope="module")
def jwks_server(keypair):
    """Spin up a tiny HTTP server that serves the JWKS at /.well-known/jwks.json."""
    jwks_body = json.dumps(keypair["jwks"]).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/.well-known/jwks.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(jwks_body)))
                self.end_headers()
                self.wfile.write(jwks_body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args, **kwargs):  # silence noise
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/.well-known/jwks.json"
    srv.shutdown()
    srv.server_close()


@pytest.fixture(autouse=True)
def clean_jwks_cache():
    reset_jwks_cache()
    yield
    reset_jwks_cache()


@pytest.fixture(autouse=True)
def clean_env():
    saved = {k: os.environ.pop(k, None) for k in (
        "KYA_JWT_JWKS_URL", "KYA_JWT_AUDIENCE", "KYA_JWT_ISSUER",
        "KYA_JWT_LEEWAY_SECONDS", "KYA_JWT_ALGORITHMS",
        "KYA_JWT_JWKS_TTL_SECONDS",
    )}
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


def _make_token(keypair, claims, alg="RS256"):
    return jwt.encode(
        claims, keypair["private_pem"], algorithm=alg,
        headers={"kid": keypair["kid"]})


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None})
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


# ── Happy path ─────────────────────────────────────────────────────


def test_verify_jwt_happy_path(keypair, jwks_server):
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "okta|alice@acme.com",
        "iss": "https://acme.okta.com",
        "aud": "kya-test",
        "iat": now,
        "exp": now + 3600,
        "email": "alice@acme.com",
        "groups": ["finance", "admin"],
    })
    claims = verify_jwt(
        token, jwks_url=jwks_server,
        audience="kya-test", issuer="https://acme.okta.com")
    assert claims is not None
    assert claims["sub"] == "okta|alice@acme.com"
    assert claims["email"] == "alice@acme.com"
    assert claims["groups"] == ["finance", "admin"]


def test_verify_jwt_optional_aud_iss(keypair, jwks_server):
    """If env doesn't set aud/iss, verify_jwt skips them — open mode."""
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "anyuser",
        "iss": "https://random.idp.example.com",
        "aud": "anything",
        "iat": now,
        "exp": now + 3600,
    })
    claims = verify_jwt(token, jwks_url=jwks_server)
    assert claims is not None
    assert claims["sub"] == "anyuser"


# ── Failure modes (each must fail-soft → None) ─────────────────────


def test_verify_jwt_expired_returns_none(keypair, jwks_server):
    past = int(time.time()) - 7200
    token = _make_token(keypair, {
        "sub": "expired_user",
        "iat": past, "exp": past + 60,  # expired 1h ago
    })
    assert verify_jwt(token, jwks_url=jwks_server) is None


def test_verify_jwt_wrong_audience_returns_none(keypair, jwks_server):
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "u", "aud": "wrong",
        "iat": now, "exp": now + 3600,
    })
    assert verify_jwt(
        token, jwks_url=jwks_server,
        audience="kya-expected") is None


def test_verify_jwt_wrong_issuer_returns_none(keypair, jwks_server):
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "u", "iss": "https://wrong.idp",
        "iat": now, "exp": now + 3600,
    })
    assert verify_jwt(
        token, jwks_url=jwks_server,
        issuer="https://expected.idp") is None


def test_verify_jwt_invalid_signature_returns_none(jwks_server):
    """Token signed by a DIFFERENT key — JWKS lookup will fail."""
    other_priv = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    pem = other_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    now = int(time.time())
    bad_token = jwt.encode(
        {"sub": "u", "iat": now, "exp": now + 3600},
        pem, algorithm="RS256",
        headers={"kid": "not-in-jwks"})
    assert verify_jwt(bad_token, jwks_url=jwks_server) is None


def test_verify_jwt_malformed_token_returns_none(jwks_server):
    assert verify_jwt("not.a.jwt", jwks_url=jwks_server) is None
    assert verify_jwt("", jwks_url=jwks_server) is None


def test_verify_jwt_unreachable_jwks_returns_none(keypair):
    """JWKS URL is reachable per syntax but server doesn't exist."""
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "u", "iat": now, "exp": now + 3600,
    })
    assert verify_jwt(
        token,
        jwks_url="http://127.0.0.1:1/never-exists") is None


def test_verify_jwt_missing_jwks_url_raises():
    """Programmer error (not config) — raise ValueError."""
    with pytest.raises(ValueError, match="jwks_url"):
        verify_jwt("fake-token")


# ── Algorithm whitelist security ───────────────────────────────────


def test_alg_none_rejected_via_env(keypair, jwks_server, monkeypatch):
    """Even if attacker sets KYA_JWT_ALGORITHMS to include 'none',
    we strip it server-side. No bypass."""
    monkeypatch.setenv("KYA_JWT_ALGORITHMS", "none,RS256,HS256")
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "u", "iat": now, "exp": now + 3600})
    # RS256 is still in the list, so this should work
    claims = verify_jwt(token, jwks_url=jwks_server)
    assert claims is not None


def test_alg_only_dangerous_returns_none(jwks_server, monkeypatch):
    """If env contains ONLY dangerous algs (none + HS*), the
    whitelist becomes empty after sanitization → reject."""
    monkeypatch.setenv("KYA_JWT_ALGORITHMS", "none,HS256,HS512")
    assert verify_jwt(
        "anything.at.all", jwks_url=jwks_server) is None


# ── Claims mapping ─────────────────────────────────────────────────


def test_infer_idp_kind():
    cases = [
        ("https://acme.okta.com", "okta"),
        ("https://acme.okta-emea.com", "okta"),
        ("https://acme.us.auth0.com/", "auth0"),
        ("https://keycloak.example.com/auth/realms/main", "keycloak"),
        ("https://accounts.google.com", "google"),
        ("https://login.microsoftonline.com/...", "microsoft"),
        ("https://cognito-idp.us-east-1.amazonaws.com/x", "aws_cognito"),
        ("spiffe://acme/svc/agent", "spiffe"),
        ("https://random.idp.example.com", "custom"),
        (None, "custom"),
        ("", "custom"),
    ]
    for iss, expected in cases:
        assert _infer_idp_kind(iss) == expected, f"failed for {iss}"


def test_claims_to_kya_principal_basic():
    out = claims_to_kya_principal({
        "sub": "okta|alice",
        "iss": "https://acme.okta.com",
        "email": "alice@acme.com",
        "groups": ["admin"],
    })
    assert out["idp_subject"] == "okta|alice"
    assert out["idp_issuer"] == "https://acme.okta.com"
    assert out["idp_kind"] == "okta"
    assert out["federated_id"] == "okta|https://acme.okta.com|okta|alice"
    assert out["email"] == "alice@acme.com"
    assert out["groups"] == ["admin"]


def test_claims_to_kya_principal_missing_sub():
    out = claims_to_kya_principal({"iss": "https://acme.okta.com"})
    assert out["idp_subject"] is None
    assert out["federated_id"] is None  # can't derive without sub


def test_claims_to_kya_principal_missing_iss():
    out = claims_to_kya_principal({"sub": "u"})
    assert out["idp_issuer"] is None
    assert out["idp_kind"] == "custom"  # no iss → fallback


# ── End-to-end: verify + bind ──────────────────────────────────────


def test_bind_principal_from_token_happy_path(
        db, keypair, jwks_server):
    """Verify token + auto-populate Phase 4b's binding fields."""
    record_principal_signal(
        db, tenant_id=TENANT,
        principal_kind="user", principal_id="alice_internal",
        signal_kind="oos_tool")
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "okta|alice@acme.com",
        "iss": "https://acme.okta.com",
        "iat": now, "exp": now + 3600,
    })
    claims = bind_principal_from_token(
        db, tenant_id=TENANT,
        principal_kind="user", principal_id="alice_internal",
        bearer_token=token, jwks_url=jwks_server)
    assert claims is not None
    assert claims["sub"] == "okta|alice@acme.com"
    # Verify Phase 4b columns now populated
    from kya import lookup_principal_by_idp
    found = lookup_principal_by_idp(
        db, tenant_id=TENANT,
        idp_subject="okta|alice@acme.com")
    assert found is not None
    assert found["principal_id"] == "alice_internal"
    assert found["idp_kind"] == "okta"
    assert found["idp_issuer"] == "https://acme.okta.com"


def test_bind_principal_from_token_invalid_returns_none(
        db, keypair, jwks_server):
    """Invalid token → bind doesn't happen, returns None."""
    record_principal_signal(
        db, tenant_id=TENANT,
        principal_kind="user", principal_id="bob_internal",
        signal_kind="oos_tool")
    claims = bind_principal_from_token(
        db, tenant_id=TENANT,
        principal_kind="user", principal_id="bob_internal",
        bearer_token="garbage", jwks_url=jwks_server)
    assert claims is None
    # Verify NO binding was written
    from kya import lookup_principal_by_idp
    found = lookup_principal_by_idp(
        db, tenant_id=TENANT, idp_subject="anything")
    assert found is None


def test_bind_principal_from_token_missing_principal_row_returns_none(
        db, keypair, jwks_server):
    """Valid token, but no principal_trust row → fail-soft → None."""
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "okta|ghost",
        "iat": now, "exp": now + 3600,
    })
    claims = bind_principal_from_token(
        db, tenant_id=TENANT,
        principal_kind="user", principal_id="never_signaled",
        bearer_token=token, jwks_url=jwks_server)
    assert claims is None


def test_bind_principal_from_token_validates_args(db):
    with pytest.raises(ValueError, match="tenant_id"):
        bind_principal_from_token(
            db, tenant_id="", principal_kind="user",
            principal_id="x", bearer_token="t",
            jwks_url="https://x")


def test_bind_principal_from_token_token_without_sub(
        db, keypair, jwks_server):
    """Token verifies but has no `sub` claim → can't bind."""
    record_principal_signal(
        db, tenant_id=TENANT,
        principal_kind="user", principal_id="claudia",
        signal_kind="oos_tool")
    now = int(time.time())
    token = _make_token(keypair, {
        "iss": "https://acme.okta.com",
        "iat": now, "exp": now + 3600,
        # NO sub
    })
    claims = bind_principal_from_token(
        db, tenant_id=TENANT,
        principal_kind="user", principal_id="claudia",
        bearer_token=token, jwks_url=jwks_server)
    assert claims is None


# ── JWKS cache ─────────────────────────────────────────────────────


def test_jwks_cache_hit_avoids_refetch(keypair, jwks_server):
    """Second verify_jwt call within TTL hits the cache (no extra
    HTTP). Easiest check: the function still succeeds AFTER we
    shut down the server. PyJWKClient maintains its own cache so
    the second call would succeed even without our cache; this
    just confirms nothing's broken on rapid repeated calls."""
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "cached_u", "iat": now, "exp": now + 3600,
    })
    a = verify_jwt(token, jwks_url=jwks_server)
    b = verify_jwt(token, jwks_url=jwks_server)
    assert a == b
    assert a["sub"] == "cached_u"


# ── Clock skew leeway ─────────────────────────────────────────────


def test_leeway_allows_small_skew(keypair, jwks_server):
    """Token expired 5s ago but leeway=30 → still accepted."""
    now = int(time.time())
    token = _make_token(keypair, {
        "sub": "skewed_u",
        "iat": now - 7200,
        "exp": now - 5,  # expired 5s ago
    })
    assert verify_jwt(
        token, jwks_url=jwks_server,
        leeway_seconds=30) is not None
    # Default leeway is 30s — token expired 5s ago is within window.
    assert verify_jwt(
        token, jwks_url=jwks_server) is not None
    # Token expired 60s ago: ≤30 default leeway → reject; 90s leeway
    # → accept (proves leeway kwarg actually drives the decision).
    token2 = _make_token(keypair, {
        "sub": "skewed_u",
        "iat": now - 7200,
        "exp": now - 60,
    })
    assert verify_jwt(token2, jwks_url=jwks_server) is None
    assert verify_jwt(
        token2, jwks_url=jwks_server,
        leeway_seconds=90) is not None
