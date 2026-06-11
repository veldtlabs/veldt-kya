"""Tests for DPoP-bound /v1/principals/me (Phase 6 step 1 of friction→capability).

The endpoint was previously protected only by an in-process per-IP rate
limit (friction). Phase 6 requires a fresh DPoP JWT signed by the DID's
authentication key — replay-grinding becomes impossible without the
private key.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import types

import pytest

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import jwt as pyjwt

from fastapi.testclient import TestClient

from kya_gateway.config import (
    AuditConfig, BackendConfig, DIDConfig, GatewayBindConfig, GatewayConfig,
    IdentityConfig, JWTConfig, PolicyConfig,
)
from kya_gateway.server import Gateway


# ─── Fixtures ────────────────────────────────────────────────────────


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture
def agent_key():
    """Generate an Ed25519 keypair and corresponding did:jwk URI."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(pk)}
    suffix = _b64url(json.dumps(jwk).encode())
    did = f"did:jwk:{suffix}"
    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {"did": did, "sk_pem": sk_pem, "jwk": jwk}


@pytest.fixture
def other_key():
    """A second keypair — for negative tests (signed by unknown key)."""
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(autouse=True)
def _clean_me_rate_window():
    """Reset the per-IP rate limit dict so DPoP tests aren't blocked by
    state leaked from `test_principals_me_per_ip_rate_limit`."""
    from kya_gateway import server as _srv
    _srv._ME_RATE_WINDOWS.clear()
    yield
    _srv._ME_RATE_WINDOWS.clear()


@pytest.fixture
def gateway_app():
    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t1"),
        identity=IdentityConfig(
            methods=["did"],
            did=DIDConfig(
                resolvers=["key", "web", "jwk"],
                trusted_issuers=[],
                allow_header_trust=False,
                pop_audience="http://testserver/mcp",
                require_dpop_on_me=True,
                dpop_audience="http://testserver",
                dpop_leeway_seconds=30,
            ),
        ),
        backends=[BackendConfig(name="default", url="http://127.0.0.1:9099")],
        policy=PolicyConfig(),
        audit=AuditConfig(),
    )
    return Gateway(cfg).app


def _mint_pop(agent: dict, audience: str) -> str:
    now = int(time.time())
    return pyjwt.encode(
        {"iss": agent["did"], "aud": audience, "iat": now, "exp": now + 60},
        agent["sk_pem"],
        algorithm="EdDSA",
        headers={"kid": f"{agent['did']}#0"},
    )


def _mint_dpop(agent: dict, *, htm: str, htu: str,
               iat_offset: int = 0, key_pem: bytes | None = None) -> str:
    now = int(time.time()) + iat_offset
    return pyjwt.encode(
        {
            "iss": agent["did"],
            "htm": htm,
            "htu": htu,
            "iat": now,
            "jti": _b64url(os.urandom(16)),
        },
        key_pem if key_pem is not None else agent["sk_pem"],
        algorithm="EdDSA",
        headers={"kid": f"{agent['did']}#0", "typ": "dpop+jwt"},
    )


# ─── 1. DPoP missing → 401 with WWW-Authenticate hint ────────────────


def test_me_without_dpop_returns_401_with_dpop_hint(gateway_app, agent_key):
    client = TestClient(gateway_app)
    r = client.get(
        "/v1/principals/me",
        headers={
            "X-KYA-DID": agent_key["did"],
            "X-KYA-DID-Proof": _mint_pop(agent_key, "http://testserver/mcp"),
        },
    )
    assert r.status_code == 401, r.text
    www = r.headers.get("www-authenticate", "")
    assert "DPoP" in www, f"missing DPoP hint, got: {www!r}"


# ─── 2. DPoP signed by wrong key → 401 ───────────────────────────────


def test_me_with_dpop_signed_by_unknown_key_returns_401(
    gateway_app, agent_key, other_key,
):
    client = TestClient(gateway_app)
    dpop = _mint_dpop(
        agent_key,
        htm="GET",
        htu="http://testserver/v1/principals/me",
        key_pem=other_key,
    )
    r = client.get(
        "/v1/principals/me",
        headers={
            "X-KYA-DID": agent_key["did"],
            "X-KYA-DID-Proof": _mint_pop(agent_key, "http://testserver/mcp"),
            "DPoP": dpop,
        },
    )
    assert r.status_code == 401, r.text


# ─── 3. DPoP with wrong htm → 401 ────────────────────────────────────


def test_me_with_dpop_wrong_htm_returns_401(gateway_app, agent_key):
    client = TestClient(gateway_app)
    dpop = _mint_dpop(
        agent_key, htm="POST",
        htu="http://testserver/v1/principals/me",
    )
    r = client.get(
        "/v1/principals/me",
        headers={
            "X-KYA-DID": agent_key["did"],
            "X-KYA-DID-Proof": _mint_pop(agent_key, "http://testserver/mcp"),
            "DPoP": dpop,
        },
    )
    assert r.status_code == 401


# ─── 4. DPoP with wrong htu → 401 ────────────────────────────────────


def test_me_with_dpop_wrong_htu_returns_401(gateway_app, agent_key):
    client = TestClient(gateway_app)
    dpop = _mint_dpop(
        agent_key, htm="GET",
        htu="http://other-gateway.example/v1/principals/me",
    )
    r = client.get(
        "/v1/principals/me",
        headers={
            "X-KYA-DID": agent_key["did"],
            "X-KYA-DID-Proof": _mint_pop(agent_key, "http://testserver/mcp"),
            "DPoP": dpop,
        },
    )
    assert r.status_code == 401


# ─── 5. DPoP iat too far in the future → 401 ────────────────────────


def test_me_with_dpop_future_iat_returns_401(gateway_app, agent_key):
    client = TestClient(gateway_app)
    dpop = _mint_dpop(
        agent_key, htm="GET",
        htu="http://testserver/v1/principals/me",
        iat_offset=3600,  # 1h in the future, far past 30s leeway
    )
    r = client.get(
        "/v1/principals/me",
        headers={
            "X-KYA-DID": agent_key["did"],
            "X-KYA-DID-Proof": _mint_pop(agent_key, "http://testserver/mcp"),
            "DPoP": dpop,
        },
    )
    assert r.status_code == 401


# ─── 6. Valid DPoP → 200 echo ────────────────────────────────────────


def test_me_with_valid_dpop_returns_200(gateway_app, agent_key):
    client = TestClient(gateway_app)
    dpop = _mint_dpop(
        agent_key, htm="GET",
        htu="http://testserver/v1/principals/me",
    )
    r = client.get(
        "/v1/principals/me",
        headers={
            "X-KYA-DID": agent_key["did"],
            "X-KYA-DID-Proof": _mint_pop(agent_key, "http://testserver/mcp"),
            "DPoP": dpop,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["external_subject"] == agent_key["did"]
    assert body["method"] == "did"
