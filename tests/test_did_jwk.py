"""Tests for kya.did_methods.jwk — did:jwk resolver."""
from __future__ import annotations

import base64
import json
import os

import pytest

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"

from kya.did import DIDInvalidIdentifier, resolve_did


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_resolve_ed25519_jwk():
    """A well-formed Ed25519 JWK round-trips through did:jwk."""
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }
    suffix = _b64url_no_pad(json.dumps(jwk).encode("utf-8"))
    did = f"did:jwk:{suffix}"

    doc = resolve_did(did)
    assert doc.id == did
    assert len(doc.verification_methods) == 1
    vm = doc.verification_methods[0]
    assert vm.type == "JsonWebKey2020"
    assert vm.public_key_jwk == jwk


def test_resolve_rsa_jwk():
    """did:jwk works for RSA keys (any JWK type, identified by kty)."""
    jwk = {
        "kty": "RSA",
        "n": "AAA",
        "e": "AQAB",
    }
    suffix = _b64url_no_pad(json.dumps(jwk).encode("utf-8"))
    doc = resolve_did(f"did:jwk:{suffix}")
    assert doc.verification_methods[0].public_key_jwk["kty"] == "RSA"


def test_invalid_base64_raises():
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did("did:jwk:!!!notbase64!!!")


def test_invalid_json_raises():
    suffix = _b64url_no_pad(b"not json {{{")
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did(f"did:jwk:{suffix}")


def test_jwk_without_kty_raises():
    suffix = _b64url_no_pad(json.dumps({"x": "abc"}).encode("utf-8"))
    with pytest.raises(DIDInvalidIdentifier, match="kty"):
        resolve_did(f"did:jwk:{suffix}")


def test_non_object_payload_raises():
    suffix = _b64url_no_pad(json.dumps(["not", "an", "object"]).encode("utf-8"))
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did(f"did:jwk:{suffix}")
