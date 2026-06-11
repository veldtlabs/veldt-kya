"""Tests for kya.vc — Verifiable Credentials (JWT-VC) verifier.

Uses an Ed25519 key for the issuer; signs a JWT-VC; verifies via did:jwk
so the test is fully offline (no network for did:web).
"""
from __future__ import annotations

import base64
import json
import os
import time

import pytest

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

import jwt as pyjwt

from kya.vc import (
    VCExpired,
    VCIssuerNotTrusted,
    VCMalformed,
    VCSignatureInvalid,
    verify_vc,
)


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture
def ed25519_issuer():
    """Generate an Ed25519 keypair and the matching did:jwk URI."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pk_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_no_pad(pk_raw),
    }
    suffix = _b64url_no_pad(json.dumps(jwk).encode("utf-8"))
    issuer_did = f"did:jwk:{suffix}"

    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return {
        "did": issuer_did,
        "sk_pem": sk_pem,
        "sk": sk,
        "pk_raw": pk_raw,
        "jwk": jwk,
    }


def _make_jwt_vc(
    issuer: dict,
    *,
    subject: str = "did:web:bank.example:user42",
    extra_claims: dict | None = None,
    exp_offset: int = 3600,
    nbf_offset: int = 0,
) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer["did"],
        "sub": subject,
        "iat": now,
        "nbf": now + nbf_offset,
        "exp": now + exp_offset,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "AgentAuthorityCredential"],
            "credentialSubject": {"id": subject, "role": "planner"},
        },
    }
    if extra_claims:
        claims.update(extra_claims)
    return pyjwt.encode(claims, issuer["sk_pem"], algorithm="EdDSA")


def test_verify_valid_vc(ed25519_issuer):
    """Happy path: a well-formed VC from a trusted issuer verifies."""
    vc = _make_jwt_vc(ed25519_issuer)
    result = verify_vc(vc, trusted={ed25519_issuer["did"]})
    assert result.issuer_did == ed25519_issuer["did"]
    assert result.subject_did == "did:web:bank.example:user42"
    assert result.claims["vc"]["credentialSubject"]["role"] == "planner"
    assert len(result.issuer_doc_hash) == 64  # SHA-256 hex


def test_verify_expired_vc(ed25519_issuer):
    """An expired VC raises VCExpired."""
    vc = _make_jwt_vc(ed25519_issuer, exp_offset=-3600)
    with pytest.raises(VCExpired):
        verify_vc(vc, trusted={ed25519_issuer["did"]})


def test_verify_untrusted_issuer_raises(ed25519_issuer):
    """A VC from an issuer not in the trusted set raises."""
    vc = _make_jwt_vc(ed25519_issuer)
    with pytest.raises(VCIssuerNotTrusted):
        verify_vc(vc, trusted={"did:web:other.example"})


def test_verify_tampered_signature_raises(ed25519_issuer):
    """If the payload is altered after signing, signature must fail."""
    vc = _make_jwt_vc(ed25519_issuer)
    parts = vc.split(".")
    # Tamper with the body
    body = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8"))
    body["vc"]["credentialSubject"]["role"] = "admin"
    tampered_body = _b64url_no_pad(json.dumps(body).encode("utf-8"))
    tampered = f"{parts[0]}.{tampered_body}.{parts[2]}"

    with pytest.raises(VCSignatureInvalid):
        verify_vc(tampered, trusted={ed25519_issuer["did"]})


def test_verify_malformed_jwt_raises():
    with pytest.raises(VCMalformed):
        verify_vc("notajwt")


def test_verify_jwt_without_did_iss_raises():
    """If iss is not a DID, the verifier refuses upfront."""
    plain_jwt = pyjwt.encode({"iss": "https://idp.example/realms/main"}, "secret", algorithm="HS256")
    with pytest.raises(VCMalformed):
        verify_vc(plain_jwt)


def test_verify_with_audience_check(ed25519_issuer):
    """When ``audience`` is set, the aud claim must match."""
    vc = _make_jwt_vc(ed25519_issuer, extra_claims={"aud": "kya-gateway-prod"})
    # Right audience → verifies
    result = verify_vc(vc, audience="kya-gateway-prod", trusted={ed25519_issuer["did"]})
    assert result.issuer_did == ed25519_issuer["did"]
    # Wrong audience → fails
    with pytest.raises(VCSignatureInvalid):
        verify_vc(vc, audience="some-other-relying-party", trusted={ed25519_issuer["did"]})


# ─── Canonical JWT verifier bugs (B3 + B4 + the alg-confusion classics) ─────


def test_alg_none_rejected(ed25519_issuer):
    """A JWT with alg=none MUST NOT be accepted as a VC.

    Even a JWT with no signature must fail. Canonical JWT verifier bug —
    if PyJWT's algorithms allowlist is ever bypassed, alg=none becomes a
    universal forgery primitive.
    """
    now = int(time.time())
    claims = {
        "iss": ed25519_issuer["did"],
        "sub": "did:web:any.example",
        "iat": now,
        "exp": now + 3600,
    }
    header = _b64url_no_pad(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
    payload = _b64url_no_pad(json.dumps(claims).encode("utf-8"))
    # alg=none JWT has an empty signature segment.
    none_jwt = f"{header}.{payload}."
    with pytest.raises((VCSignatureInvalid, VCMalformed)):
        verify_vc(none_jwt, trusted={ed25519_issuer["did"]})


def test_alg_confusion_hs256_with_pubkey_rejected(ed25519_issuer):
    """The canonical JWT confusion attack.

    Attacker signs a JWT with HS256 using the issuer's PUBLIC KEY BYTES as
    the HMAC secret. A verifier that picks alg from the JWS header (rather
    than from the JWK) would accept this. Our verifier must pin EdDSA and
    reject HS256 outright.
    """
    now = int(time.time())
    claims = {
        "iss": ed25519_issuer["did"],
        "sub": "did:web:victim.example",
        "iat": now,
        "exp": now + 3600,
    }
    # Forge HS256 token using the public key bytes as the HMAC secret.
    hs256_token = pyjwt.encode(
        claims, ed25519_issuer["pk_raw"], algorithm="HS256"
    )
    with pytest.raises(VCSignatureInvalid):
        verify_vc(hs256_token, trusted={ed25519_issuer["did"]})


def test_vc_missing_exp_rejected(ed25519_issuer):
    """A VC with no `exp` claim must be rejected (require=['exp', 'iss'])."""
    now = int(time.time())
    claims = {
        "iss": ed25519_issuer["did"],
        "sub": "did:web:any.example",
        "iat": now,
        # exp deliberately omitted
    }
    token = pyjwt.encode(claims, ed25519_issuer["sk_pem"], algorithm="EdDSA")
    with pytest.raises((VCSignatureInvalid, VCMalformed, VCExpired)):
        verify_vc(token, trusted={ed25519_issuer["did"]})


def test_vc_not_yet_valid(ed25519_issuer):
    """A VC with nbf in the future raises VCNotYetValid."""
    from kya.vc import VCNotYetValid
    vc = _make_jwt_vc(ed25519_issuer, nbf_offset=3600)  # nbf = now + 1h
    with pytest.raises(VCNotYetValid):
        verify_vc(vc, trusted={ed25519_issuer["did"]}, leeway_seconds=30)


def test_vc_within_leeway_succeeds(ed25519_issuer):
    """A VC expired 10s ago verifies when leeway_seconds=60."""
    vc = _make_jwt_vc(ed25519_issuer, exp_offset=-10)
    result = verify_vc(
        vc, trusted={ed25519_issuer["did"]}, leeway_seconds=60
    )
    assert result.issuer_did == ed25519_issuer["did"]


# ─── B3: kid must be honored when the issuer doc has multiple VMs ─────


def _build_multi_vm_doc(did_uri: str, vms: list[tuple[str, dict]]) -> dict:
    """Helper: assemble a raw DID document with N verification methods.

    ``vms`` is a list of (vm_id_fragment, jwk) tuples.
    """
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did_uri,
        "verificationMethod": [
            {
                "id": f"{did_uri}#{frag}",
                "type": "JsonWebKey2020",
                "controller": did_uri,
                "publicKeyJwk": jwk,
            }
            for frag, jwk in vms
        ],
        "assertionMethod": [f"{did_uri}#{frag}" for frag, _ in vms],
        "authentication": [f"{did_uri}#{frag}" for frag, _ in vms],
    }


@pytest.fixture
def multi_vm_issuer(monkeypatch):
    """Issuer DID with TWO Ed25519 keys (k1 and k2).

    Registers a fake resolver for did:custom: so the test is fully offline.
    Signs JWTs with sk2 — the SECOND key — so a verifier that always picks
    VM[0] (the current bug) cannot succeed.
    """
    sk1 = Ed25519PrivateKey.generate()
    sk2 = Ed25519PrivateKey.generate()
    pk1 = sk1.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pk2 = sk2.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk1 = {"kty": "OKP", "crv": "Ed25519", "x": _b64url_no_pad(pk1)}
    jwk2 = {"kty": "OKP", "crv": "Ed25519", "x": _b64url_no_pad(pk2)}
    did_uri = "did:custom:multi-vm-issuer"
    raw_doc = _build_multi_vm_doc(did_uri, [("k1", jwk1), ("k2", jwk2)])

    monkeypatch.setenv("KYA_DID_RESOLVERS", "key,web,jwk,custom")
    from kya.did import register_did_method
    from kya.did_methods.web import _parse_doc
    register_did_method(
        "custom",
        lambda _suffix: _parse_doc(raw_doc, requested_did=did_uri),
    )

    sk2_pem = sk2.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sk1_pem = sk1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {
        "did": did_uri,
        "sk1_pem": sk1_pem,
        "sk2_pem": sk2_pem,
        "k1_id": f"{did_uri}#k1",
        "k2_id": f"{did_uri}#k2",
    }


def test_kid_honored_for_second_key(multi_vm_issuer):
    """JWT signed by k2 with kid=k2 must verify even though k1 is VM[0].

    On the buggy code path (always picks VM[0] = k1), the signature check
    against k1's pubkey fails because the token was signed by k2.
    """
    now = int(time.time())
    claims = {
        "iss": multi_vm_issuer["did"],
        "sub": "did:web:agent.example",
        "iat": now,
        "exp": now + 3600,
        "vc": {"type": ["VerifiableCredential"]},
    }
    token = pyjwt.encode(
        claims,
        multi_vm_issuer["sk2_pem"],
        algorithm="EdDSA",
        headers={"kid": multi_vm_issuer["k2_id"]},
    )
    result = verify_vc(token, trusted={multi_vm_issuer["did"]})
    assert result.issuer_did == multi_vm_issuer["did"]


def test_kid_mismatch_rejected(multi_vm_issuer):
    """Token signed by k2 but kid says k1 — must fail signature check."""
    now = int(time.time())
    claims = {
        "iss": multi_vm_issuer["did"],
        "sub": "did:web:agent.example",
        "iat": now,
        "exp": now + 3600,
    }
    # Sign with sk2 but claim kid=k1 → verifier looks up k1, signature fails.
    token = pyjwt.encode(
        claims,
        multi_vm_issuer["sk2_pem"],
        algorithm="EdDSA",
        headers={"kid": multi_vm_issuer["k1_id"]},
    )
    with pytest.raises(VCSignatureInvalid):
        verify_vc(token, trusted={multi_vm_issuer["did"]})


def test_kid_pointing_at_unknown_vm_rejected(multi_vm_issuer):
    """kid that doesn't match any VM in the document must reject upfront."""
    now = int(time.time())
    claims = {
        "iss": multi_vm_issuer["did"],
        "sub": "did:web:agent.example",
        "iat": now,
        "exp": now + 3600,
    }
    token = pyjwt.encode(
        claims,
        multi_vm_issuer["sk2_pem"],
        algorithm="EdDSA",
        headers={"kid": f"{multi_vm_issuer['did']}#ghost-key"},
    )
    with pytest.raises(VCSignatureInvalid, match=r"(?i)kid"):
        verify_vc(token, trusted={multi_vm_issuer["did"]})


def test_multi_vm_doc_without_kid_rejected(multi_vm_issuer):
    """Multi-VM document + no kid header → ambiguous → reject.

    The verifier MUST NOT silently pick VM[0] when multiple keys are
    possible. That's a footgun for key rotation.
    """
    now = int(time.time())
    claims = {
        "iss": multi_vm_issuer["did"],
        "sub": "did:web:agent.example",
        "iat": now,
        "exp": now + 3600,
    }
    token = pyjwt.encode(
        claims,
        multi_vm_issuer["sk1_pem"],
        algorithm="EdDSA",
        # No kid header
    )
    with pytest.raises(VCSignatureInvalid, match=r"(?i)(kid|ambig)"):
        verify_vc(token, trusted={multi_vm_issuer["did"]})
