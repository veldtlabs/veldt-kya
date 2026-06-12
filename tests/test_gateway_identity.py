"""Tests for kya_gateway.identity.IdentityResolver.

Covers B10 (method fallthrough must not happen when a header was present
but invalid), B13 (principal_kind from unsigned claims must not be
trusted), and B14 (DID identity must require proof of possession).
"""
from __future__ import annotations

import base64
import json
import os
import time

import pytest

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk,custom"

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kya_gateway.config import DIDConfig, IdentityConfig, JWTConfig
from kya_gateway.errors import IdentityBindingFailed
from kya_gateway.identity import (
    HEADER_AUTHORIZATION,
    HEADER_DID,
    IdentityResolver,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def did_keypair():
    """Generate an Ed25519 keypair + corresponding did:jwk."""
    sk = Ed25519PrivateKey.generate()
    pk_raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(pk_raw)}
    suffix = _b64url(json.dumps(jwk).encode("utf-8"))
    did = f"did:jwk:{suffix}"
    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {"did": did, "sk_pem": sk_pem, "jwk": jwk}


@pytest.fixture
def other_keypair():
    """A second unrelated keypair for negative tests."""
    sk = Ed25519PrivateKey.generate()
    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {"sk_pem": sk_pem}


def _make_pop(did: str, sk_pem: bytes, *, aud: str = "https://gw.example/mcp",
              iat_offset: int = 0, exp_offset: int = 60) -> str:
    """Mint a DID proof-of-possession JWT."""
    now = int(time.time())
    headers = {"kid": f"{did}#0"}
    claims = {
        "iss": did,
        "aud": aud,
        "iat": now + iat_offset,
        "exp": now + exp_offset,
    }
    return pyjwt.encode(claims, sk_pem, algorithm="EdDSA", headers=headers)


def _make_did_config(allow_header_trust: bool = False,
                     trusted_issuers: list[str] | None = None,
                     audience: str = "https://gw.example/mcp") -> DIDConfig:
    return DIDConfig(
        resolvers=["key", "web", "jwk"],
        trusted_issuers=trusted_issuers or [],
        allow_header_trust=allow_header_trust,
        pop_audience=audience,
    )


def _make_resolver(methods: list[str], *, did_cfg: DIDConfig | None = None,
                   jwt_cfg: JWTConfig | None = None,
                   trusted_jwt_issuers: list[str] | None = None) -> IdentityResolver:
    cfg = IdentityConfig(
        methods=methods,
        jwt=jwt_cfg or JWTConfig(trusted_issuers=trusted_jwt_issuers or []),
        did=did_cfg,
    )
    return IdentityResolver(cfg)


# ─── B14: DID without proof-of-possession must reject ────────────────


def test_did_header_alone_rejected_by_default(monkeypatch, did_keypair):
    """Sending only X-KYA-DID without proof must NOT bind that DID.

    Without PoP, anyone can claim any DID and become that principal —
    a critical impersonation primitive.
    """
    # Mock did resolution to succeed (the DID is real).
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        resolver = _make_resolver(["did"], did_cfg=_make_did_config())
        with pytest.raises(IdentityBindingFailed, match=r"(?i)proof|pop"):
            resolver.resolve({HEADER_DID: did_keypair["did"]})
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_did_with_valid_pop_accepted(monkeypatch, did_keypair):
    """X-KYA-DID + valid X-KYA-DID-PROOF signed by the DID's key → bind."""
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop = _make_pop(did_keypair["did"], did_keypair["sk_pem"])
        resolver = _make_resolver(["did"], did_cfg=_make_did_config())
        principal = resolver.resolve({
            HEADER_DID: did_keypair["did"],
            "X-KYA-DID-Proof": pop,
        })
        assert principal.method == "did"
        assert principal.external_subject == did_keypair["did"]
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_did_with_pop_signed_by_other_key_rejected(monkeypatch, did_keypair,
                                                    other_keypair):
    """A PoP JWT signed by a key NOT in the DID document must fail."""
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop_bad = _make_pop(did_keypair["did"], other_keypair["sk_pem"])
        resolver = _make_resolver(["did"], did_cfg=_make_did_config())
        with pytest.raises(IdentityBindingFailed):
            resolver.resolve({
                HEADER_DID: did_keypair["did"],
                "X-KYA-DID-Proof": pop_bad,
            })
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_did_with_future_iat_pop_rejected(monkeypatch, did_keypair):
    """A PoP with iat far in the future must be rejected.

    Without this check, attacker mints `iat=now+3600, exp=now+3700` and
    the `exp-iat` lifetime math sees a 100s window — but the PoP is
    actually usable from now until exp, defeating the lifetime cap.
    """
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop_future = _make_pop(did_keypair["did"], did_keypair["sk_pem"],
                                iat_offset=3600, exp_offset=3700)
        resolver = _make_resolver(["did"], did_cfg=_make_did_config())
        with pytest.raises(IdentityBindingFailed):
            resolver.resolve({
                HEADER_DID: did_keypair["did"],
                "X-KYA-DID-Proof": pop_future,
            })
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_did_pop_without_audience_when_not_configured_rejected(monkeypatch, did_keypair):
    """When `pop_audience` is None (not configured), the resolver must REFUSE
    to accept a PoP — otherwise it's a cross-gateway replay surface.

    Default-safe means audience binding is required for the DID method.
    Operators who explicitly want headerless trust can set
    `allow_header_trust=true`.
    """
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop = _make_pop(did_keypair["did"], did_keypair["sk_pem"])
        # Build config with pop_audience explicitly None
        did_cfg = DIDConfig(
            resolvers=["jwk"], trusted_issuers=[],
            allow_header_trust=False,
            pop_audience=None,
        )
        resolver = _make_resolver(["did"], did_cfg=did_cfg)
        with pytest.raises(IdentityBindingFailed, match=r"(?i)audience|pop_audience"):
            resolver.resolve({
                HEADER_DID: did_keypair["did"],
                "X-KYA-DID-Proof": pop,
            })
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_did_pop_with_empty_authentication_set_rejected(monkeypatch, did_keypair):
    """When the DID document publishes no `authentication` list, a PoP must
    be rejected — no key is marked as authoritative for authentication."""
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            # ↓ empty authentication: would silently degrade in buggy code
            authentication=[],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop = _make_pop(did_keypair["did"], did_keypair["sk_pem"])
        resolver = _make_resolver(["did"], did_cfg=_make_did_config())
        with pytest.raises(IdentityBindingFailed, match=r"(?i)authentication"):
            resolver.resolve({
                HEADER_DID: did_keypair["did"],
                "X-KYA-DID-Proof": pop,
            })
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_did_with_expired_pop_rejected(monkeypatch, did_keypair):
    """An expired PoP JWT must fail."""
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop_expired = _make_pop(did_keypair["did"], did_keypair["sk_pem"],
                                iat_offset=-3600, exp_offset=-3500)
        resolver = _make_resolver(["did"], did_cfg=_make_did_config())
        with pytest.raises(IdentityBindingFailed):
            resolver.resolve({
                HEADER_DID: did_keypair["did"],
                "X-KYA-DID-Proof": pop_expired,
            })
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_did_with_wrong_audience_pop_rejected(monkeypatch, did_keypair):
    """PoP JWT whose `aud` doesn't match the configured gateway audience."""
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop_wrong_aud = _make_pop(did_keypair["did"], did_keypair["sk_pem"],
                                   aud="https://attacker.example")
        resolver = _make_resolver(["did"], did_cfg=_make_did_config(
            audience="https://gw.example/mcp"
        ))
        with pytest.raises(IdentityBindingFailed):
            resolver.resolve({
                HEADER_DID: did_keypair["did"],
                "X-KYA-DID-Proof": pop_wrong_aud,
            })
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_did_header_trust_mode_accepts_without_pop(monkeypatch, did_keypair):
    """Backward-compat: explicit opt-in to header-trust mode bypasses PoP."""
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        resolver = _make_resolver(["did"], did_cfg=_make_did_config(
            allow_header_trust=True
        ))
        principal = resolver.resolve({HEADER_DID: did_keypair["did"]})
        assert principal.external_subject == did_keypair["did"]
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


# ─── B10: methods must NOT fall through on invalid credentials ───────


def test_malformed_jwt_does_not_fall_through_to_did(monkeypatch, did_keypair):
    """When Authorization header is present but the JWT fails to verify,
    the resolver must HARD FAIL — not fall through to a DID header the
    attacker also controls.
    """
    # Mock kya.auth.introspect_jwt to raise (simulating bad signature).
    import sys
    import types
    fake_auth = types.ModuleType("kya.auth")
    def boom(_token):
        raise ValueError("bad signature")
    fake_auth.introspect_jwt = boom
    monkeypatch.setitem(sys.modules, "kya.auth", fake_auth)

    # Set up DID resolution so the fallthrough WOULD succeed if it occurred.
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop = _make_pop(did_keypair["did"], did_keypair["sk_pem"])
        resolver = _make_resolver(
            ["bearer_jwt", "did"],
            did_cfg=_make_did_config(),
        )
        # Auth header IS present (malformed token); DID header IS present.
        # The bearer_jwt method must hard-fail rather than fall through.
        with pytest.raises(IdentityBindingFailed):
            principal = resolver.resolve({
                HEADER_AUTHORIZATION: "Bearer attacker.controlled.junk",
                HEADER_DID: did_keypair["did"],
                "X-KYA-DID-Proof": pop,
            })
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_missing_jwt_falls_through_to_did(monkeypatch, did_keypair):
    """No Authorization header → bearer_jwt is "absent" → fall through OK."""
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"], public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        pop = _make_pop(did_keypair["did"], did_keypair["sk_pem"])
        resolver = _make_resolver(
            ["bearer_jwt", "did"],
            did_cfg=_make_did_config(),
        )
        # No Authorization header — bearer_jwt should raise "header missing"
        # and the resolver should try DID next.
        principal = resolver.resolve({
            HEADER_DID: did_keypair["did"],
            "X-KYA-DID-Proof": pop,
        })
        assert principal.method == "did"
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


# ─── B13: principal_kind from JWT claims must not be trusted by default ──


def test_jwt_principal_kind_ignored_when_issuer_not_trusted(monkeypatch):
    """A JWT claiming principal_kind=service_account from an untrusted issuer
    MUST be downgraded to the safe default 'agent'."""
    import sys
    import types
    fake_auth = types.ModuleType("kya.auth")
    fake_auth.introspect_jwt = lambda _token: {
        "sub": "alice",
        "iss": "https://random-idp.example",
        "principal_kind": "service_account",  # attacker self-elevation
        "principal_id": "alice",
    }
    monkeypatch.setitem(sys.modules, "kya.auth", fake_auth)

    resolver = _make_resolver(
        ["bearer_jwt"],
        jwt_cfg=JWTConfig(trusted_issuers=[]),  # no trusted issuers
    )
    principal = resolver.resolve({HEADER_AUTHORIZATION: "Bearer dummy"})
    assert principal.principal_kind == "agent", (
        f"untrusted JWT was able to self-elevate to principal_kind="
        f"{principal.principal_kind!r}"
    )


def test_jwt_principal_kind_honored_when_issuer_trusted(monkeypatch):
    """When issuer is in jwt.trusted_issuers, principal_kind is honored."""
    import sys
    import types
    fake_auth = types.ModuleType("kya.auth")
    fake_auth.introspect_jwt = lambda _token: {
        "sub": "alice",
        "iss": "https://trusted-idp.example",
        "principal_kind": "service_account",
        "principal_id": "alice",
    }
    monkeypatch.setitem(sys.modules, "kya.auth", fake_auth)

    resolver = _make_resolver(
        ["bearer_jwt"],
        jwt_cfg=JWTConfig(trusted_issuers=["https://trusted-idp.example"]),
    )
    principal = resolver.resolve({HEADER_AUTHORIZATION: "Bearer dummy"})
    assert principal.principal_kind == "service_account"


# ─── _extract_vc_principal_attr (Phase 12 fix) ─────────────────────


def test_extract_vc_principal_attr_reads_from_vc_credentialsubject():
    """W3C VC-JWT puts custom claims under vc.credentialSubject.
    Phase 12 fix: the gateway must read from there (it was reading
    only top-level claims, so KYA's own JWTVCIssuer-produced VCs
    never matched and every agent's principal_id silently fell back
    to the agent's DID)."""
    from kya_gateway.identity import _extract_vc_principal_attr
    vc_claims = {
        "iss": "did:key:zIssuer",
        "sub": "did:key:zSubject",
        "iat": 1, "exp": 2,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {
                "id": "did:key:zSubject",
                "principal_kind": "agent",
                "principal_id": "phase12-agent-001",
            },
        },
    }
    assert _extract_vc_principal_attr(vc_claims, "principal_id") == (
        "phase12-agent-001"
    )
    assert _extract_vc_principal_attr(vc_claims, "principal_kind") == "agent"


def test_extract_vc_principal_attr_falls_back_to_top_level():
    """Non-spec-compliant issuers that stamp principal_id at the JWT
    top level (no `vc` envelope) must still work — back-compat."""
    from kya_gateway.identity import _extract_vc_principal_attr
    vc_claims = {
        "iss": "did:key:zIssuer",
        "sub": "did:key:zSubject",
        "principal_kind": "user",
        "principal_id": "legacy-top-level-id",
    }
    assert _extract_vc_principal_attr(vc_claims, "principal_id") == (
        "legacy-top-level-id"
    )
    assert _extract_vc_principal_attr(vc_claims, "principal_kind") == "user"


def test_extract_vc_principal_attr_credentialsubject_wins_over_top_level():
    """If both locations have the claim, the W3C-compliant nested
    one wins (closer to spec, prevents an issuer-vs-test-fixture
    ambiguity from silently using the wrong one)."""
    from kya_gateway.identity import _extract_vc_principal_attr
    vc_claims = {
        "principal_id": "top-level-stale",
        "vc": {
            "credentialSubject": {
                "principal_id": "nested-authoritative",
            },
        },
    }
    assert _extract_vc_principal_attr(vc_claims, "principal_id") == (
        "nested-authoritative"
    )


def test_extract_vc_principal_attr_returns_none_when_missing():
    """No claim in either location -> None (caller falls back to the
    DID or _SAFE_DEFAULT_PRINCIPAL_KIND)."""
    from kya_gateway.identity import _extract_vc_principal_attr
    assert _extract_vc_principal_attr({}, "principal_id") is None
    assert _extract_vc_principal_attr(
        {"vc": {"credentialSubject": {}}}, "principal_id"
    ) is None
    # Empty-string values count as missing (Phase 12 issuer claim
    # sanitization).
    assert _extract_vc_principal_attr(
        {"principal_id": ""}, "principal_id"
    ) is None


def test_extract_vc_principal_attr_handles_malformed_input():
    """Defensive: VC claims could be malformed in adversarial cases.
    The helper must not raise -- return None instead."""
    from kya_gateway.identity import _extract_vc_principal_attr
    # vc is not a dict
    assert _extract_vc_principal_attr(
        {"vc": "not-a-dict"}, "principal_id"
    ) is None
    # credentialSubject is not a dict
    assert _extract_vc_principal_attr(
        {"vc": {"credentialSubject": "x"}}, "principal_id"
    ) is None
    # entire payload is None / non-dict
    assert _extract_vc_principal_attr(None, "principal_id") is None
    assert _extract_vc_principal_attr("not-a-dict", "principal_id") is None


def test_try_did_extracts_principal_id_from_vc_credentialsubject_e2e(
    monkeypatch, did_keypair, other_keypair,
):
    """Integration: full _try_did path with X-KYA-DID + X-KYA-DID-Proof
    + X-KYA-VC, where the VC's claims live under vc.credentialSubject
    (W3C-compliant location). BoundPrincipal.principal_id MUST equal
    the operator-chosen id from credentialSubject, NOT the agent's DID.

    Phase 12 fix regression guard: without this test, a future refactor
    that drops the _extract_vc_principal_attr call would pass all 5
    helper-only tests while silently re-introducing the bug (gateway
    treats every agent's principal_id as their DID)."""
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument, VerificationMethod
    from kya.vc import VerifiedCredential
    from kya_gateway.identity import HEADER_VC
    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"],
            verification_methods=[VerificationMethod(
                id=f"{did_keypair['did']}#0", type="JsonWebKey2020",
                controller=did_keypair["did"],
                public_key_jwk=did_keypair["jwk"],
            )],
            authentication=[f"{did_keypair['did']}#0"],
            assertion_method=[f"{did_keypair['did']}#0"],
            raw={"id": did_keypair["did"]},
        ))

        # Monkey-patch verify_vc to return a synthetic VerifiedCredential
        # carrying the W3C-compliant nested-claims shape. We are testing
        # the resolver's extraction, not VC signature verification.
        trusted_issuer_did = (
            "did:key:z6MkrZ1xUnSyntheticIssuerForTest"
        )
        spec_compliant_claims = {
            "iss": trusted_issuer_did,
            "sub": did_keypair["did"],
            "iat": int(time.time()) - 5,
            "exp": int(time.time()) + 3600,
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "AgentAuthorityCredential"],
                "credentialSubject": {
                    "id": did_keypair["did"],
                    "principal_kind": "service_account",
                    "principal_id": "phase12-operator-chosen-id",
                },
            },
        }

        def fake_verify_vc(vc_jwt: str):
            return VerifiedCredential(
                issuer_did=trusted_issuer_did,
                subject_did=did_keypair["did"],
                claims=spec_compliant_claims,
                issuer_doc=None,  # not used by gateway path
                issuer_doc_hash="synthetic",
            )
        import kya.vc as kya_vc
        monkeypatch.setattr(kya_vc, "verify_vc", fake_verify_vc)

        pop = _make_pop(did_keypair["did"], did_keypair["sk_pem"])
        resolver = _make_resolver(
            ["did"],
            did_cfg=_make_did_config(
                trusted_issuers=[trusted_issuer_did],
            ),
        )
        principal = resolver.resolve({
            HEADER_DID: did_keypair["did"],
            "X-KYA-DID-Proof": pop,
            HEADER_VC: "synthetic-vc-jwt-string",
        })
        # The fix: principal_id comes from vc.credentialSubject, NOT
        # the agent's DID.
        assert principal.principal_id == "phase12-operator-chosen-id", (
            f"principal_id fell back to DID -- credentialSubject "
            f"extraction is regressed. got={principal.principal_id!r}"
        )
        assert principal.principal_kind == "service_account"
        assert principal.method == "did"
        # External identifiers should still be the cryptographic ones.
        assert principal.external_subject == did_keypair["did"]
        assert principal.external_issuer == trusted_issuer_did
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)


def test_jwk_resolver_fixture_cleanup_does_not_leak_when_saved_is_none(
    monkeypatch, did_keypair,
):
    """Regression #113: fixtures in this file save the prior jwk
    resolver, register a fake, and restore on exit -- but the
    restore branch was guarded by `if saved is not None`, so when
    no resolver was registered at the time of save (the common case
    in pytest's clean process), the fake leaked into subsequent
    tests in OTHER files (e.g. test_did_binding.py).

    The fix: when saved is None, pop the registration outright so
    no resolver remains. This test verifies the cleanup is complete
    regardless of the saved state.
    """
    from kya.did import _resolvers, register_did_method
    from kya.did_document import DIDDocument

    # Snapshot whatever state pytest left us in.
    pre = _resolvers.get("jwk")

    saved = _resolvers.get("jwk")
    try:
        register_did_method("jwk", lambda _s: DIDDocument(
            id=did_keypair["did"], verification_methods=[],
            authentication=[], assertion_method=[],
            raw={"id": did_keypair["did"]},
        ))
        # Resolver IS now registered while we're inside the block.
        assert _resolvers.get("jwk") is not None
    finally:
        if saved is not None:
            register_did_method("jwk", saved)
        else:
            _resolvers.pop("jwk", None)

    # After the cleanup, we should be EXACTLY where we started --
    # no leak whether `pre` was None or a real registration.
    assert _resolvers.get("jwk") is pre, (
        "jwk resolver leaked past the cleanup block; downstream "
        "test files would see this fake resolver."
    )
