"""Tests for kya.external_id.bind_did_principal — DID-rooted principal binding.

Covers B5 (sanitize + size-cap VC claims + atomic write) and B6 (reject VC
with no sub or sub != requested DID).
"""
from __future__ import annotations

import base64
import json
import os
import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import jwt as pyjwt

from kya import init_storage, record_principal_signal
from kya.external_id import bind_did_principal
from kya.vc import VCError, VCMalformed, VCSignatureInvalid


TENANT = "00000000-0000-0000-0000-0000000000dd"


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_json(value) -> dict:
    """SQLite stores JSON columns as TEXT via raw text()."""
    if value is None:
        return {}
    if isinstance(value, str):
        return json.loads(value)
    return value


@pytest.fixture(autouse=True)
def stub_did_web():
    """Stub did:web resolution to a synthetic doc so tests stay offline.

    The bind_did_principal flow calls resolve_did(did) for the target DID
    even when a VC is also presented. Test DIDs like did:web:victim.example
    don't have real DNS; we return a minimal valid doc whose id matches.
    """
    from kya.did import register_did_method, _resolvers
    from kya.did_document import DIDDocument, VerificationMethod

    saved = _resolvers.get("web")

    def fake_web_resolver(suffix: str) -> DIDDocument:
        did_uri = f"did:web:{suffix}"
        return DIDDocument(
            id=did_uri,
            verification_methods=[
                VerificationMethod(
                    id=f"{did_uri}#k1",
                    type="JsonWebKey2020",
                    controller=did_uri,
                    public_key_jwk={"kty": "OKP", "crv": "Ed25519",
                                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                )
            ],
            authentication=[f"{did_uri}#k1"],
            assertion_method=[f"{did_uri}#k1"],
            raw={"id": did_uri},
        )

    register_did_method("web", fake_web_resolver)
    yield
    if saved is not None:
        register_did_method("web", saved)


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


@pytest.fixture
def issuer():
    """An Ed25519 did:jwk issuer the tests can sign VCs with."""
    sk = Ed25519PrivateKey.generate()
    pk_raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url_no_pad(pk_raw)}
    suffix = _b64url_no_pad(json.dumps(jwk).encode("utf-8"))
    issuer_did = f"did:jwk:{suffix}"
    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {"did": issuer_did, "sk_pem": sk_pem}


def _seed_principal(db, principal_id: str = "planner"):
    """Create the kya_principal_trust row so bind_did_principal can find it."""
    record_principal_signal(
        db,
        tenant_id=TENANT,
        principal_kind="agent",
        principal_id=principal_id,
        signal_kind="clean",
    )
    db.commit()


def _make_vc(issuer: dict, *, sub: str | None, extra_top: dict | None = None,
             extra_vc: dict | None = None) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer["did"],
        "iat": now,
        "exp": now + 3600,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "AgentAuthorityCredential"],
            "credentialSubject": {"role": "planner"},
        },
    }
    if sub is not None:
        claims["sub"] = sub
        claims["vc"]["credentialSubject"]["id"] = sub
    if extra_top:
        claims.update(extra_top)
    if extra_vc:
        claims["vc"].update(extra_vc)
    return pyjwt.encode(claims, issuer["sk_pem"], algorithm="EdDSA")


# ─── B6: a VC with NO `sub` must not bind any DID ────────────────────


def test_bind_did_rejects_vc_without_sub(db, issuer):
    """A trusted issuer's VC with no `sub` claim must NOT bind to any DID.

    Without this guard, an issuer in KYA_DID_TRUSTED_ISSUERS that emits
    sub-less VCs (policy attestations) becomes a universal binding token.
    """
    _seed_principal(db)
    vc = _make_vc(issuer, sub=None)  # no subject

    with pytest.raises((VCError, VCMalformed, VCSignatureInvalid, ValueError)):
        bind_did_principal(
            db, tenant_id=TENANT,
            principal_kind="agent", principal_id="planner",
            did="did:web:any-target.example",
            vc=vc,
            trusted_issuers={issuer["did"]},
        )


def test_bind_did_rejects_vc_sub_mismatch(db, issuer):
    """VC.sub must equal the `did` argument — otherwise it's a wrong-subject VC."""
    _seed_principal(db)
    vc = _make_vc(issuer, sub="did:web:bob.example")

    with pytest.raises((VCError, VCMalformed)):
        bind_did_principal(
            db, tenant_id=TENANT,
            principal_kind="agent", principal_id="planner",
            did="did:web:alice.example",  # ≠ vc.sub
            vc=vc,
            trusted_issuers={issuer["did"]},
        )


# ─── B5: VC claims sanitization — strip non-allowlisted top-level fields ──


def test_smuggled_top_level_claim_stripped(db, issuer):
    """An issuer that includes extra top-level claims must not have them
    persisted onto principal.attributes.did_vc_claims.

    Attack: trusted issuer (or compromised one) signs a VC with
    {"kya_override": {"trust_score": 1.0}}. Downstream policy that reads
    attributes.did_vc_claims must not see this claim.
    """
    _seed_principal(db)
    sub_did = "did:web:victim.example"
    vc = _make_vc(
        issuer,
        sub=sub_did,
        extra_top={"kya_override": {"trust_score": 1.0}, "shell_cmd": "rm -rf /"},
    )
    bound = bind_did_principal(
        db, tenant_id=TENANT,
        principal_kind="agent", principal_id="planner",
        did=sub_did, vc=vc,
        trusted_issuers={issuer["did"]},
    )
    assert bound is True

    row = db.execute(text(
        "SELECT attributes FROM kya_principal_trust "
        "WHERE tenant_id=:t AND principal_id=:p"
    ), {"t": TENANT, "p": "planner"}).first()
    attrs = _load_json(row[0])
    stored = attrs.get("did_vc_claims", {})
    # Standard claims should be preserved
    assert stored.get("iss") == issuer["did"]
    assert stored.get("sub") == sub_did
    # Smuggled claims must be stripped
    assert "kya_override" not in stored, "Smuggled top-level claim leaked"
    assert "shell_cmd" not in stored, "Smuggled top-level claim leaked"


def test_smuggled_vc_field_stripped(db, issuer):
    """An issuer that includes extra fields under `vc.*` must have them stripped.

    Spec-allowed vc.* fields are an enumerated set; everything else is dropped.
    """
    _seed_principal(db)
    sub_did = "did:web:victim.example"
    vc = _make_vc(
        issuer,
        sub=sub_did,
        extra_vc={"kya_internal_override": True, "scopes": ["*"]},
    )
    bind_did_principal(
        db, tenant_id=TENANT,
        principal_kind="agent", principal_id="planner",
        did=sub_did, vc=vc,
        trusted_issuers={issuer["did"]},
    )

    row = db.execute(text(
        "SELECT attributes FROM kya_principal_trust "
        "WHERE tenant_id=:t AND principal_id=:p"
    ), {"t": TENANT, "p": "planner"}).first()
    stored_vc = _load_json(row[0]).get("did_vc_claims", {}).get("vc", {})
    assert "kya_internal_override" not in stored_vc
    assert "scopes" not in stored_vc
    # Spec-allowed fields preserved
    assert stored_vc.get("type") == ["VerifiableCredential", "AgentAuthorityCredential"]


def test_oversized_vc_claims_rejected(db, issuer):
    """A VC whose claims would serialize to > 8 KB must be rejected before bind."""
    _seed_principal(db)
    sub_did = "did:web:victim.example"
    # 20 KB payload smuggled inside credentialSubject
    huge = "x" * 20_000
    vc = _make_vc(
        issuer,
        sub=sub_did,
        extra_vc={"credentialSubject": {"id": sub_did, "blob": huge}},
    )
    with pytest.raises((VCError, ValueError)):
        bind_did_principal(
            db, tenant_id=TENANT,
            principal_kind="agent", principal_id="planner",
            did=sub_did, vc=vc,
            trusted_issuers={issuer["did"]},
        )


# ─── B5 (atomicity): bind + attribute write must be one transaction ────


def test_bind_did_happy_path_records_claims_and_idp(db, issuer):
    """Bind succeeds → both the IdP fields AND the did_vc_claims row exist."""
    _seed_principal(db)
    sub_did = "did:web:agent42.example"
    vc = _make_vc(issuer, sub=sub_did)
    assert bind_did_principal(
        db, tenant_id=TENANT,
        principal_kind="agent", principal_id="planner",
        did=sub_did, vc=vc,
        trusted_issuers={issuer["did"]},
    ) is True

    row = db.execute(text(
        "SELECT idp_kind, idp_subject, idp_issuer, attributes "
        "FROM kya_principal_trust "
        "WHERE tenant_id=:t AND principal_id=:p"
    ), {"t": TENANT, "p": "planner"}).first()
    assert row[0] == "did"
    assert row[1] == sub_did
    assert row[2] == issuer["did"]
    attrs = _load_json(row[3])
    assert attrs.get("did_vc_claims", {}).get("iss") == issuer["did"]


def test_bind_did_no_vc_still_records_idp(db, issuer):
    """Binding without a VC works — DID itself is the credential."""
    _seed_principal(db)
    assert bind_did_principal(
        db, tenant_id=TENANT,
        principal_kind="agent", principal_id="planner",
        did="did:jwk:" + _b64url_no_pad(
            json.dumps({"kty": "OKP", "crv": "Ed25519",
                        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
                       ).encode("utf-8")
        ),
    ) is True
