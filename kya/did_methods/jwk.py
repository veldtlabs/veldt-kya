"""did:jwk resolver (W3C did:jwk 0.1 spec).

did:jwk encodes a single JWK directly into the identifier as base64url.
Resolution is fully offline: decode the suffix, validate the JWK shape,
synthesize the DID document.

Format:
    did:jwk:<base64url-no-padding(json-canonical-jwk)>

Spec: https://github.com/quartzjer/did-jwk/blob/main/spec.md
"""
from __future__ import annotations

import base64
import binascii
import json

from kya.did import DIDInvalidIdentifier
from kya.did_document import DIDDocument, VerificationMethod


def _b64url_decode_no_pad(s: str) -> bytes:
    """Decode base64url with implicit padding restoration."""
    padding = (-len(s)) % 4
    try:
        return base64.urlsafe_b64decode(s + "=" * padding)
    except (binascii.Error, ValueError) as exc:
        raise DIDInvalidIdentifier(f"invalid base64url in did:jwk suffix: {exc}") from exc


def resolve(suffix: str) -> DIDDocument:
    """Resolve ``did:jwk:<suffix>`` by decoding the embedded JWK.

    The JWK's ``kty`` field determines the verification method type. KYA
    recognizes ``OKP`` (Ed25519, X25519), ``EC`` (P-256, secp256k1), and
    ``RSA``, but only synthesizes a usable VerificationMethod when the key
    is well-formed JSON. Downstream signature verification chooses the
    algorithm based on the JWK fields.
    """
    try:
        raw = _b64url_decode_no_pad(suffix)
    except DIDInvalidIdentifier:
        raise

    try:
        jwk = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DIDInvalidIdentifier(
            f"did:jwk payload is not valid JSON: {exc}"
        ) from exc

    if not isinstance(jwk, dict):
        raise DIDInvalidIdentifier("did:jwk payload must be a JSON object")
    if "kty" not in jwk:
        raise DIDInvalidIdentifier("did:jwk payload missing required 'kty' field")

    did_id = f"did:jwk:{suffix}"
    vm_id = f"{did_id}#0"

    # The spec maps kty to a JsonWebKey2020 verification method type.
    vm = VerificationMethod(
        id=vm_id,
        type="JsonWebKey2020",
        controller=did_id,
        public_key_jwk=jwk,
    )

    raw_doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did_id,
        "verificationMethod": [
            {
                "id": vm.id,
                "type": vm.type,
                "controller": vm.controller,
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [vm.id],
        "assertionMethod": [vm.id],
    }

    return DIDDocument(
        id=did_id,
        verification_methods=[vm],
        authentication=[vm.id],
        assertion_method=[vm.id],
        raw=raw_doc,
    )
