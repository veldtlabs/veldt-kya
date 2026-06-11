"""did:key resolver (W3C did:key 0.7 spec).

did:key is the simplest method: the public key is encoded directly into the
DID URI as multibase + multicodec. No network call, no external dependency
beyond the standard library.

Supported key types (MVP):
- Ed25519 (multicodec 0xed 0x01) — the signing key family KYA uses elsewhere.

Other key types (X25519, secp256k1, P-256) are parsed enough to identify them,
but their JWKs are not synthesized in MVP — they raise ``DIDResolutionFailed``
with a clear message. Adding them later is a small change.

Spec: https://w3c-ccg.github.io/did-method-key/
"""
from __future__ import annotations

import base64

from kya.did import DIDInvalidIdentifier, DIDResolutionFailed
from kya.did_document import DIDDocument, VerificationMethod

# Multicodec prefixes (varint-encoded). All KYA cares about today is Ed25519,
# but the parser identifies the others so the error message can be specific.
_MULTICODEC_ED25519 = b"\xed\x01"
_MULTICODEC_X25519 = b"\xec\x01"
_MULTICODEC_SECP256K1 = b"\xe7\x01"
_MULTICODEC_P256 = b"\x80\x24"

# Bitcoin base58 alphabet. No 0, O, I, l (visually ambiguous).
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {c: i for i, c in enumerate(_BASE58_ALPHABET)}


def _base58btc_decode(s: str) -> bytes:
    """Decode a Bitcoin-style base58 string to bytes.

    Self-contained (no third-party multibase dependency) — small enough that
    a few dozen lines beats an extra package.
    """
    if not s:
        return b""
    num = 0
    for ch in s:
        if ch not in _BASE58_INDEX:
            raise DIDInvalidIdentifier(f"invalid base58 character: {ch!r}")
        num = num * 58 + _BASE58_INDEX[ch]
    # Each leading "1" represents a leading zero byte.
    leading_zeros = 0
    for ch in s:
        if ch == "1":
            leading_zeros += 1
        else:
            break
    out = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * leading_zeros + out


def _b64url_no_pad(data: bytes) -> str:
    """Base64url-encode with no padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def resolve(suffix: str) -> DIDDocument:
    """Resolve ``did:key:<suffix>`` to its DID document.

    Args:
        suffix: The part after ``did:key:`` — must start with ``z`` (base58btc
            multibase prefix per the spec).

    Returns:
        DIDDocument with one verification method whose ``public_key_jwk`` is
        the JWK form of the encoded key.

    Raises:
        DIDInvalidIdentifier: Suffix is malformed.
        DIDResolutionFailed: Key type is recognized but unsupported in MVP.
    """
    if not suffix.startswith("z"):
        raise DIDInvalidIdentifier(
            f"did:key suffix must start with 'z' (base58btc multibase), got {suffix[:8]!r}"
        )
    raw = _base58btc_decode(suffix[1:])
    if len(raw) < 3:
        raise DIDInvalidIdentifier("did:key payload is too short to contain a key")

    prefix = bytes(raw[:2])

    if prefix == _MULTICODEC_ED25519:
        pubkey = raw[2:]
        if len(pubkey) != 32:
            raise DIDInvalidIdentifier(
                f"Ed25519 key must be 32 bytes, got {len(pubkey)}"
            )
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_no_pad(pubkey),
        }
        did_id = f"did:key:{suffix}"
        vm_id = f"{did_id}#{suffix}"
        vm = VerificationMethod(
            id=vm_id,
            type="Ed25519VerificationKey2020",
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

    # Recognized but not yet implemented — give the operator a clear next step.
    if prefix == _MULTICODEC_X25519:
        raise DIDResolutionFailed(
            "did:key X25519 keys are recognized but not implemented in this MVP. "
            "Open an issue if you need them."
        )
    if prefix == _MULTICODEC_SECP256K1:
        raise DIDResolutionFailed(
            "did:key secp256k1 keys are recognized but not implemented in this MVP. "
            "Decompressing the EC point requires the cryptography library and is "
            "scheduled for a follow-up release."
        )
    if prefix == _MULTICODEC_P256:
        raise DIDResolutionFailed(
            "did:key P-256 keys are recognized but not implemented in this MVP."
        )

    raise DIDInvalidIdentifier(
        f"unknown multicodec prefix {prefix.hex()!r}. "
        f"Supported: Ed25519 (0xed01). Recognized-but-unimplemented: "
        f"X25519, secp256k1, P-256."
    )
