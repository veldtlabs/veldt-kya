"""Ed25519 signature verification for inbound recommendations.

Threat model in `sdk/docs/inbound.md`. Defense in depth above TLS:

  • Recommendations are signed by Veldt's signing key (held separately
    from any TLS cert; cold-storage friendly; KMS/Vault rotatable).
  • SDK ships with a default *trust anchor* — one or more pinned
    public keys keyed by `signing_key_id`.
  • Customers may override the trust anchor via the
    `KYA_INBOUND_PUBLIC_KEY` env var so air-gapped + sovereign-cloud
    deployments can pin their own gateway key.
  • If a recommendation is signed with a key the SDK does NOT trust,
    OR is unsigned, OR fails verification, it is REJECTED and never
    persisted.

Canonicalization for signature scope:
  • Serialize the message dict with sorted keys, no extra whitespace,
    UTF-8.
  • The `signature` field itself is REMOVED before hashing.
  • The resulting bytes are what we sign / verify.

Env-var override format:
  KYA_INBOUND_PUBLIC_KEY = "<keyid>:<base64-32B-pubkey>[,<keyid>:<base64>...]"

  The comma separator allows pinning multiple trust anchors (current +
  next-quarter) so key rotation is invisible to customers who pin.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any, Mapping

logger = logging.getLogger(__name__)


class SignatureVerificationError(Exception):
    """Raised when a recommendation envelope fails signature verification."""


# Default trust anchor — ships with the SDK. Empty by default so the
# SDK never *silently* trusts a key. Set this to the Veldt public key
# when publishing an official release. Format identical to env-var
# override.
DEFAULT_PINNED_KEYS: dict[str, str] = {
    # "veldt-kya-2026-q2": "BASE64_32B_PUBKEY_HERE",
}


def _load_env_keys() -> dict[str, str]:
    raw = os.environ.get("KYA_INBOUND_PUBLIC_KEY", "").strip()
    if not raw:
        return {}
    out: dict[str, str] = {}
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        kid, b64 = chunk.split(":", 1)
        out[kid.strip()] = b64.strip()
    return out


def trusted_keys() -> dict[str, str]:
    """Effective trust anchor map: env overrides default pinned keys."""
    merged = dict(DEFAULT_PINNED_KEYS)
    merged.update(_load_env_keys())  # env wins
    return merged


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON for signing/verifying.

    Stable across Python versions and platforms: sorted keys, no
    whitespace, ensure_ascii so non-ASCII can't sneak in via raw
    UTF-8 differences in upstream encoders.
    """
    stripped = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def verify_envelope(envelope: Mapping[str, Any]) -> None:
    """Raises SignatureVerificationError if the envelope is not signed
    by one of the pinned trust anchors.

    Expected envelope shape:
        {
          "v": 1, "kind": "...", "signing_key_id": "veldt-kya-...",
          ..., "signature": "ed25519:<base64>"
        }
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise SignatureVerificationError(
            "cryptography library required: pip install 'veldt-kya[inbound]'"
        ) from exc

    if not isinstance(envelope, Mapping):
        raise SignatureVerificationError("envelope is not a mapping")

    signing_key_id = envelope.get("signing_key_id")
    signature_field = envelope.get("signature")
    if not signing_key_id or not signature_field:
        raise SignatureVerificationError("envelope missing signing_key_id or signature")

    if not isinstance(signature_field, str) or not signature_field.startswith("ed25519:"):
        raise SignatureVerificationError("only ed25519 signatures supported")
    sig_b64 = signature_field[len("ed25519:"):]
    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except Exception as exc:
        raise SignatureVerificationError("signature not valid base64") from exc

    keys = trusted_keys()
    pinned_b64 = keys.get(signing_key_id)
    if not pinned_b64:
        raise SignatureVerificationError(
            f"signing_key_id '{signing_key_id}' is not a trusted anchor "
            f"(known: {sorted(keys.keys()) or 'none — set KYA_INBOUND_PUBLIC_KEY'})"
        )
    try:
        pinned_bytes = base64.b64decode(pinned_b64, validate=True)
    except Exception as exc:
        raise SignatureVerificationError(
            f"pinned key for '{signing_key_id}' is not valid base64"
        ) from exc
    if len(pinned_bytes) != 32:
        raise SignatureVerificationError(
            f"pinned key for '{signing_key_id}' is not 32 bytes (Ed25519)"
        )

    try:
        pubkey = Ed25519PublicKey.from_public_bytes(pinned_bytes)
        pubkey.verify(sig_bytes, canonical_bytes(envelope))
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            f"signature does not match canonical payload "
            f"(key_id={signing_key_id})"
        ) from exc
    except Exception as exc:
        raise SignatureVerificationError(f"verify failed: {exc}") from exc
