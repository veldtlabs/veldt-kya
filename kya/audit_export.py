"""
Phase 5c — Signed audit-trail export.

KYA's evidence table is HMAC-chained (kya/evidence.py): each row's
`signed_hash` depends on the previous row's hash, so any tampering
breaks the chain. `verify_chain()` already validates this in-tenant.

What's missing is a way to give an EXTERNAL AUDITOR an offline
proof — something they can verify months later with only:
  - The exported document
  - A public key (which they keep separately)
  - NO live access to KYA

This module composes the existing HMAC chain with an Ed25519
signature over a fold-hash digest of the evidence range. Auditors
get a cryptographically verifiable artifact suitable for
compliance evidence packages (SR 11-7 model risk, EU AI Act Art. 11,
ISO 42001), legal discovery, or incident forensics.

Design contract
---------------
1. Caller supplies the Ed25519 SIGNING KEY (private). KYA does not
   own or rotate it — the customer's KMS / Vault / HSM owns the key
   lifecycle. This matches the substrate pattern (Postgres doesn't
   own your TLS cert; KYA doesn't own your audit key).
2. The signed digest is a CHAIN-FOLD over all `signed_hash` values
   in the range, ordered by row id. Each row's hash is mixed into
   a SHA-256 accumulator. Final digest is signed.
3. The export document carries:
     - manifest: tenant_id, time_range, row count, first/last
       row ids, KYA schema version
     - chain_digest: the SHA-256 fold-hash, hex-encoded
     - signature: Ed25519 sig over (canonical_manifest || chain_digest)
     - signed_at: ISO timestamp
     - signing_key_fingerprint: SHA-256 of the public key (for
       auditor sanity check)
     - rows (optional): the evidence rows themselves when
       include_payloads=True. Default OFF for confidentiality;
       auditors typically want PROOF of unalteredness, not raw
       prompt content.
4. `verify_signed_export()` is PURELY OFFLINE — no DB, no KYA,
   no network. Takes the export + the public key. Returns a
   verdict dict with `valid` + structured reasons for any failure.

What this is NOT
----------------
- Not a Merkle tree (overkill for typical audit-window sizes;
  fold-hash is simpler and as cryptographically sound for the
  use case of "prove this range is unaltered").
- Not a transparency log (no append-only public log; the customer
  publishes the export wherever they want).
- Not encryption — the export contents are signed, not encrypted.
  If you need confidentiality, encrypt the export separately.
- Not a chain of CUSTODY — KYA produces the export; the
  exported-to handling is the customer's process.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)


# Schema version of the export envelope. Bump when the document
# format changes in a way that breaks old verifiers.
EXPORT_SCHEMA_VERSION = 1


# ── Public errors ──────────────────────────────────────────────────


class AuditExportError(RuntimeError):
    """Base for export-time failures (signing key invalid,
    DB unreachable, no rows in range)."""


class SignatureVerificationFailed(RuntimeError):
    """Raised by verify_signed_export when the signature doesn't
    match the public key + payload. Carries `reason` for triage."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Signature verification failed: {reason}")


# ── Hash helpers ───────────────────────────────────────────────────


def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding for hashing/signing. Same shape
    used by kya.integrity.canonical_hash to keep audit chain hashes
    reproducible across Python versions."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        default=_json_fallback,
    ).encode("utf-8")


def _json_fallback(o: Any) -> Any:
    """Coerce non-JSON types (datetime, bytes) into stable strings."""
    if isinstance(o, datetime):
        if o.tzinfo is None:
            o = o.replace(tzinfo=timezone.utc)
        return o.isoformat()
    if isinstance(o, (bytes, bytearray)):
        return base64.b64encode(bytes(o)).decode("ascii")
    raise TypeError(
        f"audit_export: {type(o).__name__} not JSON-serializable")


def _chain_fold_hash(signed_hashes: list[str]) -> str:
    """Compose a single SHA-256 digest over an ordered list of
    HMAC signatures by folding each into a running accumulator.

    For row i, acc_{i+1} = SHA256(acc_i || hash_i).
    Starting acc_0 = SHA256(""). Final acc is the digest returned.

    Why fold-hash and not Merkle:
      - Fold-hash is O(N) compute and O(1) space at export time.
      - Auditor verification is also O(N) — they walk the rows the
        same way. Same complexity as Merkle without the tree
        construction overhead.
      - Merkle's advantage (proofs for individual rows without
        revealing siblings) isn't needed for the "prove this
        whole range is unaltered" use case.
    """
    acc = hashlib.sha256(b"").digest()
    for sig in signed_hashes:
        # Each row's signed_hash is hex-encoded SHA-256 already;
        # decode + fold. If it's not hex, fall back to UTF-8 bytes
        # (defensive — should never happen in production).
        try:
            row_bytes = bytes.fromhex(sig)
        except ValueError:
            row_bytes = sig.encode("utf-8")
        acc = hashlib.sha256(acc + row_bytes).digest()
    return acc.hex()


# Domain-separation marker for the signed payload. Bumped when the
# signing-payload construction changes (NOT when the export schema
# version changes). Old verifiers will fail signature verification
# on documents signed with a newer marker, which is the desired
# behavior — never silently accept across format breaks.
_SIGNING_DOMAIN_SEP = b"||kya-audit-v1||"


def _signing_payload(manifest: dict, chain_digest: str) -> bytes:
    """The exact bytes that get signed (and re-built at verify time).
    Centralized so the signing path and verify path cannot drift."""
    return (_canonical_json(manifest)
            + _SIGNING_DOMAIN_SEP
            + chain_digest.encode("ascii"))


def _public_key_fingerprint(public_key_pem: str) -> str:
    """SHA-256 of the PEM-encoded public key, truncated to 16 hex
    chars — short enough to compare visually, long enough to
    distinguish keys in practice."""
    return hashlib.sha256(
        public_key_pem.encode("utf-8")).hexdigest()[:16]


# ── Export ─────────────────────────────────────────────────────────


def signed_export(
    db, *,
    tenant_id: str,
    start: datetime,
    end: datetime,
    signing_key_pem: str,
    include_payloads: bool = False,
    invocation_id: int | None = None,
) -> dict[str, Any]:
    """Produce a signed audit export over a time-range of
    `kya_evidence` rows.

    Args
    ----
    db : SQLAlchemy session
    tenant_id : str
        Required. Scopes the export to one tenant.
    start, end : datetime
        UTC-aware datetimes bounding the export window. Half-open
        interval [start, end). Rows with `recorded_at` outside this
        range are excluded.
    signing_key_pem : str
        Ed25519 private key in PEM format. NOT stored or logged by
        KYA — used once, discarded after signing.
    include_payloads : bool
        When True, the full evidence rows (including `payload` JSON)
        are included in the export. Default False — exports the
        digest + signature only, which proves unalteredness without
        revealing prompt content.
    invocation_id : int | None
        Optional narrow scope: when set, only rows for this
        invocation. Useful for "give me the audit trail for the
        specific incident."

    Returns
    -------
    dict — the export document. Hand this dict (serialized as JSON)
    to your auditor alongside the public key file.

    Raises
    ------
    AuditExportError when no rows in range OR the signing key is
    malformed. Other DB / IO errors propagate.
    """
    if not tenant_id:
        raise AuditExportError("tenant_id is required")
    if not signing_key_pem:
        raise AuditExportError("signing_key_pem is required")
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if end <= start:
        raise AuditExportError("end must be after start")

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:
        raise AuditExportError(
            "audit_export requires the `cryptography` package. "
            "Install with `pip install veldt-kya[hardening]` or "
            "`pip install cryptography`.") from exc

    try:
        key_obj = serialization.load_pem_private_key(
            signing_key_pem.encode("utf-8"), password=None)
    except TypeError as exc:
        raise AuditExportError(
            "signing_key_pem appears to be encrypted; password-"
            "protected keys are not supported. Decrypt it before "
            "passing to signed_export()."
        ) from exc
    except Exception as exc:
        raise AuditExportError(
            f"signing_key_pem is not a valid PEM private key: {exc}"
        ) from exc
    if not isinstance(key_obj, Ed25519PrivateKey):
        raise AuditExportError(
            f"signing key must be Ed25519, got {type(key_obj).__name__}")

    # Derive the public key + fingerprint for the manifest
    public_key_pem = key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    fingerprint = _public_key_fingerprint(public_key_pem)

    from ._portable import qual_for_raw_sql
    schema_prefix = qual_for_raw_sql(db)
    # occurred_at is the event-time column — the moment the evidence
    # was generated by the agent. ingested_at is DB-write time and
    # would let an attacker who delays inserts shift rows out of an
    # auditor's window.
    sql = (f"SELECT id, invocation_id, evidence_kind, role, "
           f"       payload, signed_hash, occurred_at "
           f"FROM {schema_prefix}kya_evidence "
           f"WHERE tenant_id = :t "
           f"  AND occurred_at >= :s "
           f"  AND occurred_at < :e")
    params: dict[str, Any] = {"t": tenant_id, "s": start, "e": end}
    if invocation_id is not None:
        sql += " AND invocation_id = :inv"
        params["inv"] = invocation_id
    sql += " ORDER BY id"

    try:
        rows = db.execute(text(sql), params).fetchall()
    except Exception as exc:
        raise AuditExportError(
            f"DB query failed: {exc}") from exc

    if not rows:
        raise AuditExportError(
            f"No evidence rows in range [{start.isoformat()}, "
            f"{end.isoformat()}) for tenant={tenant_id}"
            + (f" inv={invocation_id}" if invocation_id else ""))

    signed_hashes = [r[5] for r in rows]
    chain_digest = _chain_fold_hash(signed_hashes)

    manifest: dict[str, Any] = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "range_start": _iso(start),
        "range_end": _iso(end),
        "invocation_id": invocation_id,
        "row_count": len(rows),
        "first_row_id": int(rows[0][0]),
        "last_row_id": int(rows[-1][0]),
        "first_recorded_at": _iso(rows[0][6]),
        "last_recorded_at": _iso(rows[-1][6]),
        "signing_key_fingerprint": fingerprint,
        "kya_export_lib_version": "1",
    }

    # Signature payload = canonical manifest || SEP || chain_digest.
    # The b"||kya-audit-v1||" separator provides domain separation
    # so that no adversarial choice of manifest content can ever be
    # confused with a chain_digest prefix (defense-in-depth even
    # though chain_digest is fixed-length 64 hex chars in practice).
    payload = _signing_payload(manifest, chain_digest)
    signature = key_obj.sign(payload)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    if include_payloads:
        logger.warning(
            "[KYA-AUDIT] signed_export(include_payloads=True): export "
            "contains raw payload JSON (prompt content, tool args). "
            "Ensure the recipient is authorized to see unredacted "
            "evidence rows.")

    out: dict[str, Any] = {
        "manifest": manifest,
        "chain_digest": chain_digest,
        "signature_b64": signature_b64,
        "signed_at": _iso(datetime.now(timezone.utc)),
        "public_key_pem": public_key_pem,
    }
    if include_payloads:
        out["rows"] = [{
            "id": int(r[0]),
            "invocation_id": int(r[1]) if r[1] is not None else None,
            "evidence_kind": r[2],
            "role": r[3],
            "payload": _coerce_payload(r[4]),
            "signed_hash": r[5],
            "recorded_at": _iso(r[6]),
        } for r in rows]
    return out


# ── Verification (OFFLINE — no DB, no KYA needed) ──────────────────


def verify_signed_export(
    export: dict[str, Any],
    *,
    public_key_pem: str | None = None,
    trust_embedded_key: bool = False,
) -> dict[str, Any]:
    """Verify a previously-produced export. Purely offline — needs
    only the export document and the public key.

    Args
    ----
    export : dict — the signed_export() return value (or its JSON
        round-trip).
    public_key_pem : str | None — Ed25519 public key in PEM. Auditors
        should ALWAYS supply this from their own secure storage
        (separate from the export document itself).
    trust_embedded_key : bool — when True AND public_key_pem is None,
        falls back to export["public_key_pem"]. INSECURE: an attacker
        who tampered with the export could swap both the signature
        and the embedded key, and verification would pass. Default
        False — verification will fail with an explanatory reason if
        no external key is supplied.

    Returns
    -------
    dict with keys:
        valid : bool
        reason : str (human-readable; "ok" if valid)
        manifest : dict (echoed for caller convenience)
        verified_at : ISO timestamp
        public_key_fingerprint : SHA-256[:16] of the key used
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        return {
            "valid": False,
            "reason": (f"cryptography not installed: {exc}. "
                       "pip install veldt-kya[hardening]"),
        }

    if public_key_pem:
        pem = public_key_pem
    elif trust_embedded_key:
        pem = export.get("public_key_pem")
        if not pem:
            return {
                "valid": False,
                "reason": ("trust_embedded_key=True but export "
                           "contains no public_key_pem"),
            }
        logger.warning(
            "[KYA-AUDIT] verify_signed_export(trust_embedded_key=True): "
            "verifying with the key embedded in the export — an "
            "attacker who tampered with the export could swap both "
            "the signature and the key. Supply public_key_pem from "
            "external storage for trustworthy verification.")
    else:
        return {
            "valid": False,
            "reason": ("public_key_pem not supplied; pass it from "
                       "external storage. To opt into trusting the "
                       "export's embedded key (insecure), set "
                       "trust_embedded_key=True."),
        }

    try:
        pubkey = serialization.load_pem_public_key(
            pem.encode("utf-8") if isinstance(pem, str) else pem)
    except Exception as exc:
        return {"valid": False,
                "reason": f"public key is not valid PEM: {exc}"}
    if not isinstance(pubkey, Ed25519PublicKey):
        return {
            "valid": False,
            "reason": (f"public key must be Ed25519, got "
                       f"{type(pubkey).__name__}"),
        }

    manifest = export.get("manifest")
    chain_digest = export.get("chain_digest")
    signature_b64 = export.get("signature_b64")
    if not (manifest and chain_digest and signature_b64):
        return {"valid": False,
                "reason": "export missing manifest / chain_digest / signature"}

    # Schema-version guard — refuse to verify documents from a
    # newer schema than we know how to interpret. The signature
    # would also fail (different signing payload across versions)
    # but a clear reason beats "signature does not match".
    declared_version = manifest.get("schema_version")
    if declared_version != EXPORT_SCHEMA_VERSION:
        return {
            "valid": False,
            "reason": (f"unsupported schema_version "
                       f"{declared_version!r}; this verifier supports "
                       f"{EXPORT_SCHEMA_VERSION}"),
            "manifest": manifest,
        }

    try:
        signature = base64.b64decode(signature_b64)
    except Exception as exc:
        return {"valid": False,
                "reason": f"signature_b64 decode failed: {exc}"}

    payload = _signing_payload(manifest, chain_digest)
    try:
        pubkey.verify(signature, payload)
    except InvalidSignature:
        return {"valid": False,
                "reason": "signature does not match public key + payload",
                "manifest": manifest}
    except Exception as exc:
        return {"valid": False,
                "reason": f"verify raised unexpected error: {exc}"}

    # If rows are included, recompute chain_digest and compare —
    # catches tampering with the rows array post-signing.
    if "rows" in export:
        rows = export["rows"]
        # Defense-in-depth: explicit row_count check before the
        # fold-hash check. Both catch the same class of tampering
        # but the explicit count gives a clearer triage reason.
        if len(rows) != manifest.get("row_count"):
            return {
                "valid": False,
                "reason": (f"row count mismatch: {len(rows)} rows in "
                           f"export, manifest claims "
                           f"{manifest.get('row_count')}"),
                "manifest": manifest,
            }
        computed = _chain_fold_hash([r["signed_hash"] for r in rows])
        if computed != chain_digest:
            return {
                "valid": False,
                "reason": ("chain_digest does not match the included "
                           "rows — rows were tampered with after "
                           "signing"),
                "manifest": manifest,
            }

    return {
        "valid": True,
        "reason": "ok",
        "manifest": manifest,
        "verified_at": _iso(datetime.now(timezone.utc)),
        "public_key_fingerprint": _public_key_fingerprint(
            pem if isinstance(pem, str) else pem.decode("utf-8")),
    }


# ── Helpers ────────────────────────────────────────────────────────


def _iso(dt) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _coerce_payload(p: Any) -> Any:
    """JSON column comes back as str on SQLite, dict on PG. Coerce
    to dict for inclusion in the export."""
    if isinstance(p, str):
        try:
            return json.loads(p)
        except json.JSONDecodeError:
            return {"_raw_string": p}
    return p


# ── CLI verifier (for auditors who don't write Python) ─────────────


def _cli_verify(argv: list[str]) -> int:
    """`python -m kya.audit_export verify <export.json> [--pubkey K.pem]
    [--trust-embedded]`.

    Exit codes:
      0 — export is valid (signature matches, no tampering)
      1 — export is invalid (any verify failure)
      2 — argument or file-IO error
    """
    import argparse
    parser = argparse.ArgumentParser(
        prog="kya.audit_export verify",
        description=("Verify a KYA signed audit-trail export. "
                     "Purely offline — no DB, no network."))
    parser.add_argument(
        "export_path",
        help="Path to the export JSON file produced by signed_export()")
    parser.add_argument(
        "--pubkey", dest="pubkey_path", default=None,
        help=("Path to the Ed25519 public key PEM file. STRONGLY "
              "recommended — supplying it from external storage "
              "(separate from the export) is the only trustworthy "
              "verification path."))
    parser.add_argument(
        "--trust-embedded", action="store_true",
        help=("Allow verification with the public key embedded in "
              "the export itself. INSECURE — an attacker who "
              "tampered could swap both the signature and the key."))
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress success output (exit code only).")
    args = parser.parse_args(argv)

    try:
        with open(args.export_path, encoding="utf-8") as f:
            export = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: export file not found: {args.export_path}")
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: export file is not valid JSON: {exc}")
        return 2

    pubkey_pem = None
    if args.pubkey_path:
        try:
            with open(args.pubkey_path, encoding="utf-8") as f:
                pubkey_pem = f.read()
        except FileNotFoundError:
            print(f"ERROR: pubkey file not found: {args.pubkey_path}")
            return 2

    result = verify_signed_export(
        export,
        public_key_pem=pubkey_pem,
        trust_embedded_key=args.trust_embedded)

    if result["valid"]:
        if not args.quiet:
            m = result.get("manifest") or {}
            # ASCII-only output — Windows cp1252 shells choke on
            # unicode arrows / em-dashes when stdout isn't UTF-8.
            print("VALID -- export verified")
            print(f"  tenant_id:    {m.get('tenant_id')}")
            print(f"  range:        {m.get('range_start')} -> "
                  f"{m.get('range_end')}")
            print(f"  rows:         {m.get('row_count')}")
            print(f"  key fp:       {result.get('public_key_fingerprint')}")
            print(f"  verified_at:  {result.get('verified_at')}")
        return 0
    else:
        print(f"INVALID -- {result.get('reason', 'unknown error')}")
        return 1


def _cli_main(argv: list[str] | None = None) -> int:
    import sys as _sys
    argv = list(_sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__ or "")
        print()
        print("Usage: python -m kya.audit_export <command> [args]")
        print()
        print("Commands:")
        print("  verify <export.json> [--pubkey <key.pem>] "
              "[--trust-embedded] [-q]")
        print("        Verify an audit export offline.")
        return 0 if argv else 2
    cmd = argv[0]
    rest = argv[1:]
    if cmd == "verify":
        return _cli_verify(rest)
    print(f"ERROR: unknown command {cmd!r}. Try 'verify' or '--help'.")
    return 2


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(_cli_main())
