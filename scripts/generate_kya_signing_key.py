"""Generate an Ed25519 signing keypair for the KYA inbound recommendations path.

What it does:
    • Mints a fresh Ed25519 keypair
    • Prints the base64-encoded PUBLIC key — paste into
      `app/agents/kya/_inbound_signing.py:DEFAULT_PINNED_KEYS`
    • Writes the PRIVATE key to a file you control (0600 perms on POSIX)

What you do with it:
    • PUBLIC key  → embed in the SDK source; ship to all customers
    • PRIVATE key → upload to your KMS / Vault / HSM IMMEDIATELY,
                    then delete the local file. NEVER commit it.

Usage:
    python scripts/generate_kya_signing_key.py \
        --key-id veldt-kya-2026 \
        --private-out ~/secure/veldt-kya-2026.priv

    # then upload ~/secure/veldt-kya-2026.priv to your KMS,
    # `shred -u` (or equivalent) the local file,
    # and paste the printed base64 PUBLIC key into _inbound_signing.py

Rotation:
    Run a SECOND time with a new key-id (e.g. veldt-kya-2026-next)
    BEFORE the active key expires. Embed BOTH public keys in
    DEFAULT_PINNED_KEYS for the overlap window so customers on the
    older SDK still verify the active key's signatures while their
    next-release SDK pre-trusts the new key.

Threat model:
    • This script DOES NOT phone home, write to any shared location,
      or ship the private key anywhere.
    • The private key exists ONLY in memory until you save it.
    • TLS / network / OS keylogger compromise of THIS machine while
      the script runs would compromise the key. Run on a hardened
      workstation or in a clean ephemeral container if your threat
      model demands it.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import stat
import sys
from pathlib import Path


def _mint_keypair() -> tuple[bytes, bytes]:
    """Returns (private_bytes_raw_32B, public_bytes_raw_32B)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat, PublicFormat,
        )
    except ImportError:
        print(
            "ERROR: cryptography library required. Install with:\n"
            "    pip install 'cryptography>=41'",
            file=sys.stderr,
        )
        sys.exit(1)

    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _validate_key_id(key_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id):
        print(
            f"ERROR: invalid --key-id {key_id!r}. Must match [A-Za-z0-9._-]{{1,64}}.",
            file=sys.stderr,
        )
        sys.exit(2)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--key-id", required=True,
        help='Identifier for this keypair (e.g. "veldt-kya-2026"). '
             "Becomes the `signing_key_id` field on signed envelopes.",
    )
    ap.add_argument(
        "--private-out", required=True,
        help="Where to write the raw 32-byte private key (binary). "
             "Upload to your KMS/Vault IMMEDIATELY and shred the local file.",
    )
    ap.add_argument(
        "--public-out", default=None,
        help="Optional path to ALSO write the base64-encoded public key. "
             "Default: only print to stdout.",
    )
    ap.add_argument(
        "--update-inbound-signing", default=None,
        help="Optional path to _inbound_signing.py. If passed, the script "
             "appends a new line to DEFAULT_PINNED_KEYS instead of asking "
             "you to paste it. Backs up the file first.",
    )
    args = ap.parse_args()

    _validate_key_id(args.key_id)

    priv_path = Path(args.private_out).expanduser().resolve()
    if priv_path.exists():
        print(f"ERROR: refusing to overwrite existing file {priv_path}", file=sys.stderr)
        sys.exit(3)

    priv_bytes, pub_bytes = _mint_keypair()
    pub_b64 = _b64(pub_bytes)

    # Write the private key with restrictive permissions.
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    try:
        if os.name == "posix":
            os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

    print()
    print("=" * 72)
    print(f"  KEY ID    : {args.key_id}")
    print(f"  PUBLIC    : {pub_b64}")
    print(f"  PRIVATE   : {priv_path}  ({len(priv_bytes)} bytes, raw Ed25519)")
    print("=" * 72)
    print()
    print("NEXT STEPS:")
    print(f"  1. Upload {priv_path} to your KMS/Vault NOW.")
    print(f"  2. Shred the local file: `shred -u {priv_path}` (or equivalent).")
    if args.update_inbound_signing:
        signing_path = Path(args.update_inbound_signing).resolve()
        _patch_inbound_signing(signing_path, args.key_id, pub_b64)
        print(f"  3. {signing_path} updated automatically.")
    else:
        print('  3. Paste this line into app/agents/kya/_inbound_signing.py:')
        print(f'         "{args.key_id}": "{pub_b64}",')
        print("     inside the DEFAULT_PINNED_KEYS dict.")
    print()
    print("  4. Customers also get this via:")
    print(f'         KYA_INBOUND_PUBLIC_KEY="{args.key_id}:{pub_b64}"')
    print()

    if args.public_out:
        Path(args.public_out).expanduser().resolve().write_text(
            f"{args.key_id}:{pub_b64}\n", encoding="ascii",
        )


def _patch_inbound_signing(path: Path, key_id: str, pub_b64: str) -> None:
    """Insert "{key_id}": "{pub_b64}", into DEFAULT_PINNED_KEYS = {...}.

    Backs the file up to <path>.bak before writing. Idempotent: if the
    same key_id is already there, leaves the file alone.
    """
    src = path.read_text(encoding="utf-8")
    if f'"{key_id}":' in src or f"'{key_id}':" in src:
        print(f"  NOTE: {key_id} already present in {path}, leaving as-is.")
        return
    path.with_suffix(path.suffix + ".bak").write_text(src, encoding="utf-8")
    new_entry = f'    "{key_id}": "{pub_b64}",\n'
    patched = re.sub(
        r"(DEFAULT_PINNED_KEYS:\s*dict\[str,\s*str\]\s*=\s*\{)",
        r"\1\n" + new_entry.rstrip("\n"),
        src,
        count=1,
    )
    if patched == src:
        raise SystemExit(
            f"ERROR: could not locate DEFAULT_PINNED_KEYS dict in {path}"
        )
    path.write_text(patched, encoding="utf-8")


if __name__ == "__main__":
    main()
