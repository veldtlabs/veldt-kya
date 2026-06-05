"""Generate KYP v0.1 test vectors from the reference implementation.

Run once to regenerate every vector in docs/specs/kyp/v0.1/test-vectors/
when the wire format or signing scheme changes intentionally. The
generated vectors are the normative authority for any non-Python
implementation of KYP v0.1.

Usage::

    python scripts/generate_kyp_test_vectors.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from kya.evidence import _canonicalize, _hmac_sign, _payload_hash

SPEC_DIR = Path(__file__).resolve().parent.parent / "docs/specs/kyp/v0.1"
CANON_DIR = SPEC_DIR / "test-vectors/canonicalization"
SIGN_DIR = SPEC_DIR / "test-vectors/signing"
CHAIN_DIR = SPEC_DIR / "test-vectors/chain"

for d in (CANON_DIR, SIGN_DIR, CHAIN_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Fixed key for reproducible signing vectors. 32 bytes.
TEST_KEY = bytes(range(32))


def _emit_canon_vector(name: str, payload: dict) -> dict:
    """Generate one canonicalization vector and return the chain entry."""
    canonical_bytes = _canonicalize(payload)
    canonical_str = canonical_bytes.decode("utf-8")
    h = hashlib.sha256(canonical_bytes).hexdigest()
    vector = {
        "name": name,
        "input": payload,
        "canonical": canonical_str,
        "payload_hash": h,
    }
    out = CANON_DIR / f"{name}.json"
    out.write_text(
        json.dumps(vector, indent=2, default=_canon_default_repr),
        encoding="utf-8",
    )
    print(f"canon: {out.relative_to(SPEC_DIR.parent.parent)}  hash={h[:12]}…")
    return vector


def _canon_default_repr(o):
    """JSON-encoder fallback for the vector file itself (different from
    the spec's canonical-default — this is just so we can write the
    vector file with the original input values readable)."""
    if hasattr(o, "isoformat"):
        return o.isoformat()
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    if isinstance(o, set):
        return sorted(o, key=repr)
    return repr(o)


def _emit_sign_vector(name: str, prev_hash: str, payload_hash: str) -> dict:
    signed = _hmac_sign(TEST_KEY, prev_hash, payload_hash)
    vector = {
        "name": name,
        "key_hex": TEST_KEY.hex(),
        "prev_hash": prev_hash,
        "payload_hash": payload_hash,
        "message_bytes_utf8": f"{prev_hash}|{payload_hash}",
        "signed_hash": signed,
    }
    out = SIGN_DIR / f"{name}.json"
    out.write_text(json.dumps(vector, indent=2), encoding="utf-8")
    print(f"sign:  {out.relative_to(SPEC_DIR.parent.parent)}  sig={signed[:12]}…")
    return vector


def _emit_chain_vector(name: str, payloads: list[dict]) -> dict:
    """Build a full chain of N records and emit the expected hashes."""
    records = []
    prev = ""
    for i, payload in enumerate(payloads):
        ph = _payload_hash(payload)
        sh = _hmac_sign(TEST_KEY, prev, ph)
        records.append({
            "invocation_id": 1,
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "evidence_kind": "system_message",
            "payload": payload,
            "payload_hash": ph,
            "prev_hash": prev or None,
            "signed_hash": sh,
            "signing_key_id": "test-v1",
        })
        prev = sh
    vector = {
        "name": name,
        "key_hex": TEST_KEY.hex(),
        "records": records,
        "expected_verification": {"valid": True, "broken_at": None,
                                   "checked": len(records)},
    }
    out = CHAIN_DIR / f"{name}.json"
    out.write_text(json.dumps(vector, indent=2), encoding="utf-8")
    print(f"chain: {out.relative_to(SPEC_DIR.parent.parent)}  N={len(records)}")
    return vector


# ── Canonicalization vectors ─────────────────────────────────────────


_emit_canon_vector("empty", {})
_emit_canon_vector("flat_strings", {"a": "hello", "b": "world"})
_emit_canon_vector("key_order_independent", {"b": 1, "a": 2, "c": 3})
_emit_canon_vector("nested", {
    "outer": {"inner_b": 2, "inner_a": 1},
    "top_a": "x",
})
_emit_canon_vector("with_datetime", {
    "ts": datetime(2026, 1, 1, tzinfo=timezone.utc),
    "msg": "hello",
})
_emit_canon_vector("uuid_as_string", {
    "id": str(uuid.UUID(int=0xdeadbeef)),
})
_emit_canon_vector("with_uuid", {"id": uuid.UUID(int=0xdeadbeef)})
_emit_canon_vector("with_bytes", {"blob": b"\x00\x01\x02\xff"})
_emit_canon_vector("null_value", {"a": None, "b": "x"})
_emit_canon_vector("empty_string", {"empty": "", "non_empty": "x"})
_emit_canon_vector("large_int", {"max_int64": 2**63 - 1, "min_int64": -(2**63)})
_emit_canon_vector("with_set", {"tags": {"b", "a", "c"}})
_emit_canon_vector("with_nested_list", {
    "items": [{"z": 1, "a": 2}, {"a": 3, "b": 4}],
})
_emit_canon_vector("numbers", {"int": 42, "float": 3.14, "neg": -1, "zero": 0})
_emit_canon_vector("unicode", {"greeting": "héllo wörld", "emoji": "rocket"})


# ── Signing vectors ──────────────────────────────────────────────────


_emit_sign_vector(
    "first_record",
    prev_hash="",
    payload_hash="0" * 64,
)
_emit_sign_vector(
    "first_record_real_payload",
    prev_hash="",
    payload_hash=_payload_hash({"content": "hello"}),
)
_emit_sign_vector(
    "follow_up_record",
    prev_hash="a" * 64,
    payload_hash="b" * 64,
)
_emit_sign_vector(
    "real_chain_link",
    prev_hash=_hmac_sign(TEST_KEY, "", _payload_hash({"content": "first"})),
    payload_hash=_payload_hash({"content": "second"}),
)


# ── Chain vectors ────────────────────────────────────────────────────


_emit_chain_vector("single_record", [
    {"content": "only record"},
])
_emit_chain_vector("three_record_chain", [
    {"content": "first"},
    {"content": "second"},
    {"content": "third"},
])
_emit_chain_vector("mixed_payload_shapes", [
    {"content": "prompt text"},
    {"tool_name": "search", "args": {"query": "x"}},
    {"judge_name": "openai_judge", "verdict": "OK"},
])


print()
print("Done.")
