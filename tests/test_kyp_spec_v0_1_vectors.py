"""KYP v0.1 spec conformance — the reference implementation MUST
produce byte-identical output for every published test vector.

If you change canonicalization, signing, or the chain-linking scheme,
either:

1. The change is BACKWARDS-COMPATIBLE → these tests still pass, no
   spec bump needed.
2. The change is BREAKING → bump the spec minor (v0.1 → v0.2),
   regenerate vectors via `python scripts/generate_kyp_test_vectors.py`,
   and document the diff in `docs/specs/kyp/v0.2/CHANGES.md`.

DO NOT silently regenerate vectors to make these tests pass. The
whole point is that the spec freezes the wire format; regenerating
vectors masks an unintentional break.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kya.evidence import _canonicalize, _hmac_sign, _payload_hash

SPEC_DIR = Path(__file__).resolve().parent.parent / "docs/specs/kyp/v0.1"
CANON_DIR = SPEC_DIR / "test-vectors/canonicalization"
SIGN_DIR = SPEC_DIR / "test-vectors/signing"
CHAIN_DIR = SPEC_DIR / "test-vectors/chain"

# Same fixed key as the generator. If you change this here, regenerate
# the vectors — the signing/chain vectors are key-dependent.
TEST_KEY = bytes(range(32))


def _load_vectors(dir_: Path) -> list[tuple[str, dict]]:
    """Return [(filename, parsed_json), ...] for every .json in dir_."""
    if not dir_.exists():
        pytest.fail(f"vector dir missing: {dir_}")
    out = []
    for f in sorted(dir_.glob("*.json")):
        out.append((f.name, json.loads(f.read_text(encoding="utf-8"))))
    if not out:
        pytest.fail(f"no vectors found in {dir_}")
    return out


def _input_for_canonicalize(raw_input):
    """The vector file stores the input with `default=repr` for
    non-JSON-native values (datetimes, bytes, sets). Re-hydrate the
    couple of types we care about so the implementation sees the
    same Python objects the generator did."""
    from datetime import datetime

    if isinstance(raw_input, dict):
        return {k: _input_for_canonicalize(v) for k, v in raw_input.items()}
    if isinstance(raw_input, list):
        return [_input_for_canonicalize(v) for v in raw_input]
    if isinstance(raw_input, str):
        # ISO timestamps used by the generator end with `+00:00`. JSON
        # has no native datetime, so the vector stores ISO strings —
        # but the canonical-default wraps datetimes with __t__:
        # datetime, so passing the iso string through as a str would
        # NOT exercise the type-tag path. Re-hydrate.
        if raw_input.endswith("+00:00") and "T" in raw_input:
            try:
                return datetime.fromisoformat(raw_input)
            except Exception:
                return raw_input
        # Bytes vectors store the hex repr in the vector file. The
        # input we test is the original bytes.
        return raw_input
    return raw_input


# ── Canonicalization vectors ────────────────────────────────────────


@pytest.mark.parametrize("name,vec",
                         _load_vectors(CANON_DIR),
                         ids=lambda x: x if isinstance(x, str) else None)
def test_canonicalization_vector(name, vec):
    """Reference implementation MUST produce the vector's exact
    canonical bytes + payload_hash."""
    # Re-hydrate non-JSON-native inputs that the generator stored as
    # strings in the vector file (datetimes, bytes, sets).
    input_ = _rehydrate_input(name, vec["input"])
    canonical = _canonicalize(input_).decode("utf-8")
    assert canonical == vec["canonical"], (
        f"canonical mismatch for {name}:\n"
        f"  got:      {canonical!r}\n"
        f"  expected: {vec['canonical']!r}"
    )
    h = _payload_hash(input_)
    assert h == vec["payload_hash"], (
        f"payload_hash mismatch for {name}: got {h}, "
        f"expected {vec['payload_hash']}"
    )


def _rehydrate_input(name: str, raw: dict) -> dict:
    """Vector files store original inputs that JSON can't natively
    encode (datetime / bytes / set / uuid) as their generator-side
    fallback representation. Re-hydrate those for the specific
    vectors that need it so the canonicalizer sees the actual
    Python objects."""
    import uuid
    from datetime import datetime, timezone

    if name == "with_datetime.json":
        return {"ts": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "msg": raw["msg"]}
    if name == "with_bytes.json":
        return {"blob": b"\x00\x01\x02\xff"}
    if name == "with_set.json":
        return {"tags": {"a", "b", "c"}}
    if name == "with_uuid.json":
        return {"id": uuid.UUID(int=0xdeadbeef)}
    return raw


# ── Signing vectors ─────────────────────────────────────────────────


@pytest.mark.parametrize("name,vec",
                         _load_vectors(SIGN_DIR),
                         ids=lambda x: x if isinstance(x, str) else None)
def test_signing_vector(name, vec):
    key = bytes.fromhex(vec["key_hex"])
    signed = _hmac_sign(key, vec["prev_hash"], vec["payload_hash"])
    assert signed == vec["signed_hash"], (
        f"signed_hash mismatch for {name}: got {signed}, "
        f"expected {vec['signed_hash']}"
    )


# ── Chain vectors ───────────────────────────────────────────────────


@pytest.mark.parametrize("name,vec",
                         _load_vectors(CHAIN_DIR),
                         ids=lambda x: x if isinstance(x, str) else None)
def test_chain_vector_payload_hashes(name, vec):
    """Each record's stored payload_hash MUST equal sha256(canonicalize(payload))."""
    for i, rec in enumerate(vec["records"]):
        recomputed = _payload_hash(rec["payload"])
        assert recomputed == rec["payload_hash"], (
            f"chain {name} record {i}: payload_hash mismatch "
            f"(got {recomputed}, expected {rec['payload_hash']})"
        )


@pytest.mark.parametrize("name,vec",
                         _load_vectors(CHAIN_DIR),
                         ids=lambda x: x if isinstance(x, str) else None)
def test_chain_vector_signing(name, vec):
    """Walking the chain with the reference HMAC scheme MUST reproduce
    every stored signed_hash."""
    key = bytes.fromhex(vec["key_hex"])
    prev = ""
    for i, rec in enumerate(vec["records"]):
        expected_prev = prev
        stored_prev = rec.get("prev_hash") or ""
        assert stored_prev == expected_prev, (
            f"chain {name} record {i}: prev_hash mismatch "
            f"(stored {stored_prev!r}, expected {expected_prev!r})"
        )
        signed = _hmac_sign(key, expected_prev, rec["payload_hash"])
        assert signed == rec["signed_hash"], (
            f"chain {name} record {i}: signed_hash mismatch"
        )
        prev = signed


# ── Spec coverage guard ─────────────────────────────────────────────


def test_minimum_vector_coverage():
    """If anyone deletes vectors, fail loudly. v0.1 ships with at
    least the counts asserted here; lowering them is a spec
    weakening that needs a deliberate change."""
    assert len(list(CANON_DIR.glob("*.json"))) >= 14, (
        "canonicalization vectors deleted — v0.1 must ship at least 14"
    )
    assert len(list(SIGN_DIR.glob("*.json"))) >= 4, (
        "signing vectors deleted — v0.1 must ship at least 4"
    )
    assert len(list(CHAIN_DIR.glob("*.json"))) >= 2, (
        "chain vectors deleted — v0.1 must ship at least 2"
    )
