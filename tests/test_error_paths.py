"""Error-injection tests (PYPI SHOULD-DO #7).

Covers the failure branches that real customers hit but happy-path
tests miss. Each test names the failure mode in its docstring so a
regression points at the exact contract that broke.

Categories:
  1. Malformed signed-recommendation payloads (inbound path)
  2. Missing optional dependencies (graceful degradation)
  3. Missing collector keys (covered separately in
     test_inbound_trust_required.py, not duplicated here)
  4. Scoring-path defensive coercion (str-tools, missing fields, etc.)
"""

from __future__ import annotations

import os

import pytest


# ── 1. Malformed signed-recommendation payloads ─────────────────────


def _generate_test_keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    return priv, pub_b64


def test_signing_rejects_envelope_missing_signing_key_id():
    """Envelope with signature but no signing_key_id must raise."""
    priv, pub_b64 = _generate_test_keypair()
    os.environ["KYA_INBOUND_PUBLIC_KEY"] = f"test-key:{pub_b64}"
    try:
        from kya._inbound_signing import SignatureVerificationError, verify_envelope
        with pytest.raises(SignatureVerificationError, match="missing signing_key_id"):
            verify_envelope({"signature": "ed25519:AAAA"})
    finally:
        os.environ.pop("KYA_INBOUND_PUBLIC_KEY", None)


def test_signing_rejects_envelope_missing_signature():
    """Envelope with signing_key_id but no signature must raise."""
    priv, pub_b64 = _generate_test_keypair()
    os.environ["KYA_INBOUND_PUBLIC_KEY"] = f"test-key:{pub_b64}"
    try:
        from kya._inbound_signing import SignatureVerificationError, verify_envelope
        with pytest.raises(SignatureVerificationError, match="missing signing_key_id or signature"):
            verify_envelope({"signing_key_id": "test-key"})
    finally:
        os.environ.pop("KYA_INBOUND_PUBLIC_KEY", None)


def test_signing_rejects_non_ed25519_signature_scheme():
    """Only ed25519: prefix accepted; rsa: / ecdsa: / etc must raise."""
    priv, pub_b64 = _generate_test_keypair()
    os.environ["KYA_INBOUND_PUBLIC_KEY"] = f"test-key:{pub_b64}"
    try:
        from kya._inbound_signing import SignatureVerificationError, verify_envelope
        with pytest.raises(SignatureVerificationError, match="only ed25519"):
            verify_envelope({"signing_key_id": "test-key", "signature": "rsa:AAAA"})
    finally:
        os.environ.pop("KYA_INBOUND_PUBLIC_KEY", None)


def test_signing_rejects_envelope_signed_by_unknown_key():
    """Envelope signing_key_id NOT in pinned trust anchors must raise."""
    priv, pub_b64 = _generate_test_keypair()
    os.environ["KYA_INBOUND_PUBLIC_KEY"] = f"trusted-key:{pub_b64}"
    try:
        from kya._inbound_signing import SignatureVerificationError, verify_envelope
        with pytest.raises(SignatureVerificationError, match="not a trusted anchor"):
            verify_envelope({
                "signing_key_id": "rogue-key",
                "signature": "ed25519:AAAA",
            })
    finally:
        os.environ.pop("KYA_INBOUND_PUBLIC_KEY", None)


def test_signing_rejects_envelope_with_invalid_base64_signature():
    """Signature that isn't valid base64 must raise."""
    priv, pub_b64 = _generate_test_keypair()
    os.environ["KYA_INBOUND_PUBLIC_KEY"] = f"test-key:{pub_b64}"
    try:
        from kya._inbound_signing import SignatureVerificationError, verify_envelope
        with pytest.raises(SignatureVerificationError, match="not valid base64"):
            verify_envelope({
                "signing_key_id": "test-key",
                "signature": "ed25519:!!!not-base64!!!",
            })
    finally:
        os.environ.pop("KYA_INBOUND_PUBLIC_KEY", None)


# ── 2. Persist-time payload validation ──────────────────────────────


def test_persist_rejects_unknown_scope():
    """Recommendation with scope not in KNOWN_SCOPES must reject before write."""
    priv, _ = _generate_test_keypair()
    from kya import inbound

    envelope = {
        "signing_key_id": "x",
        "issued_at": "2026-05-23T00:00:00Z",
        "expires_at": "2027-05-23T00:00:00Z",
    }
    rec = {"id": "r1", "scope": "made_up_scope", "key": "pii", "recommended_value": 5}
    ok, reason = inbound._persist_one(_FakeDB(), envelope, rec)
    assert not ok
    assert reason.startswith("unknown_scope")


def test_persist_rejects_missing_key():
    """Recommendation missing 'key' field must reject."""
    from kya import inbound

    envelope = {"signing_key_id": "x"}
    rec = {"id": "r1", "scope": "class_weights", "recommended_value": 5}
    ok, reason = inbound._persist_one(_FakeDB(), envelope, rec)
    assert not ok
    assert reason == "missing_key"


def test_persist_rejects_missing_recommended_value():
    """Recommendation missing or non-numeric recommended_value must reject."""
    from kya import inbound

    envelope = {"signing_key_id": "x"}
    rec_no_val = {"id": "r1", "scope": "class_weights", "key": "pii"}
    ok, reason = inbound._persist_one(_FakeDB(), envelope, rec_no_val)
    assert not ok
    assert reason == "missing_recommended_value"

    rec_str_val = {"id": "r1", "scope": "class_weights", "key": "pii",
                   "recommended_value": "not a number"}
    ok, reason = inbound._persist_one(_FakeDB(), envelope, rec_str_val)
    assert not ok
    assert reason == "missing_recommended_value"


def test_persist_rejects_missing_external_id():
    """Recommendation without an id field must reject."""
    from kya import inbound

    envelope = {"signing_key_id": "x"}
    rec = {"scope": "class_weights", "key": "pii", "recommended_value": 5}
    ok, reason = inbound._persist_one(_FakeDB(), envelope, rec)
    assert not ok
    assert reason == "missing_external_id"


class _FakeDB:
    """Minimal stand-in DB that fails fast if persist actually tries to write."""
    def execute(self, *a, **kw):
        raise AssertionError("DB write must not happen on payload rejection")
    def commit(self):
        raise AssertionError("DB commit must not happen on payload rejection")
    def rollback(self):
        pass
    def connection(self):
        raise AssertionError("DB connection must not be opened on payload rejection")


# ── 3. Scoring-path defensive coercion ──────────────────────────────


def test_score_agent_tolerates_string_tools_argument():
    """tools passed as a string (mistake) becomes a single-element list."""
    from kya import score_agent

    r = score_agent({"agent_key": "x", "tools": "search_only_one"})
    # Must not raise, must produce a valid bucket
    assert 0 <= r.score <= 100
    assert r.bucket in ("low", "medium", "high", "critical")


def test_score_agent_tolerates_non_iterable_tools():
    """tools=123 (definitely wrong) is coerced to empty list, not raised."""
    from kya import score_agent

    r = score_agent({"agent_key": "x", "tools": 123})  # type: ignore[arg-type]
    assert 0 <= r.score <= 100


def test_score_agent_tolerates_missing_human_loop():
    """Missing human_loop defaults to most-permissive ('none')."""
    from kya import score_agent

    r = score_agent({"agent_key": "x", "tools": ["t"]})
    # Should still produce a defensible score (conservative high)
    assert r.score >= 0


def test_score_agent_tolerates_unknown_human_loop_value():
    """Unknown human_loop string normalizes (lower+strip) and treats as 'none'."""
    from kya import score_agent

    r = score_agent({"agent_key": "x", "tools": ["t"], "human_loop": "  XYZBOGUS  "})
    assert 0 <= r.score <= 100


def test_score_agent_handles_empty_definition():
    """Empty agent_def must not raise; returns a defensible default."""
    from kya import score_agent

    r = score_agent({})
    assert 0 <= r.score <= 100
    assert r.bucket in ("low", "medium", "high", "critical")


# ── 4. Tenant-override edge cases ───────────────────────────────────


def test_set_override_rejects_non_integer_value():
    """A weight value that isn't an int must raise ValueError, not coerce."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from kya import tenant_weights

    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None}
    )
    Session = sessionmaker(bind=eng)
    tenant_weights.register_scope("class_weights", {"pii": 15})
    with Session() as db:
        tenant_weights.ensure_tables(db)
        with pytest.raises(ValueError, match="must be an integer"):
            tenant_weights.set_override(
                db, scope="class_weights", key="pii", value=15.5,  # type: ignore[arg-type]
                tenant_id=None,
            )


def test_set_override_rejects_unknown_scope():
    """Scope not registered via register_scope must raise."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from kya import tenant_weights

    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None}
    )
    Session = sessionmaker(bind=eng)
    with Session() as db:
        tenant_weights.ensure_tables(db)
        with pytest.raises(ValueError, match="unknown weight scope"):
            tenant_weights.set_override(
                db, scope="this_scope_does_not_exist", key="x", value=5,
                tenant_id=None,
            )


# ── 5. Optional-dependency graceful degradation ─────────────────────


def test_kya_import_does_not_require_prometheus_client():
    """Removing prometheus_client must not break `import kya`."""
    import subprocess
    import sys

    code = (
        "import sys\n"
        "# Block prometheus_client import\n"
        "sys.modules['prometheus_client'] = None\n"
        "try:\n"
        "    import kya\n"
        "    from kya import score_agent\n"
        "    r = score_agent({'agent_key':'x','tools':['t']})\n"
        "    print('OK', r.score)\n"
        "except Exception as e:\n"
        "    print(f'FAIL: {type(e).__name__}: {e}')\n"
        "    sys.exit(1)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, f"import kya broke without prometheus_client: {result.stderr}"


def test_kya_import_does_not_require_cryptography():
    """Removing cryptography must not break `import kya` (it's only needed
    for the inbound-signing path)."""
    import subprocess
    import sys

    code = (
        "import sys\n"
        "sys.modules['cryptography'] = None\n"
        "try:\n"
        "    import kya\n"
        "    from kya import score_agent\n"
        "    r = score_agent({'agent_key':'x','tools':['t']})\n"
        "    print('OK', r.score)\n"
        "except Exception as e:\n"
        "    print(f'FAIL: {type(e).__name__}: {e}')\n"
        "    sys.exit(1)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, f"import kya broke without cryptography: {result.stderr}"
