"""Tests for kya.inbound — cross-tenant inbound recommendations.

Spins up an in-process HTTP collector that signs payloads with a freshly
generated Ed25519 key. Pins that key via KYA_INBOUND_PUBLIC_KEY for the
duration of the test, exercises fetch / verify / persist / approve.

Negative paths covered: wrong key, expired envelope, tampered payload,
unknown scope, signature missing. None of these may persist a row OR
apply a weight.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytestmark = pytest.mark.skipif(
    "KYA_TEST_PG_URL" not in os.environ,
    reason="PG integration test — set KYA_TEST_PG_URL to enable",
)


# ── Signing fixture ──────────────────────────────────────────────────


@pytest.fixture(scope="module")
def keypair():
    """Generate a fresh Ed25519 keypair for this test module."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_bytes).decode()
    key_id = "test-kya-1"
    return {
        "private": priv,
        "public_b64": pub_b64,
        "key_id": key_id,
        "env_value": f"{key_id}:{pub_b64}",
    }


@pytest.fixture(autouse=True)
def _pin_trust_anchor(keypair, monkeypatch):
    monkeypatch.setenv("KYA_INBOUND_PUBLIC_KEY", keypair["env_value"])
    yield


# ── Mock collector ───────────────────────────────────────────────────


class _Collector:
    def __init__(self, keypair) -> None:
        self.keypair = keypair
        self.next_envelope: dict | None = None
        self.tamper = False  # if True, flip a byte after signing
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address
        return f"http://{host}:{port}/recommendations"

    def sign_envelope(self, payload: dict, *, key_id: str | None = None) -> dict:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        body = dict(payload)
        body["signing_key_id"] = key_id or self.keypair["key_id"]
        canonical = json.dumps(
            {k: v for k, v in body.items() if k != "signature"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        priv: Ed25519PrivateKey = self.keypair["private"]
        sig = priv.sign(canonical)
        body["signature"] = "ed25519:" + base64.b64encode(sig).decode()
        return body

    def start(self) -> None:
        coll = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args): pass

            def do_GET(self):
                with coll._lock:
                    coll.requests.append({"path": self.path, "headers": dict(self.headers)})
                    env = coll.next_envelope
                    tamper = coll.tamper
                if env is None:
                    self.send_response(204)
                    self.end_headers()
                    return
                body = json.dumps(env).encode("utf-8")
                if tamper:
                    # flip a single byte in the rationale (post-signature)
                    body = body.replace(b"rationale", b"rotionale", 1)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)


@pytest.fixture
def collector(keypair):
    c = _Collector(keypair)
    c.start()
    try:
        yield c
    finally:
        c.stop()


# ── DB fixture ──────────────────────────────────────────────────────


@pytest.fixture
def db():
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    eng = create_engine(os.environ["KYA_TEST_PG_URL"])
    with eng.begin() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
    Session = sessionmaker(bind=eng)
    session = Session()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        eng.dispose()


# ── Helpers ─────────────────────────────────────────────────────────


def _make_envelope(extra_recs=None, *, expires_offset_min=60):
    now = datetime.now(timezone.utc)
    return {
        "v": 1,
        "kind": "kya_inbound_recommendations",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=expires_offset_min)).isoformat(),
        "deployment_id": None,
        "recommendations": extra_recs or [
            {
                "id": f"rec_{int(time.time() * 1000)}",
                "scope": "class_weights",
                "key": "pii",
                "current_value_at_issue": 20,
                "recommended_value": 25,
                "rationale": "cross-tenant pattern: 3.2x elevated incident rate",
                "evidence_summary": {"deployments_observed": 47, "window": "7d"},
            }
        ],
    }


# ── Tests ───────────────────────────────────────────────────────────


def test_valid_signed_envelope_persists(collector, db):
    import kya

    collector.next_envelope = collector.sign_envelope(_make_envelope())
    result = kya.fetch_inbound_now(db, collector_url=collector.url)
    assert result["ok"] is True
    assert result["persisted"] == 1
    assert result["rejected"] == 0
    assert result["auto_applied"] == 0

    pending = kya.list_recommendations(db, status="pending")
    assert len(pending) == 1
    assert pending[0]["scope"] == "class_weights"
    assert pending[0]["key"] == "pii"
    assert int(pending[0]["recommended_value"]) == 25


def test_wrong_signing_key_rejected(collector, db, monkeypatch, keypair):
    """If the signer's key is NOT in our trust anchor, reject."""
    # Pin a DIFFERENT key — collector still signs with its own.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    import kya
    other = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv("KYA_INBOUND_PUBLIC_KEY", f"some-other-key:{base64.b64encode(other).decode()}")

    collector.next_envelope = collector.sign_envelope(_make_envelope())
    result = kya.fetch_inbound_now(db, collector_url=collector.url)
    assert result["ok"] is False
    assert result["reason"] == "signature_invalid"
    pending = kya.list_recommendations(db, status="pending")
    assert all(p["external_id"] != collector.next_envelope["recommendations"][0]["id"] for p in pending)


def test_tampered_body_rejected(collector, db):
    """Signature is valid but the body the SDK sees has been mutated in
    flight — SDK must reject (defense against CDN-rewriting attacks)."""
    import kya
    collector.next_envelope = collector.sign_envelope(_make_envelope())
    collector.tamper = True  # flip a byte after signing
    result = kya.fetch_inbound_now(db, collector_url=collector.url)
    assert result["ok"] is False
    assert result["reason"] in ("signature_invalid", "not_json")


def test_expired_envelope_rejected(collector, db):
    """Recommendations past expires_at must not be persisted."""
    import kya
    env = _make_envelope(expires_offset_min=-5)  # expired 5 min ago
    collector.next_envelope = collector.sign_envelope(env)
    result = kya.fetch_inbound_now(db, collector_url=collector.url)
    # The envelope itself is well-signed, but every recommendation is
    # individually rejected with expired_at_fetch:
    assert result["ok"] is True
    assert result["persisted"] == 0
    assert result["rejected"] == 1
    assert result["rejections"][0][1] == "expired_at_fetch"


def test_unknown_scope_rejected(collector, db):
    import kya
    env = _make_envelope(extra_recs=[{
        "id": "rec_bad_scope",
        "scope": "weights_for_underwear_color",  # not a known scope
        "key": "pii",
        "recommended_value": 25,
        "rationale": "no",
    }])
    collector.next_envelope = collector.sign_envelope(env)
    result = kya.fetch_inbound_now(db, collector_url=collector.url)
    assert result["ok"] is True
    assert result["persisted"] == 0
    assert result["rejected"] == 1
    assert result["rejections"][0][1].startswith("unknown_scope:")


def test_unsigned_envelope_rejected(collector, db):
    import kya
    env = _make_envelope()
    env["signing_key_id"] = "test-kya-1"
    # NO signature field
    collector.next_envelope = env
    result = kya.fetch_inbound_now(db, collector_url=collector.url)
    assert result["ok"] is False
    assert result["reason"] == "signature_invalid"


def test_approve_routes_through_set_override(collector, db):
    """Operator-approval applies the override and effective weight changes."""
    import kya
    from kya.data_classes import CLASS_WEIGHTS
    from kya.tenant_weights import ensure_tables, get_effective_weights, register_scope

    ensure_tables(db)
    register_scope("class_weights", CLASS_WEIGHTS)

    tenant_id = None  # platform-default change
    rec_id = f"rec_approve_{int(time.time() * 1000)}"
    env = _make_envelope(extra_recs=[{
        "id": rec_id,
        "scope": "class_weights",
        "key": "phi",
        "current_value_at_issue": int(CLASS_WEIGHTS["phi"]),
        "recommended_value": int(CLASS_WEIGHTS["phi"]) + 4,
        "rationale": "approve-path test",
    }])
    collector.next_envelope = collector.sign_envelope(env)
    kya.fetch_inbound_now(db, collector_url=collector.url)

    pending = [p for p in kya.list_recommendations(db, status="pending") if p["external_id"] == rec_id]
    assert len(pending) == 1
    pk_id = int(pending[0]["id"])

    before = get_effective_weights(db, "class_weights", tenant_id=tenant_id)
    decision = kya.approve_recommendation(db, pk_id, approved_by=None, notes="ok")
    assert decision["status"] == "applied"
    after = get_effective_weights(db, "class_weights", tenant_id=tenant_id)
    assert int(after["phi"]) == int(before["phi"]) + 4


def test_auto_apply_allowlist(collector, db):
    """A (scope, key) on the customer allowlist auto-applies immediately."""
    import kya
    from kya.data_classes import CLASS_WEIGHTS
    from kya.tenant_weights import ensure_tables, get_effective_weights, register_scope

    ensure_tables(db)
    register_scope("class_weights", CLASS_WEIGHTS)
    tenant_id = None
    rec_id = f"rec_auto_{int(time.time() * 1000)}"
    env = _make_envelope(extra_recs=[{
        "id": rec_id,
        "scope": "class_weights",
        "key": "confidential",
        "current_value_at_issue": int(CLASS_WEIGHTS["confidential"]),
        "recommended_value": int(CLASS_WEIGHTS["confidential"]) + 3,
        "rationale": "auto-apply allowlist test",
    }])
    collector.next_envelope = collector.sign_envelope(env)

    before = get_effective_weights(db, "class_weights", tenant_id=tenant_id)
    result = kya.fetch_inbound_now(
        db, collector_url=collector.url,
        auto_apply_allowlist=[("class_weights", "confidential")],
    )
    assert result["auto_applied"] == 1
    after = get_effective_weights(db, "class_weights", tenant_id=tenant_id)
    assert int(after["confidential"]) == int(before["confidential"]) + 3

    # The status should be 'auto_applied', not 'pending'
    rows = kya.list_recommendations(db)
    auto_rows = [r for r in rows if r["external_id"] == rec_id]
    assert len(auto_rows) == 1
    assert auto_rows[0]["status"] == "auto_applied"


def test_idempotent_refetch(collector, db):
    """Re-fetching the same envelope must NOT create duplicate rows."""
    import kya
    rec_id = f"rec_idem_{int(time.time() * 1000)}"
    env = _make_envelope(extra_recs=[{
        "id": rec_id,
        "scope": "class_weights",
        "key": "pii",
        "current_value_at_issue": 20,
        "recommended_value": 25,
        "rationale": "idempotency test",
    }])
    collector.next_envelope = collector.sign_envelope(env)
    r1 = kya.fetch_inbound_now(db, collector_url=collector.url)
    r2 = kya.fetch_inbound_now(db, collector_url=collector.url)
    assert r1["persisted"] == 1
    assert r2["persisted"] == 1  # row created at INSERT step but ON CONFLICT swallowed

    # Only one row materialized
    rows = [r for r in kya.list_recommendations(db) if r["external_id"] == rec_id]
    assert len(rows) == 1


def test_inbound_status_reflects_state(collector, db):
    import kya
    st = kya.inbound_status()
    # Off until enable_inbound is called — but trust anchors should be loaded
    assert st["enabled"] is False
    assert "test-kya-1" in st["trust_anchors"]
