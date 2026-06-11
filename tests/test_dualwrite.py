"""Tests for kya.dualwrite + kya.telemetry — opt-in collector pipeline.

Each test stands up an in-process HTTP server, calls enable_dual_write
(or telemetry equivalent), exercises a recorder, then asserts the
correct payload reached the collector. All tests run on SQLite to avoid
external infra.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

# ─── Mock collector ────────────────────────────────────────────────────


class _Collector:
    """In-process HTTP collector with controllable status / latency."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.status_code = 200
        self.latency_s = 0.0
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address
        return f"http://{host}:{port}/collect"

    def start(self) -> None:
        coll = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8") if length else ""
                if coll.latency_s:
                    time.sleep(coll.latency_s)
                with coll._lock:
                    parsed = json.loads(body) if body else {}
                    coll.requests.append(
                        {
                            "headers": dict(self.headers),
                            "body": parsed,
                        }
                    )
                    sc = coll.status_code
                self.send_response(sc)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def all_rows(self) -> list[dict]:
        out: list[dict] = []
        with self._lock:
            for req in self.requests:
                for r in req["body"].get("rows", []):
                    out.append(r)
        return out


@pytest.fixture
def collector():
    c = _Collector()
    c.start()
    try:
        yield c
    finally:
        c.stop()


# ─── DB fixture ───────────────────────────────────────────────────────


@pytest.fixture
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    eng = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=eng)()
    try:
        yield session
    finally:
        session.close()
        eng.dispose()


@pytest.fixture(autouse=True)
def _reset_kya():
    """Tear down any active dual-write between tests."""
    import kya

    kya.disable_dual_write()
    kya.disable_telemetry()
    yield
    kya.disable_dual_write()
    kya.disable_telemetry()


# ─── enable / disable round-trip ──────────────────────────────────────


def test_off_by_default():
    import kya

    status = kya.dual_write_status()
    assert status == {"enabled": False}


def test_enable_status_then_disable(collector):
    import kya

    kya.enable_dual_write(
        collector_url=collector.url,
        api_key="test-key",
        allowlist=["agent_versions"],
    )
    st = kya.dual_write_status()
    assert st["enabled"] is True
    assert st["allowlist"] == ["agent_versions"]
    kya.disable_dual_write()
    assert kya.dual_write_status() == {"enabled": False}


def test_allowlist_validation():
    import kya

    with pytest.raises(kya.DualWriteAllowlistError):
        kya.enable_dual_write(
            collector_url="http://localhost:0/collect",
            api_key="test-key",
            allowlist=["totally_made_up_table"],
        )


def test_collector_url_required():
    import kya

    with pytest.raises(ValueError):
        kya.enable_dual_write(
            collector_url="",
            api_key="x",
            allowlist=["agent_versions"],
        )


# ─── End-to-end recorder hand-off ─────────────────────────────────────


def _wait_for(collector, predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(collector):
            return True
        time.sleep(0.1)
    return False


def test_snapshot_agent_forwards(collector, db):
    import kya

    kya.enable_dual_write(
        collector_url=collector.url,
        api_key="test-key",
        allowlist=["agent_versions"],
        flush_interval_s=0.5,
    )
    kya.snapshot_agent(
        db,
        tenant_id="00000000-0000-0000-0000-000000000001",
        agent_key="test_agent",
        definition={"tools": ["search_kg"], "model": "claude-sonnet-4-6"},
        note="initial",
    )
    ok = _wait_for(collector, lambda c: len(c.all_rows()) >= 1, timeout=5)
    assert ok, "collector never received the row"
    rows = collector.all_rows()
    assert rows[0]["table"] == "agent_versions"
    assert rows[0]["row"]["agent_key"] == "test_agent"
    assert rows[0]["row"]["version_no"] == 1


def test_allowlist_blocks_non_listed_tables(collector, db):
    """A table NOT in the allowlist must be silently dropped."""
    import kya

    kya.enable_dual_write(
        collector_url=collector.url,
        api_key="test-key",
        allowlist=["kya_invocations"],  # not agent_versions
        flush_interval_s=0.5,
    )
    kya.snapshot_agent(
        db,
        tenant_id="00000000-0000-0000-0000-000000000001",
        agent_key="excluded",
        definition={"tools": []},
    )
    # Wait a beat so the worker has time to flush.
    time.sleep(1.5)
    assert collector.all_rows() == []


def test_redaction_hashes_pii(collector, db):
    """PII fields should be sha256-hashed before reaching the collector."""
    import kya

    kya.enable_dual_write(
        collector_url=collector.url,
        api_key="test-key",
        allowlist=["kya_principal_trust"],
        flush_interval_s=0.5,
    )
    kya.record_principal_signal(
        db,
        tenant_id="00000000-0000-0000-0000-000000000001",
        principal_kind="user",
        principal_id="alice@example.com",
        signal_kind="oos_tool",
    )
    assert _wait_for(collector, lambda c: len(c.all_rows()) >= 1, timeout=5)
    row = collector.all_rows()[0]["row"]
    assert row["principal_id"].startswith("sha256:")
    assert "alice@example.com" not in json.dumps(row)


def test_redaction_can_be_disabled(collector, db):
    import kya

    kya.enable_dual_write(
        collector_url=collector.url,
        api_key="test-key",
        allowlist=["kya_principal_trust"],
        redact=False,
        flush_interval_s=0.5,
    )
    kya.record_principal_signal(
        db,
        tenant_id="00000000-0000-0000-0000-000000000001",
        principal_kind="user",
        principal_id="bob@example.com",
        signal_kind="oos_tool",
    )
    assert _wait_for(collector, lambda c: len(c.all_rows()) >= 1, timeout=5)
    row = collector.all_rows()[0]["row"]
    assert row["principal_id"] == "bob@example.com"


def test_authorization_header_carries_api_key(collector, db):
    import kya

    kya.enable_dual_write(
        collector_url=collector.url,
        api_key="super-secret-key",
        allowlist=["agent_versions"],
        flush_interval_s=0.5,
    )
    kya.snapshot_agent(
        db,
        tenant_id="00000000-0000-0000-0000-000000000001",
        agent_key="auth_test",
        definition={"tools": []},
    )
    assert _wait_for(collector, lambda c: len(c.requests) >= 1, timeout=5)
    headers = collector.requests[0]["headers"]
    assert headers.get("Authorization") == "Bearer super-secret-key"


def test_5xx_then_recovery(collector, db):
    """A 5xx should retry with backoff; eventually succeed once collector recovers."""
    import kya

    collector.status_code = 500
    kya.enable_dual_write(
        collector_url=collector.url,
        api_key="test-key",
        allowlist=["agent_versions"],
        flush_interval_s=0.3,
        max_retries=3,
    )
    kya.snapshot_agent(
        db,
        tenant_id="00000000-0000-0000-0000-000000000001",
        agent_key="flaky",
        definition={"tools": []},
    )
    # Wait for at least one 500 attempt to land.
    assert _wait_for(collector, lambda c: len(c.requests) >= 1, timeout=5)
    collector.status_code = 200
    # Subsequent batches should now succeed.
    kya.snapshot_agent(
        db,
        tenant_id="00000000-0000-0000-0000-000000000001",
        agent_key="flaky",
        definition={"tools": []},
        note="after recovery",
    )
    assert _wait_for(collector, lambda c: len(c.all_rows()) >= 1, timeout=10)


# ─── Telemetry (aggregate counters) ──────────────────────────────────


def test_telemetry_counters_increment(db):
    """Even without a telemetry URL, recorders should bump in-process counters."""
    import kya

    # Telemetry off-by-import flips when disable_telemetry() ran in fixture
    kya.enable_telemetry(url=None)  # counters on, no transmission

    kya.snapshot_agent(
        db,
        tenant_id="00000000-0000-0000-0000-000000000001",
        agent_key="telemetry_test",
        definition={"tools": []},
    )
    status = kya.telemetry_status()
    assert status["disabled"] is False
    assert status["in_flight"]["totals"].get("snapshot_agent", 0) >= 1


def test_telemetry_transmits_to_url(collector):
    """When a URL is configured, the periodic flush should POST aggregates."""
    import kya
    from kya import telemetry as _t

    # Enable BEFORE recording — the fixture disabled telemetry, which makes
    # record_event() a no-op until re-enabled.
    kya.enable_telemetry(url=collector.url, flush_interval_s=60)

    _t.record_event("snapshot_agent")
    _t.record_event("rogue_event", kind="oos_tool")
    _t.record_event("rogue_event", kind="oos_tool")

    # Flush immediately rather than waiting 60s.
    _t._TX._flush()  # type: ignore[attr-defined]

    assert _wait_for(collector, lambda c: len(c.requests) >= 1, timeout=3)
    body = collector.requests[-1]["body"]
    assert body["kind"] == "kya_aggregate_telemetry"
    assert "deployment_id" in body
    # The aggregate carries counts only — no payloads
    counts = body.get("counts", {})
    assert "snapshot_agent" in counts
    assert counts["rogue_event"]["by_kind"]["oos_tool"] == 2
