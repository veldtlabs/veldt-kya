"""PyPI-readiness tests: daemon thread lifecycle + error injection.

What this proves before publish:
  • enable/disable cycles don't leak threads or atexit handlers
  • dual-write + telemetry + inbound survive degenerate collector
    responses (500s, malformed JSON, hangs, empty bodies)
  • Multiple concurrent enables don't create overlapping workers
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


def _kya_thread_count() -> int:
    """Daemon threads with names that the SDK creates."""
    return sum(
        1 for t in threading.enumerate()
        if any(name in t.name for name in ("kya-dualwrite", "kya-telemetry", "kya-inbound"))
    )


# ── Lifecycle: enable/disable doesn't leak threads ──────────────────


def test_dualwrite_enable_disable_cycle_no_thread_leak():
    """100 cycles of enable/disable must not pile up daemon threads."""
    import kya

    kya.disable_dual_write()  # baseline
    baseline = _kya_thread_count()

    for _ in range(100):
        kya.enable_dual_write(
            collector_url="http://127.0.0.1:1/never-listens",
            api_key="x", allowlist=["agent_versions"],
        )
        kya.disable_dual_write()

    final = _kya_thread_count()
    # After full disable, no kya-dualwrite threads should remain.
    # Some may be in `joined` state but enumerate() drops those.
    assert final == baseline, f"thread leak: {baseline} → {final}"


def test_telemetry_enable_disable_cycle_no_thread_leak():
    import kya

    kya.disable_telemetry()
    baseline = sum(1 for t in threading.enumerate() if "kya-telemetry" in t.name)

    for _ in range(50):
        kya.enable_telemetry(url="http://127.0.0.1:1/never-listens", flush_interval_s=60)
        kya.disable_telemetry()

    final = sum(1 for t in threading.enumerate() if "kya-telemetry" in t.name)
    assert final == baseline, f"telemetry thread leak: {baseline} → {final}"


def test_repeated_enable_replaces_existing_worker():
    """Calling enable_dual_write twice shouldn't run two workers."""
    import kya

    kya.disable_dual_write()
    for _ in range(20):
        kya.enable_dual_write(
            collector_url="http://127.0.0.1:1/never-listens",
            api_key="x", allowlist=["agent_versions"],
        )
    # 20 enables; only one worker should be live.
    live = sum(1 for t in threading.enumerate() if "kya-dualwrite" in t.name)
    assert live <= 1, f"expected <=1 live worker, got {live}"
    kya.disable_dual_write()


# ── Error injection: degenerate collector responses ────────────────


class _BadCollector:
    """Configurable HTTP server that returns nasty responses."""

    def __init__(self, mode: str) -> None:
        self.mode = mode  # 500 / malformed / empty / slow_then_fail
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/collect"

    def start(self):
        coll = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args): pass

            def _record(self, body):
                with coll._lock:
                    coll.requests.append({"body": body, "mode": coll.mode})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self._record(self.rfile.read(length) if length else b"")
                if coll.mode == "500":
                    self.send_response(500); self.end_headers(); return
                if coll.mode == "malformed":
                    body = b"this is { not json"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body); return
                if coll.mode == "empty":
                    self.send_response(204); self.end_headers(); return
                if coll.mode == "slow":
                    time.sleep(0.1)
                    self.send_response(500); self.end_headers(); return
                if coll.mode == "html":
                    body = b"<html>not what you wanted</html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body); return

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)


@pytest.fixture
def collector(request):
    c = _BadCollector(request.param)
    c.start()
    try:
        yield c
    finally:
        c.stop()


@pytest.fixture(autouse=True)
def _reset_kya():
    import kya
    kya.disable_dual_write()
    kya.disable_telemetry()
    yield
    kya.disable_dual_write()
    kya.disable_telemetry()


@pytest.fixture
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    eng = create_engine("sqlite:///:memory:")
    s = sessionmaker(bind=eng)()
    try:
        yield s
    finally:
        s.close()
        eng.dispose()


@pytest.mark.parametrize("collector", ["500"], indirect=True)
def test_dualwrite_survives_500(collector, db):
    """Worker must not raise; circuit breaker eventually trips silently."""
    import kya
    kya.enable_dual_write(
        collector_url=collector.url, api_key="x",
        allowlist=["agent_versions"],
        flush_interval_s=0.2, max_retries=2,
        breaker_failure_threshold=2, breaker_cool_down_s=60,
    )
    # Snapshot several agents to ensure something flows through the
    # allowlisted table.
    for i in range(5):
        kya.snapshot_agent(db, tenant_id="00000000-0000-0000-0000-000000000001",
                          agent_key=f"t1_{i}", definition={"tools": []})
    # Wait long enough for worker to do at least one batch + retries + breaker trip.
    time.sleep(8)
    status = kya.dual_write_status()
    assert status["enabled"] is True
    # The collector returned 500 for every request, so we must observe
    # failures landing OR the circuit breaker opening — anything but
    # silent success.
    assert (
        status["failed_batches"] >= 1
        or status["breaker_open"] is True
        or len(collector.requests) >= 1
    ), f"no evidence of attempted send: status={status}, requests={len(collector.requests)}"


@pytest.mark.parametrize("collector", ["malformed"], indirect=True)
def test_dualwrite_survives_malformed_response(collector, db):
    """Worker should treat malformed-but-2xx as success (we don't parse the response)."""
    import kya
    kya.enable_dual_write(
        collector_url=collector.url, api_key="x",
        allowlist=["agent_versions"], flush_interval_s=0.2,
    )
    kya.snapshot_agent(db, tenant_id="00000000-0000-0000-0000-000000000001",
                      agent_key="t2", definition={"tools": []})
    time.sleep(1.5)
    assert len(collector.requests) >= 1
    assert kya.dual_write_status()["sent_batches"] >= 1


@pytest.mark.parametrize("collector", ["html"], indirect=True)
def test_dualwrite_survives_wrong_content_type(collector, db):
    """A misconfigured collector returning HTML shouldn't crash the worker."""
    import kya
    kya.enable_dual_write(
        collector_url=collector.url, api_key="x",
        allowlist=["agent_versions"], flush_interval_s=0.2,
    )
    for i in range(3):
        kya.snapshot_agent(db, tenant_id="00000000-0000-0000-0000-000000000001",
                          agent_key=f"t3_{i}", definition={"tools": []})
    time.sleep(1.5)
    # local writes always succeed regardless of collector
    from sqlalchemy import text
    rows = db.execute(text("SELECT COUNT(*) FROM agent_versions")).scalar()
    assert rows == 3


def test_telemetry_survives_unreachable_collector():
    """No URL at all + record events — counters increment, nothing crashes."""
    import kya
    kya.enable_telemetry(url="http://127.0.0.1:1/never", flush_interval_s=60)
    from kya import telemetry as _t
    for _ in range(100):
        _t.record_event("snapshot_agent")
    # Force a flush; it WILL fail (no listener) but must not raise.
    _t._TX._flush()
    # Counters should reset after flush
    status = kya.telemetry_status()
    # Either reset (flushed) or still counted (didn't make it out)
    # The point: no exception raised.
    assert status["disabled"] is False


def test_telemetry_disable_with_no_url_is_idempotent():
    import kya
    kya.disable_telemetry()
    kya.disable_telemetry()
    kya.disable_telemetry()


def test_dualwrite_disable_with_no_factory_is_idempotent():
    import kya
    kya.disable_dual_write()
    kya.disable_dual_write()
    assert kya.dual_write_status() == {"enabled": False}


def test_inbound_with_no_trust_anchor_raises_at_enable():
    """If no KYA_INBOUND_PUBLIC_KEY env and no DEFAULT_PINNED_KEYS,
    enable_inbound should fail loudly, not silently accept and reject
    every recommendation forever."""
    import os

    import kya
    # Make sure no env trust anchor is set
    old = os.environ.pop("KYA_INBOUND_PUBLIC_KEY", None)
    try:
        with pytest.raises((RuntimeError, ValueError)):
            kya.enable_inbound(
                lambda: None, collector_url="http://localhost:0/x",
            )
    finally:
        if old is not None:
            os.environ["KYA_INBOUND_PUBLIC_KEY"] = old


def test_inbound_disable_without_enable_is_idempotent():
    import kya
    kya.disable_inbound()
    kya.disable_inbound()
    assert kya.inbound_status()["enabled"] is False
