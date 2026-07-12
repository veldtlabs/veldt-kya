"""Tests for kya.gateway_client — SDK poll+resume primitive (#101 layer 3).

Mocks ``urllib.request.urlopen`` at the module level so we can drive
every HTTP path deterministically without a live gateway or dashboard.
Real-agent HTTP round-trips live in #103 (real-agent E2E suite).

Coverage:
    - invoke returns raw response on non-2xx (428 comes back through the
      HTTPError path in urllib; must land as GatewayResponse not raise)
    - transport errors raise KyaGatewayTransportError
    - poll_status parses the JSON envelope
    - resume returns the final GatewayResponse
    - invoke_with_hitl: non-428 returns unchanged
    - invoke_with_hitl: 428 missing pending_id raises KyaGatewayError
    - invoke_with_hitl: 428 with pending_id polls, sees "approved",
      resumes, returns the resumed body
    - invoke_with_hitl: "denied" → KyaHitlDeniedError with reason_codes
    - invoke_with_hitl: "expired" → KyaHitlExpiredError
    - invoke_with_hitl: "resumed by someone else" → KyaGatewayError
    - invoke_with_hitl: wait_timeout_sec exhausted → KyaHitlTimeoutError
    - invoke_with_hitl: Retry-After respected for first sleep
    - poll_status without dashboard_url raises KyaGatewayError
    - resume without dashboard_url raises KyaGatewayError
"""
from __future__ import annotations

import io
import json
from urllib.error import HTTPError, URLError

import pytest

from kya.gateway_client import (
    GatewayResponse,
    KyaGatewayClient,
    KyaGatewayError,
    KyaGatewayTransportError,
    KyaHitlDeniedError,
    KyaHitlExpiredError,
    KyaHitlTimeoutError,
    PendingStatus,
)


# ── Test infra: mock urlopen with a scripted response queue ──────────


class _FakeResp:
    """Duck-types urllib's response object."""
    def __init__(self, *, status: int, body: bytes,
                 headers: dict[str, str] | None = None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _install_mock_urlopen(monkeypatch, script):
    """Install a mock urlopen that pops from ``script`` per call.

    Each entry is either:
      - A _FakeResp (returned successfully)
      - An HTTPError instance (raised as HTTPError)
      - A URLError instance (raised as URLError)
      - A callable(url, timeout) -> _FakeResp
    """
    import kya.gateway_client as gc
    calls: list[tuple[str, dict]] = []

    def _fake(req, timeout=None):
        # req may be a Request or a URL string.
        url = req.get_full_url() if hasattr(req, "get_full_url") else req
        method = req.get_method() if hasattr(req, "get_method") else "GET"
        headers = dict(req.headers) if hasattr(req, "headers") else {}
        calls.append((url, {"method": method, "headers": headers}))
        if not script:
            raise RuntimeError(f"unscripted urlopen call to {url}")
        item = script.pop(0)
        if callable(item):
            return item(url, timeout)
        if isinstance(item, HTTPError):
            raise item
        if isinstance(item, URLError):
            raise item
        return item

    monkeypatch.setattr(gc.urllib.request, "urlopen", _fake)
    return calls


def _http_error_428(headers: dict, body: dict) -> HTTPError:
    """Build an HTTPError that quacks like a 428 with headers + JSON body."""
    payload = json.dumps(body).encode("utf-8")
    e = HTTPError(
        url="http://gw/mcp",
        code=428,
        msg="Precondition Required",
        hdrs=headers,  # HTTPError uses this as its headers attribute
        fp=io.BytesIO(payload),
    )
    return e


def _http_error(code: int, headers: dict, body: dict | bytes) -> HTTPError:
    payload = (
        json.dumps(body).encode("utf-8")
        if isinstance(body, dict) else body
    )
    return HTTPError(
        url="http://gw/mcp", code=code, msg="err",
        hdrs=headers, fp=io.BytesIO(payload),
    )


# ═══════════════════════════════════════════════════════════════════════
# invoke — non-HITL, direct HTTP round-trip
# ═══════════════════════════════════════════════════════════════════════


def test_invoke_returns_2xx_body_and_headers(monkeypatch):
    _install_mock_urlopen(monkeypatch, [
        _FakeResp(status=200, body=b'{"ok": true}',
                  headers={"content-type": "application/json"}),
    ])
    c = KyaGatewayClient("http://gw")
    r = c.invoke(body=b'{"m":"x"}')
    assert r.status_code == 200
    assert r.body == b'{"ok": true}'
    assert r.headers["content-type"] == "application/json"
    assert r.json() == {"ok": True}


def test_invoke_returns_non_2xx_as_gatewayresponse_not_raise(monkeypatch):
    """428 arrives at urllib as HTTPError. GatewayClient must catch and
    surface it as a normal GatewayResponse so invoke_with_hitl can
    inspect the headers + body."""
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "pid-1"},
                    {"error": {"data": {"verdict": "flag_for_review"}}}),
    ])
    c = KyaGatewayClient("http://gw")
    r = c.invoke(body=b'{}')
    assert r.status_code == 428
    assert r.headers.get("X-Kya-Pending-Id") == "pid-1"


def test_invoke_raises_on_transport_error(monkeypatch):
    _install_mock_urlopen(monkeypatch, [URLError("connection refused")])
    c = KyaGatewayClient("http://gw")
    with pytest.raises(KyaGatewayTransportError):
        c.invoke(body=b'{}')


def test_invoke_forwards_default_and_call_headers(monkeypatch):
    calls = _install_mock_urlopen(monkeypatch, [
        _FakeResp(status=200, body=b'{}', headers={}),
    ])
    c = KyaGatewayClient(
        "http://gw",
        default_headers={"authorization": "Bearer x", "x-custom": "d"},
    )
    c.invoke(body=b'{}', headers={"x-call": "c", "x-custom": "override"})
    _, meta = calls[0]
    # Both default + call headers present; call overrides default on collision.
    hdrs = {k.lower(): v for k, v in meta["headers"].items()}
    assert hdrs.get("authorization") == "Bearer x"
    assert hdrs.get("x-call") == "c"
    assert hdrs.get("x-custom") == "override"


# ═══════════════════════════════════════════════════════════════════════
# poll_status
# ═══════════════════════════════════════════════════════════════════════


def test_poll_status_parses_json_envelope(monkeypatch):
    _install_mock_urlopen(monkeypatch, [
        _FakeResp(status=200,
                  body=b'{"id": "p1", "status": "pending", "reason_codes": ["A"]}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    s = c.poll_status("p1")
    assert s.id == "p1"
    assert s.status == "pending"
    assert s.reason_codes == ["A"]


def test_poll_status_raises_when_dashboard_url_missing():
    c = KyaGatewayClient("http://gw", dashboard_url=None)
    with pytest.raises(KyaGatewayError, match="dashboard_url"):
        c.poll_status("p1")


def test_poll_status_raises_on_404(monkeypatch):
    _install_mock_urlopen(monkeypatch, [
        _http_error(404, {}, {"error": "not_found"}),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    with pytest.raises(KyaGatewayError, match="404"):
        c.poll_status("p1")


def test_poll_status_wraps_transport_error(monkeypatch):
    _install_mock_urlopen(monkeypatch, [URLError("dns")])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    with pytest.raises(KyaGatewayTransportError):
        c.poll_status("p1")


# ═══════════════════════════════════════════════════════════════════════
# resume
# ═══════════════════════════════════════════════════════════════════════


def test_resume_returns_replayed_body(monkeypatch):
    _install_mock_urlopen(monkeypatch, [
        _FakeResp(status=200, body=b'{"result": "replayed"}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    r = c.resume("p1")
    assert r.status_code == 200
    assert r.json() == {"result": "replayed"}


def test_resume_raises_when_dashboard_url_missing():
    c = KyaGatewayClient("http://gw")
    with pytest.raises(KyaGatewayError, match="dashboard_url"):
        c.resume("p1")


def test_resume_returns_non_2xx_as_response(monkeypatch):
    _install_mock_urlopen(monkeypatch, [
        _http_error(410, {}, {"error": "already_resumed"}),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    r = c.resume("p1")
    assert r.status_code == 410


# ═══════════════════════════════════════════════════════════════════════
# invoke_with_hitl — the whole poll+resume dance
# ═══════════════════════════════════════════════════════════════════════


def test_invoke_with_hitl_non_428_returns_first_response(monkeypatch):
    _install_mock_urlopen(monkeypatch, [
        _FakeResp(status=200, body=b'{"ok": 1}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    r = c.invoke_with_hitl(body=b'{}')
    assert r.status_code == 200


def test_invoke_with_hitl_deny_403_returned_unchanged(monkeypatch):
    """A gateway deny (403) is a terminal state — no HITL, no resume.
    invoke_with_hitl returns it directly."""
    _install_mock_urlopen(monkeypatch, [
        _http_error(403, {}, {"error": {"data": {"verdict": "deny"}}}),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    r = c.invoke_with_hitl(body=b'{}')
    assert r.status_code == 403


def test_invoke_with_hitl_428_without_pending_id_raises(monkeypatch):
    """Gateway couldn't persist → no X-Kya-Pending-Id → no HITL path."""
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {}, {"error": {"data": {"verdict": "flag_for_review"}}}),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    with pytest.raises(KyaGatewayError, match="pending row could not"):
        c.invoke_with_hitl(body=b'{}')


def test_invoke_with_hitl_full_approve_then_resume(monkeypatch):
    """Happy path: 428 with pending_id → poll returns approved →
    resume → replayed response returned to caller as if there was no 428."""
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "p1"},
                    {"error": {"data": {"verdict": "flag_for_review",
                                        "pending_id": "p1"}}}),
        _FakeResp(status=200, body=b'{"id":"p1","status":"approved","reason_codes":[]}'),
        _FakeResp(status=200, body=b'{"result": "human said yes"}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    r = c.invoke_with_hitl(
        body=b'{}',
        wait_timeout_sec=60.0,
        poll_interval_sec=0.01,  # fast test
    )
    assert r.status_code == 200
    assert r.json() == {"result": "human said yes"}


def test_invoke_with_hitl_denied_raises_denied_error(monkeypatch):
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "p1"}, {}),
        _FakeResp(
            status=200,
            body=b'{"id":"p1","status":"denied","reason_codes":["MANUAL_DENY"]}',
        ),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    with pytest.raises(KyaHitlDeniedError) as exc_info:
        c.invoke_with_hitl(body=b'{}', poll_interval_sec=0.01)
    assert exc_info.value.pending_id == "p1"
    assert "MANUAL_DENY" in exc_info.value.reason_codes


def test_invoke_with_hitl_expired_raises_expired_error(monkeypatch):
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "p1"}, {}),
        _FakeResp(status=200,
                  body=b'{"id":"p1","status":"expired","reason_codes":[]}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    with pytest.raises(KyaHitlExpiredError) as exc_info:
        c.invoke_with_hitl(body=b'{}', poll_interval_sec=0.01)
    assert exc_info.value.pending_id == "p1"


def test_invoke_with_hitl_already_resumed_raises_specific_error(monkeypatch):
    """Concurrent SDK client resumed first — we can't retrieve the
    body from our side. Surface a specific error the caller can pattern-match."""
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "p1"}, {}),
        _FakeResp(status=200,
                  body=b'{"id":"p1","status":"resumed","reason_codes":[]}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    with pytest.raises(KyaGatewayError, match="already resumed"):
        c.invoke_with_hitl(body=b'{}', poll_interval_sec=0.01)


def test_invoke_with_hitl_timeout_raises_timeout_error(monkeypatch):
    """Approver never decides — the client gives up cleanly. The pending
    row is untouched server-side."""
    # 428 then INFINITE "pending" replies.
    def _keep_pending(*a):
        return _FakeResp(
            status=200,
            body=b'{"id":"p1","status":"pending","reason_codes":[]}',
        )
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "p1"}, {}),
    ] + [_keep_pending] * 100)

    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    with pytest.raises(KyaHitlTimeoutError) as exc_info:
        c.invoke_with_hitl(
            body=b'{}',
            wait_timeout_sec=0.05,  # tiny — bail almost immediately
            poll_interval_sec=0.01,
        )
    assert exc_info.value.pending_id == "p1"


def test_invoke_with_hitl_retry_after_seeds_first_sleep(monkeypatch):
    """Retry-After header on the 428 hints how long to wait before the
    first poll. Must be honored (default) so the client doesn't hammer
    the dashboard immediately."""
    import time
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "p1", "Retry-After": "0.05"},
                    {}),
        _FakeResp(status=200,
                  body=b'{"id":"p1","status":"approved","reason_codes":[]}'),
        _FakeResp(status=200, body=b'{"result":"ok"}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    t0 = time.monotonic()
    c.invoke_with_hitl(
        body=b'{}',
        wait_timeout_sec=60.0,
        poll_interval_sec=0.001,  # tiny so the ONLY delay is Retry-After
    )
    elapsed = time.monotonic() - t0
    # Retry-After said 50ms; we should have waited at least that long
    # (with generous slack for CI noise).
    assert elapsed >= 0.03, (
        f"Retry-After was not respected — elapsed={elapsed:.3f}s"
    )


def test_invoke_with_hitl_retry_after_ignored_when_flag_off(monkeypatch):
    """Callers who prefer their own scheduling can opt out."""
    import time
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "p1", "Retry-After": "10"}, {}),
        _FakeResp(status=200,
                  body=b'{"id":"p1","status":"approved","reason_codes":[]}'),
        _FakeResp(status=200, body=b'{"result":"ok"}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    t0 = time.monotonic()
    r = c.invoke_with_hitl(
        body=b'{}',
        wait_timeout_sec=60.0,
        poll_interval_sec=0.01,
        retry_after_respect=False,
    )
    elapsed = time.monotonic() - t0
    assert r.status_code == 200
    # We ignored the 10s Retry-After → should complete in milliseconds.
    assert elapsed < 1.0, f"Retry-After was NOT ignored ({elapsed:.2f}s)"


def test_invoke_with_hitl_ignores_malformed_retry_after(monkeypatch):
    """A garbage Retry-After doesn't crash the flow — silently falls
    back to poll_interval_sec."""
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"X-Kya-Pending-Id": "p1",
                         "Retry-After": "not-a-number"}, {}),
        _FakeResp(status=200,
                  body=b'{"id":"p1","status":"approved","reason_codes":[]}'),
        _FakeResp(status=200, body=b'{"result":"ok"}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    r = c.invoke_with_hitl(body=b'{}', poll_interval_sec=0.01)
    assert r.status_code == 200


def test_invoke_with_hitl_case_insensitive_header_lookup(monkeypatch):
    """urllib normalizes header names in some backends and preserves
    case in others. Client must be defensive."""
    _install_mock_urlopen(monkeypatch, [
        _http_error(428, {"x-kya-pending-id": "p1"}, {}),  # lowercase
        _FakeResp(status=200,
                  body=b'{"id":"p1","status":"approved","reason_codes":[]}'),
        _FakeResp(status=200, body=b'{"result":"ok"}'),
    ])
    c = KyaGatewayClient("http://gw", dashboard_url="http://dash")
    r = c.invoke_with_hitl(body=b'{}', poll_interval_sec=0.01)
    assert r.status_code == 200
