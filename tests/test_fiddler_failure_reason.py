"""Bug B follow-up regression: fiddler_bridge records specific failure
reasons that scorer_orchestrator surfaces in JudgeResult, so operators
can tell apart "no API key" / "requests missing" / "HTTP 4xx" / "HTTP
exception" / "JSON parse failed" instead of a generic
"fiddler API unavailable".

Pre-fix, every Fiddler failure mode collapsed to the same opaque
error string. The diagnostic that drove Bug A + Bug B specifically
called out this as the missing piece for operator-side debuggability.
"""

from __future__ import annotations

import sys

import pytest

from kya.fiddler_bridge import (
    _FAILURE_HTTP_EXCEPTION,
    _FAILURE_HTTP_STATUS,
    _FAILURE_JSON_PARSE,
    _FAILURE_NO_API_KEY,
    _FAILURE_NO_REQUESTS,
    _clear_failure,
    check_faithfulness,
    check_safety,
    get_last_failure_reason,
)


@pytest.fixture(autouse=True)
def _reset_failure_state(monkeypatch):
    """Each test starts with a clean thread-local AND no FIDDLER_API_KEY
    leaking in from the host environment."""
    monkeypatch.delenv("FIDDLER_API_KEY", raising=False)
    _clear_failure("check_safety")
    _clear_failure("check_faithfulness")
    yield
    _clear_failure("check_safety")
    _clear_failure("check_faithfulness")


# ── No-API-key reason ─────────────────────────────────────────────


def test_check_safety_records_no_api_key_reason():
    r = check_safety(input_text="hello")
    assert r is None
    assert get_last_failure_reason("check_safety") == _FAILURE_NO_API_KEY


def test_check_faithfulness_records_no_api_key_reason():
    r = check_faithfulness(response_text="x", context="y")
    assert r is None
    assert get_last_failure_reason("check_faithfulness") == _FAILURE_NO_API_KEY


# ── No-requests reason ───────────────────────────────────────────


def test_check_safety_records_requests_missing(monkeypatch):
    monkeypatch.setenv("FIDDLER_API_KEY", "test-token")
    # Force `import requests` inside check_safety to raise ImportError
    # by shadowing the module in sys.modules with None (sentinel).
    monkeypatch.setitem(sys.modules, "requests", None)
    r = check_safety(input_text="hello")
    assert r is None
    assert get_last_failure_reason("check_safety") == _FAILURE_NO_REQUESTS


# ── HTTP-exception reason ─────────────────────────────────────────


def test_check_safety_records_http_exception(monkeypatch):
    monkeypatch.setenv("FIDDLER_API_KEY", "test-token")
    import requests

    def _raise(*args, **kwargs):
        raise requests.ConnectionError("simulated network failure")

    monkeypatch.setattr(requests, "post", _raise)
    r = check_safety(input_text="hello")
    assert r is None
    reason = get_last_failure_reason("check_safety")
    assert reason is not None
    assert reason.startswith(_FAILURE_HTTP_EXCEPTION)
    assert "ConnectionError" in reason


# ── HTTP non-2xx reason ───────────────────────────────────────────


def test_check_safety_records_http_status(monkeypatch):
    monkeypatch.setenv("FIDDLER_API_KEY", "test-token")
    import requests

    class _Resp:
        status_code = 401
        text = "unauthorized"

    monkeypatch.setattr(requests, "post", lambda *a, **kw: _Resp())
    r = check_safety(input_text="hello")
    assert r is None
    reason = get_last_failure_reason("check_safety")
    assert reason is not None
    assert reason.startswith(_FAILURE_HTTP_STATUS)
    assert "401" in reason


# ── JSON parse reason ─────────────────────────────────────────────


def test_check_safety_records_json_parse(monkeypatch):
    monkeypatch.setenv("FIDDLER_API_KEY", "test-token")
    import requests

    class _Resp:
        status_code = 200
        text = "not-json"

        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(requests, "post", lambda *a, **kw: _Resp())
    r = check_safety(input_text="hello")
    assert r is None
    assert get_last_failure_reason("check_safety") == _FAILURE_JSON_PARSE


# ── Cleared on success ────────────────────────────────────────────


def test_failure_reason_cleared_on_success(monkeypatch):
    """Once check_safety succeeds, get_last_failure_reason returns None
    even if a prior call recorded a reason."""
    # First call: no key → records no_api_key
    r1 = check_safety(input_text="hello")
    assert r1 is None
    assert get_last_failure_reason("check_safety") == _FAILURE_NO_API_KEY

    # Second call: key present, mocked successful response
    monkeypatch.setenv("FIDDLER_API_KEY", "test-token")
    import requests

    class _Resp:
        status_code = 200
        text = "{}"

        def json(self):
            return {k: 0.1 for k in (
                "fdl_jailbreaking", "fdl_roleplaying", "fdl_illegal",
                "fdl_hateful", "fdl_harassing", "fdl_racist",
                "fdl_sexist", "fdl_violent", "fdl_sexual",
                "fdl_harmful", "fdl_unethical",
            )}

    monkeypatch.setattr(requests, "post", lambda *a, **kw: _Resp())
    r2 = check_safety(input_text="hello")
    assert r2 is not None
    assert get_last_failure_reason("check_safety") is None


# ── Per-function isolation ────────────────────────────────────────


def test_safety_and_faithfulness_reasons_are_independent(monkeypatch):
    """The two functions record on independent keys — a safety failure
    doesn't leak into faithfulness reads, and vice versa."""
    r1 = check_safety(input_text="hello")
    assert r1 is None
    assert get_last_failure_reason("check_safety") == _FAILURE_NO_API_KEY
    assert get_last_failure_reason("check_faithfulness") is None

    _clear_failure("check_safety")
    r2 = check_faithfulness(response_text="x", context="y")
    assert r2 is None
    assert get_last_failure_reason("check_faithfulness") == _FAILURE_NO_API_KEY
    assert get_last_failure_reason("check_safety") is None


# ── Orchestrator integration ──────────────────────────────────────


def test_judge_fiddler_safety_surfaces_specific_reason():
    """JudgeResult.error and JudgeResult.detail['failure_reason'] both
    carry the specific reason from check_safety, not the generic
    'fiddler API unavailable' that operators couldn't act on."""
    from kya.scorer_orchestrator import _judge_fiddler_safety

    # No FIDDLER_API_KEY in env (cleared by autouse fixture)
    result = _judge_fiddler_safety("hello", "ignored", None)
    assert result.verdict == "ERROR"
    assert _FAILURE_NO_API_KEY in result.error
    assert result.detail["failure_reason"] == _FAILURE_NO_API_KEY


def test_judge_fiddler_faithfulness_surfaces_specific_reason():
    from kya.scorer_orchestrator import _judge_fiddler_faithfulness

    result = _judge_fiddler_faithfulness("input", "response", "context")
    assert result.verdict == "ERROR"
    assert _FAILURE_NO_API_KEY in result.error
    assert result.detail["failure_reason"] == _FAILURE_NO_API_KEY
