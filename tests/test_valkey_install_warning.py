"""Phase 12 gap #4 regression: when the operator HAS set
KYA_VALKEY_URL / REDIS_URL but redis-py is not installed, the loud
WARNING fires (not the silent DEBUG message).

Pre-fix: a DEBUG-level log was the only signal, so a misconfigured
gateway (gateway extra installed, redis-py missing) silently
fail-opened the rate limiter and revocation cache. Operators only
discovered the degradation when traffic spiked past the budget AND
the limiter never engaged. Phase 12 surfaced this and the loud
WARNING + bundling redis in `[gateway]` extra fixes it.
"""
from __future__ import annotations

import logging
import sys

import pytest


def _reset_valkey_module_state():
    """The accessor caches the resolved client in module-level
    globals. Reset them so each test sees a clean state."""
    import kya._valkey as v
    v._CLIENT = None
    v._CLIENT_RESOLVED = False


@pytest.fixture(autouse=True)
def _reset_state():
    _reset_valkey_module_state()
    yield
    _reset_valkey_module_state()


def test_warning_fires_when_url_set_but_redis_missing(
    caplog, monkeypatch,
):
    """Operator set KYA_VALKEY_URL but redis-py is not importable
    -> WARNING level log so the misconfiguration is visible in
    startup logs."""
    monkeypatch.setenv("KYA_VALKEY_URL", "redis://localhost:6379")
    monkeypatch.delenv("REDIS_URL", raising=False)
    # Force the import to fail.
    saved = sys.modules.pop("redis", None)
    sys.modules["redis"] = None  # makes `import redis` raise

    try:
        from kya._valkey import get_valkey
        with caplog.at_level(logging.WARNING, logger="kya._valkey"):
            client = get_valkey()
        assert client is None
        warning_lines = [
            r.message for r in caplog.records
            if r.levelno >= logging.WARNING
            and "redis-py is not installed" in r.message
        ]
        assert warning_lines, (
            "Expected a WARNING-level log when KYA_VALKEY_URL is set "
            f"but redis-py is missing. Got records: "
            f"{[(r.levelname, r.message) for r in caplog.records]}"
        )
    finally:
        if saved is not None:
            sys.modules["redis"] = saved
        else:
            sys.modules.pop("redis", None)


def test_no_warning_when_url_unset_and_redis_missing(
    caplog, monkeypatch,
):
    """If the operator never set KYA_VALKEY_URL, missing redis-py is
    the expected fast-path -- should remain at DEBUG, not WARNING."""
    monkeypatch.delenv("KYA_VALKEY_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    saved = sys.modules.pop("redis", None)
    sys.modules["redis"] = None

    try:
        from kya._valkey import get_valkey
        with caplog.at_level(logging.DEBUG, logger="kya._valkey"):
            client = get_valkey()
        assert client is None
        warning_lines = [
            r.message for r in caplog.records
            if r.levelno >= logging.WARNING
        ]
        assert not warning_lines, (
            "When no URL is configured, missing redis-py is the "
            f"normal fast path -- should NOT WARN. Got: "
            f"{[(r.levelname, r.message) for r in caplog.records]}"
        )
    finally:
        if saved is not None:
            sys.modules["redis"] = saved
        else:
            sys.modules.pop("redis", None)
