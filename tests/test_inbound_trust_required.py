"""Regression tests for the "no implicit trust" policy in kya.inbound.

KYA v0.1 ships with an empty DEFAULT_PINNED_KEYS. The inbound apply
path (enable_inbound and fetch_now) MUST hard-refuse with RuntimeError
when no trust anchors are configured, rather than silently no-op.

See: docs/PYPI_RELEASE_CHECKLIST.md item 2; commit (Option B chosen
over shipping a vendor key in v0.1).
"""

from __future__ import annotations

import os

import pytest


def _clear_env_keys():
    """Wipe any KYA_INBOUND_PUBLIC_KEY left by other tests."""
    os.environ.pop("KYA_INBOUND_PUBLIC_KEY", None)


def test_require_trusted_keys_raises_when_empty():
    """The helper itself refuses cleanly when nothing is pinned."""
    _clear_env_keys()
    from kya._inbound_signing import require_trusted_keys

    with pytest.raises(RuntimeError, match="no trust anchors configured"):
        require_trusted_keys()


def test_trusted_keys_quiet_getter_still_returns_empty():
    """trusted_keys() must stay non-raising — inbound_status() depends on it."""
    _clear_env_keys()
    from kya._inbound_signing import trusted_keys

    assert trusted_keys() == {}


def test_require_trusted_keys_accepts_env_pinned_key():
    """When KYA_INBOUND_PUBLIC_KEY is set, require_trusted_keys() succeeds."""
    os.environ["KYA_INBOUND_PUBLIC_KEY"] = "test-key:" + ("A" * 44)
    try:
        from kya._inbound_signing import require_trusted_keys
        keys = require_trusted_keys()
        assert "test-key" in keys
    finally:
        _clear_env_keys()


def test_enable_inbound_refuses_without_trust_anchor():
    """enable_inbound MUST refuse to start the daemon if no keys pinned."""
    _clear_env_keys()
    from kya import enable_inbound

    def _db_factory():
        raise AssertionError("db_factory must not be called when refusing to start")

    with pytest.raises(RuntimeError, match="no trust anchors configured"):
        enable_inbound(_db_factory, collector_url="https://collector.invalid")


def test_fetch_now_refuses_without_trust_anchor():
    """fetch_now MUST refuse BEFORE any HTTP request when no keys pinned."""
    _clear_env_keys()
    from kya.inbound import fetch_now

    # If the trust check is missing or out of order, this would try
    # to import `requests` and hit the (invalid) collector URL. The
    # refusal must fire before that happens.
    class _DB:
        def execute(self, *a, **kw):
            raise AssertionError("DB must not be touched on hard-refuse")

        def commit(self):
            raise AssertionError("DB must not be touched on hard-refuse")

    with pytest.raises(RuntimeError, match="no trust anchors configured"):
        fetch_now(_DB(), collector_url="https://collector.invalid")
