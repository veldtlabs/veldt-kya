"""Phase 5a — replay protection tests.

Off-by-default is the most important contract: KYA must add zero
behavior unless KYA_REPLAY_PROTECTION is explicitly enabled. These
tests verify both the off-by-default no-op path AND the actual
replay detection when configured."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from kya import (
    ReplayDetectedError,
    generate_nonce,
    is_valid_nonce,
    reset_replay_state,
    verify_request_nonce,
)


TENANT = "11111111-2222-3333-4444-dddddddddddd"
PRINCIPAL = "alice_internal"


@pytest.fixture(autouse=True)
def clean_env():
    keys = [k for k in list(os.environ.keys())
            if k.startswith("KYA_REPLAY")]
    saved = {k: os.environ.pop(k) for k in keys}
    yield
    for k, v in saved.items():
        os.environ[k] = v
    reset_replay_state()


# ── Off-by-default contract ───────────────────────────────────────


def test_replay_off_by_default():
    """No env → verify_request_nonce returns True immediately."""
    # Even with the same nonce twice — no check fires
    n = generate_nonce()
    assert verify_request_nonce(
        tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is True
    assert verify_request_nonce(
        tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is True


def test_replay_off_env_variants_are_off():
    """Various 'off'-style env values all keep protection disabled."""
    for off_val in ("off", "0", "false", "no", "disabled", ""):
        os.environ["KYA_REPLAY_PROTECTION"] = off_val
        n = generate_nonce()
        # Should not check — both calls succeed even with same nonce
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is True
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is True


# ── Nonce structural validation ───────────────────────────────────


def test_generate_nonce_produces_valid():
    for _ in range(5):
        n = generate_nonce()
        assert is_valid_nonce(n)
        assert len(n) == 32  # token_hex(16) = 32 chars


def test_invalid_nonce_shapes():
    assert not is_valid_nonce("")
    assert not is_valid_nonce("short")           # < 8
    assert not is_valid_nonce("x" * 257)         # > 256
    assert not is_valid_nonce("has space")       # whitespace
    assert not is_valid_nonce("has\ttab")        # whitespace
    assert not is_valid_nonce(None)              # type
    assert not is_valid_nonce(b"bytes")          # type
    # Valid:
    assert is_valid_nonce("abcd1234abcd1234")
    assert is_valid_nonce("a" * 256)


# ── Input validation (programmer errors → ValueError) ─────────────


def test_missing_tenant_raises(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    with pytest.raises(ValueError, match="tenant_id"):
        verify_request_nonce(
            tenant_id="", principal_id=PRINCIPAL,
            nonce=generate_nonce())


def test_missing_principal_raises(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    with pytest.raises(ValueError, match="principal_id"):
        verify_request_nonce(
            tenant_id=TENANT, principal_id="",
            nonce=generate_nonce())


# ── Replay detection (with mocked Valkey) ─────────────────────────


def _make_fake_redis(initial_keys=None):
    """In-memory fake redis with .set(key, val, nx=True, ex=N) semantics."""
    keys = dict(initial_keys or {})
    fake = MagicMock()
    def _set(key, val, nx=False, ex=None):
        if nx and key in keys:
            return None  # already exists
        keys[key] = val
        return True
    fake.set = _set
    fake.delete = lambda k: keys.pop(k, None)
    def _scan_iter(match=None):
        if match is None:
            return iter(list(keys.keys()))
        # crude glob: only handles trailing '*'
        prefix = match.rstrip("*")
        return iter([k for k in keys if k.startswith(prefix)])
    fake.scan_iter = _scan_iter
    return fake, keys


def test_first_request_accepted_then_replay_rejected(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _store = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        n = generate_nonce()
        # First request succeeds
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is True
        # Replay (same nonce) — rejected (returns False)
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is False


def test_replay_hard_mode_raises(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _store = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        n = generate_nonce()
        verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n)
        with pytest.raises(ReplayDetectedError) as exc_info:
            verify_request_nonce(
                tenant_id=TENANT, principal_id=PRINCIPAL,
                nonce=n, mode="hard")
        err = exc_info.value
        assert err.tenant_id == TENANT
        assert err.principal_id == PRINCIPAL
        assert err.reason == "nonce_already_seen_within_window"


def test_different_principals_can_reuse_nonce(monkeypatch):
    """Same nonce string, two different principals → both accepted."""
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _store = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        n = generate_nonce()
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id="alice", nonce=n) is True
        # Different principal — same nonce — accepted (different scope)
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id="bob", nonce=n) is True


def test_different_tenants_can_reuse_nonce(monkeypatch):
    """Same nonce + same principal, different tenants → both accepted."""
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _store = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        n = generate_nonce()
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is True
        # Same nonce, same principal name, different tenant
        assert verify_request_nonce(
            tenant_id="22222222-2222-2222-2222-222222222222",
            principal_id=PRINCIPAL, nonce=n) is True


# ── Timestamp freshness check ─────────────────────────────────────


def test_timestamp_too_old_rejected(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _store = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        old_ts = (datetime.now(timezone.utc)
                  - timedelta(seconds=600)).isoformat()
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL,
            nonce=generate_nonce(),
            timestamp_iso=old_ts,
            max_age_s=300) is False


def test_timestamp_in_future_rejected(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _store = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        future_ts = (datetime.now(timezone.utc)
                     + timedelta(seconds=600)).isoformat()
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL,
            nonce=generate_nonce(),
            timestamp_iso=future_ts,
            max_age_s=300) is False


def test_timestamp_within_window_accepted(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _store = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        recent_ts = (datetime.now(timezone.utc)
                     - timedelta(seconds=60)).isoformat()
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL,
            nonce=generate_nonce(),
            timestamp_iso=recent_ts,
            max_age_s=300) is True


def test_malformed_timestamp_rejected(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _store = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL,
            nonce=generate_nonce(),
            timestamp_iso="not a date") is False


# ── Fail-soft when Valkey unavailable ─────────────────────────────


def test_valkey_unavailable_fail_open(monkeypatch):
    """Critical contract: replay protection MUST NOT break KYA when
    Valkey is down. Falls open to True."""
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    with patch("kya._valkey.get_valkey", return_value=None):
        n = generate_nonce()
        # Both calls succeed — no nonce tracking possible
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is True
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL, nonce=n) is True


def test_malformed_nonce_soft_rejected(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _ = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL,
            nonce="") is False
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL,
            nonce="too short") is False


def test_malformed_nonce_hard_raises(monkeypatch):
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    fake, _ = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        with pytest.raises(ReplayDetectedError) as exc_info:
            verify_request_nonce(
                tenant_id=TENANT, principal_id=PRINCIPAL,
                nonce="x", mode="hard")
        assert "malformed_nonce" in str(exc_info.value)


# ── Per-tenant max_age override via env ────────────────────────────


def test_per_tenant_max_age_override(monkeypatch):
    """Per-tenant env overrides global."""
    monkeypatch.setenv("KYA_REPLAY_PROTECTION", "on")
    monkeypatch.setenv("KYA_REPLAY_MAX_AGE_SECONDS", "60")
    safe = TENANT.replace("-", "_").upper()
    monkeypatch.setenv(
        f"KYA_REPLAY_MAX_AGE_SECONDS_{safe}", "600")
    fake, _ = _make_fake_redis()
    with patch("kya._valkey.get_valkey", return_value=fake):
        # Timestamp 300s old: global limit is 60 (would reject),
        # tenant override is 600 (accept)
        ts = (datetime.now(timezone.utc)
              - timedelta(seconds=300)).isoformat()
        assert verify_request_nonce(
            tenant_id=TENANT, principal_id=PRINCIPAL,
            nonce=generate_nonce(),
            timestamp_iso=ts) is True
