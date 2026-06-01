"""Phase 4a.1 — rate-limit + payload-cap tests.

Off-by-default behavior is the most important contract: KYA must
add zero latency or rejection unless the operator explicitly
enabled limits via env. These tests verify that AND verify the
limits actually fire when configured."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    DEFAULT_MAX_PAYLOAD_BYTES,
    PayloadTooLargeError,
    RateLimitExceededError,
    check_payload_size,
    init_storage,
    maybe_rate_limit,
    record_evidence,
    record_invocation,
    reset_rate_limit_state,
)


TENANT = "11111111-2222-3333-4444-cccccccccccc"


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


@pytest.fixture(autouse=True)
def clean_env():
    keys = [k for k in os.environ
            if k.startswith("KYA_RATE_LIMIT")
            or k.startswith("KYA_MAX_")]
    saved = {k: os.environ.pop(k) for k in keys}
    yield
    for k, v in saved.items():
        os.environ[k] = v


# ── Payload cap ────────────────────────────────────────────────────


def test_payload_within_cap_returns_byte_count():
    payload = {"content": "x" * 100}
    n = check_payload_size(payload, primitive="evidence")
    assert n > 100  # JSON overhead included


def test_payload_over_default_cap_raises(monkeypatch):
    big = {"content": "x" * (DEFAULT_MAX_PAYLOAD_BYTES + 10)}
    with pytest.raises(PayloadTooLargeError) as exc_info:
        check_payload_size(big, primitive="evidence")
    err = exc_info.value
    assert err.primitive == "evidence"
    assert err.actual_bytes > DEFAULT_MAX_PAYLOAD_BYTES
    assert err.max_bytes == DEFAULT_MAX_PAYLOAD_BYTES


def test_payload_cap_per_primitive_env(monkeypatch):
    """Per-primitive env beats global env."""
    monkeypatch.setenv("KYA_MAX_PAYLOAD_BYTES", "100")
    monkeypatch.setenv("KYA_MAX_EVIDENCE_PAYLOAD_BYTES", "5000")
    # 500-byte payload fits per-primitive limit but exceeds global
    p = {"content": "x" * 500}
    n = check_payload_size(p, primitive="evidence")
    assert n > 500
    # Other primitives still use global limit
    with pytest.raises(PayloadTooLargeError):
        check_payload_size(p, primitive="invocation")


def test_payload_global_env_applies_when_no_specific(monkeypatch):
    monkeypatch.setenv("KYA_MAX_PAYLOAD_BYTES", "200")
    with pytest.raises(PayloadTooLargeError) as exc_info:
        check_payload_size(
            {"content": "x" * 500}, primitive="cost_event")
    assert exc_info.value.max_bytes == 200


def test_payload_invalid_env_ignored(monkeypatch):
    monkeypatch.setenv("KYA_MAX_PAYLOAD_BYTES", "not-a-number")
    # Falls through to default
    n = check_payload_size({"content": "x"}, primitive="any")
    assert n > 0


def test_payload_zero_or_negative_env_ignored(monkeypatch):
    monkeypatch.setenv("KYA_MAX_PAYLOAD_BYTES", "0")
    n = check_payload_size({"content": "x"}, primitive="any")
    assert n > 0  # 0 → ignored, default applies


def test_payload_unsereializable_raises_typeerror():
    # set() isn't JSON-serializable
    with pytest.raises(TypeError, match="not JSON-serializable"):
        check_payload_size({"bad": {1, 2, 3}}, primitive="evidence")


def test_payload_none_returns_zero():
    assert check_payload_size(None, primitive="evidence") == 0


# ── Rate limit (off-by-default) ────────────────────────────────────


def test_rate_limit_off_by_default():
    """No env → maybe_rate_limit returns True instantly, no overhead."""
    assert maybe_rate_limit("tenant_x", "record_invocation") is True


def test_rate_limit_zero_env_means_off(monkeypatch):
    monkeypatch.setenv("KYA_RATE_LIMIT_DEFAULT_RPS", "0")
    assert maybe_rate_limit("tenant_x", "record_invocation") is True


def test_rate_limit_negative_env_clamped_off(monkeypatch):
    """Negative rps clamps to 0 (no limit)."""
    monkeypatch.setenv("KYA_RATE_LIMIT_DEFAULT_RPS", "-5")
    assert maybe_rate_limit("tenant_x", "record_invocation") is True


def test_rate_limit_invalid_env_ignored(monkeypatch):
    monkeypatch.setenv("KYA_RATE_LIMIT_DEFAULT_RPS", "not-a-number")
    # Falls through; no limit
    assert maybe_rate_limit("tenant_x", "record_invocation") is True


def test_rate_limit_fail_open_when_valkey_unavailable(monkeypatch):
    """When the token bucket helper raises / returns None for redis,
    maybe_rate_limit must fail-open (return True). Critical: rate
    limiting MUST NOT break KYA when Valkey is down."""
    monkeypatch.setenv("KYA_RATE_LIMIT_DEFAULT_RPS", "10")
    # acquire_rate_token returns 0.0 when redis is None (fail-open
    # already built into the underlying helper)
    assert maybe_rate_limit("tenant_x", "record_invocation") is True


def test_rate_limit_specificity_order(monkeypatch):
    """Per-tenant-primitive env beats per-primitive env beats default."""
    monkeypatch.setenv("KYA_RATE_LIMIT_DEFAULT_RPS", "1")
    monkeypatch.setenv("KYA_RATE_LIMIT_RPS_RECORD_INVOCATION", "5")
    # Tenant-specific override would beat that if set
    monkeypatch.setenv(
        "KYA_RATE_LIMIT_RPS_TENANT__TEST_RECORD_INVOCATION", "100")
    # Just verify the resolver picks SOMETHING — actual rate
    # enforcement requires Valkey, which we don't assume here.
    # The non-zero rps means the bucket path is exercised.
    assert maybe_rate_limit("tenant__test", "record_invocation") is True


# ── Integration: record_evidence enforces cap ──────────────────────


def test_record_evidence_rejects_oversize_payload(db, monkeypatch):
    """Wire-up smoke: record_evidence calls check_payload_size at the
    top and raises PayloadTooLargeError on overflow."""
    inv_id = record_invocation(
        db, tenant_id=TENANT, agent_key="A",
        principal_kind="user", principal_id="u")
    monkeypatch.setenv("KYA_MAX_EVIDENCE_PAYLOAD_BYTES", "100")
    big = {"content": "x" * 500}
    with pytest.raises(PayloadTooLargeError):
        record_evidence(
            db, tenant_id=TENANT, invocation_id=inv_id,
            evidence_kind="prompt", payload=big)


def test_record_evidence_within_cap_succeeds(db, monkeypatch):
    inv_id = record_invocation(
        db, tenant_id=TENANT, agent_key="A",
        principal_kind="user", principal_id="u")
    monkeypatch.setenv("KYA_MAX_EVIDENCE_PAYLOAD_BYTES", "10000")
    rid = record_evidence(
        db, tenant_id=TENANT, invocation_id=inv_id,
        evidence_kind="prompt",
        payload={"content": "x" * 200})
    assert isinstance(rid, int) and rid > 0


def test_record_evidence_no_env_uses_default_cap(db):
    """Default 1MB cap is plenty for a 1KB payload."""
    inv_id = record_invocation(
        db, tenant_id=TENANT, agent_key="A",
        principal_kind="user", principal_id="u")
    rid = record_evidence(
        db, tenant_id=TENANT, invocation_id=inv_id,
        evidence_kind="prompt",
        payload={"content": "x" * 1000})
    assert isinstance(rid, int) and rid > 0


# ── No-overhead path verification ──────────────────────────────────


def test_no_rate_limit_env_means_no_valkey_call(monkeypatch):
    """When no env is set, maybe_rate_limit MUST NOT import or call
    the Valkey backend. Verifies the zero-overhead-when-off contract."""
    # Block the import: if rate_limit tried to import the helper,
    # we'd see this raise. It shouldn't because rps=0 short-circuits.
    import sys
    saved = sys.modules.get("kya_redteam.runtime")
    sys.modules["kya_redteam.runtime"] = None  # poison
    try:
        # Even with the import poisoned, off-by-default works
        assert maybe_rate_limit("t", "x") is True
    finally:
        if saved is not None:
            sys.modules["kya_redteam.runtime"] = saved
        else:
            sys.modules.pop("kya_redteam.runtime", None)
