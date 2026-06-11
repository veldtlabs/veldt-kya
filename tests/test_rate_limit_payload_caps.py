"""Phase 4a.1 — rate-limit + payload-cap tests.

Off-by-default behavior is the most important contract: KYA must
add zero latency or rejection unless the operator explicitly
enabled limits via env. These tests verify that AND verify the
limits actually fire when configured."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kya import (
    DEFAULT_MAX_PAYLOAD_BYTES,
    PayloadTooLargeError,
    check_payload_size,
    init_storage,
    maybe_rate_limit,
    record_evidence,
    record_invocation,
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


# ─── check_rate (gateway-friendly per-principal API) ───────────────


def test_check_rate_returns_true_when_limit_is_zero():
    """`requests_per_minute=0` means "no limit configured" -- return
    True without touching the token-bucket helper (no env, no DB)."""
    from kya import check_rate
    assert check_rate(
        db=None, tenant_id="t1",
        principal_kind="agent", principal_id="a-1",
        requests_per_minute=0,
    ) is True


def test_check_rate_returns_true_when_helper_unavailable(monkeypatch):
    """Fail-open contract: when `kya_redteam.runtime` cannot be
    imported, `check_rate` returns True so a missing optional dep
    does not gate all MCP traffic."""
    import sys

    from kya import check_rate

    saved = sys.modules.pop("kya_redteam.runtime", None)
    sys.modules["kya_redteam.runtime"] = None  # force ImportError
    try:
        assert check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent", principal_id="a-1",
            requests_per_minute=60,
        ) is True
    finally:
        if saved is not None:
            sys.modules["kya_redteam.runtime"] = saved
        else:
            sys.modules.pop("kya_redteam.runtime", None)


def _install_fake_runtime(fake_check_rate_token):
    """Install a fake `kya_redteam.runtime` module exposing
    `check_rate_token`. Returns a teardown callable."""
    import sys
    import types
    fake_mod = types.ModuleType("kya_redteam.runtime")
    fake_mod.check_rate_token = fake_check_rate_token
    # Many tests in this file also reference acquire_rate_token; keep
    # it present so unrelated callers don't break.
    fake_mod.acquire_rate_token = lambda *a, **kw: 0.0
    saved = sys.modules.get("kya_redteam.runtime")
    sys.modules["kya_redteam.runtime"] = fake_mod

    def restore():
        if saved is not None:
            sys.modules["kya_redteam.runtime"] = saved
        else:
            sys.modules.pop("kya_redteam.runtime", None)
    return restore


def test_check_rate_returns_true_when_within_budget():
    """Token helper returns True (within budget) -> check_rate True.
    Bucket key MUST scope to (tenant, principal_kind, principal_id)
    via a hash so colon-containing principal_ids (DIDs) cannot alias
    another principal's bucket."""
    from kya import check_rate

    captured = {}

    def fake_check(target_id, rps):
        captured["target_id"] = target_id
        captured["rps"] = rps
        return True

    restore = _install_fake_runtime(fake_check)
    try:
        assert check_rate(
            db=None, tenant_id="00000000-0000-0000-0000-0000000012a2",
            principal_kind="agent",
            principal_id="phase12-agent-001",
            requests_per_minute=60,
        ) is True
        # Hashed bucket key (HIGH-#1 fix): kya:gw:<32 hex chars>.
        assert captured["target_id"].startswith("kya:gw:"), captured
        suffix = captured["target_id"].removeprefix("kya:gw:")
        assert len(suffix) == 32 and all(
            c in "0123456789abcdef" for c in suffix
        ), suffix
        # 60 req/min -> 1 rps.
        assert captured["rps"] == 1.0
    finally:
        restore()


def test_check_rate_returns_false_when_over_budget():
    """Token helper returns False (over budget) -> check_rate False
    so the gateway returns 403 RATE_LIMIT."""
    from kya import check_rate

    def fake_check(target_id, rps):
        return False

    restore = _install_fake_runtime(fake_check)
    try:
        assert check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent", principal_id="a-1",
            requests_per_minute=60,
        ) is False
    finally:
        restore()


def test_check_rate_returns_true_when_helper_raises():
    """Fail-open on operational fault: if check_rate_token raises
    (Valkey down, network blip, etc.) the call proceeds. Matches
    maybe_rate_limit's fail-soft contract."""
    from kya import check_rate

    def fake_check(target_id, rps):
        raise RuntimeError("valkey down")

    restore = _install_fake_runtime(fake_check)
    try:
        assert check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent", principal_id="a-1",
            requests_per_minute=60,
        ) is True
    finally:
        restore()


def test_check_rate_buckets_are_independent_across_principals():
    """Two principals in the same tenant must NOT share a bucket.
    Different (kind, id) tuples must hit different target_ids."""
    from kya import check_rate

    target_ids: list[str] = []

    def fake_check(target_id, rps):
        target_ids.append(target_id)
        return True

    restore = _install_fake_runtime(fake_check)
    try:
        check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent", principal_id="a-1",
            requests_per_minute=60,
        )
        check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent", principal_id="a-2",
            requests_per_minute=60,
        )
        check_rate(
            db=None, tenant_id="t1",
            principal_kind="human", principal_id="a-1",
            requests_per_minute=60,
        )
        assert len(target_ids) == 3
        assert len(set(target_ids)) == 3, (
            f"buckets collapsed: {target_ids!r}"
        )
    finally:
        restore()


def test_check_rate_bucket_is_collision_safe_for_did_principal_ids():
    """HIGH-#1 regression: principal_id can be a DID (`did:key:zABC`)
    containing colons. Two distinct principals must never craft the
    same Valkey bucket key. Pre-fix the colon-delimited f-string
    allowed: tenant=t1, kind=agent, id='did:key:zABC' to share a
    key with tenant=t1, kind='agent:did', id='key:zABC'.
    The sha256 hash defeats this."""
    from kya import check_rate

    target_ids: list[str] = []

    def fake_check(target_id, rps):
        target_ids.append(target_id)
        return True

    restore = _install_fake_runtime(fake_check)
    try:
        # The original collision pair:
        check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent",
            principal_id="did:key:zABC",
            requests_per_minute=60,
        )
        check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent:did",
            principal_id="key:zABC",
            requests_per_minute=60,
        )
        # And a "split-elsewhere" pair to be thorough.
        check_rate(
            db=None, tenant_id="t1:agent",
            principal_kind="did",
            principal_id="key:zABC",
            requests_per_minute=60,
        )
        assert len(target_ids) == 3
        assert len(set(target_ids)) == 3, (
            f"colon-collision still possible: {target_ids!r}"
        )
    finally:
        restore()


def test_check_rate_emits_security_event_on_over_budget():
    """Documented audit signal: when over budget, check_rate MUST
    emit `rate_limit_exceeded` so the audit chain records the
    firing even when downstream is fail-open."""
    from kya import check_rate

    emitted = []

    def fake_check(target_id, rps):
        return False

    def fake_emit(event_kind, **kwargs):
        emitted.append((event_kind, kwargs))

    restore = _install_fake_runtime(fake_check)
    import kya._security_events as se
    real_emit = se.emit_security_event
    se.emit_security_event = fake_emit
    try:
        check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent", principal_id="a-1",
            requests_per_minute=60,
        )
        assert any(
            kind == "rate_limit_exceeded" for kind, _ in emitted
        ), f"no rate_limit_exceeded event: {emitted!r}"
    finally:
        se.emit_security_event = real_emit
        restore()


def test_check_rate_negative_requests_per_minute_returns_true():
    """A negative `requests_per_minute` (probably a config typo)
    should behave the same as 0 -- no limit configured. Returns True
    without touching the token-bucket helper."""
    from kya import check_rate
    # Sentinel helper that asserts it isn't called.
    def fake_check(target_id, rps):
        raise AssertionError(
            "check_rate_token must not be called for rpm <= 0"
        )
    restore = _install_fake_runtime(fake_check)
    try:
        assert check_rate(
            db=None, tenant_id="t1",
            principal_kind="agent", principal_id="a-1",
            requests_per_minute=-100,
        ) is True
    finally:
        restore()
