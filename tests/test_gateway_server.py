"""End-to-end tests for kya_gateway.server (POST /mcp etc.).

Covers B3 (JSON-RPC notifications return 204), B8 (invocation_id passed
to policy pipeline), B9 (config errors include backend index), B15 (IPv6
bind parsing), plus the deny/allow/require_human → HTTP code mapping
that has zero prior test coverage.
"""
from __future__ import annotations

import json
import os
import sys
import types

import pytest

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"

from fastapi.testclient import TestClient

from kya_gateway.config import (
    AuditConfig,
    BackendConfig,
    EnforcementConfig,
    GatewayBindConfig,
    GatewayConfig,
    IdentityConfig,
    JWTConfig,
    PolicyConfig,
    PayloadCapsConfig,
    RBACConfig,
    RBACRule,
)
from kya_gateway.identity import BoundPrincipal
from kya_gateway.policy_pipeline import Verdict
from kya_gateway.server import Gateway, build_app


# ─── Fixtures ────────────────────────────────────────────────────────


def _patch_kya_core(monkeypatch, *, invocation_id_returned=12345,
                     record_evidence_calls=None,
                     record_signal_calls=None):
    """Install a stub `kya` module so the gateway doesn't need a real DB."""
    if record_evidence_calls is None:
        record_evidence_calls = []
    if record_signal_calls is None:
        record_signal_calls = []

    class _Session:
        def __init__(self):
            self.committed = False
        def commit(self):
            self.committed = True
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    def default_session():
        return _Session()

    def record_invocation(db, **kw):
        return invocation_id_returned

    def record_evidence(db, **kw):
        record_evidence_calls.append(kw)
        return 1

    def record_principal_signal(db, **kw):
        record_signal_calls.append(kw)
        return 1

    class AccessDeniedError(Exception):
        pass

    def require_action(*args, **kw):
        pass

    fake_kya = types.ModuleType("kya")
    fake_kya.default_session = default_session
    fake_kya.record_invocation = record_invocation
    fake_kya.record_evidence = record_evidence
    fake_kya.record_principal_signal = record_principal_signal
    fake_kya.AccessDeniedError = AccessDeniedError
    fake_kya.require_action = require_action
    monkeypatch.setitem(sys.modules, "kya", fake_kya)
    return {
        "evidence": record_evidence_calls,
        "signals": record_signal_calls,
    }


def _patch_identity_to(monkeypatch, principal):
    """Replace IdentityResolver.resolve to return ``principal`` unconditionally."""
    from kya_gateway import identity as _identity_mod
    monkeypatch.setattr(
        _identity_mod.IdentityResolver,
        "resolve",
        lambda self, headers: principal,
    )


def _patch_forwarder_to_echo(monkeypatch, status_code=200, body=b'{"ok":true}'):
    """Replace Forwarder.forward_json with an echo that records the call."""
    from kya_gateway import forwarder as _fwd_mod
    captured = {"calls": []}

    async def fake_forward_json(self, backend_name, payload, **_kwargs):
        captured["calls"].append({"backend": backend_name, "payload": payload})
        return _fwd_mod.ForwardResult(
            status_code=status_code,
            body=body,
            headers={"content-type": "application/json"},
        )

    monkeypatch.setattr(_fwd_mod.Forwarder, "forward_json", fake_forward_json)
    return captured


def _build_gateway(*, rbac=None, payload_caps=None, methods=("bearer_jwt",),
                   enforcement_mode="audit_only"):
    return GatewayConfig(
        gateway=GatewayBindConfig(bind="0.0.0.0:8080", tenant_id="t1"),
        identity=IdentityConfig(methods=list(methods), jwt=JWTConfig()),
        backends=[BackendConfig(name="default", url="http://localhost:9001")],
        policy=PolicyConfig(rbac=rbac, payload_caps=payload_caps),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode=enforcement_mode),
    )


def _principal():
    return BoundPrincipal(
        principal_kind="agent",
        principal_id="planner",
        method="bearer_jwt",
        external_subject="planner",
        external_issuer=None,
    )


def _post_mcp(client, body):
    return client.post("/mcp", data=json.dumps(body),
                       headers={"Content-Type": "application/json",
                                "Authorization": "Bearer dummy"})


# ─── B8: record_invocation must run BEFORE policy pipeline ───────────


def test_invocation_id_passed_to_policy_pipeline(monkeypatch):
    """The server must record_invocation FIRST and pass the resulting id
    into evaluate_policy — otherwise replay protection is dead code."""
    _patch_kya_core(monkeypatch, invocation_id_returned=42)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    captured: dict = {}

    def fake_evaluate(**kw):
        captured.update(kw)
        return Verdict(verdict="allow", reason_codes=[], signal_kind="clean_invocation")

    from kya_gateway import server as _server
    monkeypatch.setattr(_server, "evaluate_policy", fake_evaluate)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    r = _post_mcp(client, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {}},
    })
    assert r.status_code == 200, r.text
    assert captured.get("invocation_id") == 42, (
        f"invocation_id not wired into policy pipeline: {captured}"
    )


# ─── B3: notifications return 204, never an envelope ────────────────


def test_notification_returns_204_no_body(monkeypatch):
    """JSON-RPC notification (no id) must NOT get a response envelope back.

    Per JSON-RPC 2.0 §4.1 — server MUST NOT reply to notifications.
    Today the server returns full envelopes with id:null even for
    notifications, which violates the spec.
    """
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    # Notification: jsonrpc + method + (optional params), NO id.
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 5},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code == 204, f"expected 204, got {r.status_code}: {r.text!r}"
    assert r.content in (b"", b" "), f"notification leaked body: {r.content!r}"


# ─── Verdict → HTTP code mapping ────────────────────────────────────


def test_deny_returns_403_with_jsonrpc_error(monkeypatch):
    """An RBAC deny verdict must surface as HTTP 403 + JSON-RPC -32001."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    # Pre-5g default was implicit "enforce". With the 5g shift to
    # `audit_only` default, this regression test opts back in.
    cfg = _build_gateway(rbac=RBACConfig(default="deny", rules=[]),
                          enforcement_mode="enforce")
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    r = _post_mcp(client, {
        "jsonrpc": "2.0", "id": 99, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {}},
    })
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["error"]["code"] == -32001
    assert "RBAC_DENY" in body["error"]["data"]["reason_codes"]


def test_require_human_returns_428_with_verdict_data(monkeypatch):
    """Phase 5g-tail — require_human verdict surfaces as HTTP 428
    Precondition Required (RFC 6585 §3) + JSON-RPC -32007, with the
    structured `data.verdict='require_human'` for clients.
    The 5g-tail rename from 403 reflects semantics: the action isn't
    permanently denied, it needs a precondition (human approval)."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    cfg = _build_gateway(rbac=RBACConfig(default="deny", rules=[
        RBACRule(principal_kind="agent",
                 actions=["mcp.filesystem.delete_file"],
                 verdict="require_human"),
    ]), enforcement_mode="enforce")
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    r = _post_mcp(client, {
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "filesystem.delete_file", "arguments": {}},
    })
    # Phase 5g-tail — require_human now returns 428 (RFC 6585 §3) with
    # the distinct -32007 JSON-RPC code, NOT 403/-32001.
    assert r.status_code == 428, r.text
    body = r.json()
    assert body["error"]["code"] == -32007
    assert body["error"]["data"]["verdict"] == "require_human"


def test_allow_forwards_to_backend(monkeypatch):
    """Allow verdict → backend body is returned to caller."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    captured = _patch_forwarder_to_echo(monkeypatch, body=b'{"result":"hello"}')

    cfg = _build_gateway(rbac=RBACConfig(default="deny", rules=[
        RBACRule(principal_kind="agent",
                 actions=["mcp.filesystem.read_file"],
                 verdict="allow"),
    ]))
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    r = _post_mcp(client, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read_file", "arguments": {}},
    })
    assert r.status_code == 200, r.text
    assert b"hello" in r.content
    assert len(captured["calls"]) == 1
    assert captured["calls"][0]["backend"] == "filesystem"


# ─── B2 end-to-end: RBAC rule matching the canonical action form ────


def test_rbac_rule_actually_matches_canonical_action(monkeypatch):
    """An RBAC rule for `mcp.filesystem.read_file` must match a tools/call
    with name=`filesystem.read_file`. Pre-fix, the action was built as
    `mcp.filesystem.filesystem.read_file` and the rule silently never
    matched, leaving the call to fall through to the default deny.
    """
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    cfg = _build_gateway(rbac=RBACConfig(default="deny", rules=[
        RBACRule(principal_kind="agent",
                 actions=["mcp.filesystem.read_file"],
                 verdict="allow"),
    ]))
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    r = _post_mcp(client, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read_file", "arguments": {}},
    })
    # Should be 200 (allow), not 403 (default deny).
    assert r.status_code == 200, (
        f"RBAC rule did not match canonical action — got {r.status_code} "
        f"with body {r.text!r}"
    )


# ─── Health / liveness ──────────────────────────────────────────────


def test_healthz_returns_ok():
    cfg = _build_gateway()
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ─── B15: IPv6 bind parsing must not crash ──────────────────────────


def test_ipv6_bind_parses_without_crash():
    """`[::1]:8080` bind string must produce host='::1', port=8080.

    Pre-fix, str.partition(':') on '[::1]:8080' returned ('[', ':', ':1]:8080')
    leading to int(':1]:8080') ValueError at startup.
    """
    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="[::1]:8080", tenant_id="t1"),
        identity=IdentityConfig(methods=["bearer_jwt"], jwt=JWTConfig()),
        backends=[BackendConfig(name="default", url="http://localhost:9001")],
        policy=PolicyConfig(),
        audit=AuditConfig(),
    )
    gw = Gateway(cfg)
    # Don't actually start uvicorn — just probe the parser.
    from kya_gateway.server import _parse_bind  # added in fix
    host, port = _parse_bind(cfg.gateway.bind)
    assert host == "::1"
    assert port == 8080


def test_plain_bare_port_rejected():
    """A bind string like '8080' (no colon) must produce a clear error."""
    from kya_gateway.server import _parse_bind
    with pytest.raises(ValueError, match=r"(?i)bind"):
        _parse_bind("8080")


# ─── Body size limit (defense against 1 GB body DoS) ────────────────


def test_http_body_over_hard_cap_returns_413_before_policy(monkeypatch):
    """A request body exceeding the HTTP-layer hard cap must return 413
    BEFORE identity / policy run.

    Critically: identity is patched to RAISE — if the gateway lets the body
    through to policy, the test would 401 (identity failure) not 413.
    A 413 proves the body cap fired at the HTTP boundary.
    """
    from kya_gateway import server as _server

    # Make identity raise so any path past the body cap would 401.
    def boom_identity(self, headers):
        raise RuntimeError("identity must not be reached when body is too big")
    monkeypatch.setattr(_server.IdentityResolver, "resolve", boom_identity)

    # Shrink the hard cap so the test stays fast.
    monkeypatch.setattr(_server, "_MAX_HTTP_BODY_BYTES", 1024)

    cfg = _build_gateway()
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    big_body = b'{"jsonrpc":"2.0","id":1,"method":"tools/call",' \
               b'"params":{"name":"x","arguments":{"x":"' + b"A" * 2048 + b'"}}}'
    r = client.post("/mcp", content=big_body,
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413, (
        f"HTTP body cap did not fire BEFORE policy — got {r.status_code}: {r.text!r}"
    )


def test_http_body_content_length_over_cap_returns_413(monkeypatch):
    """When Content-Length declares > cap, reject without reading the body."""
    from kya_gateway import server as _server
    monkeypatch.setattr(_server, "_MAX_HTTP_BODY_BYTES", 1024)

    cfg = _build_gateway()
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    # 100 KB body, cap 1 KB.
    r = client.post("/mcp", content=b"A" * (100 * 1024),
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_policy_payload_caps_still_fires_within_http_cap(monkeypatch):
    """Within the HTTP hard cap, policy.payload_caps still fires when set
    smaller. The HTTP cap and policy cap are TWO independent defenses."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    cfg = _build_gateway(payload_caps=PayloadCapsConfig(max_bytes=512),
                          enforcement_mode="enforce")
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    args = {"x": "A" * 2048}
    r = _post_mcp(client, {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": args},
    })
    assert r.status_code == 403
    body = r.json()
    assert "PAYLOAD_TOO_LARGE" in body["error"]["data"]["reason_codes"]


# ─── /v1/principals/me rate limit ───────────────────────────────────


def test_rate_limit_tracking_dict_is_bounded(monkeypatch):
    """The per-IP rate limit dict must NOT grow unboundedly.

    Attacker that rotates X-Forwarded-For (or behind churning NAT) could
    otherwise OOM the gateway by exhausting the tracking dict.
    """
    from kya_gateway import server as _server
    # Reset state and shrink the cap so the test stays fast.
    _server._ME_RATE_WINDOWS.clear()
    monkeypatch.setattr(_server, "_ME_RATE_MAX_TRACKED_IPS", 50)

    # Synthetically dial through 200 IPs — much more than the cap.
    for i in range(200):
        _server._me_rate_limit_check(f"10.0.{i // 256}.{i % 256}")

    assert len(_server._ME_RATE_WINDOWS) <= 50, (
        f"rate-limit tracking dict grew to {len(_server._ME_RATE_WINDOWS)} "
        f"entries — must be bounded at 50"
    )


def test_principals_me_per_ip_rate_limit(monkeypatch):
    """/v1/principals/me must be rate-limited per source IP, otherwise
    it's a free credential-validation oracle."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    # Hammer the endpoint. Default limit is 60/min — 70 calls should
    # hit the cap.
    statuses = set()
    for _ in range(70):
        r = client.get("/v1/principals/me",
                       headers={"Authorization": "Bearer dummy"})
        statuses.add(r.status_code)
    assert 429 in statuses, (
        f"/v1/principals/me not rate-limited — saw statuses {statuses}"
    )


# ─── B9: config error names the backend index ───────────────────────


# ─── Phase 6: strict envelope schema for /mcp ────────────────────────


def test_envelope_with_extra_top_level_key_rejected(monkeypatch):
    """Bodies with unexpected top-level keys must be rejected as -32600."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {}},
        "extra_key": "evil",
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == -32600


def test_envelope_with_params_as_array_rejected(monkeypatch):
    """MCP requires params as a named object — array form must reject."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": ["positional", "args"],
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32600


def test_envelope_with_unknown_method_returns_method_not_found(monkeypatch):
    """Methods outside the MCP allowlist must return -32601."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "evil/exfiltrate",
        "params": {},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code in (400, 404), r.text
    assert r.json()["error"]["code"] == -32601


def test_envelope_with_deeply_nested_arguments_rejected(monkeypatch):
    """params.arguments depth > 8 must be rejected as -32600."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    # Build a 12-deep nest.
    deep = "value"
    for _ in range(12):
        deep = {"x": deep}

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": deep},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32600


def test_envelope_with_oversized_name_rejected(monkeypatch):
    """An attacker-controlled `params.name` of 10 MB must be rejected.

    Pre-fix, `_check_arguments_shape` only bounded `params.arguments`.
    `params.name` flowed through unbounded → action string → policy →
    evidence audit row. A 10 MB action exhausts the policy engine and
    persists garbage. Real exploit reported by review.
    """
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    huge_name = "A" * 100_000   # 100 KB string, far over 16 KB cap
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": huge_name, "arguments": {}},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == -32600


def test_envelope_with_integer_bomb_rejected(monkeypatch):
    """An attacker-supplied huge integer (Python has unbounded int
    precision) must be rejected. JSON like `"x": 10**5000` parses to a
    Python int with O(n) digit count and triggers O(n²) ops downstream.
    """
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    huge_int = 10 ** 1000  # ~3320-bit integer
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "x", "arguments": {"big": huge_int}},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == -32600


def test_envelope_with_integer_bomb_inside_list_rejected(monkeypatch):
    """An attacker-supplied huge int inside a LIST element must also be
    rejected — the recursive shape check must traverse list values."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "x", "arguments": {"xs": [10 ** 1000]}},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32600


def test_method_allowlist_positive_enumeration(monkeypatch):
    """Pin the spec-aligned methods so an accidental deletion of any
    entry surfaces as a test failure, not silent runtime breakage."""
    from kya_gateway.mcp_protocol import _ALLOWED_METHODS
    expected_minimum = {
        "initialize", "ping",
        "tools/list", "tools/call",
        "resources/list", "resources/read",
        "prompts/list", "prompts/get",
        "notifications/cancelled", "notifications/progress",
        "notifications/initialized",
    }
    missing = expected_minimum - _ALLOWED_METHODS
    assert not missing, (
        f"MCP method allowlist regressed — missing: {sorted(missing)}"
    )


def test_envelope_with_oversized_string_in_arguments_rejected(monkeypatch):
    """A single string > 16 KB in arguments must be rejected."""
    _patch_kya_core(monkeypatch)
    _patch_identity_to(monkeypatch, _principal())
    _patch_forwarder_to_echo(monkeypatch)

    gw = Gateway(_build_gateway())
    client = TestClient(gw.app)
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read",
                   "arguments": {"path": "A" * 20000}},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32600


def test_config_error_includes_backend_index():
    """Missing field in backends[2] must mention 'backends[2]', not just
    KeyError on the field name."""
    from kya_gateway.errors import GatewayConfigError
    raw = {
        "gateway": {"bind": "0.0.0.0:8080", "tenant_id": "t1"},
        "identity": {"methods": ["bearer_jwt"]},
        "backends": [
            {"name": "ok1", "url": "http://x"},
            {"name": "ok2", "url": "http://y"},
            {"url": "http://z"},  # ← missing 'name'
        ],
        "policy": {},
        "audit": {},
    }
    with pytest.raises(GatewayConfigError, match=r"backends\[2\]"):
        GatewayConfig.from_dict(raw)
