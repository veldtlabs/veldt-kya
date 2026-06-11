"""Phase 5g — regression tests for the review-cycle fixes.

Each test pins one finding from the adversarial review (5g-A-01..12).
A failure here means the corresponding regression has come back.
"""
from __future__ import annotations

import json
import os

import pytest

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"

from fastapi.testclient import TestClient

from kya_gateway.config import (
    AuditConfig, BackendConfig, DIDConfig, EnforcementConfig,
    GatewayBindConfig, GatewayConfig, IdentityConfig, JWTConfig,
    PolicyConfig, RBACConfig,
)
from kya_gateway.errors import GatewayConfigError, IdentityCredentialInvalid
from kya_gateway.identity import BoundPrincipal
from kya_gateway.server import Gateway


def _cfg(mode="audit_only", *, with_rbac_deny=False):
    rbac = RBACConfig(default="deny", rules=[]) if with_rbac_deny else None
    return GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t1"),
        identity=IdentityConfig(
            methods=["bearer_jwt"], jwt=JWTConfig(),
            did=DIDConfig(
                resolvers=["key"], trusted_issuers=[],
                allow_header_trust=True,
                pop_audience="http://testserver/mcp",
                dpop_audience="http://testserver",
                require_dpop_on_me=False,
            ),
        ),
        backends=[BackendConfig(name="default", url="http://localhost:1")],
        policy=PolicyConfig(rbac=rbac),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode=mode),
    )


def _stub_kya(monkeypatch, *, evidence_sink=None, invocation_sink=None):
    import sys
    import types
    fake = types.ModuleType("kya")

    class _Sess:
        def commit(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fake.default_session = lambda: _Sess()

    def rec_inv(db, **kw):
        if invocation_sink is not None:
            invocation_sink.append(kw)
        return 1

    def rec_ev(db, **kw):
        if evidence_sink is not None:
            evidence_sink.append(kw)
        return 1

    fake.record_invocation = rec_inv
    fake.record_evidence = rec_ev
    fake.record_principal_signal = lambda db, **kw: 1
    class _ADE(Exception): pass
    fake.AccessDeniedError = _ADE
    fake.require_action = lambda *a, **k: True
    monkeypatch.setitem(sys.modules, "kya", fake)


def _stub_identity_ok(monkeypatch):
    from kya_gateway import identity as _id_mod
    monkeypatch.setattr(_id_mod.IdentityResolver, "resolve",
                        lambda self, h: BoundPrincipal(
                            principal_kind="agent", principal_id="planner",
                            method="bearer_jwt", external_subject="planner",
                            external_issuer=None,
                        ))


def _stub_identity_fail(monkeypatch):
    from kya_gateway import identity as _id_mod
    def fail(self, h):
        raise IdentityCredentialInvalid("forged JWT signature")
    monkeypatch.setattr(_id_mod.IdentityResolver, "resolve", fail)


def _stub_forwarder(monkeypatch, *, body=b'{"result":"ok"}',
                     content_type="application/json", capture=None):
    from kya_gateway import forwarder as _fwd
    async def fake(self, backend_name, payload, **kwargs):
        if capture is not None:
            capture.append({
                "backend": backend_name,
                "payload": payload,
                "headers": kwargs.get("extra_request_headers") or {},
            })
        return _fwd.ForwardResult(
            status_code=200, body=body,
            headers={"content-type": content_type},
        )
    monkeypatch.setattr(_fwd.Forwarder, "forward_json", fake)


def _post_mcp(client, **kwargs):
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {}},
    }
    body.update(kwargs.get("body", {}))
    return client.post("/mcp", data=json.dumps(body), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer dummy",
    })


# ─── 5g-A-01 — advise merges into JSON-RPC envelope under result, not top ─


def test_advise_merges_under_jsonrpc_result_not_top_level(monkeypatch):
    """JSON-RPC backend body must keep envelope spec-conformant.
    `kya_verdict` at top level corrupts the envelope; must go under `result`."""
    _stub_kya(monkeypatch)
    _stub_identity_ok(monkeypatch)
    _stub_forwarder(
        monkeypatch,
        body=b'{"jsonrpc":"2.0","id":1,"result":{"value":42}}',
    )
    gw = Gateway(_cfg(mode="advise", with_rbac_deny=True))
    r = TestClient(gw.app).post(
        "/mcp",
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call",
                          "params":{"name":"filesystem.read","arguments":{}}}),
        headers={"Content-Type":"application/json",
                 "Authorization":"Bearer dummy"})
    body = r.json()
    # No envelope-poisoning top-level key.
    assert "kya_verdict" not in body, (
        f"top-level kya_verdict pollutes envelope: {body}"
    )
    assert body["jsonrpc"] == "2.0" and body["id"] == 1
    # Verdict lives under result.
    assert body["result"]["kya_verdict"]["verdict"] == "deny"


def test_advise_jsonrpc_error_body_puts_verdict_under_error_data(monkeypatch):
    _stub_kya(monkeypatch)
    _stub_identity_ok(monkeypatch)
    _stub_forwarder(
        monkeypatch,
        body=b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"oops"}}',
    )
    gw = Gateway(_cfg(mode="advise", with_rbac_deny=True))
    r = TestClient(gw.app).post(
        "/mcp",
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call",
                          "params":{"name":"filesystem.read","arguments":{}}}),
        headers={"Content-Type":"application/json","Authorization":"Bearer x"})
    body = r.json()
    assert "kya_verdict" not in body
    assert body["error"]["data"]["kya_verdict"]["verdict"] == "deny"


# ─── 5g-A-02 — backend sees outbound KYA signal headers ──────────────────


def test_audit_only_forwards_kya_headers_to_backend(monkeypatch):
    """Backend must see X-KYA-Verdict + X-KYA-Mode + X-KYA-Principal-Id
    so a backend that trusted "gateway forwarded → authenticated" can
    detect the new permissive behavior."""
    _stub_kya(monkeypatch)
    _stub_identity_fail(monkeypatch)
    capture = []
    _stub_forwarder(monkeypatch, capture=capture)
    gw = Gateway(_cfg(mode="audit_only"))
    r = _post_mcp(TestClient(gw.app))
    assert r.status_code == 200
    assert len(capture) == 1
    fwd_headers = capture[0]["headers"]
    assert fwd_headers.get("X-KYA-Verdict") == "identity_invalid"
    assert fwd_headers.get("X-KYA-Mode") == "audit_only"
    assert fwd_headers.get("X-KYA-Principal-Kind") == "agent"
    assert "kya-unauth" in fwd_headers.get("X-KYA-Principal-Id", "")


def test_enforce_does_not_leak_kya_headers_on_allow(monkeypatch):
    """In enforce mode KYA returns 200/blocks; no need for advisory
    headers on the outbound — keeps the wire clean."""
    _stub_kya(monkeypatch)
    _stub_identity_ok(monkeypatch)
    capture = []
    _stub_forwarder(monkeypatch, capture=capture)
    gw = Gateway(_cfg(mode="enforce"))
    _post_mcp(TestClient(gw.app))
    assert capture[0]["headers"] == {}


# ─── 5g-A-03 — distinct bad credentials → distinct principal_ids ─────────


def test_distinct_bad_credentials_get_distinct_principal_ids(monkeypatch):
    """Two different bad credentials must hash to different agent_keys
    so replay-protection / rate-limit accounting doesn't collapse them
    into one shared lineage."""
    _stub_kya(monkeypatch)
    _stub_identity_fail(monkeypatch)
    capture = []
    _stub_forwarder(monkeypatch, capture=capture)
    gw = Gateway(_cfg(mode="audit_only"))
    client = TestClient(gw.app)
    r1 = client.post("/mcp",
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call",
                          "params":{"name":"filesystem.read","arguments":{}}}),
        headers={"Content-Type":"application/json",
                 "Authorization":"Bearer attacker-token-A"})
    r2 = client.post("/mcp",
        data=json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/call",
                          "params":{"name":"filesystem.read","arguments":{}}}),
        headers={"Content-Type":"application/json",
                 "Authorization":"Bearer attacker-token-B"})
    assert r1.status_code == 200 and r2.status_code == 200
    pid_a = capture[0]["headers"]["X-KYA-Principal-Id"]
    pid_b = capture[1]["headers"]["X-KYA-Principal-Id"]
    assert pid_a != pid_b, (
        f"distinct bad creds collided on principal_id: {pid_a} vs {pid_b}"
    )


# ─── 5g-A-04 — internal exception class names not leaked ─────────────────


def test_reason_codes_are_stable_enum_not_class_names(monkeypatch):
    """X-KYA-Reason-Codes must surface a stable enum, not the
    internal exception class name."""
    _stub_kya(monkeypatch)
    _stub_identity_fail(monkeypatch)
    _stub_forwarder(monkeypatch)
    gw = Gateway(_cfg(mode="audit_only"))
    r = _post_mcp(TestClient(gw.app))
    codes = r.headers.get("X-KYA-Reason-Codes", "")
    assert "IDENTITY_CRED_INVALID" in codes
    # No internal class name leak.
    assert "IdentityCredentialInvalid" not in codes
    assert "Exception" not in codes


# ─── 5g-A-06 — discovery passthrough attaches verdict headers ────────────


def test_discovery_tools_list_attaches_verdict_header_in_audit_only(monkeypatch):
    """tools/list in audit_only must NOT respond without the verdict
    header — otherwise the customer enforcement layer has no signal
    that the caller was unauthenticated."""
    _stub_kya(monkeypatch)
    _stub_identity_fail(monkeypatch)
    capture = []
    _stub_forwarder(monkeypatch, capture=capture,
                     body=b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}')
    gw = Gateway(_cfg(mode="audit_only"))
    r = TestClient(gw.app).post("/mcp",
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        headers={"Content-Type":"application/json",
                 "Authorization":"Bearer bad"})
    assert r.status_code == 200
    assert r.headers.get("X-KYA-Verdict") == "identity_invalid"


# ─── 5g-A-07 — unauth evidence is throttled per-IP ───────────────────────


def test_unauth_evidence_is_throttled(monkeypatch):
    """A flood of bad-cred traffic from one IP must not 1:1 amplify
    into evidence-chain writes. After the per-second budget, evidence
    is dropped with a counter incremented."""
    monkeypatch.setenv("KYA_GATEWAY_UNAUTH_EVIDENCE_RATE_PER_S", "2")
    # Reset bucket state.
    from kya_gateway import server as _srv
    _srv._UNAUTH_EVIDENCE_LAST.clear()
    _srv._METRICS["unauth_evidence_dropped"] = 0
    # Reload to pick up the new env. The module reads it at import; for
    # tests we patch the constant directly.
    monkeypatch.setattr(_srv, "_UNAUTH_EVIDENCE_RATE_PER_S", 2)
    ev = []
    _stub_kya(monkeypatch, evidence_sink=ev)
    _stub_identity_fail(monkeypatch)
    _stub_forwarder(monkeypatch)
    gw = Gateway(_cfg(mode="audit_only"))
    client = TestClient(gw.app)
    for _ in range(10):
        _post_mcp(client)
    # 10 calls, 2 written, 8 dropped.
    assert len(ev) <= 3, f"expected at most 3 evidence rows, got {len(ev)}"
    assert _srv._METRICS["unauth_evidence_dropped"] >= 5


# ─── 5g-A-09 — startup logs the active mode at WARNING ───────────────────


def test_startup_logs_mode_at_warning(monkeypatch, caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="kya_gateway.server")
    _stub_kya(monkeypatch)
    Gateway(_cfg(mode="audit_only"))
    # Must contain the mode + the explicit-block intent.
    matched = [r for r in caplog.records
               if "enforcement.mode" in r.message
               and "audit_only" in r.message
               and "NOT block" in r.message]
    assert matched, f"no startup WARNING for mode; saw: {caplog.records}"


# ─── 5g-A-12 — YAML with enforcement: { } but missing mode is rejected ───


def test_yaml_enforcement_block_without_mode_is_rejected():
    raw = {
        "gateway": {"bind": "127.0.0.1:0", "tenant_id": "t"},
        "identity": {"methods": ["bearer_jwt"], "jwt": {}},
        "backends": [{"name": "default", "url": "http://localhost:1"}],
        "policy": {},
        "audit": {},
        "enforcement": {},  # block present, no mode
    }
    with pytest.raises(GatewayConfigError, match=r"(?i)mode"):
        GatewayConfig.from_dict(raw)


# ─── F1 — advise body merge survives non-dict result ────────────────


@pytest.mark.parametrize("backend_body", [
    b'{"jsonrpc":"2.0","id":1,"result":"OK"}',           # str
    b'{"jsonrpc":"2.0","id":1,"result":[1,2,3]}',        # list
    b'{"jsonrpc":"2.0","id":1,"result":null}',           # null
    b'{"jsonrpc":"2.0","id":1,"result":42}',             # int
])
def test_advise_handles_non_dict_jsonrpc_result(monkeypatch, backend_body):
    """F1 regression — backend may return any JSON type for result;
    merging kya_verdict must not TypeError."""
    _stub_kya(monkeypatch)
    _stub_identity_ok(monkeypatch)
    _stub_forwarder(monkeypatch, body=backend_body)
    gw = Gateway(_cfg(mode="advise", with_rbac_deny=True))
    r = TestClient(gw.app).post(
        "/mcp",
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call",
                          "params":{"name":"filesystem.read","arguments":{}}}),
        headers={"Content-Type":"application/json","Authorization":"Bearer x"})
    assert r.status_code == 200, r.text
    body = r.json()
    # The verdict must land somewhere reachable without losing backend data.
    assert "kya_verdict" in body.get("result", {})


def test_advise_handles_jsonrpc_error_data_list(monkeypatch):
    """F9 regression — JSON-RPC error.data may be any JSON type; a
    list must not be silently clobbered."""
    _stub_kya(monkeypatch)
    _stub_identity_ok(monkeypatch)
    _stub_forwarder(
        monkeypatch,
        body=b'{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x","data":[1,2,3]}}',
    )
    gw = Gateway(_cfg(mode="advise", with_rbac_deny=True))
    r = TestClient(gw.app).post(
        "/mcp",
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call",
                          "params":{"name":"filesystem.read","arguments":{}}}),
        headers={"Content-Type":"application/json","Authorization":"Bearer x"})
    body = r.json()
    data = body["error"]["data"]
    assert data["backend_data"] == [1, 2, 3]
    assert data["kya_verdict"]["verdict"] == "deny"


# ─── F2 — discovery passthrough forwards principal headers ──────────


def test_discovery_passes_principal_headers_to_backend(monkeypatch):
    """tools/list (discovery) must forward X-KYA-Principal-* outbound
    so the backend can distinguish anon vs known callers."""
    _stub_kya(monkeypatch)
    _stub_identity_fail(monkeypatch)
    capture = []
    _stub_forwarder(monkeypatch, capture=capture,
                     body=b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}')
    gw = Gateway(_cfg(mode="audit_only"))
    TestClient(gw.app).post("/mcp",
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        headers={"Content-Type":"application/json","Authorization":"Bearer bad"})
    assert capture and "X-KYA-Principal-Id" in capture[0]["headers"]
    assert "kya-unauth" in capture[0]["headers"]["X-KYA-Principal-Id"]


# ─── F3 — XFF honored when trusted-proxy CIDR is configured ─────────


def test_xff_honored_only_with_trusted_proxy_cidr(monkeypatch):
    """Without trusted-proxy config, X-Forwarded-For is ignored
    (untrusted callers can't spoof IPs). With config, the first XFF
    hop is honored."""
    from kya_gateway import server as _srv
    # Untrusted: header is ignored.
    monkeypatch.delenv("KYA_GATEWAY_TRUSTED_PROXIES", raising=False)

    class _FakeReq:
        class client:
            host = "10.0.0.1"
        headers = {"x-forwarded-for": "203.0.113.7"}
    assert _srv._client_ip(_FakeReq) == "10.0.0.1"

    # Trusted: header is honored.
    monkeypatch.setenv("KYA_GATEWAY_TRUSTED_PROXIES", "10.0.0.0/8")
    assert _srv._client_ip(_FakeReq) == "203.0.113.7"


# ─── F4 — startup log has structured `extra` for mode field ─────────


def test_startup_log_has_structured_mode_field(monkeypatch, caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="kya_gateway.server")
    _stub_kya(monkeypatch)
    Gateway(_cfg(mode="audit_only"))
    matched = [r for r in caplog.records
               if getattr(r, "kya_enforcement_mode", None) == "audit_only"]
    assert matched, "startup log missing structured extra={'kya_enforcement_mode': ...}"
    assert matched[0].kya_enforcement_blocking is False


def test_yaml_no_enforcement_block_defaults_to_audit_only():
    raw = {
        "gateway": {"bind": "127.0.0.1:0", "tenant_id": "t"},
        "identity": {"methods": ["bearer_jwt"], "jwt": {}},
        "backends": [{"name": "default", "url": "http://localhost:1"}],
        "policy": {},
        "audit": {},
    }
    cfg = GatewayConfig.from_dict(raw)
    assert cfg.enforcement.mode == "audit_only"
