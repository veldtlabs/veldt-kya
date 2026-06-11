"""Phase 5g-tail — require_human verdict returns HTTP 428 (RFC 6585 §3).

Pre-5g-tail behavior was HTTP 403, semantically wrong (Forbidden = "you
will never be allowed"). 428 Precondition Required is the correct code
for "this action needs a precondition (human approval) before it can
proceed."

Mode interaction:
  - enforce: 428 + distinct JSON-RPC code (-32007) + WWW-Authenticate hint
  - audit_only / advise: unchanged — forwards with X-KYA-Verdict header
"""
from __future__ import annotations

import json
import os

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"


def test_require_human_enforce_returns_428_not_403(monkeypatch):
    """A require_human verdict in enforce mode must return HTTP 428
    Precondition Required, not 403 Forbidden. The distinction matters
    because 403 tells clients "this is permanently denied"; 428 tells
    them "satisfy the precondition (human approval) and retry."
    """
    import sys
    import types

    fake_kya = types.ModuleType("kya")

    class _Sess:
        def commit(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fake_kya.default_session = lambda: _Sess()
    fake_kya.record_invocation = lambda db, **kw: 1
    fake_kya.record_evidence = lambda db, **kw: 1
    fake_kya.record_principal_signal = lambda db, **kw: 1
    class _ADE(Exception): pass
    fake_kya.AccessDeniedError = _ADE
    fake_kya.require_action = lambda *a, **k: True
    monkeypatch.setitem(sys.modules, "kya", fake_kya)

    from fastapi.testclient import TestClient
    from kya_gateway.config import (
        AuditConfig, BackendConfig, EnforcementConfig,
        GatewayBindConfig, GatewayConfig, IdentityConfig, JWTConfig,
        PolicyConfig, RBACConfig, RBACRule,
    )
    from kya_gateway.identity import BoundPrincipal
    from kya_gateway.server import Gateway

    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t-rh"),
        identity=IdentityConfig(methods=["bearer_jwt"], jwt=JWTConfig()),
        backends=[BackendConfig(name="default", url="http://x")],
        policy=PolicyConfig(rbac=RBACConfig(default="deny", rules=[
            RBACRule(principal_kind="agent",
                     actions=["mcp.filesystem.delete_file"],
                     verdict="require_human"),
        ])),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode="enforce"),
    )
    gw = Gateway(cfg)

    from kya_gateway import identity as _id_mod
    monkeypatch.setattr(
        _id_mod.IdentityResolver, "resolve",
        lambda self, h: BoundPrincipal(
            principal_kind="agent", principal_id="p1",
            method="bearer_jwt", external_subject="p1",
            external_issuer=None,
        ),
    )

    client = TestClient(gw.app)
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.delete_file", "arguments": {}},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer x"})
    assert r.status_code == 428, r.text
    body = r.json()
    # Distinct JSON-RPC code so clients can programmatically
    # distinguish deny (-32001) from require_human (-32007).
    assert body["error"]["code"] == -32007
    assert body["error"]["data"]["verdict"] == "require_human"
    # Discovery hint for the human-approval flow.
    assert "Human-Approval" in r.headers.get("WWW-Authenticate", "") or \
           "KYA-Human-Approval" in r.headers.get("WWW-Authenticate", "")


def test_require_human_deny_still_returns_403(monkeypatch):
    """Regression: deny verdict must STILL return 403; only
    require_human moved to 428."""
    import sys
    import types

    fake_kya = types.ModuleType("kya")

    class _Sess:
        def commit(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fake_kya.default_session = lambda: _Sess()
    fake_kya.record_invocation = lambda db, **kw: 1
    fake_kya.record_evidence = lambda db, **kw: 1
    fake_kya.record_principal_signal = lambda db, **kw: 1
    class _ADE(Exception): pass
    fake_kya.AccessDeniedError = _ADE
    fake_kya.require_action = lambda *a, **k: True
    monkeypatch.setitem(sys.modules, "kya", fake_kya)

    from fastapi.testclient import TestClient
    from kya_gateway.config import (
        AuditConfig, BackendConfig, EnforcementConfig,
        GatewayBindConfig, GatewayConfig, IdentityConfig, JWTConfig,
        PolicyConfig, RBACConfig,
    )
    from kya_gateway.identity import BoundPrincipal
    from kya_gateway.server import Gateway

    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t-d"),
        identity=IdentityConfig(methods=["bearer_jwt"], jwt=JWTConfig()),
        backends=[BackendConfig(name="default", url="http://x")],
        policy=PolicyConfig(rbac=RBACConfig(default="deny", rules=[])),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode="enforce"),
    )
    gw = Gateway(cfg)
    from kya_gateway import identity as _id_mod
    monkeypatch.setattr(
        _id_mod.IdentityResolver, "resolve",
        lambda self, h: BoundPrincipal(
            principal_kind="agent", principal_id="p1",
            method="bearer_jwt", external_subject="p1",
            external_issuer=None,
        ),
    )
    client = TestClient(gw.app)
    r = client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {}},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer x"})
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == -32001
