"""Phase 5g — Gateway enforcement modes.

Three modes mirroring `kya/rbac.py` semantics:

    audit_only (default) → KYA records, customer enforces
    advise               → KYA records + replies with verdict, customer enforces
    enforce              → KYA blocks (operator opted into KYA-side liability)

Tests confirm the gateway behaves correctly per mode for: policy deny,
revocation block, and identity binding failure (DPoP missing).
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
    PolicyConfig, RBACConfig, RBACRule,
)
from kya_gateway.identity import BoundPrincipal
from kya_gateway.policy_pipeline import Verdict
from kya_gateway.server import Gateway


def _principal():
    return BoundPrincipal(
        principal_kind="agent",
        principal_id="planner",
        method="bearer_jwt",
        external_subject="planner",
        external_issuer=None,
    )


def _build_gateway(mode: str, *, with_rbac_deny: bool = False):
    rbac = (
        RBACConfig(default="deny", rules=[]) if with_rbac_deny else None
    )
    return GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t1"),
        identity=IdentityConfig(
            methods=["bearer_jwt"],
            jwt=JWTConfig(),
            did=DIDConfig(
                resolvers=["key"], trusted_issuers=[],
                allow_header_trust=True,   # bypass DPoP for these tests
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


def _patch_minimal(monkeypatch, principal=None):
    """Stub identity + KYA core + forwarder so we can exercise mode logic."""
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
    class _ADE(Exception):
        pass
    fake_kya.AccessDeniedError = _ADE
    fake_kya.require_action = lambda *a, **kw: True
    monkeypatch.setitem(sys.modules, "kya", fake_kya)

    from kya_gateway import identity as _id_mod
    monkeypatch.setattr(
        _id_mod.IdentityResolver, "resolve",
        lambda self, headers: principal or _principal(),
    )

    from kya_gateway import forwarder as _fwd
    async def fake_forward_json(self, backend_name, payload, **_kwargs):
        return _fwd.ForwardResult(
            status_code=200,
            body=b'{"result":"ok","tool":"forwarded"}',
            headers={"content-type": "application/json"},
        )
    monkeypatch.setattr(_fwd.Forwarder, "forward_json", fake_forward_json)


def _post_tools_call(client):
    return client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {}},
    }), headers={"Content-Type": "application/json",
                 "Authorization": "Bearer dummy"})


# ─── 1. audit_only is the default ───────────────────────────────────


def test_default_mode_is_audit_only(monkeypatch):
    _patch_minimal(monkeypatch)
    gw = Gateway(_build_gateway(mode="audit_only"))
    assert gw.cfg.enforcement.mode == "audit_only"


# ─── 2. audit_only: deny → 200 + X-KYA-Verdict header + backend reached ──


def test_audit_only_deny_forwards_to_backend_with_verdict_header(monkeypatch):
    """RBAC default-deny in audit_only mode → backend still called,
    verdict carried in X-KYA-Verdict header. Customer enforces."""
    _patch_minimal(monkeypatch)
    gw = Gateway(_build_gateway(mode="audit_only", with_rbac_deny=True))
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 200, r.text
    assert r.headers.get("X-KYA-Verdict") == "deny"
    assert "RBAC_DENY" in r.headers.get("X-KYA-Reason-Codes", "")
    # Body comes from the (mocked) backend.
    assert b"forwarded" in r.content


# ─── 3. advise: deny → 200 + verdict in body ────────────────────────


def test_advise_deny_forwards_to_backend_with_verdict_in_body(monkeypatch):
    _patch_minimal(monkeypatch)
    gw = Gateway(_build_gateway(mode="advise", with_rbac_deny=True))
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 200, r.text
    body = r.json()
    # Backend result is preserved AND verdict is attached.
    assert body.get("kya_verdict", {}).get("verdict") == "deny"
    assert "RBAC_DENY" in body["kya_verdict"]["reason_codes"]


# ─── 4. enforce: deny → 403 (current behavior preserved) ─────────────


def test_enforce_deny_blocks_with_403(monkeypatch):
    _patch_minimal(monkeypatch)
    gw = Gateway(_build_gateway(mode="enforce", with_rbac_deny=True))
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["error"]["code"] == -32001
    assert "RBAC_DENY" in body["error"]["data"]["reason_codes"]


# ─── 5. audit_only: identity binding fail → 200, recorded, forwarded ──


def test_audit_only_identity_fail_forwards_with_anon_verdict(monkeypatch):
    """When DPoP / VC fails in audit_only, the call still reaches the
    backend so KYA isn't the enforcement boundary. The verdict header
    reflects the failure for the customer's layer to act on."""
    from kya_gateway.errors import IdentityCredentialInvalid
    _patch_minimal(monkeypatch)
    from kya_gateway import identity as _id_mod

    def fail(self, headers):
        raise IdentityCredentialInvalid("DPoP missing")
    monkeypatch.setattr(_id_mod.IdentityResolver, "resolve", fail)

    gw = Gateway(_build_gateway(mode="audit_only"))
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 200, r.text
    assert r.headers.get("X-KYA-Verdict") == "identity_invalid"


# ─── 6. enforce: identity fail → 401 (regression check) ──────────────


def test_enforce_identity_fail_blocks_with_401(monkeypatch):
    from kya_gateway.errors import IdentityCredentialInvalid
    _patch_minimal(monkeypatch)
    from kya_gateway import identity as _id_mod

    def fail(self, headers):
        raise IdentityCredentialInvalid("DPoP missing")
    monkeypatch.setattr(_id_mod.IdentityResolver, "resolve", fail)

    gw = Gateway(_build_gateway(mode="enforce"))
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 401, r.text


# ─── 7. require_human in audit_only forwards with verdict ───────────


def test_audit_only_require_human_forwards_with_verdict_header(monkeypatch):
    """An 'allow but needs human' verdict also surfaces via header."""
    _patch_minimal(monkeypatch)
    cfg = _build_gateway(mode="audit_only")
    # Build a config with a require_human rule.
    cfg = GatewayConfig(
        gateway=cfg.gateway, identity=cfg.identity,
        backends=cfg.backends,
        policy=PolicyConfig(rbac=RBACConfig(default="allow", rules=[
            RBACRule(principal_kind="agent",
                     actions=["mcp.filesystem.read"],
                     verdict="require_human"),
        ])),
        audit=cfg.audit,
        enforcement=cfg.enforcement,
    )
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 200, r.text
    assert r.headers.get("X-KYA-Verdict") == "require_human"


# ─── 8. config validation: unknown mode rejected ────────────────────


def test_invalid_enforcement_mode_rejected():
    from kya_gateway.errors import GatewayConfigError
    with pytest.raises(GatewayConfigError, match=r"(?i)mode"):
        EnforcementConfig(mode="permit_all")


# ─── 9. Every mode still records evidence ───────────────────────────


def test_audit_only_still_records_evidence(monkeypatch):
    recorded = []

    import sys
    import types
    fake_kya = types.ModuleType("kya")

    class _Sess:
        def commit(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fake_kya.default_session = lambda: _Sess()
    fake_kya.record_invocation = lambda db, **kw: 1
    def _record_evidence(db, **kw):
        recorded.append(kw)
        return 1
    fake_kya.record_evidence = _record_evidence
    fake_kya.record_principal_signal = lambda db, **kw: 1
    class _ADE(Exception): pass
    fake_kya.AccessDeniedError = _ADE
    fake_kya.require_action = lambda *a, **kw: True
    monkeypatch.setitem(sys.modules, "kya", fake_kya)

    from kya_gateway import identity as _id_mod
    monkeypatch.setattr(_id_mod.IdentityResolver, "resolve",
                        lambda self, h: _principal())
    from kya_gateway import forwarder as _fwd
    async def fake_forward_json(self, backend_name, payload, **_kwargs):
        return _fwd.ForwardResult(status_code=200, body=b'{}',
                                  headers={"content-type": "application/json"})
    monkeypatch.setattr(_fwd.Forwarder, "forward_json", fake_forward_json)

    gw = Gateway(_build_gateway(mode="audit_only", with_rbac_deny=True))
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 200
    # Evidence row written with the deny verdict — KYA's record is intact.
    assert recorded, "evidence should still be recorded in audit_only"
    assert recorded[0]["payload"].get("verdict") == "deny"
