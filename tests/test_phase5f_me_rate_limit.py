"""Phase 5f rewire — /v1/principals/me delegates to kya.rate_limit.

Originally lived in veldt-kya-pro but the test needs `kya_gateway`
which is OSS-only. Moved here for proper repo placement.
"""
from __future__ import annotations

import os

os.environ.setdefault("KYA_DID_RESOLVERS", "key,web,jwk")


def test_me_endpoint_wires_to_kya_rate_limit(monkeypatch):
    """The /me handler must delegate to kya.rate_limit.maybe_rate_limit
    so multi-replica deployments use the existing Valkey-backed token
    bucket — not the in-process per-IP fallback. Verifies tenant_id +
    primitive + mode are propagated."""
    import sys
    import types

    captured: list = []

    fake_rl = types.ModuleType("kya.rate_limit")

    class _RateLimitExceededError(RuntimeError):
        def __init__(self, *a, **kw):
            super().__init__("simulated")
            self.retry_after_s = 0.5

    def maybe_rate_limit(tenant_id, primitive, *,
                         mode="soft", max_wait_s=5.0, **kwargs):
        captured.append((tenant_id, primitive, mode))
        # Trip on the second call so we exercise the 429 path.
        if len(captured) >= 2:
            raise _RateLimitExceededError()
        return True

    fake_rl.maybe_rate_limit = maybe_rate_limit
    fake_rl.RateLimitExceededError = _RateLimitExceededError
    monkeypatch.setitem(sys.modules, "kya.rate_limit", fake_rl)

    from fastapi.testclient import TestClient
    from kya_gateway.config import (
        AuditConfig, BackendConfig, DIDConfig, EnforcementConfig,
        GatewayBindConfig, GatewayConfig, IdentityConfig, JWTConfig,
        PolicyConfig,
    )
    from kya_gateway.server import Gateway

    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t-rewire"),
        identity=IdentityConfig(
            methods=["bearer_jwt"], jwt=JWTConfig(),
            did=DIDConfig(
                resolvers=["key"], trusted_issuers=[],
                allow_header_trust=False,
                pop_audience="http://testserver/mcp",
                dpop_audience="http://testserver",
                require_dpop_on_me=False,
            ),
        ),
        backends=[BackendConfig(name="default", url="http://x")],
        policy=PolicyConfig(),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode="audit_only"),
    )
    gw = Gateway(cfg)
    from kya_gateway import server as _srv
    _srv._ME_RATE_WINDOWS.clear()

    from kya_gateway.identity import BoundPrincipal
    monkeypatch.setattr(
        _srv.IdentityResolver, "resolve",
        lambda self, headers: BoundPrincipal(
            principal_kind="agent", principal_id="p1",
            method="bearer_jwt", external_subject="p1",
            external_issuer=None,
        ),
    )

    client = TestClient(gw.app)
    r1 = client.get("/v1/principals/me")
    assert r1.status_code == 200, r1.text
    r2 = client.get("/v1/principals/me")
    assert r2.status_code == 429, r2.text
    assert len(captured) == 2
    assert captured[0] == ("t-rewire", "principals_me", "hard")
