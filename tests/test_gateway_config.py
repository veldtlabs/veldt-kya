"""Tests for kya_gateway.config — YAML schema parsing + validation."""
from __future__ import annotations

import textwrap

import pytest

from kya_gateway.config import GatewayConfig
from kya_gateway.errors import GatewayConfigError


def _yaml(s: str) -> str:
    return textwrap.dedent(s).lstrip()


def test_minimal_config(tmp_path):
    p = tmp_path / "gateway.yaml"
    p.write_text(_yaml("""
    gateway:
      bind: "0.0.0.0:8080"
      tenant_id: "tenant-alpha"
    identity:
      methods: ["bearer_jwt"]
      jwt:
        jwks_url: "https://idp.example/.well-known/jwks.json"
    backends:
      - name: "filesystem"
        url: "http://mcp-fs:9001"
    policy:
      min_trust: 70
    audit:
      evidence_signing_key_env: "KYA_EVIDENCE_SIGNING_KEY"
    """))
    cfg = GatewayConfig.from_yaml(str(p))
    assert cfg.gateway.tenant_id == "tenant-alpha"
    assert cfg.identity.methods == ["bearer_jwt"]
    assert cfg.identity.jwt is not None
    assert cfg.identity.jwt.jwks_url == "https://idp.example/.well-known/jwks.json"
    assert len(cfg.backends) == 1
    assert cfg.backends[0].name == "filesystem"
    assert cfg.policy.min_trust == 70


def test_dpop_audience_required_when_require_dpop_on_me_is_true(tmp_path):
    """Phase 6: boot-time validation refuses a DID config that demands
    DPoP without specifying the audience to bind to. WARN-then-fallback
    on every request was a documented operator footgun."""
    from kya_gateway.errors import GatewayConfigError
    p = tmp_path / "bad.yaml"
    p.write_text(_yaml("""
    identity:
      methods: ["did"]
      did:
        resolvers: ["jwk"]
        # require_dpop_on_me defaults to true; dpop_audience deliberately omitted
    backends:
      - name: "x"
        url: "http://x:9001"
    """))
    with pytest.raises(GatewayConfigError, match=r"(?i)dpop_audience"):
        GatewayConfig.from_yaml(str(p))


def test_full_config_with_rbac_and_did(tmp_path):
    p = tmp_path / "gateway.yaml"
    p.write_text(_yaml("""
    gateway:
      tenant_id: "tenant-bravo"
    identity:
      methods: ["did", "bearer_jwt"]
      did:
        resolvers: ["key", "web"]
        trusted_issuers:
          - "did:web:bank.example"
        dpop_audience: "https://gateway.example"
      jwt:
        jwks_url: "https://idp.example/.well-known/jwks.json"
    backends:
      - name: "filesystem"
        url: "http://mcp-fs:9001"
        timeout_s: 15
      - name: "postgres"
        url: "http://mcp-pg:9002"
    policy:
      min_trust: 60
      rate_limit:
        requests_per_minute: 600
      payload_caps:
        max_bytes: 65536
      tenant_budget:
        daily_usd: 50
      rbac:
        default: "deny"
        rules:
          - principal_kind: "agent"
            actions: ["mcp.filesystem.read", "mcp.postgres.read"]
            verdict: "allow"
          - principal_kind: "agent"
            actions: ["mcp.filesystem.write"]
            verdict: "require_human"
    audit:
      hmac_chain: true
    """))
    cfg = GatewayConfig.from_yaml(str(p))
    assert cfg.identity.methods == ["did", "bearer_jwt"]
    assert cfg.identity.did is not None
    assert "did:web:bank.example" in cfg.identity.did.trusted_issuers
    assert len(cfg.backends) == 2
    assert cfg.policy.rbac is not None
    assert cfg.policy.rbac.default == "deny"
    assert len(cfg.policy.rbac.rules) == 2
    assert cfg.policy.rbac.rules[1].verdict == "require_human"


def test_missing_file_raises():
    with pytest.raises(GatewayConfigError, match="not found"):
        GatewayConfig.from_yaml("/nope/does/not/exist.yaml")


def test_empty_methods_raises(tmp_path):
    p = tmp_path / "gateway.yaml"
    p.write_text(_yaml("""
    identity:
      methods: []
    backends:
      - name: "x"
        url: "http://x"
    """))
    with pytest.raises(GatewayConfigError, match="methods"):
        GatewayConfig.from_yaml(str(p))


def test_empty_backends_raises(tmp_path):
    p = tmp_path / "gateway.yaml"
    p.write_text(_yaml("""
    identity:
      methods: ["bearer_jwt"]
    backends: []
    """))
    with pytest.raises(GatewayConfigError, match="backends"):
        GatewayConfig.from_yaml(str(p))


def test_invalid_rbac_verdict_raises(tmp_path):
    p = tmp_path / "gateway.yaml"
    p.write_text(_yaml("""
    identity:
      methods: ["bearer_jwt"]
    backends:
      - name: "x"
        url: "http://x"
    policy:
      rbac:
        default: "deny"
        rules:
          - principal_kind: "agent"
            actions: ["mcp.x.read"]
            verdict: "not-a-valid-verdict"
    """))
    with pytest.raises(GatewayConfigError, match="verdict"):
        GatewayConfig.from_yaml(str(p))
