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


# ─── rate_limit YAML schema (two modes) ─────────────────────────────


def test_yaml_rate_limit_mode_a_requests_per_minute(tmp_path):
    """### YAML loader Mode A

    The canonical HTTP-style config. Loader honors the integer
    value and constructs RateLimitConfig with requests_per_minute
    only.
    """
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
      rate_limit:
        requests_per_minute: 120
    audit:
      evidence_signing_key_env: "KYA_EVIDENCE_SIGNING_KEY"
    """))
    cfg = GatewayConfig.from_yaml(str(p))
    assert cfg.policy.rate_limit is not None
    assert cfg.policy.rate_limit.requests_per_minute == 120
    assert cfg.policy.rate_limit.min_interval_seconds is None


def test_yaml_rate_limit_mode_b_min_interval_seconds(tmp_path):
    """### YAML loader Mode B

    The cooldown / batch config. Loader honors the (possibly
    fractional) float value and constructs RateLimitConfig with
    min_interval_seconds only.
    """
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
      rate_limit:
        min_interval_seconds: 30
    audit:
      evidence_signing_key_env: "KYA_EVIDENCE_SIGNING_KEY"
    """))
    cfg = GatewayConfig.from_yaml(str(p))
    assert cfg.policy.rate_limit is not None
    assert cfg.policy.rate_limit.requests_per_minute is None
    assert cfg.policy.rate_limit.min_interval_seconds == 30.0


def test_yaml_rate_limit_both_modes_set_raises(tmp_path):
    """### YAML loader rejects ambiguous configuration

    When the operator sets both fields, the YAML loader passes both
    to RateLimitConfig which raises ValueError -- surfaces as a
    GatewayConfigError-equivalent ValueError at gateway startup,
    NOT silently at runtime.
    """
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
      rate_limit:
        requests_per_minute: 120
        min_interval_seconds: 30
    audit:
      evidence_signing_key_env: "KYA_EVIDENCE_SIGNING_KEY"
    """))
    with pytest.raises(ValueError, match="at most one|may be set"):
        GatewayConfig.from_yaml(str(p))


def test_yaml_rate_limit_low_requests_per_minute_raises(tmp_path):
    """### YAML loader catches the Phase-12 footgun

    A customer who writes `requests_per_minute: 6` thinking "6 per
    minute, bursts OK" gets a loud ValueError at config-load time
    pointing them at min_interval_seconds=10.0 -- the explicit
    spelling of their actual intent.
    """
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
      rate_limit:
        requests_per_minute: 6
    audit:
      evidence_signing_key_env: "KYA_EVIDENCE_SIGNING_KEY"
    """))
    with pytest.raises(ValueError) as exc_info:
        GatewayConfig.from_yaml(str(p))
    msg = str(exc_info.value)
    assert "< 60" in msg
    assert "min_interval_seconds=10.0" in msg


def test_yaml_no_rate_limit_block_means_no_limit(tmp_path):
    """### YAML loader: absent rate_limit block is valid

    Operators who don't want any rate limit simply omit the
    `rate_limit` block. PolicyConfig.rate_limit ends up None and
    the gateway's policy pipeline skips the check entirely.
    """
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
    assert cfg.policy.rate_limit is None
