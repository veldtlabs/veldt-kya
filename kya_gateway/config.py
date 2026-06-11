"""YAML config schema for KYA Gateway.

Single source of truth for the gateway's runtime knobs. Loaded once at
startup, exposed as a typed dataclass tree to the rest of the package.

Schema lives close to the requirements doc — see
``docs/requirements/kya_gateway.md`` §8 (Config schema excerpt).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from kya_gateway.errors import GatewayConfigError


@dataclass(frozen=True)
class BackendConfig:
    name: str
    url: str
    timeout_s: float = 30.0


@dataclass(frozen=True)
class JWTConfig:
    jwks_url: str | None = None
    issuer: str | None = None
    # Issuers whose `principal_kind` / `principal_id` claims may be honored.
    # When empty (default), all JWT-claimed principal_kind values are
    # downgraded to the safe default "agent" — an arbitrary IdP cannot
    # self-elevate principals.
    trusted_issuers: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DIDConfig:
    resolvers: list[str] = field(default_factory=lambda: ["key", "web", "jwk"])
    trusted_issuers: list[str] = field(default_factory=list)
    # When False (default), the gateway REQUIRES a proof-of-possession
    # JWT in `X-KYA-DID-Proof` signed by a key in the DID document's
    # authentication set. When True, the gateway trusts `X-KYA-DID`
    # alone — only safe behind a service mesh that has already
    # authenticated the caller.
    allow_header_trust: bool = False
    # Required `aud` claim in the PoP JWT. Set to the gateway's externally
    # visible URL so a PoP minted for another KYA gateway can't be replayed.
    pop_audience: str | None = None
    # Clock skew tolerance on the PoP JWT's iat/exp.
    pop_leeway_seconds: int = 30
    # When True, the gateway lazy-imports kya_pro.revocation and runs
    # the W3C Status List 2021 check after VC signature verification.
    # No-op if kya_pro isn't installed (degrades gracefully).
    revocation_check: bool = False
    # Cache TTL for fetched status list VCs (seconds). 0 = no caching
    # (revocation propagates instantly — useful for tests).
    revocation_cache_ttl_seconds: int = 60
    # Phase 6: DPoP-bound /v1/principals/me. When True (default), every
    # /me call requires a fresh DPoP JWT signed by a key in the DID's
    # authentication set. Replay-grinding requires the private key —
    # the endpoint stops being a free credential-validation oracle.
    require_dpop_on_me: bool = True
    # Required `htu` host (scheme + host) for the DPoP proof. Set to
    # this gateway's externally visible base URL so a DPoP minted for
    # another KYA gateway can't be replayed here.
    dpop_audience: str | None = None
    # Clock skew tolerance on the DPoP `iat` claim.
    dpop_leeway_seconds: int = 30


@dataclass(frozen=True)
class IdentityConfig:
    methods: list[str]
    jwt: JWTConfig | None = None
    did: DIDConfig | None = None


@dataclass(frozen=True)
class RateLimitConfig:
    requests_per_minute: int = 600


@dataclass(frozen=True)
class PayloadCapsConfig:
    max_bytes: int = 65536


@dataclass(frozen=True)
class BudgetConfig:
    daily_usd: float | None = None


@dataclass(frozen=True)
class RBACRule:
    principal_kind: str
    actions: list[str]
    verdict: str  # "allow" | "deny" | "require_human"


@dataclass(frozen=True)
class RBACConfig:
    default: str = "deny"   # "allow" | "deny"
    rules: list[RBACRule] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyConfig:
    min_trust: int = 0
    rate_limit: RateLimitConfig | None = None
    payload_caps: PayloadCapsConfig | None = None
    tenant_budget: BudgetConfig | None = None
    rbac: RBACConfig | None = None


@dataclass(frozen=True)
class AuditConfig:
    evidence_signing_key_env: str = "KYA_EVIDENCE_SIGNING_KEY"
    hmac_chain: bool = True
    ed25519_export_on_shutdown: bool = False


@dataclass(frozen=True)
class GatewayBindConfig:
    bind: str = "0.0.0.0:8080"
    tenant_id: str = "default"


# Phase 5g — three modes mirroring `kya/rbac.py` off/flag/block. Default
# is `audit_only` so the gateway matches the library's "KYA records, the
# customer enforces" liability-isolation model. Operators who want the
# gateway to BE the security boundary must opt in to `enforce`.
_ENFORCEMENT_MODES = frozenset({"audit_only", "advise", "enforce"})


@dataclass(frozen=True)
class EnforcementConfig:
    mode: str = "audit_only"

    def __post_init__(self):
        if self.mode not in _ENFORCEMENT_MODES:
            raise GatewayConfigError(
                f"enforcement.mode must be one of "
                f"{sorted(_ENFORCEMENT_MODES)!r}, got {self.mode!r}"
            )


@dataclass(frozen=True)
class GatewayConfig:
    """Top-level config. Loaded from YAML; immutable after load."""

    gateway: GatewayBindConfig
    identity: IdentityConfig
    backends: list[BackendConfig]
    policy: PolicyConfig
    audit: AuditConfig
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)

    @classmethod
    def from_yaml(cls, path: str) -> GatewayConfig:
        """Load and validate a config from a YAML file."""
        if not os.path.isfile(path):
            raise GatewayConfigError(f"config file not found: {path!r}")
        try:
            with open(path, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise GatewayConfigError(f"invalid YAML in {path!r}: {exc}") from exc
        if not isinstance(raw, dict):
            raise GatewayConfigError(f"{path!r} must contain a top-level mapping")
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> GatewayConfig:
        """Parse and validate a config from a dict."""
        try:
            gw_block = raw.get("gateway") or {}
            gateway = GatewayBindConfig(
                bind=gw_block.get("bind", "0.0.0.0:8080"),
                tenant_id=gw_block.get("tenant_id", "default"),
            )

            id_block = raw.get("identity") or {}
            methods = id_block.get("methods") or []
            if not isinstance(methods, list) or not methods:
                raise GatewayConfigError("identity.methods must be a non-empty list")
            jwt_block = id_block.get("jwt")
            did_block = id_block.get("did")
            identity = IdentityConfig(
                methods=[str(m) for m in methods],
                jwt=JWTConfig(
                    jwks_url=jwt_block.get("jwks_url") if jwt_block else None,
                    issuer=jwt_block.get("issuer") if jwt_block else None,
                    trusted_issuers=list(jwt_block.get("trusted_issuers", []))
                                    if jwt_block else [],
                ) if jwt_block else None,
                did=DIDConfig(
                    resolvers=did_block.get("resolvers", ["key", "web", "jwk"]),
                    trusted_issuers=list(did_block.get("trusted_issuers", [])),
                    allow_header_trust=bool(did_block.get("allow_header_trust", False)),
                    pop_audience=did_block.get("pop_audience"),
                    pop_leeway_seconds=int(did_block.get("pop_leeway_seconds", 30)),
                    revocation_check=bool(did_block.get("revocation_check", False)),
                    revocation_cache_ttl_seconds=int(did_block.get(
                        "revocation_cache_ttl_seconds", 60)),
                    require_dpop_on_me=bool(did_block.get("require_dpop_on_me", True)),
                    dpop_audience=did_block.get("dpop_audience"),
                    dpop_leeway_seconds=int(did_block.get("dpop_leeway_seconds", 30)),
                ) if did_block else None,
            )

            backends_block = raw.get("backends") or []
            if not isinstance(backends_block, list) or not backends_block:
                raise GatewayConfigError("backends must be a non-empty list")
            backends: list[BackendConfig] = []
            for idx, b in enumerate(backends_block):
                if not isinstance(b, dict):
                    raise GatewayConfigError(
                        f"backends[{idx}] must be a mapping, got {type(b).__name__}"
                    )
                if "name" not in b:
                    raise GatewayConfigError(f"backends[{idx}] missing required field 'name'")
                if "url" not in b:
                    raise GatewayConfigError(f"backends[{idx}] missing required field 'url'")
                backends.append(BackendConfig(
                    name=b["name"],
                    url=b["url"],
                    timeout_s=float(b.get("timeout_s", 30.0)),
                ))

            pol = raw.get("policy") or {}
            policy = PolicyConfig(
                min_trust=int(pol.get("min_trust", 0)),
                rate_limit=RateLimitConfig(
                    requests_per_minute=int(pol["rate_limit"]["requests_per_minute"])
                ) if pol.get("rate_limit") else None,
                payload_caps=PayloadCapsConfig(
                    max_bytes=int(pol["payload_caps"]["max_bytes"])
                ) if pol.get("payload_caps") else None,
                tenant_budget=BudgetConfig(
                    daily_usd=float(pol["tenant_budget"]["daily_usd"])
                ) if pol.get("tenant_budget") else None,
                rbac=_parse_rbac(pol.get("rbac")),
            )

            audit_block = raw.get("audit") or {}
            audit = AuditConfig(
                evidence_signing_key_env=audit_block.get(
                    "evidence_signing_key_env", "KYA_EVIDENCE_SIGNING_KEY"
                ),
                hmac_chain=bool(audit_block.get("hmac_chain", True)),
                ed25519_export_on_shutdown=bool(
                    audit_block.get("ed25519_export_on_shutdown", False)
                ),
            )

            # 5g-A-12: when the `enforcement:` block is PRESENT but
            # `mode:` is missing, fail loudly rather than silently
            # default — the typo would otherwise pin the gateway to
            # audit_only when the operator intended `enforce`. When the
            # block is ABSENT, default to audit_only (Phase 5g default).
            enforce_block = raw.get("enforcement")
            if enforce_block is None:
                enforcement = EnforcementConfig()
            else:
                if not isinstance(enforce_block, dict):
                    raise GatewayConfigError(
                        "enforcement must be a mapping if present"
                    )
                if "mode" not in enforce_block:
                    raise GatewayConfigError(
                        "enforcement block is present but missing required "
                        "field 'mode'. Set enforcement.mode to one of "
                        "audit_only / advise / enforce, or remove the "
                        "enforcement block to accept the default (audit_only)."
                    )
                enforcement = EnforcementConfig(mode=str(enforce_block["mode"]))
        except KeyError as exc:
            raise GatewayConfigError(f"missing required config field: {exc}") from exc

        # Phase 6 boot-time validation: capability-removal requires a
        # CONFIGURED dpop_audience. A WARN-then-fallback on every request
        # is an operator footgun behind a reverse proxy (cross-gateway
        # replay surface). Refuse to start the gateway rather than
        # paper over it.
        if (identity.did is not None
                and identity.did.require_dpop_on_me
                and not identity.did.dpop_audience):
            raise GatewayConfigError(
                "identity.did.dpop_audience is required when "
                "require_dpop_on_me=true. Set it to this gateway's "
                "externally visible URL (e.g. 'https://gateway.example')."
            )

        return cls(
            gateway=gateway,
            identity=identity,
            backends=backends,
            policy=policy,
            audit=audit,
            enforcement=enforcement,
        )


def _parse_rbac(block: dict | None) -> RBACConfig | None:
    if not block:
        return None
    default = block.get("default", "deny")
    if default not in ("allow", "deny"):
        raise GatewayConfigError(f"rbac.default must be 'allow' or 'deny', got {default!r}")
    rules_raw = block.get("rules") or []
    rules: list[RBACRule] = []
    for r in rules_raw:
        verdict = r.get("verdict", "deny")
        if verdict not in ("allow", "deny", "require_human"):
            raise GatewayConfigError(
                f"rbac rule verdict must be allow/deny/require_human, got {verdict!r}"
            )
        rules.append(RBACRule(
            principal_kind=r["principal_kind"],
            actions=list(r.get("actions") or []),
            verdict=verdict,
        ))
    return RBACConfig(default=default, rules=rules)
