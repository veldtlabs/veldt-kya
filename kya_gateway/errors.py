"""Typed errors emitted by KYA Gateway.

All public errors descend from ``GatewayError`` so callers can catch broadly
or narrowly. JSON-RPC error codes follow the spec's reserved range.
"""
from __future__ import annotations

# JSON-RPC 2.0 reserved range starts at -32000.
# https://www.jsonrpc.org/specification#error_object
JSONRPC_ERR_POLICY_DENIED = -32001
JSONRPC_ERR_IDENTITY_MISSING = -32002
JSONRPC_ERR_BACKEND_UNREACHABLE = -32003
JSONRPC_ERR_REPLAY_DETECTED = -32004
JSONRPC_ERR_BUDGET_EXCEEDED = -32005
JSONRPC_ERR_RATE_LIMITED = -32006
# Phase 5g-tail — distinct code for require_human so clients can
# programmatically distinguish "denied" from "needs human approval to
# proceed." RFC 6585 §3 (HTTP 428 Precondition Required) is the right
# transport mapping.
JSONRPC_ERR_HUMAN_APPROVAL_REQUIRED = -32007


class GatewayError(Exception):
    """Base class for all gateway errors."""

    jsonrpc_code: int = -32000
    http_status: int = 500


class GatewayConfigError(GatewayError):
    """Configuration loaded from YAML is invalid."""

    http_status = 500


class IdentityBindingFailed(GatewayError):
    """Couldn't resolve the calling principal (no JWT/DID/SPIFFE, or invalid)."""

    jsonrpc_code = JSONRPC_ERR_IDENTITY_MISSING
    http_status = 401


class IdentityCredentialInvalid(IdentityBindingFailed):
    """A credential header was PRESENT but failed verification.

    Distinguishing this from a plain ``IdentityBindingFailed`` is the
    difference between "this method has no header — try the next" and
    "this method's header is present and invalid — hard-fail." The
    resolver MUST NOT fall through on the latter, or a malformed JWT
    becomes a free pass to whatever DID header the attacker also sends.
    """


class RevocationBlocked(IdentityCredentialInvalid):
    """Phase 5g #3 — the credential's status-list bit is set.

    Distinct from a generic credential-invalid so the gateway can emit
    a `revocation_blocked` security event (and surface the
    `IDENTITY_REVOKED` reason code) when this fires, separate from
    "JWT signature is wrong" or "DID didn't resolve."

    Phase 14a #145 — carry the verified principal info (principal_kind
    + principal_id) on the exception so the gateway's identity-failure
    handler can ALSO write a ``revocation_blocked`` row into
    ``kya_principal_trust.signal_counts``. Without this, the closed
    behavioral-revoke loop is observable only via
    ``kya_security_events`` (a separate table that
    ``kya.rogue.get_rogue_signals`` does NOT read), and a detector
    polling ``rogue_score`` can never see its own loop closing.
    """

    def __init__(self, message: str = "",
                 *, principal_kind: str | None = None,
                 principal_id: str | None = None):
        super().__init__(message)
        self.principal_kind = principal_kind
        self.principal_id = principal_id


class PolicyDenied(GatewayError):
    """The policy pipeline denied the action.

    ``reason_codes`` is a short machine-readable list (e.g.,
    ``["MIN_TRUST_NOT_MET", "BUDGET_EXCEEDED"]``) — callers can include
    these in audit records and downstream telemetry.
    """

    jsonrpc_code = JSONRPC_ERR_POLICY_DENIED
    http_status = 403

    def __init__(self, message: str, *, reason_codes: list[str] | None = None):
        super().__init__(message)
        self.reason_codes = reason_codes or []


class BackendUnreachable(GatewayError):
    """The backend MCP server returned an error or couldn't be contacted."""

    jsonrpc_code = JSONRPC_ERR_BACKEND_UNREACHABLE
    http_status = 502
