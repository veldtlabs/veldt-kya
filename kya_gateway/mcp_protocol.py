"""JSON-RPC 2.0 + MCP method routing.

The gateway speaks the subset of MCP needed for the proxy use case:

    initialize       — handshake (returns server capabilities)
    tools/list       — discover tools the backend exposes
    tools/call       — invoke a tool (THIS is the action the gateway gates)

Anything else is passed through to the backend untouched.

Reference: https://modelcontextprotocol.io/specification
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from kya_gateway.errors import GatewayError

PROTOCOL_VERSION = "2024-11-05"
JSONRPC_VERSION = "2.0"

# Phase 6: strict envelope schema. Rejecting by SHAPE (not just by size)
# is capability-removal — an attacker cannot send arbitrarily structured
# JSON to the gateway to probe the parser. The 32 MB body cap remains as
# a belt-and-suspenders ceiling.

# Top-level keys allowed on /mcp bodies.
_ALLOWED_ENVELOPE_KEYS = frozenset({"jsonrpc", "id", "method", "params"})

# MCP methods the gateway honors. tools/call goes through the policy
# pipeline; everything else either passes through to the backend (list /
# discovery) or returns a built-in response (initialize / ping).
_ALLOWED_METHODS = frozenset({
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "completion/complete",
    "logging/setLevel",
    # JSON-RPC notifications MCP uses.
    "notifications/cancelled",
    "notifications/progress",
    "notifications/initialized",
    "notifications/message",
    "notifications/resources/list_changed",
    "notifications/resources/updated",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
})

# Bounds on the WHOLE `params` shape (not just `arguments` — the prior
# review caught that `params.name` was unbounded and could be set to
# 10 MB, exhausting the policy engine and the audit chain).
_MAX_PARAMS_DEPTH = 8
_MAX_KEYS_PER_LEVEL = 64
_MAX_STRING_LENGTH = 16384
_MAX_ARRAY_LENGTH = 1024
# Integer bit-length cap — Python ints are arbitrary precision; without
# a cap, an attacker sends a 30 MB digit string and consumes O(n²) CPU
# on subsequent ops.
_MAX_INT_BIT_LENGTH = 256


def _check_params_shape(value, *, depth: int = 0) -> None:
    """Recursively bound a `params` value (or any nested element).

    Raises GatewayError when any bound is violated. Capability removal:
    "send a well-shaped but huge nested object anywhere in params" is
    no longer possible. The body cap remains as belt-and-suspenders.
    """
    if depth > _MAX_PARAMS_DEPTH:
        raise GatewayError(
            f"params nested deeper than {_MAX_PARAMS_DEPTH} levels"
        )
    if isinstance(value, dict):
        if len(value) > _MAX_KEYS_PER_LEVEL:
            raise GatewayError(
                f"params has {len(value)} keys at depth {depth} "
                f"(cap: {_MAX_KEYS_PER_LEVEL})"
            )
        for k, v in value.items():
            if not isinstance(k, str) or len(k) > _MAX_STRING_LENGTH:
                raise GatewayError(
                    f"params key is not a bounded string"
                )
            _check_params_shape(v, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > _MAX_ARRAY_LENGTH:
            raise GatewayError(
                f"params array length {len(value)} exceeds cap "
                f"{_MAX_ARRAY_LENGTH}"
            )
        for v in value:
            _check_params_shape(v, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > _MAX_STRING_LENGTH:
            raise GatewayError(
                f"params string of length {len(value)} exceeds "
                f"cap {_MAX_STRING_LENGTH}"
            )
    elif isinstance(value, bool):
        # bool is a subclass of int — check before int.
        return
    elif isinstance(value, int):
        if value.bit_length() > _MAX_INT_BIT_LENGTH:
            raise GatewayError(
                f"params integer too large "
                f"(bit_length={value.bit_length()}, cap={_MAX_INT_BIT_LENGTH})"
            )
    # float, None pass through — finite size.


@dataclass(frozen=True)
class MCPRequest:
    """Parsed MCP request."""

    raw: dict[str, Any]
    method: str
    params: dict[str, Any]
    request_id: int | str | None
    is_notification: bool      # JSON-RPC notifications have no id.

    @property
    def tool_name(self) -> str | None:
        """For tools/call, the tool being invoked. None otherwise."""
        if self.method != "tools/call":
            return None
        return self.params.get("name")

    @property
    def tool_arguments(self) -> dict[str, Any]:
        """For tools/call, the arguments passed to the tool."""
        if self.method != "tools/call":
            return {}
        return self.params.get("arguments") or {}


class JSONRPCBatchNotSupported(GatewayError):
    """Caller sent a JSON-RPC batch request. Maps to -32600 (Invalid Request)."""


class MCPMethodNotFound(GatewayError):
    """Caller sent a method not in the MCP allowlist. Maps to -32601."""

    def __init__(self, method: str):
        super().__init__(f"method {method!r} is not implemented")
        self.method = method


def parse_request(raw_body: bytes) -> MCPRequest:
    """Parse a JSON-RPC 2.0 request body into an MCPRequest.

    Raises:
        GatewayError: Malformed JSON (-32700 Parse error) or missing/wrong
            required fields (-32600 Invalid Request).
        JSONRPCBatchNotSupported: Body parses but is a list — batches are
            not supported (also -32600).
    """
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise GatewayError(f"malformed JSON in request body: {exc}") from exc
    if isinstance(parsed, list):
        raise JSONRPCBatchNotSupported(
            "JSON-RPC batch requests are not supported by KYA Gateway"
        )
    if not isinstance(parsed, dict):
        raise GatewayError("JSON-RPC request must be an object")

    # Phase 6: shape-based rejection — refuse any envelope with keys
    # outside the JSON-RPC spec set. An attacker cannot smuggle extra
    # top-level fields to probe the parser or policy primitives.
    extra = set(parsed.keys()) - _ALLOWED_ENVELOPE_KEYS
    if extra:
        raise GatewayError(
            f"JSON-RPC envelope has unexpected top-level keys: "
            f"{sorted(extra)}"
        )

    if parsed.get("jsonrpc") != JSONRPC_VERSION:
        raise GatewayError(
            f"unsupported jsonrpc version {parsed.get('jsonrpc')!r}; "
            f"expected {JSONRPC_VERSION!r}"
        )
    method = parsed.get("method")
    if not isinstance(method, str) or not method:
        raise GatewayError("JSON-RPC method must be a non-empty string")

    # Phase 6: MCP method allowlist — unknown methods get -32601 at the
    # server boundary instead of passing through to a backend that
    # might error in a less informative way.
    if method not in _ALLOWED_METHODS:
        raise MCPMethodNotFound(method)

    params_raw = parsed.get("params")
    # Phase 6: MCP uses named (object) params only. Reject array form.
    if params_raw is not None and not isinstance(params_raw, dict):
        raise GatewayError(
            f"JSON-RPC params must be an object (MCP uses named params), "
            f"got {type(params_raw).__name__}"
        )

    # Phase 6: bound the shape of THE WHOLE `params` dict — `params.name`
    # and any other params.* fields are equally capability-removing surface.
    if isinstance(params_raw, dict):
        _check_params_shape(params_raw)

    request_id = parsed.get("id")
    return MCPRequest(
        raw=parsed,
        method=method,
        params=params_raw if isinstance(params_raw, dict) else {},
        request_id=request_id,
        is_notification="id" not in parsed,
    )


def make_response(request_id: int | str | None, result: Any) -> dict[str, Any]:
    """Build a successful JSON-RPC 2.0 response envelope."""
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "result": result,
    }


def make_error(
    request_id: int | str | None,
    code: int,
    message: str,
    data: Any = None,
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error envelope."""
    err: dict[str, Any] = {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    if data is not None:
        err["error"]["data"] = data
    return err


def initialize_result(server_name: str = "kya-gateway") -> dict[str, Any]:
    """MCP ``initialize`` response payload."""
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {},
        },
        "serverInfo": {
            "name": server_name,
            "version": "0.1.0",
        },
    }


def action_from_tool_call(backend_name: str, tool_name: str) -> str:
    """Build the KYA action string for a tools/call request.

    Action format mirrors KYA's existing convention:
        ``mcp.<backend>.<tool>``
    Used by RBAC, require_action, audit records, and attack chain rules.
    """
    return f"mcp.{backend_name}.{tool_name}"
