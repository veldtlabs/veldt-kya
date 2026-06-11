"""Tests for kya_gateway.mcp_protocol — JSON-RPC 2.0 parse + envelope helpers."""
from __future__ import annotations

import json

import pytest

from kya_gateway.errors import GatewayError
from kya_gateway.mcp_protocol import (
    action_from_tool_call,
    initialize_result,
    make_error,
    make_response,
    parse_request,
)


def test_parse_initialize_request():
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {},
    }).encode("utf-8")
    req = parse_request(body)
    assert req.method == "initialize"
    assert req.request_id == 1
    assert not req.is_notification


def test_parse_tools_call():
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": "abc",
        "method": "tools/call",
        "params": {
            "name": "filesystem.read",
            "arguments": {"path": "/etc/shadow"},
        },
    }).encode("utf-8")
    req = parse_request(body)
    assert req.method == "tools/call"
    assert req.tool_name == "filesystem.read"
    assert req.tool_arguments == {"path": "/etc/shadow"}


def test_parse_notification_has_no_id():
    """A request without an 'id' is a JSON-RPC notification."""
    body = json.dumps({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 5},
    }).encode("utf-8")
    req = parse_request(body)
    assert req.is_notification
    assert req.request_id is None


def test_parse_malformed_json_raises():
    with pytest.raises(GatewayError, match="malformed JSON"):
        parse_request(b"{not json")


def test_parse_wrong_jsonrpc_version_raises():
    body = json.dumps({"jsonrpc": "1.0", "method": "x"}).encode("utf-8")
    with pytest.raises(GatewayError, match="jsonrpc"):
        parse_request(body)


def test_parse_missing_method_raises():
    body = json.dumps({"jsonrpc": "2.0", "id": 1}).encode("utf-8")
    with pytest.raises(GatewayError, match="method"):
        parse_request(body)


def test_make_response_envelope():
    env = make_response(42, {"hello": "world"})
    assert env == {"jsonrpc": "2.0", "id": 42, "result": {"hello": "world"}}


def test_make_error_envelope():
    env = make_error(7, -32001, "denied", data={"why": "MIN_TRUST"})
    assert env["error"]["code"] == -32001
    assert env["error"]["message"] == "denied"
    assert env["error"]["data"] == {"why": "MIN_TRUST"}


def test_initialize_result_shape():
    r = initialize_result()
    assert "protocolVersion" in r
    assert "serverInfo" in r
    assert r["serverInfo"]["name"] == "kya-gateway"


def test_action_from_tool_call_takes_bare_tool_name():
    """action_from_tool_call expects the BARE tool name (after prefix split).

    The caller is responsible for calling parse_backend_from_tool first to
    split `<backend>.<tool>`. Passing the raw prefixed tool name produces
    `mcp.<backend>.<backend>.<tool>` which silently bypasses RBAC rules
    written against the canonical `mcp.<backend>.<tool>` shape.
    """
    assert action_from_tool_call("filesystem", "read") == "mcp.filesystem.read"
    assert action_from_tool_call("postgres", "query") == "mcp.postgres.query"


def test_action_from_tool_call_with_parse_backend_roundtrip():
    """Integration: parse_backend_from_tool → action_from_tool_call gives
    the spec-shaped action that RBAC rules are written against."""
    from kya_gateway.forwarder import parse_backend_from_tool
    backend, bare = parse_backend_from_tool("filesystem.read_file")
    assert backend == "filesystem"
    assert bare == "read_file"
    assert action_from_tool_call(backend, bare) == "mcp.filesystem.read_file"
