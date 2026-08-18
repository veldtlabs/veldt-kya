"""aiohttp server exposing the reference MCP tools.

Endpoints
---------
    POST /mcp                  JSON-RPC 2.0 handler; MCP methods:
                                 - initialize      (handshake, no-op)
                                 - tools/list      (advertise registered tools)
                                 - tools/call      (invoke a tool)
                               Any other method → -32601 (Method not found).
    GET  /healthz              Liveness probe (always 200).
    POST /_test/reset_counters Test-only. Route registered ONLY when
                               ``KYA_MCP_TEST_MODE=1`` at boot; a
                               defence-in-depth 404 also guards the
                               handler if it somehow ran without the env.

Trust boundary
--------------
This server holds NO governance logic. It runs whatever the gateway
forwards. Protection against direct exposure is at the docker-compose
network boundary: no ``ports:`` mapping is declared on the reference
container. The gateway reaches it via internal service name; nothing else can.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from aiohttp import web

from kya_mcp_tools_ref import __version__
from kya_mcp_tools_ref.config import RefConfig
from kya_mcp_tools_ref import tools as tools_mod

logger = logging.getLogger(__name__)


# MCP protocol constants
_PROTOCOL_VERSION = "2024-11-05"
_JSONRPC_VERSION = "2.0"

# JSON-RPC 2.0 error codes we emit.
_JRPC_PARSE_ERROR = -32700
_JRPC_INVALID_REQUEST = -32600
_JRPC_METHOD_NOT_FOUND = -32601
_JRPC_INVALID_PARAMS = -32602
_JRPC_INTERNAL_ERROR = -32603

# Cap on incoming request body to prevent trivial memory exhaustion.
# Gateway already enforces 32 MB upstream; we're stricter here.
_MAX_BODY_BYTES = 4 * 1024 * 1024  # 4 MB


def _jrpc_error(id_: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": _JSONRPC_VERSION, "id": id_, "error": {"code": code, "message": message}}


def _jrpc_result(id_: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": _JSONRPC_VERSION, "id": id_, "result": result}


def _tool_spec_to_mcp(spec: tools_mod.ToolSpec) -> dict[str, Any]:
    """Shape a ToolSpec for MCP tools/list output."""
    return {
        "name": spec.name,
        "description": spec.description,
        "inputSchema": spec.input_schema,
        # Non-standard field — advertised for clients that filter by regime.
        # See package docstring re: not persisted in evidence.
        "regimes": list(spec.regimes),
    }


async def _handle_mcp(request: web.Request) -> web.Response:
    """POST /mcp — JSON-RPC 2.0 method dispatch."""
    if request.content_length is not None and request.content_length > _MAX_BODY_BYTES:
        return web.json_response(
            _jrpc_error(None, _JRPC_INVALID_REQUEST, "request body too large"),
            status=413,
        )
    raw = await request.read()
    if len(raw) > _MAX_BODY_BYTES:
        return web.json_response(
            _jrpc_error(None, _JRPC_INVALID_REQUEST, "request body too large"),
            status=413,
        )

    try:
        import json
        envelope = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return web.json_response(_jrpc_error(None, _JRPC_PARSE_ERROR, "invalid JSON"), status=400)

    if not isinstance(envelope, dict):
        return web.json_response(_jrpc_error(None, _JRPC_INVALID_REQUEST, "batch not supported"), status=400)
    if envelope.get("jsonrpc") != _JSONRPC_VERSION:
        return web.json_response(
            _jrpc_error(envelope.get("id"), _JRPC_INVALID_REQUEST, "jsonrpc must be '2.0'"),
            status=400,
        )

    method = envelope.get("method")
    params = envelope.get("params", {}) or {}
    id_ = envelope.get("id")
    if not isinstance(method, str):
        return web.json_response(
            _jrpc_error(id_, _JRPC_INVALID_REQUEST, "method must be a string"),
            status=400,
        )

    # --- initialize --------------------------------------------------
    if method == "initialize":
        return web.json_response(
            _jrpc_result(
                id_,
                {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "serverInfo": {"name": "kya-mcp-tools-ref", "version": __version__},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            )
        )

    # --- tools/list --------------------------------------------------
    if method == "tools/list":
        return web.json_response(
            _jrpc_result(
                id_,
                {"tools": [_tool_spec_to_mcp(spec) for spec in tools_mod.TOOLS.values()]},
            )
        )

    # --- tools/call --------------------------------------------------
    if method == "tools/call":
        if not isinstance(params, dict):
            return web.json_response(
                _jrpc_error(id_, _JRPC_INVALID_PARAMS, "params must be an object"),
                status=400,
            )
        tool_name = params.get("name")
        arguments = params.get("arguments", {}) or {}
        if not isinstance(tool_name, str):
            return web.json_response(
                _jrpc_error(id_, _JRPC_INVALID_PARAMS, "name must be a string"),
                status=400,
            )
        if not isinstance(arguments, dict):
            return web.json_response(
                _jrpc_error(id_, _JRPC_INVALID_PARAMS, "arguments must be an object"),
                status=400,
            )
        # The KYA gateway forwards req.raw unchanged, so a call routed as
        # ``mcp.<backend>.<tool>`` arrives here with the ``<backend>.`` prefix
        # still attached to params.name. Strip an optional leading
        # ``<anything>.`` segment so this backend is gateway-name-agnostic —
        # customers can wire it as any backend name in their gateway.yaml
        # without needing to re-register tools.
        bare_tool_name = tool_name.rsplit(".", 1)[-1]
        spec = tools_mod.TOOLS.get(bare_tool_name)
        if spec is None:
            # Tool not registered — either the name is unknown OR the
            # tool is disabled (e.g., governed_bash without env flag).
            # Both cases collapse to "unknown tool" from the client's
            # view; the client cannot discover the tool via tools/list
            # either, so this is consistent.
            return web.json_response(
                _jrpc_error(id_, _JRPC_METHOD_NOT_FOUND, f"unknown tool: {tool_name}"),
                status=404,
            )
        try:
            result = spec.handler(arguments)
        except Exception:  # noqa: BLE001
            logger.exception("tool %s raised", tool_name)
            return web.json_response(
                _jrpc_error(id_, _JRPC_INTERNAL_ERROR, "tool crashed — see server logs"),
                status=500,
            )
        return web.json_response(
            _jrpc_result(id_, {"content": result.content, "isError": result.is_error})
        )

    return web.json_response(
        _jrpc_error(id_, _JRPC_METHOD_NOT_FOUND, f"unsupported method: {method}"),
        status=404,
    )


async def _handle_healthz(request: web.Request) -> web.Response:  # noqa: ARG001
    """GET /healthz — liveness probe."""
    return web.json_response({"status": "ok"})


async def _handle_reset_counters(request: web.Request) -> web.Response:
    """POST /_test/reset_counters — test-only counter reset.

    Only registered when ``KYA_MCP_TEST_MODE=1`` at boot. Defence-in-depth:
    if the handler runs but the env is missing, return 404.
    """
    if os.environ.get("KYA_MCP_TEST_MODE") != "1":
        return web.json_response({"error": "not found"}, status=404)
    tools_mod.reset_invocation_counters()
    return web.json_response({"reset": True, "counters": tools_mod.get_invocation_counters()})


def build_app(cfg: RefConfig | None = None) -> web.Application:
    """Construct the aiohttp application.

    Reads :class:`~kya_mcp_tools_ref.config.RefConfig` once (unless passed),
    populates the :data:`~kya_mcp_tools_ref.tools.TOOLS` registry, binds
    config for handler access, ensures scratch dir exists, and wires
    routes. The test-only reset endpoint is registered ONLY when
    ``KYA_MCP_TEST_MODE=1`` at boot.
    """
    if cfg is None:
        cfg = RefConfig.from_env()

    # Ensure scratch root exists so first file_read/write does not race.
    os.makedirs(cfg.scratch_root, exist_ok=True)

    # Populate module-global registry + bind cfg for tool handlers.
    tools_mod.TOOLS.clear()
    tools_mod.TOOLS.update(tools_mod.build_registry(cfg))
    tools_mod.bind_config(cfg)

    logger.info(
        "kya-mcp-tools-ref starting: scratch=%s tools=%s test_mode=%s",
        cfg.scratch_root,
        sorted(tools_mod.TOOLS.keys()),
        cfg.test_mode,
    )

    app = web.Application(client_max_size=_MAX_BODY_BYTES)
    app.router.add_post("/mcp", _handle_mcp)
    app.router.add_get("/healthz", _handle_healthz)
    if cfg.test_mode:
        # Registered only in test mode. Production images MUST NOT set
        # KYA_MCP_TEST_MODE=1. The handler carries a second 404 check as
        # defence in depth.
        app.router.add_post("/_test/reset_counters", _handle_reset_counters)
    return app


def run(host: str = "0.0.0.0", port: int = 18090) -> None:
    """Start the aiohttp server. Blocks until terminated.

    Single-worker by design — the per-tool invocation counters are process
    globals and would diverge under multi-worker deployment. Do not front
    with gunicorn --workers=N.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    app = build_app()
    web.run_app(app, host=host, port=port, print=None)
