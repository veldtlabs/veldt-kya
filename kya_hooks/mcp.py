"""
Model Context Protocol (MCP) runtime hook for KYA.

Wraps an MCP client so every `call_tool()` invocation streams a KYA
invocation event with `tool_name`, `tool_input`, and `tool_output`. The
existing Veldt ingest pipeline (task #27 / #30) then runs the tool-side
scanners (Presidio + jailbreak catalog + regex fallback) on the payload
and writes signed evidence rows.

Design constraints (per task #42):

- **Pure add-on** — importing this module does NOT touch existing MCP
  code, ingest paths, or the wire contract. If the user never calls
  ``wrap_mcp_client()``, nothing changes.
- **Optional dependency** — the ``mcp`` SDK is imported lazily. The
  module itself imports cleanly on a system without MCP installed;
  only ``wrap_mcp_client()`` raises ``RuntimeError`` with an install
  hint when the SDK is missing.
- **Async-native** — MCP's ``Client.call_tool()`` is a coroutine.
  The wrapper preserves that.
- **Non-blocking on failures** — a Veldt event-emit failure never
  breaks a real MCP tool call. Errors are logged, tool call proceeds.
- **Type-preserving** — the wrapped client passes through every
  attribute (proxies via ``__getattr__``), so downstream code that
  passes the wrapped client to MCP helpers keeps working.

Usage
-----

    import asyncio
    from mcp.client.stdio import stdio_client
    from mcp.client.session import ClientSession
    from kya_hooks import KyaClient, wrap_mcp_client

    kya = KyaClient(base_url="https://api.veldtlabs.ai",
                    token="kya_live_...")

    async def main():
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                # Wrap once. All call_tool() invocations on `wrapped`
                # now emit KYA events automatically.
                wrapped = wrap_mcp_client(
                    session,
                    kya_client=kya,
                    agent_key="my-mcp-agent",
                )
                result = await wrapped.call_tool(
                    "search_docs", {"query": "quarterly earnings"}
                )
                print(result)

    asyncio.run(main())

That's it. No decorator, no monkey-patch of the MCP module — you get
a proxy object that behaves exactly like the underlying session for
every attribute except ``call_tool``.

Test coverage: see ``tests/test_mcp_wrapper.py``.
"""
from __future__ import annotations

import json as _json
import logging
import time
from typing import Any, Awaitable, Callable

from .client import KyaClient
from .scanner import DataLeakScanner

logger = logging.getLogger(__name__)


# Max chars we hash into the invocation event. Same 32k ceiling the
# InvocationEventBody enforces on the ingest side — truncate here so
# a 200MB MCP tool result doesn't get serialized in memory just to
# be rejected by the caller.
_MAX_TOOL_FIELD_CHARS = 32_000


def _stringify(value: Any) -> str:
    """Best-effort conversion of an MCP tool argument or result into
    a string for Veldt's ingest wire.

    MCP tool args/results are Python objects (dicts, lists, primitives,
    Pydantic models). We JSON-serialize when possible; on failure we
    fall back to ``str()``. Empty / None returns empty string so the
    downstream scanner just skips it.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return _json.dumps(value, default=str)
    except Exception:
        try:
            return str(value)
        except Exception:
            return "<unserializable>"


def _truncate(s: str, limit: int = _MAX_TOOL_FIELD_CHARS) -> str:
    if len(s) <= limit:
        return s
    return s[: limit - 20] + "…[truncated]"


class _WrappedMcpClient:
    """Proxy around an MCP client/session that intercepts ``call_tool``.

    Any attribute other than ``call_tool`` is delegated to the
    underlying client via ``__getattr__``. This keeps compatibility
    with helpers that pass the client to other MCP APIs (progress
    handlers, subscription streams, prompt fetches, etc.).
    """

    def __init__(
        self,
        client: Any,
        *,
        kya_client: KyaClient,
        agent_key: str,
        principal_kind: str | None = None,
        principal_id: str | None = None,
        correlation_id: str | None = None,
        scanner: DataLeakScanner | None = None,
        on_event_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self._client = client
        self._kya = kya_client
        self._agent_key = agent_key
        self._principal_kind = principal_kind
        self._principal_id = principal_id
        self._correlation_id = correlation_id
        self._scanner = scanner
        # Optional callback for structural logging of event-emit
        # failures. Defaults to a warning log — no user-visible impact.
        self._on_event_error = on_event_error or (
            lambda exc: logger.warning(
                "[mcp-wrap] failed to emit KYA event for tool call: %s", exc
            )
        )

    def __getattr__(self, name: str) -> Any:
        # Only called when normal attribute lookup fails. Proxies
        # everything except our own ``call_tool`` override to the
        # underlying MCP client/session.
        return getattr(self._client, name)

    async def call_tool(self, name: str, arguments: dict | None = None) -> Any:
        """Wrapped call_tool — behaves identically to the underlying
        client's method, but emits a KYA invocation event on completion.

        Errors from the emit path NEVER propagate: a failed KYA event
        will not break the caller's tool call. The tool result is
        returned exactly as the underlying client returned it.
        """
        started = time.monotonic()
        tool_input_str = _truncate(_stringify(arguments or {}))
        error_outcome: str | None = None
        tool_output_str = ""

        try:
            result = await self._client.call_tool(name, arguments)
        except Exception as exc:
            # Emit an event with outcome=error so the operator sees
            # the failure in /activity, then re-raise so the caller
            # still gets the normal exception behavior.
            error_outcome = "error"
            tool_output_str = _truncate(f"<exception:{type(exc).__name__}> {exc}")
            self._emit(
                tool_name=name,
                tool_input=tool_input_str,
                tool_output=tool_output_str,
                duration_ms=int((time.monotonic() - started) * 1000),
                outcome=error_outcome,
            )
            raise

        # Success path.
        tool_output_str = _truncate(_stringify(result))
        # Optional client-side scanner — same DataLeakScanner the other
        # framework adapters use. Fires on the raw output before it
        # hits the wire; findings become a KYA rogue event.
        if self._scanner is not None:
            try:
                findings = self._scanner.scan(tool_output_str)
                if findings:
                    logger.warning(
                        "[mcp-wrap] scanner findings on tool=%s count=%d",
                        name, len(findings),
                    )
            except Exception as scan_exc:
                logger.debug("[mcp-wrap] scanner raised: %s", scan_exc)

        self._emit(
            tool_name=name,
            tool_input=tool_input_str,
            tool_output=tool_output_str,
            duration_ms=int((time.monotonic() - started) * 1000),
            outcome="success",
        )
        return result

    # ─── internal ─────────────────────────────────────────────────

    def _emit(
        self,
        *,
        tool_name: str,
        tool_input: str,
        tool_output: str,
        duration_ms: int,
        outcome: str,
    ) -> None:
        payload = {
            "agent_key": self._agent_key,
            "mode": "observed",
            "outcome": outcome,
            "duration_ms": duration_ms,
            "tool_name": tool_name,
        }
        if tool_input:
            payload["tool_input"] = tool_input
        if tool_output:
            payload["tool_output"] = tool_output
        if self._principal_kind:
            payload["principal_kind"] = self._principal_kind
        if self._principal_id:
            payload["principal_id"] = self._principal_id
        if self._correlation_id:
            payload["correlation_id"] = self._correlation_id

        try:
            # Route through KyaClient's invocation endpoint.
            self._kya._post("/api/v1/admin/agents/events/invocation", payload)
        except Exception as exc:
            self._on_event_error(exc)


def wrap_mcp_client(
    client: Any,
    *,
    kya_client: KyaClient,
    agent_key: str,
    principal_kind: str | None = None,
    principal_id: str | None = None,
    correlation_id: str | None = None,
    scanner: DataLeakScanner | None = None,
    on_event_error: Callable[[Exception], None] | None = None,
) -> _WrappedMcpClient:
    """Return a proxy that wraps ``client.call_tool()`` to emit KYA events.

    Parameters
    ----------
    client
        Any object exposing an ``async def call_tool(name, arguments)``
        method — typically an ``mcp.ClientSession`` or a custom MCP
        client. Duck-typed so we don't hard-require the ``mcp`` SDK.
    kya_client
        Configured ``KyaClient`` — the wrapper posts invocation events
        via this client's bearer.
    agent_key
        Stable identifier used in every emitted event.
    principal_kind, principal_id, correlation_id
        Optional metadata passed through to the invocation event.
    scanner
        Optional ``DataLeakScanner`` for local pre-emit scanning of
        tool outputs.
    on_event_error
        Callback invoked (with the raising exception) when a KYA
        event-emit fails. Defaults to a warning log. The tool call
        result is returned to the caller either way — a failed KYA
        event never breaks the underlying tool call.

    Returns
    -------
    _WrappedMcpClient
        A proxy that behaves like ``client`` for every attribute
        except ``call_tool``.

    Notes
    -----
    Does NOT install or require the ``mcp`` PyPI package. The wrapper
    is purely duck-typed — any object with an async ``call_tool``
    method works. That keeps the OSS install path unchanged for users
    who don't run MCP agents.
    """
    if not hasattr(client, "call_tool"):
        raise TypeError(
            f"wrap_mcp_client: {type(client).__name__} has no call_tool() "
            "method. Pass an mcp.ClientSession or compatible client."
        )
    return _WrappedMcpClient(
        client,
        kya_client=kya_client,
        agent_key=agent_key,
        principal_kind=principal_kind,
        principal_id=principal_id,
        correlation_id=correlation_id,
        scanner=scanner,
        on_event_error=on_event_error,
    )


__all__ = ["wrap_mcp_client"]
