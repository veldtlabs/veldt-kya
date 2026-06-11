"""Forwarder — proxies authorized MCP calls to the configured backend.

The forwarder is intentionally narrow:
    * Map ``backend_name`` from the tool name (first segment after ``mcp.``).
    * POST the original JSON-RPC envelope.
    * Stream the response back (SSE-friendly).
    * Convert transport/protocol errors into ``BackendUnreachable``.

It never inspects or rewrites the payload — that's the job of the policy
pipeline upstream. The forwarder's only job is "deliver this bytes blob
and return the response bytes blob, preserving streaming semantics."
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx

from kya_gateway.config import BackendConfig
from kya_gateway.errors import BackendUnreachable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ForwardResult:
    """A non-streaming forwarder result."""

    status_code: int
    body: bytes
    headers: dict[str, str]


class Forwarder:
    """Backend-name → BackendConfig lookup plus the actual HTTP forwarding."""

    def __init__(self, backends: list[BackendConfig]):
        self._backends: dict[str, BackendConfig] = {b.name: b for b in backends}
        # Persistent client per forwarder; gives us connection pooling.
        # The gateway calls ``aclose()`` on shutdown.
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def get_backend(self, backend_name: str) -> BackendConfig:
        """Look up the configured backend; raise if not configured."""
        b = self._backends.get(backend_name)
        if b is None:
            raise BackendUnreachable(
                f"unknown backend {backend_name!r}. "
                f"Configured: {sorted(self._backends.keys())}"
            )
        return b

    async def forward_json(
        self,
        backend_name: str,
        payload: dict,
        *,
        extra_request_headers: dict[str, str] | None = None,
    ) -> ForwardResult:
        """Forward a non-streaming JSON-RPC call.

        5xx backend responses are coerced into ``BackendUnreachable`` so
        the gateway returns a 502 to the client (consistent with
        ``forward_stream``). 4xx responses are passed through unchanged
        — those typically encode JSON-RPC errors from the backend (e.g.,
        method-not-found) and the body has structured info the client
        needs.

        ``extra_request_headers`` carry KYA signals to the backend
        (Phase 5g — 5g-A-02). Default-empty so existing call sites
        don't change behavior.
        """
        backend = self.get_backend(backend_name)
        try:
            resp = await self._client.post(
                backend.url,
                json=payload,
                timeout=backend.timeout_s,
                headers=extra_request_headers or None,
            )
        except httpx.HTTPError as exc:
            raise BackendUnreachable(
                f"failed to reach backend {backend_name!r} at {backend.url!r}: {exc}"
            ) from exc
        if resp.status_code >= 500:
            raise BackendUnreachable(
                f"backend {backend_name!r} returned HTTP {resp.status_code}: "
                f"{resp.content[:256]!r}"
            )
        return ForwardResult(
            status_code=resp.status_code,
            body=resp.content,
            headers=dict(resp.headers),
        )

    async def forward_stream(
        self,
        backend_name: str,
        payload: dict,
    ) -> AsyncIterator[bytes]:
        """Forward a JSON-RPC call and stream the response chunks back.

        Yields raw bytes so the caller can pass them straight to a
        Server-Sent Events response without transcoding.
        """
        backend = self.get_backend(backend_name)
        try:
            async with self._client.stream(
                "POST",
                backend.url,
                json=payload,
                timeout=backend.timeout_s,
            ) as resp:
                if resp.status_code >= 400:
                    body = await resp.aread()
                    raise BackendUnreachable(
                        f"backend {backend_name!r} returned HTTP {resp.status_code}: "
                        f"{body[:512]!r}"
                    )
                async for chunk in resp.aiter_bytes():
                    if chunk:
                        yield chunk
        except httpx.HTTPError as exc:
            raise BackendUnreachable(
                f"streaming forward failed to backend {backend_name!r}: {exc}"
            ) from exc


def parse_backend_from_tool(tool_name: str) -> tuple[str, str]:
    """Split a fully-qualified tool name into (backend, tool).

    The MCP convention KYA follows is ``<backend>.<tool>``. If the tool
    doesn't have a backend prefix, return ``("default", tool_name)`` so
    a single-backend gateway still works.

    Returns:
        (backend_name, bare_tool_name)
    """
    if "." not in tool_name:
        return "default", tool_name
    backend, _, bare = tool_name.partition(".")
    return backend, bare
