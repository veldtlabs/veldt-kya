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
import unicodedata
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

        ``extra_request_headers`` carry KYA signals to the backend.
        Default-empty so existing call sites don't change behavior.
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


class MalformedToolName(ValueError):
    """Raised when ``tool_name`` is not a valid ``<backend>.<tool>`` or ``<tool>``.

    Callers should surface this as a JSON-RPC ``_JRPC_INVALID_PARAMS``
    (``-32602``) response with HTTP 400 rather than letting it bubble to
    a 500. The gateway's ``tools/call`` dispatch wraps this into the
    correct envelope shape.
    """


# Hard byte cap on a single tool/backend segment. Two segments joined
# by "." give a 512-byte ceiling on the total tool_name — small enough
# that a caller cannot make the RBAC scan or evidence row expensive by
# smuggling a 100 kB "tool name".
_MAX_TOOL_SEGMENT_BYTES = 256


def canonicalize_tool_segment(s: str) -> str:
    """Normalize a backend or tool name for RBAC matching.

    - NFKC compose (folds full-width, ligatures, compatibility chars)
    - casefold (broader than ``lower()`` for cross-locale case)
    - strip leading/trailing whitespace
    - reject if the resulting segment contains Unicode ``Cf`` (Format),
      ``Cc`` (Control), or non-ASCII ``Zs`` (Space Separator) chars —
      those are invisible smuggle vectors (ZWSP, NBSP, RLO, etc.)
    - reject embedded ASCII whitespace after strip — a tool identifier
      may not contain an inner space
    - reject any non-ASCII char (Cyrillic/Greek homoglyphs like ``о`` /
      ``ο`` for Latin ``o`` are 100% smuggle attempts and NFKC does
      NOT fold them)
    - reject empty result (input was pure whitespace)
    - reject > ``_MAX_TOOL_SEGMENT_BYTES`` bytes (UTF-8)

    Raises :class:`MalformedToolName` on any of the above; callers
    surface as HTTP 400 with ``MALFORMED_TOOL_NAME`` reason code (see
    ``kya_gateway.server`` /mcp and /v1/policy/decide handlers).
    """
    if not isinstance(s, str):
        raise MalformedToolName(
            f"tool segment must be a string, got {type(s).__name__}"
        )
    # Byte-length check on the ORIGINAL input — an attacker cannot
    # inflate past the cap and hope NFKC shrinks it below.
    if len(s.encode("utf-8")) > _MAX_TOOL_SEGMENT_BYTES:
        raise MalformedToolName(
            f"tool segment exceeds {_MAX_TOOL_SEGMENT_BYTES} bytes"
        )
    canon = unicodedata.normalize("NFKC", s).casefold().strip()
    if not canon:
        raise MalformedToolName("tool segment is empty after canonicalization")
    for ch in canon:
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc"):
            raise MalformedToolName(
                f"tool segment contains disallowed control/format char "
                f"(U+{ord(ch):04X})"
            )
        if cat == "Zs" and ch != " ":
            raise MalformedToolName(
                f"tool segment contains non-ASCII whitespace "
                f"(U+{ord(ch):04X})"
            )
        # After strip, an embedded ASCII space is still suspicious for
        # a tool identifier — reject rather than silently paper over.
        if ch == " ":
            raise MalformedToolName(
                "tool segment contains embedded whitespace"
            )
        # Tool identifiers are ASCII-only. Cyrillic/Greek homoglyphs
        # (e.g., Cyrillic ``о`` U+043E vs Latin ``o`` U+006F) do NOT
        # fold via NFKC and would otherwise bypass RBAC on lookalike
        # names. Reject non-ASCII outright.
        if ord(ch) > 0x7F:
            raise MalformedToolName(
                f"tool segment contains non-ASCII char "
                f"(U+{ord(ch):04X}); tool identifiers must be ASCII"
            )
    return canon


def parse_backend_from_tool(tool_name: str) -> tuple[str, str]:
    """Split a fully-qualified tool name into (backend, tool).

    The MCP convention KYA follows is ``<backend>.<tool>``. If the tool
    doesn't have a backend prefix, return ``("default", tool_name)`` so
    a single-backend gateway still works.

    Rejects (raises :class:`MalformedToolName`):
        * Non-string ``tool_name`` — a bare int or list would otherwise
          raise ``TypeError`` inside ``"." not in ...`` and surface as an
          uncaught 500 with a leaked traceback.
        * More than one dot — e.g. ``reference.reference.governed_bash``.
          The tail-dot would still produce a valid backend + bare-tool
          split, but the resulting RBAC action string
          (``mcp.reference.reference.governed_bash``) would NOT match a
          deny rule written for ``mcp.reference.governed_bash``, giving
          a policy bypass. Fail-closed here as defence in depth so a
          backend that forgets to check the shape is still safe.

    Returns:
        (backend_name, bare_tool_name)
    """
    if not isinstance(tool_name, str):
        raise MalformedToolName(
            f"tool name must be a string, got {type(tool_name).__name__}"
        )
    if "." not in tool_name:
        # Single-segment tool. Canonicalize it AND return "default" as
        # backend — canonical form is what RBAC + evidence records use.
        return "default", canonicalize_tool_segment(tool_name)
    # Reject prefix-repeat / nested-dot names — see docstring.
    if tool_name.count(".") > 1:
        raise MalformedToolName(
            "tool name must be '<backend>.<tool>' or '<tool>' "
            "(nested dots are not allowed)"
        )
    backend, _, bare = tool_name.partition(".")
    # Canonicalize BOTH segments (NFKC + casefold + strip + reject
    # invisibles / non-ASCII / oversized). The canonical form is what
    # RBAC matches against AND what evidence records. Callers that
    # named the tool with case/Unicode variants see their canonical
    # form in evidence — fair; they should have used it in the first
    # place.
    return (
        canonicalize_tool_segment(backend),
        canonicalize_tool_segment(bare),
    )
