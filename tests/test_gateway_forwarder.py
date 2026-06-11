"""Tests for kya_gateway.forwarder — backend HTTP proxy.

Covers backend lookup, error coercion (B7 — 5xx → BackendUnreachable;
4xx passed through), httpx error mapping, and parse_backend_from_tool.
"""
from __future__ import annotations

import pytest

from kya_gateway.config import BackendConfig
from kya_gateway.errors import BackendUnreachable
from kya_gateway.forwarder import (
    Forwarder,
    parse_backend_from_tool,
)

# ─── parse_backend_from_tool ───────────────────────────────────────


def test_parse_backend_with_dot():
    assert parse_backend_from_tool("filesystem.read") == ("filesystem", "read")


def test_parse_backend_without_dot_defaults():
    assert parse_backend_from_tool("read") == ("default", "read")


def test_parse_backend_nested_dots():
    """Only the FIRST dot separates backend from tool name."""
    assert parse_backend_from_tool("k8s.pods.list") == ("k8s", "pods.list")


# ─── Backend lookup ────────────────────────────────────────────────


def test_unknown_backend_raises_backend_unreachable():
    fwd = Forwarder([BackendConfig(name="default", url="http://x")])
    with pytest.raises(BackendUnreachable, match=r"(?i)unknown backend"):
        fwd.get_backend("nonexistent")


def test_known_backend_returns_config():
    fwd = Forwarder([BackendConfig(name="fs", url="http://x")])
    assert fwd.get_backend("fs").name == "fs"


# ─── forward_json error coercion ───────────────────────────────────


@pytest.fixture
def fwd():
    return Forwarder([BackendConfig(name="default", url="http://localhost:9999")])


class _FakeResponse:
    def __init__(self, status_code: int, content: bytes = b"", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}


class _FakeAsyncClient:
    def __init__(self, *, raises=None, response=None):
        self._raises = raises
        self._response = response

    async def post(self, *args, **kwargs):
        if self._raises is not None:
            raise self._raises
        return self._response

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_forward_json_5xx_raises_backend_unreachable(fwd, monkeypatch):
    """5xx backend response must coerce to BackendUnreachable so the
    gateway returns 502 (consistent with forward_stream)."""
    fwd._client = _FakeAsyncClient(response=_FakeResponse(500, b"server boom"))
    with pytest.raises(BackendUnreachable, match=r"(?i)500"):
        await fwd.forward_json("default", {"jsonrpc": "2.0"})


@pytest.mark.asyncio
async def test_forward_json_4xx_passes_through(fwd):
    """4xx responses (typically JSON-RPC errors from the backend) are
    relayed unchanged — the body has structured info the client needs."""
    fwd._client = _FakeAsyncClient(
        response=_FakeResponse(404, b'{"error":"method not found"}'),
    )
    result = await fwd.forward_json("default", {"jsonrpc": "2.0"})
    assert result.status_code == 404
    assert b"method not found" in result.body


@pytest.mark.asyncio
async def test_forward_json_httpx_error_raises_backend_unreachable(fwd):
    """Transport-level httpx errors must coerce to BackendUnreachable."""
    import httpx
    fwd._client = _FakeAsyncClient(raises=httpx.ConnectError("connection refused"))
    with pytest.raises(BackendUnreachable, match=r"(?i)fail.*reach"):
        await fwd.forward_json("default", {"jsonrpc": "2.0"})


@pytest.mark.asyncio
async def test_forward_json_happy_path_returns_body(fwd):
    fwd._client = _FakeAsyncClient(
        response=_FakeResponse(200, b'{"result":"hello"}',
                               headers={"content-type": "application/json"}),
    )
    result = await fwd.forward_json("default", {"jsonrpc": "2.0"})
    assert result.status_code == 200
    assert result.body == b'{"result":"hello"}'
    assert result.headers["content-type"] == "application/json"
