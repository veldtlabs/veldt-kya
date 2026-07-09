"""Tests for kya_hooks.mcp — the MCP runtime wrapper (task #42).

These tests use a duck-typed fake MCP client, so we don't require the
``mcp`` PyPI package to be installed. The wrapper is designed to work
with anything that exposes an ``async def call_tool(name, arguments)``
method — verified here.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from kya_hooks import wrap_mcp_client
from kya_hooks.client import KyaClient


class _FakeMcpSession:
    """Duck-typed stand-in for mcp.ClientSession.

    Records the call_tool arguments and can be configured to return
    a value or raise. Also carries an unrelated attribute + method to
    verify the wrapper's __getattr__ proxy.
    """

    def __init__(self, return_value=None, raises=None):
        self._return_value = return_value
        self._raises = raises
        self.calls: list[tuple[str, dict | None]] = []
        self.session_metadata = {"tenant": "tenant-a"}  # arbitrary attr

    async def call_tool(self, name: str, arguments: dict | None = None):
        self.calls.append((name, arguments))
        if self._raises:
            raise self._raises
        return self._return_value

    def unrelated_helper(self) -> str:
        return "hi from helper"


@pytest.fixture
def kya_client(monkeypatch):
    """A KyaClient with its network POST replaced by a mock."""
    client = KyaClient(base_url="http://kya-test", token="kya_live_test")
    posts: list[tuple[str, dict]] = []

    def _post(path, body):
        posts.append((path, body))
        return {}

    monkeypatch.setattr(client, "_post", _post)
    client.captured_posts = posts  # type: ignore[attr-defined]
    return client


# ─── Happy path ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wrap_returns_result_and_emits_event(kya_client):
    """Wrapper calls through to the underlying session and returns
    its result unmodified. A single KYA invocation event is posted."""
    session = _FakeMcpSession(return_value={"answer": 42})
    wrapped = wrap_mcp_client(
        session, kya_client=kya_client, agent_key="test-agent"
    )

    result = await wrapped.call_tool("compute", {"x": 1})

    assert result == {"answer": 42}
    assert session.calls == [("compute", {"x": 1})]
    assert len(kya_client.captured_posts) == 1
    path, body = kya_client.captured_posts[0]
    assert path == "/api/v1/admin/agents/events/invocation"
    assert body["agent_key"] == "test-agent"
    assert body["tool_name"] == "compute"
    assert body["outcome"] == "success"
    assert body["mode"] == "observed"
    assert '"x": 1' in body["tool_input"]
    assert body["tool_output"] == '{"answer": 42}'
    assert body["duration_ms"] >= 0


# ─── Attribute proxying ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wrap_proxies_other_attributes(kya_client):
    """Attributes/methods other than call_tool should pass through
    unmodified via __getattr__."""
    session = _FakeMcpSession(return_value="ok")
    wrapped = wrap_mcp_client(session, kya_client=kya_client, agent_key="a")

    # Attribute proxy
    assert wrapped.session_metadata == {"tenant": "tenant-a"}
    # Method proxy
    assert wrapped.unrelated_helper() == "hi from helper"


# ─── Error path ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wrap_reraises_but_still_emits_event(kya_client):
    """When the underlying tool raises, the wrapper emits an event
    with outcome=error THEN re-raises. Caller behavior unchanged."""
    session = _FakeMcpSession(raises=RuntimeError("boom"))
    wrapped = wrap_mcp_client(session, kya_client=kya_client, agent_key="a")

    with pytest.raises(RuntimeError, match="boom"):
        await wrapped.call_tool("failing_tool", {"input": "x"})

    assert len(kya_client.captured_posts) == 1
    body = kya_client.captured_posts[0][1]
    assert body["outcome"] == "error"
    assert body["tool_name"] == "failing_tool"
    assert "RuntimeError" in body["tool_output"]
    assert "boom" in body["tool_output"]


# ─── Event-emit failure isolation ──────────────────────────────────


@pytest.mark.asyncio
async def test_wrap_ignores_event_emit_failure():
    """A failed KYA event-emit must NOT break the caller's tool call.
    The tool result should be returned; only a warning logged."""
    session = _FakeMcpSession(return_value={"result": "ok"})
    broken_client = MagicMock(spec=KyaClient)
    broken_client._post.side_effect = ConnectionError("kya unreachable")

    error_captures: list[Exception] = []

    def _capture(exc):
        error_captures.append(exc)

    wrapped = wrap_mcp_client(
        session,
        kya_client=broken_client,
        agent_key="a",
        on_event_error=_capture,
    )

    # Should complete without raising, returning the tool result.
    result = await wrapped.call_tool("noop", {})
    assert result == {"result": "ok"}
    # Error hook fired exactly once with the ConnectionError.
    assert len(error_captures) == 1
    assert isinstance(error_captures[0], ConnectionError)


# ─── Duck-typing guard ─────────────────────────────────────────────


def test_wrap_rejects_client_without_call_tool(kya_client):
    """Guardrail — passing something without an async call_tool()
    method should raise a clear TypeError, not fail silently later."""

    class NoCallTool:
        pass

    with pytest.raises(TypeError, match="no call_tool"):
        wrap_mcp_client(NoCallTool(), kya_client=kya_client, agent_key="a")


# ─── Payload truncation ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wrap_truncates_large_payloads(kya_client):
    """tool_input / tool_output over 32 KB should be truncated with
    a marker so downstream ingest doesn't reject the wire body."""
    big_input = "x" * 40_000
    big_output = "y" * 40_000
    session = _FakeMcpSession(return_value=big_output)
    wrapped = wrap_mcp_client(session, kya_client=kya_client, agent_key="a")

    await wrapped.call_tool("big_tool", {"payload": big_input})

    body = kya_client.captured_posts[0][1]
    assert len(body["tool_input"]) <= 32_000
    assert len(body["tool_output"]) <= 32_000
    assert body["tool_output"].endswith("[truncated]")


# ─── Optional metadata pass-through ────────────────────────────────


@pytest.mark.asyncio
async def test_wrap_passes_optional_metadata(kya_client):
    """principal_kind, principal_id, correlation_id should ride through
    to the emitted event when supplied at wrap time."""
    session = _FakeMcpSession(return_value="ok")
    wrapped = wrap_mcp_client(
        session,
        kya_client=kya_client,
        agent_key="a",
        principal_kind="agent",
        principal_id="a-instance-1",
        correlation_id="corr-1234",
    )
    await wrapped.call_tool("noop", {})

    body = kya_client.captured_posts[0][1]
    assert body["principal_kind"] == "agent"
    assert body["principal_id"] == "a-instance-1"
    assert body["correlation_id"] == "corr-1234"
