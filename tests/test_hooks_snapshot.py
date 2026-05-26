"""Tests for snapshot-on-first-sight wiring in kya_hooks adapters."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import init_storage
from kya_hooks._snapshot import (
    maybe_snapshot_first_sight,
    reset_cache,
    seen_keys,
)


TENANT = "00000000-0000-0000-0000-000000000bbb"


@pytest.fixture
def db_factory(tmp_path):
    """Yields a session_factory backed by a fresh on-disk sqlite db."""
    url = f"sqlite:///{tmp_path / 'kya.db'}"
    eng = create_engine(url).execution_options(
        schema_translate_map={"prov_schema": None})
    SessionLocal = sessionmaker(bind=eng)
    # Initialize tables once
    with SessionLocal() as db:
        init_storage(db)
    yield SessionLocal
    eng.dispose()


@pytest.fixture(autouse=True)
def clean_cache():
    reset_cache()
    yield
    reset_cache()


# ── Core cache behavior ────────────────────────────────────────────


def test_first_call_writes_snapshot(db_factory):
    agent_def = {"agent_key": "A1", "tools": ["t1"],
                 "model": "gpt-4o-mini"}
    wrote = maybe_snapshot_first_sight(
        tenant_id=TENANT, agent_key="A1",
        agent_def=agent_def, session_factory=db_factory)
    assert wrote is True

    with db_factory() as db:
        rows = db.execute(text(
            "SELECT agent_key FROM agent_versions WHERE agent_key=:k"
        ), {"k": "A1"}).fetchall()
    assert len(rows) == 1
    assert ("A1",) in [(r[0],) for r in rows]


def test_second_call_is_cache_hit(db_factory):
    agent_def = {"agent_key": "A2", "tools": []}
    a = maybe_snapshot_first_sight(
        tenant_id=TENANT, agent_key="A2",
        agent_def=agent_def, session_factory=db_factory)
    b = maybe_snapshot_first_sight(
        tenant_id=TENANT, agent_key="A2",
        agent_def=agent_def, session_factory=db_factory)
    assert a is True
    assert b is False  # cache hit
    assert (TENANT, "A2") in seen_keys()


def test_disabled_returns_false_and_doesnt_snapshot(db_factory):
    wrote = maybe_snapshot_first_sight(
        tenant_id=TENANT, agent_key="A3",
        agent_def={"agent_key": "A3"},
        session_factory=db_factory, enabled=False)
    assert wrote is False
    with db_factory() as db:
        rows = db.execute(text(
            "SELECT * FROM agent_versions WHERE agent_key=:k"
        ), {"k": "A3"}).fetchall()
    assert rows == []


def test_no_tenant_returns_false(db_factory):
    wrote = maybe_snapshot_first_sight(
        tenant_id=None, agent_key="A4",
        agent_def={"agent_key": "A4"},
        session_factory=db_factory)
    assert wrote is False


def test_db_failure_releases_cache_slot(monkeypatch):
    """If the underlying snapshot raises, the cache marker must be
    rolled back so a later call retries."""
    def broken_factory():
        raise RuntimeError("connection refused")
    wrote = maybe_snapshot_first_sight(
        tenant_id=TENANT, agent_key="A5",
        agent_def={"agent_key": "A5"},
        session_factory=broken_factory)
    assert wrote is False
    # Must NOT have left the cache marker set
    assert (TENANT, "A5") not in seen_keys()


# ── OpenAI Agents adapter ──────────────────────────────────────────


@pytest.fixture
def fake_openai_agents_sdk(monkeypatch):
    """Inject minimal stubs for the `agents` package so the lazy
    import inside openai_agents_hooks() succeeds without the real
    SDK installed."""

    class Agent: ...
    class RunHooks:
        def __init__(self):
            pass
    class RunContextWrapper: ...

    fake_mod = SimpleNamespace(
        Agent=Agent,
        RunHooks=RunHooks,
        RunContextWrapper=RunContextWrapper,
    )
    monkeypatch.setitem(__import__("sys").modules, "agents", fake_mod)
    yield {"Agent": Agent, "RunHooks": RunHooks,
            "RunContextWrapper": RunContextWrapper}


def test_openai_hook_on_tool_start_snapshots(db_factory,
                                              fake_openai_agents_sdk):
    import asyncio
    from kya_hooks.openai_agents import openai_agents_hooks

    client = MagicMock()
    hooks = openai_agents_hooks(
        client,
        allowed_tools_per_agent={"agentX": {"lookup"}},
        tenant_id=TENANT,
        session_factory=db_factory,
    )

    Agent = fake_openai_agents_sdk["Agent"]
    agent = Agent()
    agent.name = "agentX"
    agent.instructions = "be helpful"
    agent.model = "gpt-4o-mini"
    agent.tools = [SimpleNamespace(name="lookup")]

    tool = SimpleNamespace(name="lookup")
    ctx = MagicMock()

    asyncio.get_event_loop().run_until_complete(
        hooks.on_tool_start(ctx, agent, tool))

    with db_factory() as db:
        rows = db.execute(text(
            "SELECT agent_key, definition FROM agent_versions "
            "WHERE agent_key='agentX'"
        )).fetchall()
    assert len(rows) == 1


def test_openai_hook_on_handoff_snapshots_both_agents(db_factory,
                                                       fake_openai_agents_sdk):
    import asyncio
    from kya_hooks.openai_agents import openai_agents_hooks

    client = MagicMock()
    client.record_invocation = MagicMock(return_value={"id": 1})
    hooks = openai_agents_hooks(
        client,
        tenant_id=TENANT,
        session_factory=db_factory,
    )

    Agent = fake_openai_agents_sdk["Agent"]
    from_a = Agent(); from_a.name = "Orch"; from_a.instructions = ""
    from_a.tools = []; from_a.model = "gpt-4o-mini"
    to_a = Agent(); to_a.name = "Sub"; to_a.instructions = ""
    to_a.tools = []; to_a.model = "gpt-4o-mini"
    ctx = MagicMock()

    asyncio.get_event_loop().run_until_complete(
        hooks.on_handoff(ctx, from_a, to_a))

    with db_factory() as db:
        rows = db.execute(text(
            "SELECT agent_key FROM agent_versions "
            "WHERE agent_key IN ('Orch','Sub') ORDER BY agent_key"
        )).fetchall()
    keys = [r[0] for r in rows]
    assert "Orch" in keys
    assert "Sub" in keys
    client.record_invocation.assert_called_once()


def test_openai_hook_no_tenant_skips_snapshot(db_factory,
                                                fake_openai_agents_sdk):
    import asyncio
    from kya_hooks.openai_agents import openai_agents_hooks

    client = MagicMock()
    hooks = openai_agents_hooks(client)  # no tenant_id

    Agent = fake_openai_agents_sdk["Agent"]
    agent = Agent()
    agent.name = "noTenantAgent"
    agent.instructions = ""; agent.tools = []; agent.model = "x"
    tool = SimpleNamespace(name="t")
    ctx = MagicMock()

    asyncio.get_event_loop().run_until_complete(
        hooks.on_tool_start(ctx, agent, tool))

    with db_factory() as db:
        rows = db.execute(text(
            "SELECT * FROM agent_versions "
            "WHERE agent_key='noTenantAgent'"
        )).fetchall()
    assert rows == []


# ── Claude Agent adapter ───────────────────────────────────────────


@pytest.fixture
def fake_claude_sdk(monkeypatch):
    class HookMatcher:
        def __init__(self, matcher=None, hooks=None):
            self.matcher = matcher
            self.hooks = hooks
    fake_mod = SimpleNamespace(HookMatcher=HookMatcher)
    monkeypatch.setitem(__import__("sys").modules,
                         "claude_agent_sdk", fake_mod)
    yield {"HookMatcher": HookMatcher}


def test_claude_hook_pre_tool_snapshots(db_factory, fake_claude_sdk):
    import asyncio
    from kya_hooks.claude_agent import claude_agent_hooks

    client = MagicMock()
    hooks = claude_agent_hooks(
        client, agent_key="claudeBot",
        allowed_tools={"Read", "Grep"},
        tenant_id=TENANT,
        session_factory=db_factory,
    )

    # Pull out the registered PreToolUse callable
    pre_callable = hooks["PreToolUse"][0].hooks[0]

    asyncio.get_event_loop().run_until_complete(
        pre_callable({"tool_name": "Read"}, "id1", None))

    with db_factory() as db:
        rows = db.execute(text(
            "SELECT agent_key FROM agent_versions "
            "WHERE agent_key='claudeBot'"
        )).fetchall()
    assert len(rows) == 1


def test_claude_hook_custom_agent_def_used(db_factory, fake_claude_sdk):
    import asyncio, json
    from kya_hooks.claude_agent import claude_agent_hooks

    client = MagicMock()
    custom = {
        "agent_key": "claudeStrict",
        "system_prompt": "Be strict.",
        "tools": ["Read"],
        "model": "claude-haiku-4-5",
        "access_level": "read",
        "data_classes": ["pii"],
        "human_loop": "in_the_loop",
    }
    hooks = claude_agent_hooks(
        client, agent_key="claudeStrict",
        tenant_id=TENANT, session_factory=db_factory,
        agent_def=custom,
    )
    pre_callable = hooks["PreToolUse"][0].hooks[0]
    asyncio.get_event_loop().run_until_complete(
        pre_callable({"tool_name": "Read"}, "id1", None))

    with db_factory() as db:
        rows = db.execute(text(
            "SELECT definition FROM agent_versions "
            "WHERE agent_key='claudeStrict'"
        )).fetchall()
    assert len(rows) == 1
    # JSON column on sqlite is text; deserialize defensively
    raw = rows[0][0]
    payload = json.loads(raw) if isinstance(raw, str) else raw
    assert payload["access_level"] == "read"
    assert payload["data_classes"] == ["pii"]
    assert payload["human_loop"] == "in_the_loop"
