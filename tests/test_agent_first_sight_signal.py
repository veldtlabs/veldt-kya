"""Tests for the agent_first_sight realtime signal.

The signal fires only on TRUE first sight (no prior versions). Drift
(definition change on an already-known agent) and idempotent re-calls
must NOT fire it.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kya import (
    ALLOWED_SIGNAL_KINDS,
    init_storage,
    snapshot_on_first_sight,
)


TENANT = "00000000-0000-0000-0000-000000000ccc"


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None})
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


def test_first_sight_emits_signal(db):
    agent_def = {"agent_key": "A_novel", "tools": ["t1"],
                 "system_prompt": "x", "model": "gpt-4o-mini"}
    # versioning.py imports record_signal lazily inside the function,
    # so patching the canonical kya.realtime.record_signal catches it.
    with patch("kya.realtime.record_signal") as mock_rt_signal:
        v, is_new = snapshot_on_first_sight(
            db, tenant_id=TENANT, agent_key="A_novel",
            definition=agent_def)
    assert is_new is True
    assert v == 1
    mock_rt_signal.assert_called_once()
    call_kwargs = mock_rt_signal.call_args.kwargs
    assert call_kwargs["tenant_id"] == TENANT
    assert call_kwargs["agent_key"] == "A_novel"
    assert call_kwargs["signal_kind"] == "agent_first_sight"
    assert call_kwargs["severity"] == "info"
    assert call_kwargs["detail"]["first_version_no"] == 1
    assert "definition_hash" in call_kwargs["detail"]


def test_idempotent_recall_does_not_emit_signal(db):
    agent_def = {"agent_key": "A_idem", "tools": [],
                 "system_prompt": "x"}
    # First call — triggers signal (we don't assert, just unrelated path)
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="A_idem", definition=agent_def)
    # Second call with identical def — must NOT trigger
    with patch("kya.realtime.record_signal") as mock_rt_signal:
        v, is_new = snapshot_on_first_sight(
            db, tenant_id=TENANT, agent_key="A_idem",
            definition=agent_def)
    assert is_new is False
    assert v == 1
    mock_rt_signal.assert_not_called()


def test_drift_does_not_emit_first_sight_signal(db):
    """A definition change on an EXISTING agent_key is drift — it bumps
    the version but must NOT fire agent_first_sight (that's reserved
    for truly novel agent_keys)."""
    v1_def = {"agent_key": "A_drift", "tools": ["t1"], "model": "m1"}
    v2_def = {"agent_key": "A_drift", "tools": ["t1", "t2"], "model": "m1"}
    snapshot_on_first_sight(
        db, tenant_id=TENANT, agent_key="A_drift", definition=v1_def)
    with patch("kya.realtime.record_signal") as mock_rt_signal:
        v, is_new = snapshot_on_first_sight(
            db, tenant_id=TENANT, agent_key="A_drift",
            definition=v2_def)
    assert is_new is True
    assert v == 2  # version bumped
    mock_rt_signal.assert_not_called()  # but NO first-sight signal


def test_signal_kind_in_whitelist():
    assert "agent_first_sight" in ALLOWED_SIGNAL_KINDS


def test_failing_signal_emit_does_not_break_snapshot(db):
    """If realtime.record_signal raises (Valkey down), the snapshot
    write must still succeed."""
    agent_def = {"agent_key": "A_safe", "tools": [], "model": "m"}
    with patch("kya.realtime.record_signal",
                side_effect=RuntimeError("valkey down")):
        v, is_new = snapshot_on_first_sight(
            db, tenant_id=TENANT, agent_key="A_safe",
            definition=agent_def)
    # Snapshot must still have succeeded
    assert is_new is True
    assert v == 1
    # And the row must be in the DB
    from sqlalchemy import text
    rows = db.execute(text(
        "SELECT version_no FROM agent_versions WHERE agent_key='A_safe'"
    )).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == 1


def test_different_tenants_each_get_first_sight(db):
    """The same agent_key in two tenants → each tenant gets its own
    first-sight signal."""
    agent_def = {"agent_key": "A_multi", "tools": []}
    other_tenant = "11111111-1111-1111-1111-111111111111"

    with patch("kya.realtime.record_signal") as mock_rt_signal:
        snapshot_on_first_sight(
            db, tenant_id=TENANT, agent_key="A_multi",
            definition=agent_def)
        snapshot_on_first_sight(
            db, tenant_id=other_tenant, agent_key="A_multi",
            definition=agent_def)
    assert mock_rt_signal.call_count == 2
    tenants_seen = {c.kwargs["tenant_id"] for c in mock_rt_signal.call_args_list}
    assert tenants_seen == {TENANT, other_tenant}
