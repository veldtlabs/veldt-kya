"""Task #242 - VALID_OUTCOMES round-trip + fail-loud regression.

Pre-fix, ``kya.invocations.record_invocation`` silent-coerced any outcome
NOT in ``VALID_OUTCOMES`` to ``"success"`` via a debug-level log line. The
missing ``"failure"`` (and aliases ``"denied"``/``"throttled"`` that the
API docs advertised) meant every failed call was written as
``outcome="success"``, which then made the Pro ``_storage.list_activity``
derive ``verdict="allow"`` for the whole failure population, and the Pro
ingest router's trust-ticker gate tick trust UPWARD on every failure.

Two-part fix on this side:
  1. Expand VALID_OUTCOMES to cover every documented value.
  2. Replace the silent-coerce with a raise. Fail-loud.

This file asserts both.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest


_VALID_OUTCOMES = [
    "success",
    "failure",
    "refused",
    "denied",
    "blocked",
    "error",
    "throttled",
    "partial",
    "in_progress",
]


def test_valid_outcomes_constant_matches_expected_set() -> None:
    from kya.invocations import VALID_OUTCOMES
    assert VALID_OUTCOMES == set(_VALID_OUTCOMES), (
        f"VALID_OUTCOMES drifted from documented set. Actual: "
        f"{sorted(VALID_OUTCOMES)!r}, Expected: {sorted(_VALID_OUTCOMES)!r}"
    )


@pytest.fixture
def sqlite_session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    url = f"sqlite:///{tmp_path / 't.db'}"
    eng = create_engine(url)
    with Session(eng) as db:
        yield db


@pytest.mark.parametrize("outcome", _VALID_OUTCOMES)
def test_record_invocation_accepts_valid_outcome(
    sqlite_session, outcome: str,
) -> None:
    from kya.invocations import list_invocations, record_invocation
    inv_id = record_invocation(
        db=sqlite_session,
        tenant_id="tenant-x",
        agent_key="agent-round-trip",
        principal_kind="user",
        principal_id="user-1",
        mode="autonomous",
        outcome=outcome,
        occurred_at=datetime.now(timezone.utc),
    )
    assert inv_id > 0
    rows = list_invocations(sqlite_session, tenant_id="tenant-x")
    assert len(rows) == 1
    assert rows[0]["outcome"] == outcome, (
        f"outcome={outcome!r} round-trip failed - stored as "
        f"{rows[0]['outcome']!r}. If it stored as 'success', the "
        f"silent-coerce is back."
    )


@pytest.mark.parametrize(
    "bad", ["banana", "SUCCESS", "successs", "ok", "", "cancelled"],
)
def test_record_invocation_raises_on_unknown_outcome(
    sqlite_session, bad: str,
) -> None:
    from kya.invocations import record_invocation
    with pytest.raises(ValueError, match="invalid outcome"):
        record_invocation(
            db=sqlite_session,
            tenant_id="tenant-x",
            agent_key="agent-neg",
            mode="autonomous",
            outcome=bad,
            occurred_at=datetime.now(timezone.utc),
        )


def test_banana_outcome_is_not_persisted_as_success(sqlite_session) -> None:
    from kya.invocations import list_invocations, record_invocation
    with pytest.raises(ValueError):
        record_invocation(
            db=sqlite_session,
            tenant_id="tenant-x",
            agent_key="agent-canary",
            outcome="banana",
        )
    assert list_invocations(sqlite_session, tenant_id="tenant-x") == []
