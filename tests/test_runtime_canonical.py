"""Tests for the canonical runtime-event types.

Layer 1 of the runtime-bridge test stack: dataclass behavior in
isolation. No parser, no bridge, no DB.
"""
from __future__ import annotations

import dataclasses

import pytest

from kya.runtime import (
    PrincipalHint,
    ProcessRef,
    RuntimeEvent,
)


def test_runtime_event_minimal_construction():
    """An event with just the six required fields constructs cleanly
    and defaults the optional fields to None / empty tuple / empty
    dict so the bridge never has to special-case None vs missing."""
    ev = RuntimeEvent(
        source_tool="falco",
        source_rule_id="r1",
        occurred_at_ts=100.0,
        severity="high",
        action="some_action",
        message="msg",
    )
    assert ev.source_tool == "falco"
    assert ev.container_id is None
    assert ev.process is None
    assert ev.principal_hints == ()
    assert ev.tags == ()
    assert ev.raw == {}


def test_runtime_event_is_frozen():
    """Frozen so the bridge can't accidentally mutate evidence after
    receiving it -- runtime alerts ARE evidence; mutating them after
    record_evidence() would invalidate the HMAC chain."""
    ev = RuntimeEvent(
        source_tool="falco", source_rule_id="r",
        occurred_at_ts=1.0, severity="low",
        action="a", message="m",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.severity = "critical"  # type: ignore[misc]


def test_runtime_event_uses_slots_for_memory_efficiency():
    """High-volume runtime collectors push 10^4-10^6 events / hour;
    slots cuts per-event memory ~40 %. The frozen+slots combination
    raises on setattr, but the cleanest assertion is checking
    ``__slots__`` exists on the class -- this is what catches a
    refactor that drops ``slots=True`` without changing behavior."""
    assert hasattr(RuntimeEvent, "__slots__")
    assert "source_tool" in RuntimeEvent.__slots__
    # Slotted dataclasses also have no per-instance __dict__.
    ev = RuntimeEvent(
        source_tool="falco", source_rule_id="r",
        occurred_at_ts=1.0, severity="low",
        action="a", message="m",
    )
    assert not hasattr(ev, "__dict__")


def test_process_ref_defaults_all_none():
    p = ProcessRef()
    assert p.image is None
    assert p.pid is None
    assert p.user is None


def test_principal_hint_kinds_are_typed():
    """`kind` is a Literal; any string assignment is accepted at
    runtime (we don't enforce in code), but the type-check forms
    accepted by mypy/pyright are exactly the documented set."""
    h = PrincipalHint(kind="container_label", value="agent_42")
    assert h.kind == "container_label"
    assert h.value == "agent_42"


def test_runtime_event_carries_multiple_principal_hints_in_order():
    """The bridge tries hints in registration order. Verify the
    tuple ordering is preserved through construction."""
    ev = RuntimeEvent(
        source_tool="falco", source_rule_id="r",
        occurred_at_ts=1.0, severity="low",
        action="a", message="m",
        principal_hints=(
            PrincipalHint("container_label", "agent_42"),
            PrincipalHint("service_account", "ns/svc"),
            PrincipalHint("process_user", "root"),
        ),
    )
    kinds = [h.kind for h in ev.principal_hints]
    assert kinds == ["container_label", "service_account", "process_user"]


def test_runtime_event_raw_payload_detached_from_caller_dict():
    """The bridge takes a reference to ``raw`` from the parser. The
    parser is responsible for detaching it from its caller's mutable
    JSON dict; we don't enforce a copy at the dataclass level (would
    be wasteful for high-volume ingest). Document the contract here
    so a future change doesn't accidentally tighten or loosen it."""
    raw = {"rule": "x"}
    ev = RuntimeEvent(
        source_tool="falco", source_rule_id="x",
        occurred_at_ts=1.0, severity="low",
        action="a", message="m",
        raw=raw,
    )
    # Same identity by design -- parser detaches if it wants to.
    assert ev.raw is raw
