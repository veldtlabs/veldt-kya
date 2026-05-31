"""Unit tests for DAG-mode attack-chain rules.

What this validates
-------------------
- **Linear backward compat**: rules without ``mode`` (or with
  ``mode: "linear"``) behave EXACTLY as before -- same advancement,
  same emission, same isolation. This is the regression guard for
  the entire PartialMatch + loader migration.
- **DAG diamond**: ``A -> (B + C) -> D`` -- B and C can complete in
  EITHER order; D fires only after both are done; rule fires only
  after all four are completed.
- **DAG AND-join**: when a step's ``after`` is a list, ALL listed
  predecessors must be in the completed set before the step is
  considered "ready" to match.
- **Already-completed step is not re-fired** within one partial
  match (a single step appears at most once in completed_step_ids).
- **Per-step within_seconds** in DAG mode is measured against the
  LATEST predecessor's completion timestamp, not just the most
  recent event.
- **PartialMatch ValkeyStateStore round-trip** keeps
  ``completed_step_ids`` intact across serialize/deserialize.
"""
from __future__ import annotations

import pytest

from kya.attack_chains import (
    AttackChainEngine,
    InMemoryStateStore,
    PartialMatch,
    load_rule,
)
from kya.attack_chains._state import ValkeyStateStore

# ── Fixtures / helpers ─────────────────────────────────────────────


def _engine(rule, state_store=None):
    fired: list[tuple[str, str]] = []

    def emitter(_db, _t, _p, signal_kind, _eid, r):
        fired.append((r.id, signal_kind))

    eng = AttackChainEngine(
        rules=[rule],
        state_store=state_store or InMemoryStateStore(),
        signal_emitter=emitter,
    )
    return eng, fired


def _diamond_rule():
    """A -> (B + C) -> D. Diamond AND-join pattern."""
    return load_rule(
        {
            "version": 1,
            "id": "diamond",
            "severity": "high",
            "emits_signal": "rogue_diamond",
            "correlate_by": ["tenant_id", "principal_id"],
            "mode": "dag",
            "steps": [
                {"id": "a", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "init"}},
                {"id": "b", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "branch_b"},
                 "after": "a"},
                {"id": "c", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "branch_c"},
                 "after": "a"},
                {"id": "d", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "join"},
                 "after": ["b", "c"]},
            ],
        },
        source_label="<test>",
    )


def _step(engine, *, tool, ts):
    return engine.process_evidence(
        None, tenant_id="t1", principal_id="p1",
        evidence_kind="tool_call",
        payload={"tool": tool},
        occurred_at_ts=ts,
    )


# ══════════════════════════════════════════════════════════════════
# Linear backward compat
# ══════════════════════════════════════════════════════════════════


def test_linear_rule_without_mode_field_unchanged():
    """A v1 rule with no ``mode`` field must behave exactly as before:
    sequential steps, single-string ``after``, no DAG bookkeeping."""
    rule = load_rule(
        {
            "version": 1,
            "id": "linear",
            "severity": "high",
            "emits_signal": "rogue_linear",
            "correlate_by": ["tenant_id", "principal_id"],
            "steps": [
                {"id": "s1", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "a"}},
                {"id": "s2", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "b"},
                 "after": "s1"},
            ],
        },
        source_label="<test>",
    )
    assert rule.mode == "linear"
    engine, fired = _engine(rule)
    assert _step(engine, tool="a", ts=100.0) == []
    assert _step(engine, tool="b", ts=110.0) == ["linear"]
    assert fired == [("linear", "rogue_linear")]


def test_linear_rule_with_explicit_mode_field_unchanged():
    """Same as above but with ``mode: linear`` explicit."""
    rule = load_rule(
        {
            "version": 1,
            "id": "linear_explicit",
            "severity": "high",
            "emits_signal": "rogue_linear_explicit",
            "correlate_by": ["tenant_id", "principal_id"],
            "mode": "linear",
            "steps": [
                {"id": "s1", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "a"}},
                {"id": "s2", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "b"},
                 "after": "s1"},
            ],
        },
        source_label="<test>",
    )
    engine, fired = _engine(rule)
    _step(engine, tool="a", ts=100.0)
    assert _step(engine, tool="b", ts=110.0) == ["linear_explicit"]


# ══════════════════════════════════════════════════════════════════
# Diamond pattern (the defining DAG capability)
# ══════════════════════════════════════════════════════════════════


def test_diamond_fires_when_branches_complete_in_b_then_c_order():
    engine, fired = _engine(_diamond_rule())
    assert _step(engine, tool="init", ts=100.0) == []
    assert _step(engine, tool="branch_b", ts=110.0) == []
    assert _step(engine, tool="branch_c", ts=120.0) == []
    # D's after = [b, c]; both done now -> join can fire.
    assert _step(engine, tool="join", ts=130.0) == ["diamond"]
    assert fired == [("diamond", "rogue_diamond")]


def test_diamond_fires_when_branches_complete_in_c_then_b_order():
    """The whole point of DAG: order of independent branches doesn't
    matter. Same rule, branches reversed, identical result."""
    engine, fired = _engine(_diamond_rule())
    _step(engine, tool="init", ts=100.0)
    _step(engine, tool="branch_c", ts=110.0)
    _step(engine, tool="branch_b", ts=120.0)
    assert _step(engine, tool="join", ts=130.0) == ["diamond"]
    assert fired == [("diamond", "rogue_diamond")]


def test_diamond_does_not_fire_when_only_one_branch_completes():
    """Join step ``D`` requires BOTH ``B`` and ``C``. With only B
    done, ``D`` matching the event must NOT complete the rule."""
    engine, fired = _engine(_diamond_rule())
    _step(engine, tool="init", ts=100.0)
    _step(engine, tool="branch_b", ts=110.0)
    # No branch_c yet; the join event must NOT fire because C
    # hasn't completed.
    assert _step(engine, tool="join", ts=120.0) == []
    assert fired == []


def test_diamond_join_with_missing_root_does_not_fire():
    """Branches require ``A``. With ``A`` skipped, no branch is
    ready, so the rule never advances."""
    engine, fired = _engine(_diamond_rule())
    assert _step(engine, tool="branch_b", ts=100.0) == []
    assert _step(engine, tool="branch_c", ts=110.0) == []
    assert _step(engine, tool="join", ts=120.0) == []
    assert fired == []


# ══════════════════════════════════════════════════════════════════
# Per-step within_seconds in DAG mode
# ══════════════════════════════════════════════════════════════════


def test_dag_within_seconds_measures_from_latest_predecessor():
    """For an AND-join step with multiple predecessors and
    within_seconds, the time bound is measured from the LATEST
    predecessor's completion -- the strictest sane interpretation."""
    rule = load_rule(
        {
            "version": 1,
            "id": "tight_join",
            "severity": "high",
            "emits_signal": "rogue_join_tight",
            "correlate_by": ["tenant_id", "principal_id"],
            "mode": "dag",
            "steps": [
                {"id": "a", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "a"}},
                {"id": "b", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "b"}},
                {"id": "join", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "join"},
                 "after": ["a", "b"], "within_seconds": 30},
            ],
        },
        source_label="<test>",
    )
    engine, fired = _engine(rule)
    _step(engine, tool="a", ts=100.0)   # a done at 100
    _step(engine, tool="b", ts=150.0)   # b done at 150 (latest pred)
    # Join arrives at 175. gap from latest pred (b @ 150) = 25 -> ok.
    assert _step(engine, tool="join", ts=175.0) == ["tight_join"]
    assert fired == [("tight_join", "rogue_join_tight")]


def test_dag_within_seconds_rejects_when_late_relative_to_latest():
    rule = load_rule(
        {
            "version": 1,
            "id": "tight_join_late",
            "severity": "high",
            "emits_signal": "rogue_late",
            "correlate_by": ["tenant_id", "principal_id"],
            "mode": "dag",
            "steps": [
                {"id": "a", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "a"}},
                {"id": "b", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "b"}},
                {"id": "join", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "join"},
                 "after": ["a", "b"], "within_seconds": 30},
            ],
        },
        source_label="<test>",
    )
    engine, fired = _engine(rule)
    _step(engine, tool="a", ts=100.0)
    _step(engine, tool="b", ts=150.0)
    # 200 - 150 = 50 > 30 -> window closed; rule does NOT fire and
    # the partial match is aborted.
    assert _step(engine, tool="join", ts=200.0) == []
    assert fired == []


# ══════════════════════════════════════════════════════════════════
# Step completion uniqueness
# ══════════════════════════════════════════════════════════════════


def test_dag_step_not_re_added_when_event_repeats_a_completed_step():
    """A second event matching an already-completed step must NOT
    re-add it to the completed set (would otherwise let a chain
    "loop"). The engine skips already-completed steps when scanning
    for ready candidates."""
    engine, fired = _engine(_diamond_rule())
    _step(engine, tool="init", ts=100.0)
    _step(engine, tool="branch_b", ts=110.0)
    # Replay branch_b -- must be ignored.
    assert _step(engine, tool="branch_b", ts=115.0) == []
    _step(engine, tool="branch_c", ts=120.0)
    assert _step(engine, tool="join", ts=130.0) == ["diamond"]
    assert fired == [("diamond", "rogue_diamond")]


# ══════════════════════════════════════════════════════════════════
# Valkey serialization round-trip preserves completed_step_ids
# ══════════════════════════════════════════════════════════════════


class _FakeValkey:
    """Tiny fake redis-py client used by other valkey tests too."""

    def __init__(self):
        self._strings: dict[str, str] = {}
        self._zsets: dict[str, dict[str, float]] = {}

    def get(self, k):
        return self._strings.get(k)

    def set(self, k, v, ex=None):
        self._strings[k] = v
        return True

    def delete(self, *keys):
        n = 0
        for k in keys:
            if self._strings.pop(k, None) is not None:
                n += 1
            if self._zsets.pop(k, None) is not None:
                n += 1
        return n

    def zadd(self, k, mapping):
        z = self._zsets.setdefault(k, {})
        z.update({m: float(s) for m, s in mapping.items()})
        return len(mapping)

    def zrange(self, k, start, end):
        z = self._zsets.get(k, {})
        ordered = sorted(z.items(), key=lambda kv: (kv[1], kv[0]))
        members = [m for m, _ in ordered]
        return members[start:] if end == -1 else members[start:end + 1]

    def zrangebyscore(self, k, lo, hi):
        z = self._zsets.get(k, {})
        lo_f = float("-inf") if str(lo) == "-inf" else float(lo)
        hi_f = float("inf") if str(hi) == "+inf" else float(hi)
        return [m for m, s in z.items() if lo_f <= s <= hi_f]

    def zrem(self, k, *members):
        z = self._zsets.get(k)
        if not z:
            return 0
        return sum(1 for m in members if z.pop(m, None) is not None)

    def scan_iter(self, match=None):
        import fnmatch
        keys = set(self._strings) | set(self._zsets)
        for k in sorted(keys):
            if match is None or fnmatch.fnmatch(k, match):
                yield k

    def ping(self):
        return True


def test_valkey_round_trip_preserves_completed_step_ids():
    """The DAG bookkeeping field MUST survive the JSON round-trip in
    ValkeyStateStore, otherwise cross-process DAG chains would
    silently fall back to linear semantics."""
    store = ValkeyStateStore(client=_FakeValkey())
    pm = PartialMatch(
        rule_id="r1", correlate_key=("t1", "p1"),
        current_step_idx=2,
        steps_ts=[100.0, 110.0],
        steps_evidence_ids=[1, 2],
        completed_step_ids=("a", "b"),
    )
    store.update(pm)
    got = store.get("r1", ("t1", "p1"))
    assert got is not None
    assert got.completed_step_ids == ("a", "b")
    assert got.current_step_idx == 2
    assert got.steps_ts == [100.0, 110.0]


def test_valkey_round_trip_default_empty_completed_for_linear():
    """Legacy / linear partial matches use the default empty tuple --
    they MUST be readable with no schema change (the field is
    optional in _loads)."""
    store = ValkeyStateStore(client=_FakeValkey())
    pm = PartialMatch(
        rule_id="r2", correlate_key=("t1", "p2"),
        current_step_idx=1,
        steps_ts=[100.0], steps_evidence_ids=[1],
        # completed_step_ids defaults to ()
    )
    store.update(pm)
    got = store.get("r2", ("t1", "p2"))
    assert got is not None
    assert got.completed_step_ids == ()


# ══════════════════════════════════════════════════════════════════
# Loader rejects malformed DAG rules
# ══════════════════════════════════════════════════════════════════


def test_loader_rejects_unknown_mode():
    from kya.attack_chains import RuleLoadError
    with pytest.raises(RuleLoadError):
        load_rule(
            {
                "version": 1, "id": "bad_mode", "severity": "low",
                "emits_signal": "rogue", "correlate_by": ["tenant_id"],
                "mode": "not_a_mode",
                "steps": [
                    {"id": "s", "evidence_kind": "tool_call",
                     "match": {"payload.x": "y"}},
                ],
            },
            source_label="<test>",
        )


def test_loader_rejects_self_reference_in_after():
    from kya.attack_chains import RuleLoadError
    with pytest.raises(RuleLoadError):
        load_rule(
            {
                "version": 1, "id": "self_ref", "severity": "low",
                "emits_signal": "rogue", "correlate_by": ["tenant_id"],
                "mode": "dag",
                "steps": [
                    {"id": "s", "evidence_kind": "tool_call",
                     "match": {"payload.x": "y"}, "after": "s"},
                ],
            },
            source_label="<test>",
        )
