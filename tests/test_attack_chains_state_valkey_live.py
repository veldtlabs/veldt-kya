"""Live integration tests for ValkeyStateStore.

Gated on ``KYA_VALKEY_URL`` -- when unset, every test is SKIPPED so a
CI environment without infrastructure stays green. When set, this
file does three things the unit-suite cannot:

  1. **Real Valkey/Redis semantics.** Re-runs the parity contract
     against an actual redis-py client connected to a live instance.
     Catches any divergence between our hand-written fake and the real
     server (TTL behavior, sorted-set tie-breaking, decode_responses
     edge cases, etc.).

  2. **True cross-process correctness.** Spawns separate OS processes
     (multiprocessing) that each open their own redis-py client and
     advance one step of the same chain. Proves the value prop: a chain
     can complete on a different worker than the one that started it --
     which is structurally impossible with InMemoryStateStore.

  3. **Fault injection.** Uses a deliberately broken client to confirm
     every method degrades to safe defaults instead of raising,
     honoring KYA's "observability never breaks the request path"
     contract under real failure modes.

Local run (with the vd-valkey container the repo already uses):

    KYA_VALKEY_URL=redis://localhost:17379/15 \
        python -m pytest tests/test_attack_chains_state_valkey_live.py -v
"""
from __future__ import annotations

import multiprocessing as mp
import os
import time
import uuid

import pytest

from kya.attack_chains._state import (
    InMemoryStateStore,  # noqa: F401  -- referenced from docstring
    PartialMatch,
    ValkeyStateStore,
)

_URL = os.environ.get("KYA_VALKEY_URL", "").strip()
pytestmark = pytest.mark.skipif(
    not _URL,
    reason="KYA_VALKEY_URL not set -- live Valkey integration tests skipped",
)


# ── Live client + prefix isolation ─────────────────────────────────


def _live_client():
    """Open a fresh redis-py client against the URL under test.

    We do NOT reuse ``kya._valkey.get_valkey()`` here because the
    module-level cache would bleed connection state across tests.
    Each test wants a clean client.
    """
    import redis  # local import so the file can be collected without redis-py
    return redis.Redis.from_url(
        _URL, decode_responses=True, socket_connect_timeout=2.0,
    )


@pytest.fixture
def live_prefix():
    """Per-test unique key prefix + cleanup.

    Two safeguards against test pollution:
      - Every test gets its own ``kya:chains:test:<uuid>`` namespace.
      - On teardown we DELETE everything under that namespace so a
        re-run starts clean.
    """
    prefix = f"kya:chains:test:{uuid.uuid4().hex}"
    yield prefix
    # cleanup
    client = _live_client()
    try:
        for key in client.scan_iter(match=f"{prefix}*"):
            client.delete(key)
    finally:
        try:
            client.close()
        except Exception:
            pass


@pytest.fixture
def live_store(live_prefix):
    client = _live_client()
    try:
        yield ValkeyStateStore(
            client=client,
            key_prefix=live_prefix,
            pm_ttl_seconds=300,
        )
    finally:
        # Avoid lingering connections across the test run.
        try:
            client.close()
        except Exception:
            pass


# ── Helpers ────────────────────────────────────────────────────────


def _pm(rule_id="r1", ck=("t1", "p1"), idx=1, ts=None, ev=None):
    return PartialMatch(
        rule_id=rule_id,
        correlate_key=tuple(ck),
        current_step_idx=idx,
        steps_ts=list(ts) if ts is not None else [100.0],
        steps_evidence_ids=list(ev) if ev is not None else [10],
    )


# ══════════════════════════════════════════════════════════════════
# 1. Parity contract against a REAL Valkey
# ══════════════════════════════════════════════════════════════════


def test_live_get_missing_returns_none(live_store):
    assert live_store.get("r1", ("t1", "p1")) is None


def test_live_roundtrip(live_store):
    live_store.update(_pm())
    got = live_store.get("r1", ("t1", "p1"))
    assert got is not None
    assert got.correlate_key == ("t1", "p1")
    assert got.current_step_idx == 1
    assert got.steps_ts == [100.0]
    assert got.steps_evidence_ids == [10]


def test_live_get_or_create_and_no_clobber(live_store):
    pm = live_store.get_or_create("r1", ("t1", "p1"))
    assert pm.current_step_idx == 0
    # writing a more-advanced state, then get_or_create, must NOT
    # reset progress (real Valkey GET must see the SET we just did).
    pm.current_step_idx = 4
    live_store.update(pm)
    again = live_store.get_or_create("r1", ("t1", "p1"))
    assert again.current_step_idx == 4


def test_live_delete(live_store):
    live_store.update(_pm())
    live_store.delete("r1", ("t1", "p1"))
    assert live_store.get("r1", ("t1", "p1")) is None


def test_live_list_active_isolated_by_rule(live_store):
    live_store.update(_pm(rule_id="r1", ck=("t1", "p1")))
    live_store.update(_pm(rule_id="r1", ck=("t1", "p2")))
    live_store.update(_pm(rule_id="r2", ck=("t1", "p1")))
    r1 = list(live_store.list_active("r1"))
    r2 = list(live_store.list_active("r2"))
    assert len(r1) == 2
    assert len(r2) == 1


def test_live_expire_older_than_uses_real_zset(live_store):
    live_store.update(_pm(ck=("t1", "old")))
    time.sleep(0.08)
    live_store.update(_pm(ck=("t1", "fresh")))
    n = live_store.expire_older_than(0.04)
    assert n >= 1
    assert live_store.get("r1", ("t1", "old")) is None
    assert live_store.get("r1", ("t1", "fresh")) is not None


def test_live_correlate_keys_with_colons_isolate(live_store):
    """Real Valkey key parsing: correlate keys containing ':' must
    NOT collide via the sha1-tokenized pm_key.
    """
    live_store.update(_pm(ck=("tenant:a", "principal::x")))
    live_store.update(_pm(ck=("tenant:a", "principal::y")))
    assert live_store.get("r1", ("tenant:a", "principal::x")) is not None
    assert live_store.get("r1", ("tenant:a", "principal::y")) is not None
    assert len(list(live_store.list_active("r1"))) == 2


# ══════════════════════════════════════════════════════════════════
# 2. True cross-PROCESS correctness (the actual value prop)
# ══════════════════════════════════════════════════════════════════


# The rule must be expressible as a plain dict so we can pickle it to
# worker processes -- multiprocessing's "spawn" start method (default
# on Windows) re-imports the test module in the child and requires
# every argument to be picklable.
_CROSS_PROC_RULE = {
    "version": 1,
    "id": "cross_proc_chain",
    "severity": "high",
    "emits_signal": "rogue_cross_proc",
    "correlate_by": ["tenant_id", "principal_id"],
    "steps": [
        {"id": "s1", "evidence_kind": "tool_call",
         "match": {"payload.tool": "file_read"}},
        {"id": "s2", "evidence_kind": "tool_call",
         "match": {"payload.tool": "http_post"},
         "after": "s1", "within_seconds": 60},
    ],
}


def _worker_advance(url, prefix, rule_dict, evidence_kind, payload,
                    occurred_at_ts, return_queue):
    """Run inside a separate OS process.

    Opens its own redis-py client (no shared state with the parent
    other than what's in Valkey), builds a fresh AttackChainEngine
    bound to a ValkeyStateStore at the shared prefix, processes ONE
    evidence event, and reports back via the queue what matched and
    what was emitted.
    """
    import redis

    from kya.attack_chains._engine import AttackChainEngine
    from kya.attack_chains._loader import load_rule
    from kya.attack_chains._state import ValkeyStateStore

    client = redis.Redis.from_url(
        url, decode_responses=True, socket_connect_timeout=2.0,
    )
    rule = load_rule(rule_dict, source_label="<cross-proc>")
    fired = []

    def emitter(_db, _t, _p, signal_kind, _eid, r):
        fired.append((r.id, signal_kind))

    engine = AttackChainEngine(
        rules=[rule],
        state_store=ValkeyStateStore(client=client, key_prefix=prefix),
        signal_emitter=emitter,
    )
    matched = engine.process_evidence(
        None,
        tenant_id="t1",
        principal_id="p1",
        evidence_kind=evidence_kind,
        payload=payload,
        evidence_id=int(occurred_at_ts),
        occurred_at_ts=occurred_at_ts,
    )
    return_queue.put({"matched": matched, "fired": fired,
                      "pid": os.getpid()})


def test_live_chain_advances_across_separate_processes(live_prefix):
    """The defining test for ValkeyStateStore.

    Worker A (process 1) sees step s1 and only advances state.
    Worker B (process 2) sees step s2 -- on a DIFFERENT PID, with a
    DIFFERENT redis-py connection -- and must complete the chain.

    With InMemoryStateStore this is structurally impossible (each
    worker has its own dict). With ValkeyStateStore it MUST work --
    that's the whole point of building this.
    """
    ctx = mp.get_context("spawn")
    q = ctx.Queue()

    # Worker A: step 1.
    p_a = ctx.Process(
        target=_worker_advance,
        args=(_URL, live_prefix, _CROSS_PROC_RULE,
              "tool_call", {"tool": "file_read"},
              100.0, q),
    )
    p_a.start()
    p_a.join(timeout=20)
    assert not p_a.is_alive(), "worker A did not exit in time"
    res_a = q.get(timeout=5)
    assert res_a["matched"] == [], "step 1 must advance, not fire"
    assert res_a["fired"] == []

    # Worker B: step 2 on a different process / different connection.
    p_b = ctx.Process(
        target=_worker_advance,
        args=(_URL, live_prefix, _CROSS_PROC_RULE,
              "tool_call", {"tool": "http_post"},
              110.0, q),
    )
    p_b.start()
    p_b.join(timeout=20)
    assert not p_b.is_alive(), "worker B did not exit in time"
    res_b = q.get(timeout=5)

    # Different PIDs -- proves we really were in separate OS processes.
    assert res_a["pid"] != res_b["pid"]
    # And the chain fired on B even though A started it.
    assert res_b["matched"] == ["cross_proc_chain"]
    assert res_b["fired"] == [("cross_proc_chain", "rogue_cross_proc")]


# ══════════════════════════════════════════════════════════════════
# 3. Fault injection -- every method must fail-soft on real errors
# ══════════════════════════════════════════════════════════════════


class _BrokenClient:
    """A client where every command raises ConnectionError.

    Simulates: Valkey crashed mid-request, network partition, auth
    rejection -- anything that surfaces as an exception from redis-py.
    KYA's contract says NONE of these may break record_evidence().
    """

    def _boom(self, *_a, **_kw):
        raise ConnectionError("simulated valkey outage")

    get = set = delete = _boom
    zadd = zrem = zrange = zrangebyscore = _boom

    def scan_iter(self, match=None):
        raise ConnectionError("simulated valkey outage")


def test_fault_injection_every_method_is_fail_soft():
    store = ValkeyStateStore(client=_BrokenClient())

    # None of these may raise.
    assert store.get("r1", ("t1", "p1")) is None
    store.update(_pm())            # no raise
    store.delete("r1", ("t1", "p1"))  # no raise
    assert store.expire_older_than(60) == 0
    assert store.list_active("r1") == []


def test_fault_injection_get_or_create_handles_broken_update():
    """If the broken client makes ``update`` silently fail, the
    caller still gets a sensible PartialMatch back (not None, not a
    crash). The engine treats the returned object as the working
    state for this call; subsequent calls will retry against Valkey.
    """
    store = ValkeyStateStore(client=_BrokenClient())
    pm = store.get_or_create("r1", ("t1", "p1"))
    assert pm is not None
    assert pm.rule_id == "r1"
    assert pm.current_step_idx == 0
