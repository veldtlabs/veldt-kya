"""ValkeyStateStore — parity + cross-process tests.

Strategy
--------
1. PARITY: every behavioral test runs against BOTH InMemoryStateStore
   and ValkeyStateStore (with an injected fake client) via pytest
   parametrize, so the Valkey impl is provably a drop-in replacement.

2. CROSS-INSTANCE: a Valkey-specific test proves two store instances
   sharing one client see each other's writes — the whole point of the
   class (simulates the cross-process / multi-agent case).

3. ENGINE PARITY: running AttackChainEngine end-to-end against both
   stores must produce identical matched-rule_ids on the same evidence
   sequence. This is the strongest regression: any change to the store
   that breaks the engine contract fails here.

4. FAIL-SOFT: with no client available, every method must return a
   safe default rather than raise — KYA's "observability never breaks
   the request path" contract applies to the store too.

The fake client implements only the redis-py commands the store uses
(``get``, ``set``, ``delete``, ``zadd``, ``zrange``, ``zrangebyscore``,
``zrem``, ``scan_iter``). decode_responses=True semantics: strings in,
strings out.
"""
from __future__ import annotations

import fnmatch
import time
from typing import Any

import pytest

from kya.attack_chains._state import (
    InMemoryStateStore,
    PartialMatch,
    ValkeyStateStore,
)

# ── Minimal fake redis-py-compatible client ────────────────────────


class FakeValkey:
    """In-memory stand-in for a redis-py client (decode_responses=True).

    Implements only the commands ValkeyStateStore uses. Faithful enough
    for parity testing: command semantics match redis docs for the
    surface we touch. Multiple ValkeyStateStore instances can share one
    FakeValkey to simulate cross-process visibility.
    """

    def __init__(self) -> None:
        self._strings: dict[str, str] = {}
        self._zsets: dict[str, dict[str, float]] = {}

    # ── String ops ──
    def get(self, key: str) -> str | None:
        return self._strings.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> bool:
        # We ignore `ex` for the fake -- expiry in the store contract
        # is driven by the ZSET-based ``expire_older_than``, not the
        # value TTL (which is only a crash-safety orphan cleanup).
        self._strings[key] = value
        return True

    def delete(self, *keys: str) -> int:
        n = 0
        for k in keys:
            if self._strings.pop(k, None) is not None:
                n += 1
            if self._zsets.pop(k, None) is not None:
                n += 1
        return n

    # ── ZSET ops ──
    def zadd(self, key: str, mapping: dict[str, float]) -> int:
        z = self._zsets.setdefault(key, {})
        added = sum(1 for m in mapping if m not in z)
        z.update({m: float(s) for m, s in mapping.items()})
        return added

    def zrange(self, key: str, start: int, end: int) -> list[str]:
        z = self._zsets.get(key, {})
        ordered = sorted(z.items(), key=lambda kv: (kv[1], kv[0]))
        members = [m for m, _ in ordered]
        if end == -1:
            return members[start:]
        return members[start: end + 1]

    def zrangebyscore(
        self, key: str, min_: Any, max_: Any,
    ) -> list[str]:
        z = self._zsets.get(key, {})
        lo = float("-inf") if str(min_) == "-inf" else float(min_)
        hi = float("inf") if str(max_) == "+inf" else float(max_)
        return [
            m for m, s in sorted(z.items(), key=lambda kv: kv[1])
            if lo <= s <= hi
        ]

    def zrem(self, key: str, *members: str) -> int:
        z = self._zsets.get(key)
        if not z:
            return 0
        n = 0
        for m in members:
            if z.pop(m, None) is not None:
                n += 1
        return n

    # ── Iteration ──
    def scan_iter(self, match: str | None = None):
        keys = set(self._strings.keys()) | set(self._zsets.keys())
        for k in sorted(keys):  # deterministic order for tests
            if match is None or fnmatch.fnmatch(k, match):
                yield k

    # ── Liveness ──
    def ping(self) -> bool:
        return True


# ── Fixtures: each test runs against BOTH stores ───────────────────


@pytest.fixture(params=["memory", "valkey"])
def store(request):
    """Parametrize every test over both store implementations."""
    if request.param == "memory":
        return InMemoryStateStore()
    return ValkeyStateStore(client=FakeValkey(), pm_ttl_seconds=3600)


def _pm(rule_id: str = "r1",
        ck: tuple[str, ...] = ("t1", "p1"),
        idx: int = 1,
        ts: list[float] | None = None,
        ev: list[int] | None = None) -> PartialMatch:
    return PartialMatch(
        rule_id=rule_id,
        correlate_key=tuple(ck),
        current_step_idx=idx,
        steps_ts=list(ts) if ts is not None else [1.0],
        steps_evidence_ids=list(ev) if ev is not None else [10],
    )


# ── Parity tests (memory ≡ valkey) ─────────────────────────────────


def test_get_missing_returns_none(store):
    assert store.get("r1", ("t1", "p1")) is None


def test_update_then_get_roundtrip(store):
    pm = _pm()
    store.update(pm)

    got = store.get("r1", ("t1", "p1"))
    assert got is not None
    assert got.rule_id == "r1"
    assert got.correlate_key == ("t1", "p1")
    assert got.current_step_idx == 1
    assert got.steps_ts == [1.0]
    assert got.steps_evidence_ids == [10]


def test_get_or_create_starts_at_zero_and_persists(store):
    pm = store.get_or_create("r1", ("t1", "p1"))
    assert pm.current_step_idx == 0
    assert pm.correlate_key == ("t1", "p1")
    # And the same logical match is retrievable.
    got = store.get("r1", ("t1", "p1"))
    assert got is not None
    assert got.current_step_idx == 0


def test_get_or_create_returns_existing(store):
    store.update(_pm(idx=3))
    pm = store.get_or_create("r1", ("t1", "p1"))
    # MUST NOT clobber existing.
    assert pm.current_step_idx == 3


def test_update_advances_idx_and_appends_steps(store):
    pm = _pm(idx=1, ts=[100.0], ev=[10])
    store.update(pm)

    pm.current_step_idx = 2
    pm.steps_ts.append(110.0)
    pm.steps_evidence_ids.append(11)
    store.update(pm)

    got = store.get("r1", ("t1", "p1"))
    assert got.current_step_idx == 2
    assert got.steps_ts == [100.0, 110.0]
    assert got.steps_evidence_ids == [10, 11]


def test_delete_removes(store):
    store.update(_pm())
    store.delete("r1", ("t1", "p1"))
    assert store.get("r1", ("t1", "p1")) is None


def test_list_active_is_isolated_by_rule(store):
    store.update(_pm(rule_id="r1", ck=("t1", "p1")))
    store.update(_pm(rule_id="r1", ck=("t1", "p2")))
    store.update(_pm(rule_id="r2", ck=("t1", "p1")))

    r1 = list(store.list_active("r1"))
    r2 = list(store.list_active("r2"))

    assert len(r1) == 2
    assert len(r2) == 1
    assert {pm.correlate_key for pm in r1} == {("t1", "p1"), ("t1", "p2")}
    assert r2[0].correlate_key == ("t1", "p1")


def test_expire_older_than_drops_stale(store):
    store.update(_pm(ck=("t1", "old")))
    time.sleep(0.06)  # make "old" measurably older than the cutoff
    store.update(_pm(ck=("t1", "fresh")))

    # cutoff = now - 0.03; "old" is ~0.06s old (dropped),
    # "fresh" is ~0s old (kept).
    n = store.expire_older_than(0.03)

    assert n >= 1
    assert store.get("r1", ("t1", "old")) is None
    assert store.get("r1", ("t1", "fresh")) is not None


# ── ValkeyStateStore-specific: cross-instance visibility ───────────


def test_valkey_cross_instance_visibility():
    """Two store instances sharing a client see each other's writes.

    This is the whole point of ValkeyStateStore: in a real fleet, the
    process that handles step 1 of an attack is not the process that
    handles step 2. Both must see the same partial match.
    """
    fake = FakeValkey()
    worker_a = ValkeyStateStore(client=fake)
    worker_b = ValkeyStateStore(client=fake)

    worker_a.update(_pm(idx=1))

    # Worker B (a different "process") reads what A wrote.
    got = worker_b.get("r1", ("t1", "p1"))
    assert got is not None
    assert got.current_step_idx == 1

    # B advances; A sees the advance.
    got.current_step_idx = 2
    got.steps_ts.append(2.0)
    worker_b.update(got)

    seen_by_a = worker_a.get("r1", ("t1", "p1"))
    assert seen_by_a.current_step_idx == 2
    assert seen_by_a.steps_ts == [1.0, 2.0]


def test_valkey_correlate_keys_with_special_chars_isolate_cleanly():
    """ck_token hashing protects against ':' / unicode in correlate
    keys — the encoding must keep records distinct."""
    fake = FakeValkey()
    s = ValkeyStateStore(client=fake)
    s.update(_pm(ck=("tenant:a", "principal::x")))
    s.update(_pm(ck=("tenant:a", "principal::y")))

    a = s.get("r1", ("tenant:a", "principal::x"))
    b = s.get("r1", ("tenant:a", "principal::y"))
    assert a is not None and b is not None
    assert a.correlate_key != b.correlate_key
    assert len(list(s.list_active("r1"))) == 2


# ── ValkeyStateStore-specific: fail-soft when client is absent ─────


def test_valkey_no_client_is_fail_soft():
    """No Valkey configured -> safe no-ops, never raises."""
    # Force the lazy resolver to return None by injecting a no-op
    # client placeholder that we then replace with None. The simplest
    # path: pass client=None and ensure get_valkey returns None by
    # monkeypatching is overkill — just verify the store doesn't crash
    # by using a store whose explicit None bypasses resolution.
    s = ValkeyStateStore(client=None)
    # In a CI environment without KYA_VALKEY_URL, get_valkey() returns
    # None — so every call below must succeed and return safe defaults.
    assert s.get("r1", ("t1", "p1")) is None
    s.update(_pm())          # no-op, no raise
    s.delete("r1", ("t1", "p1"))  # no-op, no raise
    assert s.expire_older_than(60) == 0
    assert s.list_active("r1") == []


# ── Engine parity: same evidence sequence, same matches ────────────


def test_engine_parity_memory_vs_valkey():
    """The strongest regression: feed a real engine the same evidence
    sequence with each store; the matched rule_ids and emitted signals
    MUST be identical."""
    from kya.attack_chains._engine import AttackChainEngine
    from kya.attack_chains._loader import load_rule

    rule = load_rule(
        {
            "version": 1,
            "id": "filesystem_exfiltration",
            "severity": "high",
            "emits_signal": "rogue_filesystem_exfiltration",
            "correlate_by": ["tenant_id", "principal_id"],
            "steps": [
                {
                    "id": "recon",
                    "evidence_kind": "tool_call",
                    "match": {"payload.tool": "file_read"},
                },
                {
                    "id": "exfil",
                    "evidence_kind": "tool_call",
                    "match": {"payload.tool": "http_post"},
                    "after": "recon",
                    "within_seconds": 60,
                },
            ],
        },
        source_label="<inline>",
    )

    def run(store):
        captured: list[tuple[str, str]] = []

        def emitter(_db, _tenant, _principal, signal_kind,
                    _evidence_id, r):
            captured.append((r.id, signal_kind))

        engine = AttackChainEngine(
            rules=[rule],
            state_store=store,
            signal_emitter=emitter,
        )
        # Step 1: recon.
        m1 = engine.process_evidence(
            None, tenant_id="t1", principal_id="p1",
            evidence_kind="tool_call",
            payload={"tool": "file_read"},
            evidence_id=1, occurred_at_ts=100.0,
        )
        # Step 2: exfil within window -> full match.
        m2 = engine.process_evidence(
            None, tenant_id="t1", principal_id="p1",
            evidence_kind="tool_call",
            payload={"tool": "http_post"},
            evidence_id=2, occurred_at_ts=110.0,
        )
        return m1, m2, captured

    mem_m1, mem_m2, mem_caps = run(InMemoryStateStore())
    vk_m1, vk_m2, vk_caps = run(
        ValkeyStateStore(client=FakeValkey()))

    # Step 1 advances but doesn't fire; step 2 completes the chain.
    assert mem_m1 == [] and vk_m1 == []
    assert mem_m2 == ["filesystem_exfiltration"]
    assert vk_m2 == ["filesystem_exfiltration"]
    # And emitted signal payloads are identical.
    assert mem_caps == vk_caps == [
        ("filesystem_exfiltration", "rogue_filesystem_exfiltration"),
    ]


# ── resolve_state_store: env-driven default selection ─────────────


def test_resolve_state_store_memory_mode(monkeypatch):
    from kya.attack_chains._engine import resolve_state_store
    monkeypatch.setenv("KYA_ATTACK_CHAIN_STATE", "memory")
    assert isinstance(resolve_state_store(), InMemoryStateStore)


def test_resolve_state_store_valkey_mode(monkeypatch):
    from kya.attack_chains._engine import resolve_state_store
    monkeypatch.setenv("KYA_ATTACK_CHAIN_STATE", "valkey")
    assert isinstance(resolve_state_store(), ValkeyStateStore)


def test_resolve_state_store_auto_falls_back_to_memory_when_no_valkey(
    monkeypatch,
):
    """Default mode + no Valkey reachable -> in-memory (no surprises)."""
    from kya._valkey import register_valkey_factory, reset_valkey_cache
    from kya.attack_chains._engine import resolve_state_store

    monkeypatch.delenv("KYA_ATTACK_CHAIN_STATE", raising=False)
    monkeypatch.delenv("KYA_VALKEY_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    register_valkey_factory(None)
    reset_valkey_cache()
    try:
        assert isinstance(resolve_state_store(), InMemoryStateStore)
    finally:
        reset_valkey_cache()


def test_resolve_state_store_valkey_mode_warns_when_no_client(
    monkeypatch, caplog,
):
    """Forced ``valkey`` mode without a reachable Valkey is a silent
    no-op for chain detection -- operators MUST see a warning so they
    can fix the misconfiguration."""
    import logging

    from kya._valkey import register_valkey_factory, reset_valkey_cache
    from kya.attack_chains._engine import resolve_state_store

    monkeypatch.setenv("KYA_ATTACK_CHAIN_STATE", "valkey")
    monkeypatch.delenv("KYA_VALKEY_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    register_valkey_factory(None)
    reset_valkey_cache()
    try:
        with caplog.at_level(logging.WARNING, logger="kya.attack_chains._engine"):
            store = resolve_state_store()
        assert isinstance(store, ValkeyStateStore)
        warnings = [
            r for r in caplog.records
            if r.levelno >= logging.WARNING
            and "no Valkey client" in r.getMessage()
        ]
        assert warnings, (
            "expected a WARNING about missing Valkey client when "
            "KYA_ATTACK_CHAIN_STATE=valkey and no client is reachable"
        )
    finally:
        reset_valkey_cache()


def test_resolve_state_store_unknown_mode_warns_and_falls_back(
    monkeypatch, caplog,
):
    """Typo'd mode value must not crash; it falls back to auto and
    logs a warning so the typo gets fixed."""
    import logging

    from kya._valkey import register_valkey_factory, reset_valkey_cache
    from kya.attack_chains._engine import resolve_state_store

    monkeypatch.setenv("KYA_ATTACK_CHAIN_STATE", "valkeyy")  # typo
    monkeypatch.delenv("KYA_VALKEY_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    register_valkey_factory(None)
    reset_valkey_cache()
    try:
        with caplog.at_level(logging.WARNING, logger="kya.attack_chains._engine"):
            store = resolve_state_store()
        # Fell back to auto -> no Valkey -> InMemoryStateStore.
        assert isinstance(store, InMemoryStateStore)
        warnings = [
            r for r in caplog.records
            if r.levelno >= logging.WARNING
            and "unknown KYA_ATTACK_CHAIN_STATE" in r.getMessage()
        ]
        assert warnings, "expected a WARNING about the unknown mode"
    finally:
        reset_valkey_cache()


def test_resolve_state_store_auto_uses_valkey_when_client_available(
    monkeypatch,
):
    """Default mode + a Valkey client factory -> ValkeyStateStore.

    Uses the public ``register_valkey_factory`` injection point so the
    test doesn't depend on env vars OR a live Valkey -- proves the
    auto-resolver actually consults ``get_valkey()``.
    """
    from kya._valkey import register_valkey_factory, reset_valkey_cache
    from kya.attack_chains._engine import resolve_state_store

    monkeypatch.delenv("KYA_ATTACK_CHAIN_STATE", raising=False)
    register_valkey_factory(lambda: FakeValkey())
    try:
        assert isinstance(resolve_state_store(), ValkeyStateStore)
    finally:
        register_valkey_factory(None)
        reset_valkey_cache()


def test_engine_parity_cross_process_advance():
    """The defining new capability: step 1 lands on 'worker A', step 2
    lands on 'worker B' -- both share one Valkey. The chain MUST still
    fire on B, which can't happen with InMemoryStateStore.
    """
    from kya.attack_chains._engine import AttackChainEngine
    from kya.attack_chains._loader import load_rule

    rule = load_rule(
        {
            "version": 1,
            "id": "cross_proc",
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
        },
        source_label="<inline>",
    )

    fake = FakeValkey()
    fired_a: list[str] = []
    fired_b: list[str] = []

    engine_a = AttackChainEngine(
        rules=[rule], state_store=ValkeyStateStore(client=fake),
        signal_emitter=lambda *a: fired_a.append(a[3]),
    )
    engine_b = AttackChainEngine(
        rules=[rule], state_store=ValkeyStateStore(client=fake),
        signal_emitter=lambda *a: fired_b.append(a[3]),
    )

    # Step 1 lands on worker A.
    a1 = engine_a.process_evidence(
        None, tenant_id="t1", principal_id="p1",
        evidence_kind="tool_call",
        payload={"tool": "file_read"},
        evidence_id=1, occurred_at_ts=100.0,
    )
    assert a1 == []  # advanced only
    assert fired_a == []

    # Step 2 lands on worker B -- with InMemoryStateStore this would
    # NEVER fire (B has no partial state). With Valkey-shared state it
    # MUST.
    b2 = engine_b.process_evidence(
        None, tenant_id="t1", principal_id="p1",
        evidence_kind="tool_call",
        payload={"tool": "http_post"},
        evidence_id=2, occurred_at_ts=110.0,
    )
    assert b2 == ["cross_proc"]
    assert fired_b == ["rogue_cross_proc"]
    # A never saw step 2, so it shouldn't have emitted.
    assert fired_a == []
