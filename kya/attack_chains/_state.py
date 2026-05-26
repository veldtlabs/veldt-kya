"""
Partial-match state for the attack-chain engine.

`StateStore` is an abstract interface so the engine can be backed by:
  - InMemoryStateStore        -- default; per-process dict + threading.Lock
  - (future) ValkeyStateStore -- cross-process; atomic Lua updates

Engine never types against a specific store -- only the interface.
Lets us swap state backends in a release without touching the engine
or any customer rules.

The state shape (PartialMatch) is part of the STABLE in-memory contract
(same as AttackChainRule). Adding fields here means bumping the SDK
minor version; renaming/removing fields means bumping major.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class PartialMatch:
    """Tracks how far one (rule, correlate_key) tuple has progressed
    through its step sequence. When `current_step_idx` reaches
    len(rule.steps), the match is COMPLETE and the engine emits."""
    rule_id: str
    correlate_key: tuple[str, ...]   # tuple of correlate_by values
    current_step_idx: int            # 0-based; next step to match
    # Per-step ingest timestamps (epoch seconds). steps_ts[i] is when
    # step i was matched. Used for `after` / `within_seconds` checks.
    steps_ts: list[float] = field(default_factory=list)
    # Per-step source-evidence pointer (e.g., evidence row id). Lets
    # downstream consumers walk back through the matching events.
    steps_evidence_ids: list[int] = field(default_factory=list)
    # Process-time created/updated for expiry of stale partial matches.
    created_at: float = field(default_factory=time.monotonic)
    updated_at: float = field(default_factory=time.monotonic)


# ── Abstract state store interface ─────────────────────────────────


class StateStore:
    """Interface contract for partial-match state. Engine talks to
    THIS interface only. Backends (in-memory, Valkey, etc.) implement
    these methods.

    Implementations MUST be safe to call concurrently from multiple
    threads. Cross-process safety is implementation-specific (the
    in-memory store is per-process only)."""

    def get_or_create(
        self,
        rule_id: str,
        correlate_key: tuple[str, ...],
    ) -> PartialMatch:
        raise NotImplementedError

    def get(
        self,
        rule_id: str,
        correlate_key: tuple[str, ...],
    ) -> PartialMatch | None:
        raise NotImplementedError

    def update(self, pm: PartialMatch) -> None:
        raise NotImplementedError

    def delete(
        self,
        rule_id: str,
        correlate_key: tuple[str, ...],
    ) -> None:
        raise NotImplementedError

    def expire_older_than(self, max_age_seconds: float) -> int:
        """Drop partial matches whose `updated_at` is older than
        `max_age_seconds`. Returns count deleted. Engine calls this
        periodically (or on every evidence ingest)."""
        raise NotImplementedError

    def list_active(self, rule_id: str) -> Iterable[PartialMatch]:
        """Iterate all partial matches for a given rule. Used for
        introspection / debugging / cross-rule reasoning."""
        raise NotImplementedError


# ── In-memory implementation (default) ─────────────────────────────


class InMemoryStateStore(StateStore):
    """Per-process partial-match store.

    Concurrency: a single threading.Lock guards the dict. For typical
    KYA loads (1k evidence events/sec sustained, single Python
    process), this is plenty. For multi-process deployments, swap to
    a ValkeyStateStore (not yet implemented; the interface is the
    swap point).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (rule_id, correlate_key) -> PartialMatch
        self._store: dict[tuple[str, tuple[str, ...]], PartialMatch] = {}

    def get_or_create(self, rule_id, correlate_key):
        key = (rule_id, tuple(correlate_key))
        with self._lock:
            pm = self._store.get(key)
            if pm is None:
                pm = PartialMatch(
                    rule_id=rule_id,
                    correlate_key=tuple(correlate_key),
                    current_step_idx=0,
                )
                self._store[key] = pm
            return pm

    def get(self, rule_id, correlate_key):
        key = (rule_id, tuple(correlate_key))
        with self._lock:
            return self._store.get(key)

    def update(self, pm):
        key = (pm.rule_id, tuple(pm.correlate_key))
        pm.updated_at = time.monotonic()
        with self._lock:
            self._store[key] = pm

    def delete(self, rule_id, correlate_key):
        key = (rule_id, tuple(correlate_key))
        with self._lock:
            self._store.pop(key, None)

    def expire_older_than(self, max_age_seconds):
        cutoff = time.monotonic() - max_age_seconds
        n = 0
        with self._lock:
            stale = [k for k, pm in self._store.items()
                     if pm.updated_at < cutoff]
            for k in stale:
                self._store.pop(k, None)
                n += 1
        return n

    def list_active(self, rule_id):
        with self._lock:
            return [pm for (rid, _), pm in self._store.items()
                    if rid == rule_id]
