"""
Partial-match state for the attack-chain engine.

`StateStore` is an abstract interface so the engine can be backed by:
  - InMemoryStateStore   -- default; per-process dict + threading.Lock
  - ValkeyStateStore     -- cross-process; partial-match state shared
                            through Valkey/Redis so chains advance
                            across workers/agents. Each op is
                            individually atomic; concurrent advances of
                            the SAME (rule, correlate_key) are
                            last-writer-wins (fail-soft: worst case is
                            a duplicate or single emitted signal, never
                            a crash).

Engine never types against a specific store -- only the interface.
Lets us swap state backends in a release without touching the engine
or any customer rules.

The state shape (PartialMatch) is part of the STABLE in-memory contract
(same as AttackChainRule). Adding fields here means bumping the SDK
minor version; renaming/removing fields means bumping major.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


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


# ── Valkey/Redis-backed implementation (cross-process) ─────────────


class ValkeyStateStore(StateStore):
    """Cross-process partial-match store backed by Valkey/Redis.

    Solves the limitation of InMemoryStateStore: chains whose steps land
    on different workers/processes (the common case when delegated
    agents run on a fleet) are never correlated because each worker
    holds its own in-memory dict. This store persists state in Valkey so
    every worker sees the same partial matches.

    Storage layout
    --------------
    Each PartialMatch is a JSON string at::

        {prefix}:pm:{rule_id}:{ck_token}

    where ``ck_token`` is a stable hex hash of the correlate_key tuple.
    An optional TTL (``pm_ttl_seconds``) guards against orphan keys if a
    process crashes mid-chain.

    A per-rule ZSET index ``{prefix}:idx:{rule_id}`` maps ``ck_token`` ->
    wall-clock write time. This lets ``expire_older_than`` and
    ``list_active`` enumerate without SCAN-ing the keyspace and makes
    expiry **wall-clock correct across processes** -- the PartialMatch
    dataclass's monotonic ``updated_at`` field is per-process and not
    comparable across hosts, so we never rely on it for expiry; the ZSET
    score is the source of truth.

    Client injection
    ----------------
    Pass any redis-py-compatible client (string + ZSET command surface,
    ``decode_responses=True``). With ``client=None``, resolves lazily via
    :func:`kya._valkey.get_valkey` -- so SDK users just set
    ``KYA_VALKEY_URL`` / ``REDIS_URL`` and it works. The injected-client
    path makes the store trivially testable with a fake.

    Fail-soft
    ---------
    If no client is available (Valkey not configured) or a command
    raises, every method degrades to a safe no-op (``get`` returns None,
    ``update``/``delete`` skip, ``expire`` returns 0, ``list_active``
    returns []). This matches KYA's "observability never breaks the
    request path" contract. Operators who require chains MUST provision
    Valkey; absence is logged once at connect time by ``get_valkey``.

    Concurrency
    -----------
    Each command is atomic at the Valkey level. The engine's
    get-then-update pattern is NOT wrapped in a transaction here, so
    concurrent advances of the same ``(rule_id, correlate_key)`` are
    last-writer-wins. For attack-chain detection this is acceptable:
    worst case is a duplicate emission or a single missed advance, both
    of which are bounded by ``delete`` on full match and the global
    ``window_seconds`` cap. A Lua-based atomic-advance script can be
    added later WITHOUT changing the StateStore interface.
    """

    _DEFAULT_PREFIX = "kya:chains"
    _DEFAULT_TTL = 3600  # 1h orphan cleanup safety net; rule windows
                        # typically far shorter

    def __init__(
        self,
        client=None,
        *,
        key_prefix: str = _DEFAULT_PREFIX,
        pm_ttl_seconds: int | None = _DEFAULT_TTL,
    ) -> None:
        self._explicit_client = client
        self._prefix = key_prefix
        self._pm_ttl = (
            pm_ttl_seconds
            if pm_ttl_seconds is not None and pm_ttl_seconds > 0
            else None
        )

    # ── Client resolution ────────────────────────────────────────

    def _client(self):
        """Return the active Valkey client or None.

        Injected client wins; otherwise resolve lazily via the shared
        accessor so SDK users don't have to pass anything when
        ``KYA_VALKEY_URL`` is set. Lazy on every call keeps the store
        agnostic to import order and resilient to factory swaps.
        """
        if self._explicit_client is not None:
            return self._explicit_client
        try:
            # Lazy import keeps _state.py free of optional-deps imports.
            from kya._valkey import get_valkey
            return get_valkey()
        except Exception as exc:  # pragma: no cover -- defensive
            logger.debug(
                "[KYA-CHAINS] get_valkey() raised: %s", exc)
            return None

    # ── Key + serialization helpers (private, deterministic) ─────

    @staticmethod
    def _ck_token(correlate_key) -> str:
        """Stable hex token for a correlate_key tuple.

        SHA-1 of a deterministic JSON encoding. Used inside both the
        PartialMatch key and the per-rule index, so the engine never
        needs to round-trip the raw tuple through Valkey keys
        (avoids encoding pitfalls when correlate_by includes user-
        supplied strings).
        """
        raw = json.dumps(
            [str(x) for x in correlate_key],
            separators=(",", ":"),
        )
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def _pm_key(self, rule_id: str, ck_token: str) -> str:
        return f"{self._prefix}:pm:{rule_id}:{ck_token}"

    def _idx_key(self, rule_id: str) -> str:
        return f"{self._prefix}:idx:{rule_id}"

    def _idx_prefix(self) -> str:
        return f"{self._prefix}:idx:"

    @staticmethod
    def _dumps(pm: PartialMatch) -> str:
        return json.dumps(
            {
                "rule_id": pm.rule_id,
                "correlate_key": list(pm.correlate_key),
                "current_step_idx": pm.current_step_idx,
                "steps_ts": list(pm.steps_ts),
                "steps_evidence_ids": list(pm.steps_evidence_ids),
                "created_at": pm.created_at,
                "updated_at": pm.updated_at,
            },
            separators=(",", ":"),
        )

    @staticmethod
    def _loads(raw: str) -> PartialMatch:
        d = json.loads(raw)
        return PartialMatch(
            rule_id=d["rule_id"],
            correlate_key=tuple(d["correlate_key"]),
            current_step_idx=int(d["current_step_idx"]),
            steps_ts=[float(t) for t in d.get("steps_ts", [])],
            steps_evidence_ids=[
                int(e) for e in d.get("steps_evidence_ids", [])
            ],
            created_at=float(d.get("created_at", 0.0)),
            updated_at=float(d.get("updated_at", 0.0)),
        )

    # ── StateStore interface implementation ──────────────────────

    def get_or_create(self, rule_id, correlate_key):
        pm = self.get(rule_id, correlate_key)
        if pm is not None:
            return pm
        pm = PartialMatch(
            rule_id=rule_id,
            correlate_key=tuple(correlate_key),
            current_step_idx=0,
        )
        self.update(pm)
        return pm

    def get(self, rule_id, correlate_key):
        client = self._client()
        if client is None:
            return None
        try:
            key = self._pm_key(rule_id, self._ck_token(correlate_key))
            raw = client.get(key)
            return self._loads(raw) if raw is not None else None
        except Exception as exc:
            logger.warning(
                "[KYA-CHAINS] valkey get failed for rule=%s: %s",
                rule_id, exc)
            return None

    def update(self, pm):
        client = self._client()
        if client is None:
            return
        # Parity with InMemoryStateStore: refresh the in-process
        # monotonic stamp on every write so callers reading the
        # returned object see a fresh value.
        pm.updated_at = time.monotonic()
        ck_token = self._ck_token(pm.correlate_key)
        pm_key = self._pm_key(pm.rule_id, ck_token)
        idx_key = self._idx_key(pm.rule_id)
        try:
            if self._pm_ttl is not None:
                client.set(pm_key, self._dumps(pm), ex=self._pm_ttl)
            else:
                client.set(pm_key, self._dumps(pm))
            # Wall-clock score so expire_older_than is correct across
            # processes regardless of any node's monotonic clock.
            client.zadd(idx_key, {ck_token: time.time()})
        except Exception as exc:
            logger.warning(
                "[KYA-CHAINS] valkey update failed for rule=%s: %s",
                pm.rule_id, exc)

    def delete(self, rule_id, correlate_key):
        client = self._client()
        if client is None:
            return
        ck_token = self._ck_token(correlate_key)
        try:
            client.delete(self._pm_key(rule_id, ck_token))
            client.zrem(self._idx_key(rule_id), ck_token)
        except Exception as exc:
            logger.warning(
                "[KYA-CHAINS] valkey delete failed for rule=%s: %s",
                rule_id, exc)

    def expire_older_than(self, max_age_seconds: float) -> int:
        client = self._client()
        if client is None:
            return 0
        cutoff = time.time() - float(max_age_seconds)
        n = 0
        idx_prefix = self._idx_prefix()
        try:
            for idx_key in client.scan_iter(match=f"{idx_prefix}*"):
                # Indexes are keyed by raw rule_id (which can contain
                # any character including ':' per the loader), so we
                # strip the known prefix rather than splitting on ':'.
                rule_id = idx_key[len(idx_prefix):]
                stale = client.zrangebyscore(
                    idx_key, "-inf", cutoff)
                for ck_token in stale:
                    client.delete(self._pm_key(rule_id, ck_token))
                    client.zrem(idx_key, ck_token)
                    n += 1
        except Exception as exc:
            logger.warning(
                "[KYA-CHAINS] valkey expire_older_than failed: %s", exc)
        return n

    def list_active(self, rule_id):
        client = self._client()
        if client is None:
            return []
        out: list[PartialMatch] = []
        try:
            for ck_token in client.zrange(self._idx_key(rule_id), 0, -1):
                raw = client.get(self._pm_key(rule_id, ck_token))
                if raw is not None:
                    out.append(self._loads(raw))
        except Exception as exc:
            logger.warning(
                "[KYA-CHAINS] valkey list_active failed for rule=%s: %s",
                rule_id, exc)
        return out
