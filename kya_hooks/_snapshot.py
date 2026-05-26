"""Shared snapshot-on-first-sight helper for the framework adapters.

When a framework hook (OpenAI Agents, Claude Agent SDK, LangChain, ...)
observes an agent for the first time, we want to snapshot its current
definition into ``agent_versions`` so that:

    1. Drift detection has a v1 baseline to compare against.
    2. The delegation-policy check (kya.delegation_policy) has a
       parent + sub definition to compare. Without snapshots the
       check fail-softs to [], so first-sight snapshotting closes
       the only "permissive by accident" gap in v0.1.x.

This helper is framework-agnostic: it takes the canonical KYA
agent_def dict that each adapter knows how to build from its
framework's native Agent object. The cache (one ``set`` of
already-snapshotted ``(tenant_id, agent_key)`` tuples) lives for the
lifetime of the process — first call hits the DB, every subsequent
call short-circuits.

Failure modes:
    - tenant_id not supplied   → silent no-op (the hook can't snapshot
                                  without a tenant).
    - session_factory missing  → fall back to ``kya.default_session``.
    - DB transient error       → log at DEBUG, leave cache untouched
                                  so next call retries.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


# Process-wide cache. Entries are (tenant_id, agent_key) tuples that
# have already been snapshotted at least once in THIS process.
# Mutated under a lock — first-sight detection is one of the rare
# places we genuinely want exactly-once-per-key semantics even under
# concurrent hook callbacks (parallel tool calls in OpenAI Agents).
_seen: set[tuple[str, str]] = set()
_seen_lock = threading.Lock()


def maybe_snapshot_first_sight(
    *,
    tenant_id: str | None,
    agent_key: str,
    agent_def: dict[str, Any],
    session_factory: Callable[[], Any] | None = None,
    enabled: bool = True,
) -> bool:
    """Snapshot the agent if this is the first time we've seen it in
    this process. Returns True if a snapshot was actually attempted,
    False if the call was a cache hit or disabled.

    Parameters
    ----------
    tenant_id : str | None
        The tenant the agent belongs to. If None, this call is a no-op
        — we can't snapshot without knowing the tenant.
    agent_key : str
        Stable identifier for the agent (used as the key in
        ``agent_versions``).
    agent_def : dict
        Canonical KYA agent definition. The exact field set depends
        on what the calling adapter can extract — at minimum should
        include ``agent_key`` and ``tools``; richer defs (with
        ``access_level``, ``data_classes``, ``human_loop``) unlock
        the delegation-policy enforcement.
    session_factory : callable | None
        A zero-arg callable returning a SQLAlchemy ``Session``. If
        None, falls back to ``kya.default_session`` (the SDK's
        zero-config SQLite path under ~/.kya/kya.db, configurable
        via KYA_DB_URL).
    enabled : bool
        Master switch — pass False to disable snapshotting without
        removing the call site.
    """
    if not enabled:
        return False
    if not tenant_id:
        logger.debug("[KYA-SNAP] no tenant_id — skipping snapshot")
        return False
    if not agent_key:
        return False

    key = (tenant_id, agent_key)
    with _seen_lock:
        if key in _seen:
            return False
        # Optimistically mark as seen BEFORE attempting the DB write.
        # If the write fails, we remove the marker so the next call
        # gets another shot.
        _seen.add(key)

    try:
        if session_factory is not None:
            session_cm = session_factory()
            # Support both callable-returning-context-manager and
            # callable-returning-Session shapes:
            if hasattr(session_cm, "__enter__"):
                with session_cm as db:
                    _do_snapshot(db, tenant_id, agent_key, agent_def)
            else:
                db = session_cm
                try:
                    _do_snapshot(db, tenant_id, agent_key, agent_def)
                finally:
                    try: db.close()
                    except Exception: pass
        else:
            from kya import default_session
            with default_session() as db:
                _do_snapshot(db, tenant_id, agent_key, agent_def)
        return True
    except Exception as exc:
        # Restore the cache slot so a later attempt can retry.
        with _seen_lock:
            _seen.discard(key)
        logger.debug("[KYA-SNAP] snapshot of %s failed (will retry): %s",
                     agent_key, exc)
        return False


def _do_snapshot(db, tenant_id: str, agent_key: str,
                  agent_def: dict) -> None:
    """Call the public snapshot_on_first_sight() against the open DB.
    Separate so the cache logic above is decoupled from the SDK API."""
    from kya import snapshot_on_first_sight
    snapshot_on_first_sight(
        db, tenant_id=tenant_id, agent_key=agent_key,
        definition=agent_def,
        note="auto-snapshot from kya_hooks framework adapter",
    )


def reset_cache() -> None:
    """Test helper — clears the process-wide seen-set."""
    with _seen_lock:
        _seen.clear()


def seen_keys() -> set[tuple[str, str]]:
    """Test helper — snapshot of the current seen-set."""
    with _seen_lock:
        return set(_seen)
