"""
Default Valkey/Redis accessor for KYA SDK distribution.

Why this exists
---------------
KYA's hardening features (rate limit, replay protection, realtime
burst detection) need a Valkey/Redis backend. Historically the
accessor lived in `kya_redteam.runtime._get_valkey()` which does
`from db.redis import get_redis` — a Veldt-platform module that
doesn't ship with the PyPI SDK distribution.

For PyPI users (pip install veldt-kya), that import fails silently
and every hardening feature degrades to "no-op fail-open" without
any indication. Operators believe they're protected and aren't —
which is worse than not having the feature.

This module solves it. SDK users get a default accessor that reads
env vars (`KYA_VALKEY_URL`, `REDIS_URL`) and returns a redis-py
client. Veldt-platform users keep using their `db.redis` shim via
`register_valkey_factory()`.

Public API
----------
  get_valkey() -> redis.Redis | None
      Returns a cached redis-py client. Reads connection URL from
      KYA_VALKEY_URL (preferred) or REDIS_URL (common convention).
      Returns None if neither env set OR if redis-py not installed.

  register_valkey_factory(factory: Callable[[], Any]) -> None
      Inject a custom factory (e.g. Veldt's existing db.redis
      shim). When set, get_valkey() calls this instead of the
      default env-based resolver. Use this from the parent app's
      startup code.

  reset_valkey_cache() -> None
      Test helper — clears the cached client so the next call
      reconnects.

Dependency
----------
  redis-py — optional. Install with:
      pip install veldt-kya[hardening]
  or directly:
      pip install redis
  Without it, every Valkey-dependent feature degrades to no-op.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


# Process-wide cached client (set on first successful connect).
# Re-resolved when reset_valkey_cache() is called.
_CLIENT: Any | None = None
_CLIENT_LOCK = threading.Lock()
_CLIENT_RESOLVED = False  # True once we've tried (avoid re-attempt storms)

# Optional injected factory (for Veldt-platform users who already
# have their own Valkey accessor wired up).
_FACTORY: Callable[[], Any] | None = None


def register_valkey_factory(factory: Callable[[], Any] | None) -> None:
    """Inject a custom Valkey/Redis client factory. Use this from
    the parent app's startup code to plug in an existing shim.

    Pass None to clear and fall back to the env-based default
    resolver.

    The factory is called once per process (result cached). Reset
    with `reset_valkey_cache()`."""
    global _FACTORY, _CLIENT, _CLIENT_RESOLVED
    with _CLIENT_LOCK:
        _FACTORY = factory
        _CLIENT = None
        _CLIENT_RESOLVED = False


def reset_valkey_cache() -> None:
    """Test helper — clear the cached client + factory state so
    the next get_valkey() call resolves fresh."""
    global _CLIENT, _CLIENT_RESOLVED
    with _CLIENT_LOCK:
        _CLIENT = None
        _CLIENT_RESOLVED = False


def get_valkey() -> Any | None:
    """Return a redis-py client (or compatible) or None.

    Resolution order:
      1. If a custom factory is registered, call it and cache.
      2. Otherwise, read KYA_VALKEY_URL / REDIS_URL env, build a
         redis-py client, ping it, and cache.
      3. If redis-py is not installed OR env not set OR ping
         fails, cache None.

    Always returns the SAME instance for a given process lifetime
    (modulo reset_valkey_cache()). Threadsafe via lock.
    """
    global _CLIENT, _CLIENT_RESOLVED

    # Fast path — already resolved this process
    if _CLIENT_RESOLVED:
        return _CLIENT

    with _CLIENT_LOCK:
        if _CLIENT_RESOLVED:
            return _CLIENT  # someone else won the race

        client: Any | None = None

        # 1. Custom factory takes precedence (parent-app shim)
        if _FACTORY is not None:
            try:
                client = _FACTORY()
            except Exception as exc:
                logger.debug(
                    "[KYA-VALKEY] registered factory raised: %s", exc)
                client = None

        # 2. Default env-based resolution
        if client is None:
            try:
                import redis
            except ImportError:
                # Loud WARNING (not debug) when an operator HAS set
                # KYA_VALKEY_URL but redis-py isn't installed.
                # Pre-fix this was a silent debug message and Phase 12
                # gap #4 surfaced: gateway rate-limiting silently
                # degraded to fail-open. Operators should see this in
                # their startup logs.
                url_env_set = (
                    os.environ.get("KYA_VALKEY_URL")
                    or os.environ.get("REDIS_URL")
                )
                if url_env_set:
                    logger.warning(
                        "[KYA-VALKEY] KYA_VALKEY_URL / REDIS_URL is "
                        "set but redis-py is not installed -- "
                        "hardening features (rate-limit, revocation "
                        "cache, etc.) will FAIL-OPEN. Install with "
                        "`pip install veldt-kya[gateway]` (recommended "
                        "for gateway deployments) or `pip install redis`. "
                        "If you upgraded veldt-kya, re-run pip install "
                        "to pick up the new redis dependency."
                    )
                else:
                    logger.debug(
                        "[KYA-VALKEY] redis-py not installed and no "
                        "URL env set; hardening features fail-open.")
                _CLIENT = None
                _CLIENT_RESOLVED = True
                return None

            url = (
                os.environ.get("KYA_VALKEY_URL")
                or os.environ.get("REDIS_URL")
            )
            if not url:
                logger.debug(
                    "[KYA-VALKEY] no KYA_VALKEY_URL / REDIS_URL "
                    "env set — hardening features fail-open.")
                _CLIENT = None
                _CLIENT_RESOLVED = True
                return None

            try:
                client = redis.Redis.from_url(
                    url, decode_responses=True,
                    socket_connect_timeout=2.0)
                # Test the connection — fail fast if URL is bad
                client.ping()
            except Exception as exc:
                logger.warning(
                    "[KYA-VALKEY] failed to connect to %s — "
                    "hardening features fail-open. Error: %s",
                    url, exc)
                client = None

        _CLIENT = client
        _CLIENT_RESOLVED = True

        if client is not None:
            logger.info(
                "[KYA-VALKEY] connected — hardening features "
                "(rate limit, replay, realtime) active")
        return client
