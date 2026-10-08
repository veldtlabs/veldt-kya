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
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


# Process-wide cached client (set on first successful connect).
# Re-resolved when reset_valkey_cache() is called.
_CLIENT: Any | None = None
_CLIENT_LOCK = threading.Lock()
_CLIENT_RESOLVED = False  # True only for states a retry cannot change
# Monotonic deadline after a CONNECT failure. A connect failure is
# transient -- a broker restart, or workers starting before the broker is
# ready -- so it must not be cached for the life of the process. Latching
# it turns a three-second outage into a permanent, silent loss of rate
# limiting, replay protection and burst detection, with one log line at
# first use and nothing afterwards.
_CLIENT_RETRY_AFTER = 0.0

# Optional injected factory (for Veldt-platform users who already
# have their own Valkey accessor wired up).
_FACTORY: Callable[[], Any] | None = None


def _retry_cooldown_s() -> float:
    """Seconds to stay fail-open before retrying a failed connection.

    Bounded deliberately: a retry pays ``socket_connect_timeout`` on the
    request that makes it, so retrying every request would trade a
    silent outage for a latency outage.
    """
    raw = os.environ.get("KYA_VALKEY_RETRY_COOLDOWN_S", "30").strip()
    try:
        return max(1.0, float(raw))
    except ValueError:
        return 30.0


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
    global _CLIENT, _CLIENT_RESOLVED, _CLIENT_RETRY_AFTER
    with _CLIENT_LOCK:
        _CLIENT = None
        _CLIENT_RESOLVED = False
        _CLIENT_RETRY_AFTER = 0.0


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
    global _CLIENT, _CLIENT_RESOLVED, _CLIENT_RETRY_AFTER

    # Fast path — resolved to a terminal state this process
    if _CLIENT_RESOLVED:
        return _CLIENT

    # A previous connect failed and the cooldown has not elapsed: stay
    # fail-open without paying the connect timeout again.
    if _CLIENT_RETRY_AFTER and time.monotonic() < _CLIENT_RETRY_AFTER:
        return None

    with _CLIENT_LOCK:
        if _CLIENT_RESOLVED:
            return _CLIENT  # someone else won the race
        if _CLIENT_RETRY_AFTER and time.monotonic() < _CLIENT_RETRY_AFTER:
            return None

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
                # Pre-fix this was a silent debug message and gateway
                # rate-limiting silently degraded to fail-open.
                # Operators should see this in their startup logs.
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
                    socket_connect_timeout=2.0,
                    # Without this, an established-then-hung connection
                    # blocks a read or write with no bound, and these
                    # calls sit on the decision path.
                    socket_timeout=2.0)
                # Test the connection — fail fast if URL is bad
                client.ping()
            except Exception as exc:
                cooldown = _retry_cooldown_s()
                # WARNING on every attempt, not once per process: a
                # degraded control needs a recurring alarm, and the
                # retry is what makes one possible.
                logger.warning(
                    "[KYA-VALKEY] failed to connect to %s — rate "
                    "limiting, replay protection and burst detection "
                    "are FAIL-OPEN. Retrying in %.0fs. Error: %s",
                    url, cooldown, exc)
                _CLIENT = None
                _CLIENT_RETRY_AFTER = time.monotonic() + cooldown
                return None

        _CLIENT = client
        _CLIENT_RESOLVED = True
        _CLIENT_RETRY_AFTER = 0.0

        if client is not None:
            logger.info(
                "[KYA-VALKEY] connected — hardening features "
                "(rate limit, replay, realtime) active")
        return client
