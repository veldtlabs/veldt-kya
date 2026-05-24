"""Pluggable session factory for KYA recorders that need to write
async/mirror rows to a DB outside their direct call context.

Several rogue + inbound paths fan out an "attribution mirror" write
(e.g. `_emit_actor_agent_signal`, `_emit_user_signal`) to the unified
principal trust table. Inside vd-app, the platform has a globally
configured `db.database.SessionLocal`. The SDK does not have that.

This module gives both a usable default (try the platform module if
present) AND a public override so SDK users can inject any
sessionmaker-compatible callable.

Usage from SDK:

    from sqlalchemy.orm import sessionmaker
    import kya

    Session = sessionmaker(bind=my_engine)
    kya.set_session_factory(Session)

After that, any rogue.record_* / inbound paths that need a side-effect
session call into this module.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

SessionFactoryFn = Callable[[], Any]

_factory: SessionFactoryFn | None = None
_warned_missing: bool = False


def set_session_factory(factory: SessionFactoryFn | None) -> None:
    """Install or remove the SDK-side session factory.

    `factory()` must return a SQLAlchemy Session-like object with
    `.close()`. A `sessionmaker(bind=engine)` instance works directly.
    Pass `None` to clear (rogue mirror writes become no-ops).
    """
    global _factory, _warned_missing
    _factory = factory
    _warned_missing = False  # reset warning state on (re)config


def _try_platform_default() -> SessionFactoryFn | None:
    """If running inside vd-app, the platform exposes db.database.SessionLocal."""
    try:
        from db.database import SessionLocal  # type: ignore
        return SessionLocal
    except Exception:
        return None


def get_session() -> Any | None:
    """Return a fresh Session if a factory is installed (or platform default
    is available). Returns None if neither is set — callers should treat
    that as "skip the mirror write."

    Logs a one-time warning if no factory is configured, so SDK users
    notice that attribution mirrors are silently no-oping.
    """
    global _warned_missing
    factory = _factory or _try_platform_default()
    if factory is None:
        if not _warned_missing:
            logger.warning(
                "[KYA] no session factory configured — "
                "rogue/inbound mirror writes will be no-ops. "
                "Call kya.set_session_factory(sessionmaker(bind=engine)) to enable."
            )
            _warned_missing = True
        return None
    try:
        return factory()
    except Exception as exc:
        logger.debug("[KYA] session factory raised: %s", exc)
        return None


def has_factory() -> bool:
    return _factory is not None or _try_platform_default() is not None
