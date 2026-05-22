"""Default Session factory for zero-config evaluations.

KYA's storage APIs all take a SQLAlchemy ``Session`` as their first
positional argument. For evaluators kicking the tires (``pip install
veldt-kya`` and try it), provisioning a database is friction. This
module supplies a sensible default:

    1. If ``KYA_DB_URL`` is set in the environment, use it.
    2. Otherwise fall back to ``sqlite:///{KYA_HOME}/kya.db``
       (defaulting ``KYA_HOME`` to ``~/.kya``). The directory is
       created on demand.

The first time the fallback fires, a single WARN line is logged
making it clear what just happened and how to override for
production. Caller code that wants a custom session can keep
constructing its own — nothing here is enforced.

Usage::

    from kya import default_session, snapshot_agent

    with default_session() as db:
        snapshot_agent(db, tenant_id="t1", agent_key="a1",
                       definition={"agent_key": "a1", "tools": [...]})

Tables are auto-created on first use of ``default_session()`` via
``init_storage(db)``. Subsequent calls reuse the engine and table set.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


_DEFAULT_HOME = Path.home() / ".kya"

_engine = None  # SQLAlchemy Engine (set on first call)
_session_factory = None
_warned = False
_storage_initialized = False


def _resolve_db_url() -> tuple[str, bool]:
    """Return (url, is_default). is_default is True when we picked the
    SQLite fallback."""
    url = os.environ.get("KYA_DB_URL", "").strip()
    if url:
        return url, False
    home = Path(os.environ.get("KYA_HOME", "")) if os.environ.get("KYA_HOME") else _DEFAULT_HOME
    home.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{home / 'kya.db'}", True


def _ensure_engine():
    global _engine, _session_factory, _warned
    if _engine is not None:
        return
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    url, is_default = _resolve_db_url()
    _engine = create_engine(url, future=True)
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)

    if is_default and not _warned:
        logger.warning(
            "[KYA] no KYA_DB_URL set — using sqlite:///%s/kya.db. "
            "Set KYA_DB_URL=postgresql://... for production.",
            os.environ.get("KYA_HOME", str(_DEFAULT_HOME)),
        )
        _warned = True


def _ensure_storage(db) -> None:
    global _storage_initialized
    if _storage_initialized:
        return
    try:
        from .storage import init_storage
        init_storage(db)
        db.commit()
        _storage_initialized = True
    except Exception as exc:
        logger.warning("[KYA] default_session storage init failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass


@contextmanager
def default_session() -> Iterator:
    """Context-managed Session against the default database.

    Auto-creates tables on first call. Honors ``KYA_DB_URL``; falls back
    to ``sqlite:///~/.kya/kya.db`` with a single WARN log line.
    """
    _ensure_engine()
    assert _session_factory is not None  # narrow for type checkers
    db = _session_factory()
    try:
        _ensure_storage(db)
        yield db
    finally:
        db.close()


def reset_default_session() -> None:
    """Drop the cached engine. Call between tests or after KYA_DB_URL
    changes mid-process. Not for production use."""
    global _engine, _session_factory, _warned, _storage_initialized
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass
    _engine = None
    _session_factory = None
    _warned = False
    _storage_initialized = False
