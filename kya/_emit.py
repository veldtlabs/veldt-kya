"""Thread-safe global emitter hook used by all KYA recorders.

Default state: no emitter is installed and `emit()` is a no-op. When the
customer calls `kya.enable_dual_write()`, a DualWriteSink registers
itself here. Recorders call `emit(table, row)` AFTER their local DB
commit succeeds — never inside the same transaction.

Errors raised by the emitter are caught and logged at DEBUG; they
NEVER propagate to the recorder so the local DB write always succeeds
even if the collector is unreachable.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

EmitFn = Callable[[str, dict], None]

_emitter: Optional[EmitFn] = None
_lock = threading.Lock()


def set_emitter(fn: Optional[EmitFn]) -> None:
    """Atomically install (or remove) the active emitter."""
    global _emitter
    with _lock:
        _emitter = fn


def emit(table: str, row: dict) -> None:
    """Best-effort hand-off to the active emitter. Never raises."""
    fn = _emitter
    if fn is None:
        return
    try:
        fn(table, row)
    except Exception as exc:
        logger.debug("[KYA-DUALWRITE] emit %s suppressed: %s", table, exc)


def is_enabled() -> bool:
    return _emitter is not None


def _coerce(value: Any) -> Any:
    """JSON-serialisable representation for common types recorders pass in."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_coerce(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _coerce(v) for k, v in value.items()}
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return str(value)


def safe_row(row: dict) -> dict:
    """Coerce a row dict to plain JSON-safe primitives.

    Used by recorders that build the row from SQLAlchemy column values —
    keeps the dual-write side from importing dialect-specific types.
    """
    if not isinstance(row, dict):
        return {"value": _coerce(row)}
    return {str(k): _coerce(v) for k, v in row.items()}
