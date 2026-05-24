"""Aggregate-only anonymous telemetry for KYA.

ON by default. Carries ONLY counts — never row payloads, never tenant
IDs, never agent keys, never PII. Lets Veldt build platform-wide
risk-distribution baselines without learning anything about individual
customer data.

What gets transmitted on each flush (15-minute windows by default):

    {
      "v": 1,
      "kind": "kya_aggregate_telemetry",
      "kya_version": "0.1.0",
      "deployment_id": "sha256:abc…",   # salted hash of host fingerprint
      "window_start": "...",
      "window_end":   "...",
      "counts": {
        "snapshot_agent":            {"total": 142},
        "record_invocation":         {"total": 580},
        "record_evidence":           {"total": 234},
        "record_principal_signal":   {"by_kind": {"oos_tool": 12, ...}},
        "rogue_event":               {"by_kind": {"oos_tool": 12, ...}}
      }
    }

How to disable:
  • `kya.disable_telemetry()` at runtime, OR
  • `KYA_TELEMETRY=off` env var (checked at import time), OR
  • leaving `KYA_TELEMETRY_URL` unset — telemetry counts in-process
    but never transmits without a configured collector.

How to override:
  • `kya.enable_telemetry(url=..., flush_interval_s=..., disabled=False)`
  • `KYA_TELEMETRY_URL` env var
"""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
import platform
import socket
import threading
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Default off if explicitly disabled; otherwise on.
_TELEMETRY_DISABLED_AT_IMPORT = os.environ.get("KYA_TELEMETRY", "").lower() in (
    "off", "0", "false", "no",
)


def _deployment_id() -> str:
    """Stable per-installation identifier that does NOT identify the customer.

    Hash of (hostname, platform, KYA_DEPLOYMENT_SALT or random-once).
    KYA_DEPLOYMENT_ID overrides if the customer pins a value.
    """
    pinned = os.environ.get("KYA_DEPLOYMENT_ID")
    if pinned:
        return f"pinned:{pinned[:32]}"
    salt = os.environ.get("KYA_DEPLOYMENT_SALT") or "kya-default-salt"
    fingerprint = f"{socket.gethostname()}|{platform.platform()}|{salt}"
    return "sha256:" + hashlib.sha256(fingerprint.encode()).hexdigest()[:24]


# ── Counters ────────────────────────────────────────────────────────


class _Aggregator:
    """In-process counter store. Lock-protected; thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reset()

    def _reset(self) -> None:
        self._totals: dict[str, int] = {}
        self._by_kind: dict[str, dict[str, int]] = {}
        self._window_start = datetime.now(timezone.utc)

    def inc(self, key: str, kind: str | None = None, n: int = 1) -> None:
        with self._lock:
            self._totals[key] = self._totals.get(key, 0) + n
            if kind:
                bucket = self._by_kind.setdefault(key, {})
                bucket[kind] = bucket.get(kind, 0) + n

    def snapshot_and_reset(self) -> dict[str, Any]:
        with self._lock:
            payload = {
                "window_start": self._window_start.isoformat(),
                "window_end": datetime.now(timezone.utc).isoformat(),
                "counts": {},
            }
            for key, total in self._totals.items():
                entry: dict[str, Any] = {"total": total}
                if key in self._by_kind:
                    entry["by_kind"] = dict(self._by_kind[key])
                payload["counts"][key] = entry
            self._reset()
            return payload

    def peek(self) -> dict[str, Any]:
        with self._lock:
            return {
                "window_start": self._window_start.isoformat(),
                "totals": dict(self._totals),
                "by_kind": {k: dict(v) for k, v in self._by_kind.items()},
            }


_AGG = _Aggregator()


# ── Public counter API used by recorders ───────────────────────────


_DISABLED = _TELEMETRY_DISABLED_AT_IMPORT


def record_event(key: str, kind: str | None = None) -> None:
    """Increment one of the named aggregate counters. Always safe; cheap."""
    if _DISABLED:
        return
    try:
        _AGG.inc(key, kind=kind)
    except Exception:
        pass


# ── Periodic flush ─────────────────────────────────────────────────


class TelemetryTransmitter:
    """Periodic POST of aggregate counters to a configured collector.

    Started on first enable_telemetry() with a URL. Worker thread is
    daemon so it never blocks process exit. Failure to transmit silently
    drops the window — no payload retention, no retry, by design (these
    are just counters; loss is OK).
    """

    def __init__(self, url: str, flush_interval_s: float = 900.0, request_timeout_s: float = 10.0):
        self._url = url
        self._interval = max(60.0, flush_interval_s)
        self._timeout = request_timeout_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="kya-telemetry", daemon=True)
        self._thread.start()
        # Capture a stable reference: atexit.unregister cannot match a
        # fresh bound method object (Python bug-feature) — every
        # `self.shutdown` access produces a new bound-method instance
        # that compares unequal to the registered one. Storing the
        # callable here lets shutdown() unregister cleanly so
        # enable/disable cycles don't leak handlers.
        self._atexit_handle = self.shutdown
        atexit.register(self._atexit_handle)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._flush()
            except Exception as exc:
                logger.debug("[KYA-TELEMETRY] flush suppressed: %s", exc)

    def _flush(self) -> None:
        snapshot = _AGG.snapshot_and_reset()
        if not snapshot["counts"]:
            return
        try:
            from . import __version__ as KYA_VERSION  # type: ignore[attr-defined]
        except Exception:
            KYA_VERSION = "0.0.0"
        body = {
            "v": 1,
            "kind": "kya_aggregate_telemetry",
            "kya_version": KYA_VERSION,
            "deployment_id": _deployment_id(),
            **snapshot,
        }
        try:
            import requests  # type: ignore
        except ImportError:
            return
        try:
            requests.post(
                self._url,
                data=json.dumps(body),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "veldt-kya-telemetry/0.1",
                },
                timeout=self._timeout,
            )
        except Exception as exc:
            logger.debug("[KYA-TELEMETRY] post suppressed: %s", exc)

    def shutdown(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        try:
            self._flush()
        except Exception:
            pass
        # Join the worker so callers don't accumulate a stale thread
        # per enable/disable cycle. Daemon=True means process exit
        # would kill it anyway, but we want clean shutdown semantics.
        try:
            if self._thread.is_alive() and threading.current_thread() is not self._thread:
                self._thread.join(timeout=2.0)
        except Exception:
            pass
        # Unregister the atexit handler — otherwise repeated
        # enable_telemetry()/disable_telemetry() cycles accumulate
        # one atexit handler per cycle for the process lifetime
        # (one of the silent-leak modes flagged in PYPI item 8).
        try:
            atexit.unregister(self._atexit_handle)
        except Exception:
            pass


# ── Module-level API ───────────────────────────────────────────────


_TX: TelemetryTransmitter | None = None
_TX_LOCK = threading.Lock()


def enable_telemetry(
    *,
    url: str | None = None,
    flush_interval_s: float = 900.0,
    request_timeout_s: float = 10.0,
) -> None:
    """Enable + configure aggregate telemetry transmission.

    Without a `url` arg, reads `KYA_TELEMETRY_URL` from env. If neither
    is set, counters keep accumulating in-process (visible via
    `telemetry_status()`) but nothing is transmitted.
    """
    global _DISABLED, _TX
    _DISABLED = False
    resolved = url or os.environ.get("KYA_TELEMETRY_URL")
    with _TX_LOCK:
        if _TX is not None:
            _TX.shutdown()
            _TX = None
        if resolved:
            _TX = TelemetryTransmitter(
                resolved,
                flush_interval_s=flush_interval_s,
                request_timeout_s=request_timeout_s,
            )
            logger.info(
                "[KYA-TELEMETRY] enabled · url=%s · interval=%ss",
                resolved, flush_interval_s,
            )


def disable_telemetry() -> None:
    """Stop collecting and transmitting aggregate telemetry."""
    global _DISABLED, _TX
    _DISABLED = True
    with _TX_LOCK:
        if _TX is not None:
            _TX.shutdown()
            _TX = None
    logger.info("[KYA-TELEMETRY] disabled")


def telemetry_status() -> dict:
    """For dashboards: current state + in-flight counters."""
    with _TX_LOCK:
        return {
            "disabled": _DISABLED,
            "transmitting": _TX is not None,
            "url": _TX._url if _TX else None,
            "flush_interval_s": _TX._interval if _TX else None,
            "in_flight": _AGG.peek(),
        }


# Auto-start transmission if env says so. Counters always work; the
# transmitter only starts when both telemetry is enabled AND a URL is
# present. (No URL = no phone-home, ever, regardless of state.)
if not _DISABLED:
    _env_url = os.environ.get("KYA_TELEMETRY_URL")
    if _env_url:
        try:
            enable_telemetry(url=_env_url)
        except Exception as exc:
            logger.debug("[KYA-TELEMETRY] autostart suppressed: %s", exc)
