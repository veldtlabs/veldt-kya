"""Production-grade dual-write sink for KYA.

Lets self-hosted KYA deployments forward an explicit allowlist of
recorder events to the Veldt collector so the platform can build
aggregate learning over time. Off by default — customer must call
`enable_dual_write()` with `collector_url`, `api_key`, and `allowlist`.

Architecture:
  • Bounded queue (default 10 000 rows) + daemon worker thread
  • Batching (default 50 rows or 2 s flush interval)
  • Exponential backoff with jitter, max 5 retries per batch
  • Circuit breaker: N consecutive failed batches → cool-down window
  • atexit hook drains the queue (best-effort, 5 s timeout)
  • Counters surfaced via Prometheus when available

Failure contract:
  No collector-side failure ever propagates to the recorder. Local DB
  writes always succeed. Drops are visible via counters, not exceptions.

Security contract:
  • Off by default — no collector traffic unless the customer opts in
  • Positive allowlist — only the tables the customer lists flow
  • PII redaction on by default (sha256-salted hash + text truncation)
  • TLS verify on by default
  • API key passed as Bearer; never logged
"""

from __future__ import annotations

import atexit
import json
import logging
import queue
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import _emit
from ._redactor import Redactor, passthrough_redactor

logger = logging.getLogger(__name__)

# ── Counters / gauges ───────────────────────────────────────────────
_COUNTERS: dict[str, Any] = {}


def _ensure_counters() -> None:
    if _COUNTERS:
        return
    try:
        from prometheus_client import REGISTRY, Counter, Gauge

        def _get_or_register(ctor, name, *args, **kwargs):
            try:
                return ctor(name, *args, **kwargs)
            except ValueError:
                return REGISTRY._names_to_collectors.get(name)

        _COUNTERS["emitted"] = _get_or_register(
            Counter, "veldt_kya_dualwrite_emitted",
            "Rows handed to the dual-write sink by table.", ["table"],
        )
        _COUNTERS["dropped"] = _get_or_register(
            Counter, "veldt_kya_dualwrite_dropped",
            "Rows dropped before reaching the collector by reason.", ["reason"],
        )
        _COUNTERS["sent"] = _get_or_register(
            Counter, "veldt_kya_dualwrite_sent",
            "Batches handed to the collector by outcome.", ["outcome"],
        )
        _COUNTERS["queue_depth"] = _get_or_register(
            Gauge, "veldt_kya_dualwrite_queue_depth",
            "Current number of rows queued for the collector.",
        )
    except ImportError:
        pass


def _inc(name: str, **labels) -> None:
    c = _COUNTERS.get(name)
    if c is None:
        return
    try:
        (c.labels(**labels) if labels else c).inc()
    except Exception:
        pass


def _set_gauge(name: str, value: float) -> None:
    g = _COUNTERS.get(name)
    if g is None:
        return
    try:
        g.set(value)
    except Exception:
        pass


# ── Config + sink ───────────────────────────────────────────────────
@dataclass
class DualWriteConfig:
    collector_url: str
    api_key: str
    allowlist: frozenset[str]
    redactor: Redactor | None = None
    queue_max: int = 10_000
    batch_max: int = 50
    flush_interval_s: float = 2.0
    request_timeout_s: float = 10.0
    max_retries: int = 5
    breaker_failure_threshold: int = 5
    breaker_cool_down_s: float = 300.0
    verify_tls: bool = True
    extra_headers: dict[str, str] = field(default_factory=dict)


# Tables the SDK will accept in an allowlist. Anything not in this set
# is rejected at enable_dual_write() time so a typo can't silently
# send (or fail to send) what the customer expected.
ALLOWED_TABLES: frozenset[str] = frozenset({
    "agent_versions",
    "kya_invocations",
    "kya_evidence",
    "kya_principal_trust",
    "kya_user_trust",
    "kya_agent_aliases",
    "kya_weight_overrides",
    "kya_weight_changes",
    "kya_weight_suggestions",
    "kya_breach_notifications",
    "rogue_signal",
})


class DualWriteAllowlistError(ValueError):
    """Raised by enable_dual_write() when the allowlist names unknown tables."""


class DualWriteSink:
    """Background sink. One instance per active dual-write configuration."""

    def __init__(self, config: DualWriteConfig) -> None:
        self._cfg = config
        self._q: queue.Queue[tuple[str, dict]] = queue.Queue(maxsize=config.queue_max)
        self._stop = threading.Event()
        self._breaker_open_until = 0.0
        self._consecutive_failures = 0
        self._lock = threading.Lock()
        self._sent_batches = 0
        self._failed_batches = 0
        _ensure_counters()
        self._worker = threading.Thread(
            target=self._run, name="kya-dualwrite", daemon=True,
        )
        self._worker.start()
        atexit.register(self._atexit_drain)

    # ── Public hand-off from recorders ──────────────────────────────
    def emit(self, table: str, row: dict) -> None:
        """Non-blocking. Drops silently with a counter increment if the
        table is not allow-listed, the queue is full, or the breaker is open."""
        if table not in self._cfg.allowlist:
            _inc("dropped", reason="not_allowlisted")
            return
        if time.monotonic() < self._breaker_open_until:
            _inc("dropped", reason="breaker_open")
            return
        try:
            redacted = self._redact(row)
        except Exception:
            _inc("dropped", reason="redact_error")
            return
        try:
            self._q.put_nowait((table, redacted))
            _inc("emitted", table=table)
            _set_gauge("queue_depth", self._q.qsize())
        except queue.Full:
            _inc("dropped", reason="queue_full")

    def _redact(self, row: dict) -> dict:
        r = self._cfg.redactor or passthrough_redactor()
        return r.redact(row) if isinstance(row, dict) else {"value": row}

    # ── Worker loop ────────────────────────────────────────────────
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                batch = self._collect_batch()
                if batch:
                    self._send_with_retry(batch)
            except Exception as exc:
                logger.debug("[KYA-DUALWRITE] worker iteration suppressed: %s", exc)

    def _collect_batch(self) -> list[tuple[str, dict]]:
        deadline = time.monotonic() + self._cfg.flush_interval_s
        items: list[tuple[str, dict]] = []
        try:
            first = self._q.get(timeout=self._cfg.flush_interval_s)
            items.append(first)
        except queue.Empty:
            return items
        while len(items) < self._cfg.batch_max:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                items.append(self._q.get(timeout=min(remaining, 0.1)))
            except queue.Empty:
                break
        _set_gauge("queue_depth", self._q.qsize())
        return items

    def _send_with_retry(self, batch: list[tuple[str, dict]]) -> None:
        payload = {
            "v": 1,
            "rows": [{"table": t, "row": r} for t, r in batch],
        }
        body = json.dumps(payload, default=str)
        attempt = 0
        while attempt <= self._cfg.max_retries and not self._stop.is_set():
            try:
                outcome = self._do_post(body)
                if outcome == "ok":
                    _inc("sent", outcome="ok")
                    with self._lock:
                        self._consecutive_failures = 0
                        self._sent_batches += 1
                    return
                if outcome == "bad_request":
                    _inc("sent", outcome="bad_request")
                    with self._lock:
                        self._failed_batches += 1
                    return  # do not retry 4xx other than 429
            except Exception as exc:
                attempt += 1
                if attempt > self._cfg.max_retries:
                    _inc("sent", outcome="failed")
                    self._note_failure()
                    logger.warning(
                        "[KYA-DUALWRITE] batch of %d dropped after %d retries: %s",
                        len(batch), self._cfg.max_retries, exc,
                    )
                    return
                backoff = min(30.0, (2 ** attempt) + random.uniform(0, 0.5))
                if self._stop.wait(backoff):
                    return

    def _do_post(self, body: str) -> str:
        try:
            import requests  # type: ignore
        except ImportError as exc:
            raise RuntimeError("kya dualwrite needs `requests` — install kya[webhooks]") from exc
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._cfg.api_key}",
            "User-Agent": "veldt-kya-dualwrite/0.1",
            **self._cfg.extra_headers,
        }
        resp = requests.post(
            self._cfg.collector_url,
            data=body,
            headers=headers,
            timeout=self._cfg.request_timeout_s,
            verify=self._cfg.verify_tls,
        )
        if resp.status_code >= 500:
            raise RuntimeError(f"collector {resp.status_code}")
        if resp.status_code == 429:
            raise RuntimeError("collector rate-limited")
        if resp.status_code >= 400:
            logger.warning(
                "[KYA-DUALWRITE] non-retryable %d (first 200ch): %s",
                resp.status_code, (resp.text or "")[:200],
            )
            return "bad_request"
        return "ok"

    def _note_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            self._failed_batches += 1
            if self._consecutive_failures >= self._cfg.breaker_failure_threshold:
                self._breaker_open_until = time.monotonic() + self._cfg.breaker_cool_down_s
                self._consecutive_failures = 0
                logger.warning(
                    "[KYA-DUALWRITE] circuit breaker OPEN for %ss",
                    self._cfg.breaker_cool_down_s,
                )

    # ── Shutdown ───────────────────────────────────────────────────
    def shutdown(self, drain_timeout_s: float = 5.0) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        deadline = time.monotonic() + drain_timeout_s
        while not self._q.empty() and time.monotonic() < deadline:
            try:
                items: list[tuple[str, dict]] = []
                while len(items) < self._cfg.batch_max:
                    try:
                        items.append(self._q.get_nowait())
                    except queue.Empty:
                        break
                if items:
                    self._send_with_retry(items)
                else:
                    break
            except Exception:
                break
        # Join the worker so callers (and the next enable_dual_write())
        # don't accumulate a stale thread per cycle. Bounded wait so a
        # stuck worker can't block shutdown forever; daemon=True means
        # process exit will still kill it.
        try:
            if self._worker.is_alive() and threading.current_thread() is not self._worker:
                self._worker.join(timeout=max(0.1, deadline - time.monotonic() + 1.0))
        except Exception:
            pass

    def _atexit_drain(self) -> None:
        try:
            self.shutdown(drain_timeout_s=2.0)
        except Exception:
            pass

    # ── Introspection ──────────────────────────────────────────────
    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": True,
                "collector_url": self._cfg.collector_url,
                "allowlist": sorted(self._cfg.allowlist),
                "queue_depth": self._q.qsize(),
                "queue_max": self._cfg.queue_max,
                "breaker_open": time.monotonic() < self._breaker_open_until,
                "consecutive_failures": self._consecutive_failures,
                "sent_batches": self._sent_batches,
                "failed_batches": self._failed_batches,
            }


# ── Module-level API ───────────────────────────────────────────────
_ACTIVE: DualWriteSink | None = None
_ACTIVE_LOCK = threading.Lock()


def enable_dual_write(
    *,
    collector_url: str,
    api_key: str,
    allowlist: list[str],
    redact: bool = True,
    redactor: Redactor | None = None,
    **kwargs: Any,
) -> DualWriteSink:
    """Start forwarding KYA recorder events to a Veldt collector.

    Off by default. Customer must call this explicitly. The allowlist is
    *positive* — only the tables you list will flow. PII fields are
    sha256-hashed by default; override by passing `redact=False` or a
    custom `redactor=Redactor(...)`.

    Returns the active DualWriteSink instance.
    """
    global _ACTIVE
    if not collector_url or not api_key:
        raise ValueError("collector_url and api_key are required")
    bad = sorted(t for t in allowlist if t not in ALLOWED_TABLES)
    if bad:
        raise DualWriteAllowlistError(
            f"unknown tables in allowlist: {bad}. "
            f"Allowed: {sorted(ALLOWED_TABLES)}"
        )
    if redactor is None:
        redactor = Redactor() if redact else passthrough_redactor()

    with _ACTIVE_LOCK:
        if _ACTIVE is not None:
            _ACTIVE.shutdown()
        cfg = DualWriteConfig(
            collector_url=collector_url,
            api_key=api_key,
            allowlist=frozenset(allowlist),
            redactor=redactor,
            **kwargs,
        )
        _ACTIVE = DualWriteSink(cfg)
        _emit.set_emitter(_ACTIVE.emit)
    logger.info(
        "[KYA-DUALWRITE] enabled · collector=%s · tables=%s · redact=%s",
        collector_url, sorted(allowlist), redact,
    )
    return _ACTIVE


def disable_dual_write() -> None:
    """Stop forwarding events. Safe to call multiple times."""
    global _ACTIVE
    with _ACTIVE_LOCK:
        _emit.set_emitter(None)
        if _ACTIVE is not None:
            _ACTIVE.shutdown()
            _ACTIVE = None


def dual_write_status() -> dict:
    """For dashboards: current configuration + queue depth + breaker state."""
    with _ACTIVE_LOCK:
        if _ACTIVE is None:
            return {"enabled": False}
        return _ACTIVE.status()
