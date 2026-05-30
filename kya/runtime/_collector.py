"""Runtime-event collector loop.

The reusable core that the CLI (``kya.runtime.cli``) wraps. Separated
from the CLI so tests can drive it directly without subprocess, and
so embedders (custom collectors, sidecar binaries, FastAPI webhook
receivers) can reuse the same logic.

Design notes
------------
* **No third-party deps.** stdlib only -- argparse, json, signal,
  threading, logging. The MVP must run on a fresh Python 3.10+
  install with just ``veldt-kya`` installed.
* **Fail-soft.** A malformed line, a parser exception, a DB hiccup --
  none of these stop the collector. Errors increment counters and
  are logged; the loop continues. The caller chooses an
  ``--max-errors`` cap for hard fail.
* **No invocation-id synthesis.** The open package requires the
  caller to pass ``invocation_id`` (or accept ``--no-evidence-chain``
  which skips ledger attach). The premium collector adds
  per-container anchor synthesis tied to the lifecycle of the
  watched containers; doing it here would risk FK violations.
* **Cooperative shutdown.** SIGINT/SIGTERM flip a flag; the loop
  drains in-flight lines, logs a summary, and exits cleanly.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, TextIO

from ._registry import list_parsers
from . import ingest as runtime_ingest

logger = logging.getLogger(__name__)


# ── Stats ─────────────────────────────────────────────────────────


@dataclass
class CollectorStats:
    """Counters reported on exit and pollable while running."""

    started_at: float = field(default_factory=time.time)
    lines_read: int = 0
    blank_lines: int = 0
    json_decode_errors: int = 0
    parser_rejected: int = 0          # ingest returned accepted=False
    ingested: int = 0                 # accepted=True
    bound_explicit: int = 0
    bound_via_resolver: int = 0
    unbound: int = 0
    evidence_attached: int = 0        # evidence_id was not None
    attack_chain_matches: int = 0     # cumulative count of rule fires
    unexpected_errors: int = 0        # raised exceptions in the loop
    last_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "uptime_seconds": round(time.time() - self.started_at, 2),
            "lines_read": self.lines_read,
            "blank_lines": self.blank_lines,
            "json_decode_errors": self.json_decode_errors,
            "parser_rejected": self.parser_rejected,
            "ingested": self.ingested,
            "bound_explicit": self.bound_explicit,
            "bound_via_resolver": self.bound_via_resolver,
            "unbound": self.unbound,
            "evidence_attached": self.evidence_attached,
            "attack_chain_matches": self.attack_chain_matches,
            "unexpected_errors": self.unexpected_errors,
            "last_error": self.last_error,
        }


# ── Line sources ──────────────────────────────────────────────────


def iter_stdin(stream: TextIO | None = None) -> Iterable[str]:
    """Yield lines from a text stream (default stdin) until EOF."""
    src = stream if stream is not None else sys.stdin
    for line in src:
        yield line


def iter_tail(
    path: str,
    *,
    poll_interval: float = 0.5,
    from_start: bool = False,
    stop_event: threading.Event | None = None,
) -> Iterable[str]:
    """Tail a file forever, yielding new lines as they appear.

    Polling rather than ``inotify`` to keep the dep surface at zero.
    Handles truncation (logs reopen + reads from new beginning) and
    rotation (file replaced by something with a different inode --
    we re-stat each iteration). Stops only when ``stop_event`` is set.

    Args:
        from_start: when False (default), seek to EOF before yielding
            so the collector doesn't reprocess old events on startup.
            When True, read the file from the beginning -- useful for
            replaying a captured fixture.
    """
    if stop_event is None:
        stop_event = threading.Event()

    f = open(path, "r", encoding="utf-8", errors="replace")
    try:
        inode = os.fstat(f.fileno()).st_ino
        if not from_start:
            f.seek(0, os.SEEK_END)
        leftover = ""
        while not stop_event.is_set():
            chunk = f.read()
            if chunk:
                buf = leftover + chunk
                lines = buf.split("\n")
                leftover = lines.pop()  # may be a partial trailing line
                for line in lines:
                    yield line
                continue

            # No new data -- check for rotation/truncation, then sleep.
            try:
                st = os.stat(path)
            except FileNotFoundError:
                logger.warning("[KYA-RUNTIME-CLI] file gone: %s", path)
                time.sleep(poll_interval)
                continue

            if st.st_ino != inode:
                logger.info(
                    "[KYA-RUNTIME-CLI] file rotated; reopening %s", path,
                )
                f.close()
                f = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
                leftover = ""
                continue

            try:
                cur_pos = f.tell()
            except OSError:
                cur_pos = 0
            if st.st_size < cur_pos:
                logger.info(
                    "[KYA-RUNTIME-CLI] file truncated; "
                    "resetting position on %s", path,
                )
                f.seek(0)
                leftover = ""
                continue

            stop_event.wait(poll_interval)
    finally:
        f.close()


# ── Core loop ─────────────────────────────────────────────────────


def run_collector(
    lines: Iterable[str],
    *,
    source_tool: str | None = None,
    db: Any | None = None,
    invocation_id: int | None = None,
    correlation_id: str | None = None,
    max_errors: int | None = None,
    stats: CollectorStats | None = None,
    on_event: Callable[[Any, CollectorStats], None] | None = None,
) -> CollectorStats:
    """Run the collector loop over an iterable of JSON-line strings.

    Args:
        lines: any iterable of strings, one JSON document per string.
            Typically from ``iter_stdin()`` or ``iter_tail(path)``.
        source_tool: force a specific parser. When None, the bridge
            autodetects per event (slower but tool-mixed pipelines
            work).
        db: SQLAlchemy session for evidence-chain attach. Optional --
            without it, no ledger row is written but attack-chain
            dispatch still runs.
        invocation_id: anchor invocation id (per the bridge contract).
            Without it the evidence-chain attach is skipped and
            ``evidence_attached`` stays 0.
        correlation_id: forwarded to ``ingest`` for cross-agent rules.
        max_errors: hard-fail (raise RuntimeError) when total errors
            (json_decode + parser_rejected + unexpected) exceeds this.
            When None, no cap.
        stats: optional shared counters object; useful for tests +
            for embedders that want to expose them via /metrics.
        on_event: callback invoked after every accepted event with
            the ingest result + current stats. Useful for embedders
            wiring streaming metrics.

    Returns:
        The final ``CollectorStats``.
    """
    if stats is None:
        stats = CollectorStats()

    for raw_line in lines:
        stats.lines_read += 1
        line = raw_line.strip()
        if not line:
            stats.blank_lines += 1
            continue

        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            stats.json_decode_errors += 1
            stats.last_error = f"json: {exc}"
            logger.debug("[KYA-RUNTIME-CLI] bad json: %s", exc)
            _check_max_errors(stats, max_errors)
            continue

        try:
            result = runtime_ingest(
                raw,
                source_tool=source_tool,  # type: ignore[arg-type]
                db=db,
                invocation_id=invocation_id,
                correlation_id=correlation_id,
            )
        except Exception as exc:  # noqa: BLE001
            stats.unexpected_errors += 1
            stats.last_error = f"ingest exc: {exc!r}"
            logger.exception("[KYA-RUNTIME-CLI] ingest raised")
            _check_max_errors(stats, max_errors)
            continue

        if not result.accepted:
            stats.parser_rejected += 1
            stats.last_error = result.error
            _check_max_errors(stats, max_errors)
            continue

        stats.ingested += 1
        method = result.principal_binding_method
        if method == "explicit" or method == "explicit_cache":
            stats.bound_explicit += 1
        elif method == "unbound":
            stats.unbound += 1
        else:
            stats.bound_via_resolver += 1
        if result.evidence_id is not None:
            stats.evidence_attached += 1
        if result.attack_chain_matches:
            stats.attack_chain_matches += len(result.attack_chain_matches)

        if on_event is not None:
            try:
                on_event(result, stats)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "[KYA-RUNTIME-CLI] on_event callback raised "
                    "(continuing loop)")

    return stats


def _check_max_errors(stats: CollectorStats, max_errors: int | None) -> None:
    if max_errors is None:
        return
    total_errors = (
        stats.json_decode_errors
        + stats.parser_rejected
        + stats.unexpected_errors
    )
    if total_errors > max_errors:
        raise RuntimeError(
            f"--max-errors exceeded ({total_errors} > {max_errors}); "
            f"last_error={stats.last_error!r}"
        )


# ── Shutdown handling ────────────────────────────────────────────


def install_shutdown_handler(stop_event: threading.Event) -> None:
    """Wire SIGINT / SIGTERM to flip ``stop_event`` so the tail loop
    exits cleanly. The CLI calls this once at startup."""
    def _handler(signum, _frame):
        logger.info(
            "[KYA-RUNTIME-CLI] received signal %s; draining and "
            "exiting", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            # ValueError when not in main thread; OSError on Windows
            # for SIGTERM. Both are acceptable -- the embedder may
            # have its own signal handling.
            pass


# ── Listing helper used by ``--list-parsers`` ────────────────────


def parsers_summary() -> str:
    """Human-readable list of registered parsers for ``--list-parsers``."""
    names = sorted(list_parsers())
    if not names:
        return "(no parsers registered)"
    return "\n".join(f"  {n}" for n in names)
