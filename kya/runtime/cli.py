"""``kya-runtime-collect`` -- the open-source MVP runtime collector CLI.

What it does
------------
Reads JSON-per-line runtime-security events (from stdin OR a tailed
file), runs each one through ``kya.runtime.ingest(...)`` -- which
applies the auto-resolver chain, attaches to the HMAC evidence
ledger when an invocation_id anchor is provided, and dispatches to
attack-chain rules. Counters reported on exit.

Customers can swap their hand-written ~30-line collector for this
out of the box:

.. code-block:: bash

   # Stdin (Falco / Tetragon stdout):
   falco -o json_output=true | kya-runtime-collect --tool falco

   # File tail (auditbeat / fluent-bit file output):
   kya-runtime-collect --tail /var/log/falco/events.ndjson --tool falco

   # Auto-detect parser (mixed-tool pipelines):
   kya-runtime-collect --tail /var/log/runtime.ndjson

What this MVP does NOT do
-------------------------
* Persistent cursor / resume-from-position after restart
* Kafka / webhook / unix-socket transports
* Auto-create invocation_id anchors per container (FK risk)
* Health endpoint or Prometheus metrics
* Backpressure / rate limiting

Those are the differentiators that ship in ``veldt-kya-pro``'s
production collector.
"""
from __future__ import annotations

import argparse
import logging
import sys
import threading
from typing import Any

from . import __all__ as _runtime_all  # noqa: F401 -- triggers parser register
from ._collector import (
    CollectorStats,
    install_shutdown_handler,
    iter_stdin,
    iter_tail,
    parsers_summary,
    run_collector,
)

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kya-runtime-collect",
        description=(
            "KYA runtime-event collector. Reads JSON-per-line "
            "runtime-security events (Falco / Tetragon / auditbeat / "
            "etc.) and ingests them into the KYA evidence ledger + "
            "attack-chain engine. See `--help` and "
            "https://github.com/veldtlabs/veldt-kya."
        ),
    )

    # Source selection
    src = p.add_mutually_exclusive_group()
    src.add_argument(
        "--tail",
        metavar="PATH",
        help="Tail a JSON-per-line file (rotation + truncation safe).",
    )
    # default: stdin

    p.add_argument(
        "--tool",
        metavar="TOOL",
        default=None,
        help=(
            "Force a specific parser (falco / tetragon / auditd / ...). "
            "When omitted, the bridge autodetects per event. Use "
            "`--list-parsers` to see what is registered."
        ),
    )
    p.add_argument(
        "--list-parsers",
        action="store_true",
        help="Print registered parsers and exit.",
    )

    # Evidence chain anchor
    p.add_argument(
        "--invocation-id",
        type=int,
        metavar="N",
        help=(
            "Anchor invocation_id for HMAC evidence-chain attach. "
            "When omitted, attack-chain dispatch still runs but no "
            "signed ledger row is written. See "
            "kya.runtime.record_runtime_event for the rationale."
        ),
    )
    p.add_argument(
        "--correlation-id",
        metavar="ID",
        help="Cross-agent correlation id forwarded to ingest().",
    )

    # Fail-soft control
    p.add_argument(
        "--max-errors",
        type=int,
        metavar="N",
        default=None,
        help=(
            "Hard-fail when total errors "
            "(json_decode + parser_rejected + unexpected) exceeds N. "
            "Default: no cap (run forever)."
        ),
    )

    p.add_argument(
        "--from-start",
        action="store_true",
        help=(
            "For --tail mode: read the file from the beginning rather "
            "than seeking to EOF. Useful for replaying captured fixtures."
        ),
    )
    p.add_argument(
        "--stats-every",
        type=int,
        metavar="N",
        default=0,
        help=(
            "Print collector stats every N events (0 = only on exit)."
        ),
    )

    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose logging (DEBUG level).",
    )
    p.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet -- only WARNING+ to stderr.",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.quiet:
        level = logging.WARNING
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    if args.list_parsers:
        print("Registered runtime parsers:")
        print(parsers_summary())
        return 0

    stats = CollectorStats()
    stop_event = threading.Event()
    install_shutdown_handler(stop_event)

    # Pick line source
    if args.tail:
        lines = iter_tail(
            args.tail,
            from_start=args.from_start,
            stop_event=stop_event,
        )
        logger.info("[KYA-RUNTIME-CLI] tailing %s", args.tail)
    else:
        lines = iter_stdin()
        logger.info("[KYA-RUNTIME-CLI] reading stdin")

    # Stats-on-progress wrapper
    on_event = None
    if args.stats_every > 0:
        def on_event(_result: Any, s: CollectorStats) -> None:  # noqa: F811
            if s.ingested % args.stats_every == 0:
                logger.info("[KYA-RUNTIME-CLI] stats: %s", s.as_dict())

    try:
        run_collector(
            lines,
            source_tool=args.tool,
            invocation_id=args.invocation_id,
            correlation_id=args.correlation_id,
            max_errors=args.max_errors,
            stats=stats,
            on_event=on_event,
        )
    except RuntimeError as exc:
        logger.error("[KYA-RUNTIME-CLI] hard-fail: %s", exc)
        logger.error("[KYA-RUNTIME-CLI] final stats: %s", stats.as_dict())
        return 2
    except KeyboardInterrupt:
        logger.info("[KYA-RUNTIME-CLI] keyboard interrupt")
    finally:
        logger.info("[KYA-RUNTIME-CLI] final stats: %s", stats.as_dict())

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
