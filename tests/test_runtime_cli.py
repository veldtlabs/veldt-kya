"""Tests for the MVP ``kya-runtime-collect`` CLI + its collector loop.

Layers:
1. Unit -- the collector loop (drives ``run_collector`` directly).
2. Integration -- the CLI entrypoint via subprocess + file tailing.

Why two layers: the loop is the value, but a customer's first
interaction is the CLI invocation -- a regression in argparse wiring
that hid the loop entirely would slip past unit-only tests.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from kya.runtime import (
    ExplicitBindingCache,
    bind_container,
    reset_principal_resolver_to_default,
)
from kya.runtime._collector import (
    iter_stdin,
    iter_tail,
    parsers_summary,
    run_collector,
)


@pytest.fixture(autouse=True)
def _reset_state():
    ExplicitBindingCache.clear()
    reset_principal_resolver_to_default()
    yield
    ExplicitBindingCache.clear()
    reset_principal_resolver_to_default()


def _falco_line(rule: str = "Test rule", cid: str = "abc123") -> str:
    return json.dumps({
        "time": "2026-05-30T00:00:00.000Z",
        "rule": rule,
        "priority": "Warning",
        "output": "x",
        "tags": [],
        "hostname": "h",
        "source": "syscall",
        "output_fields": {
            "container.id": cid,
            "container.name": "agent_x",
            "proc.cmdline": "sh",
            "proc.name": "sh",
            "user.name": "root",
        },
    })


# ══════════════════════════════════════════════════════════════
# Layer 1: collector loop unit tests
# ══════════════════════════════════════════════════════════════


def test_run_collector_counts_clean_falco_events_as_ingested():
    lines = [_falco_line() for _ in range(5)]
    stats = run_collector(lines, source_tool="falco")
    assert stats.lines_read == 5
    assert stats.ingested == 5
    assert stats.parser_rejected == 0
    assert stats.unexpected_errors == 0


def test_run_collector_blank_and_malformed_lines_are_tolerated():
    lines = [
        "",
        "  ",
        "{this is not json}",
        _falco_line(),
        "",
        _falco_line(),
    ]
    stats = run_collector(lines, source_tool="falco")
    assert stats.lines_read == 6
    # `""`, `"  "` (whitespace-only), and `""` all count as blank
    assert stats.blank_lines == 3
    assert stats.json_decode_errors == 1
    assert stats.ingested == 2


def test_run_collector_rejects_unknown_shape_with_clean_error():
    """When autodetect fails, the result is accepted=False, NOT an
    exception. parser_rejected increments."""
    lines = [json.dumps({"alien": True}), _falco_line()]
    stats = run_collector(lines)  # no source_tool -> autodetect
    assert stats.parser_rejected == 1
    assert stats.ingested == 1


def test_run_collector_hits_max_errors_and_raises():
    lines = ["{bad json}", "{bad json}", "{bad json}"]
    with pytest.raises(RuntimeError, match="max-errors exceeded"):
        run_collector(lines, max_errors=1)


def test_run_collector_explicit_bind_classified_as_explicit():
    bind_container("explicitcid", "tenant_x", "principal_x")
    lines = [_falco_line(cid="explicitcid")]
    stats = run_collector(lines, source_tool="falco")
    assert stats.bound_explicit == 1
    assert stats.unbound == 0


def test_run_collector_invokes_on_event_callback_with_result_and_stats():
    seen: list = []

    def cb(result, stats):
        seen.append((result.principal_binding_method, stats.ingested))

    run_collector(
        [_falco_line()],
        source_tool="falco",
        on_event=cb,
    )
    assert len(seen) == 1
    assert seen[0][1] == 1


def test_run_collector_callback_exception_does_not_stop_loop():
    def cb(_r, _s):
        raise RuntimeError("oops")

    stats = run_collector(
        [_falco_line(), _falco_line()],
        source_tool="falco",
        on_event=cb,
    )
    assert stats.ingested == 2


# ══════════════════════════════════════════════════════════════
# Layer 2: line sources
# ══════════════════════════════════════════════════════════════


def test_iter_stdin_yields_each_line_until_eof():
    src = io.StringIO("a\nb\nc\n")
    out = list(iter_stdin(src))
    assert out == ["a\n", "b\n", "c\n"]


def test_iter_tail_yields_lines_added_after_open(tmp_path: Path):
    """Tail mode: open a file, then append lines from another thread,
    then verify the iterator yields them. Stops via stop_event."""
    p = tmp_path / "live.ndjson"
    p.write_text("", encoding="utf-8")

    stop = threading.Event()
    seen: list[str] = []

    def consumer():
        for line in iter_tail(
                str(p), poll_interval=0.05, stop_event=stop):
            seen.append(line)
            if len(seen) >= 3:
                stop.set()
                break

    t = threading.Thread(target=consumer, daemon=True)
    t.start()
    time.sleep(0.2)  # let consumer reach the EOF wait

    with p.open("a", encoding="utf-8") as f:
        f.write("one\ntwo\nthree\n")
        f.flush()

    t.join(timeout=3.0)
    assert seen == ["one", "two", "three"]


def test_iter_tail_from_start_replays_existing_content(tmp_path: Path):
    p = tmp_path / "captured.ndjson"
    p.write_text("a\nb\nc\n", encoding="utf-8")

    stop = threading.Event()
    seen: list[str] = []

    def consumer():
        for line in iter_tail(
                str(p), poll_interval=0.05,
                from_start=True, stop_event=stop):
            seen.append(line)
            if len(seen) >= 3:
                stop.set()
                break

    t = threading.Thread(target=consumer, daemon=True)
    t.start()
    t.join(timeout=3.0)
    assert seen == ["a", "b", "c"]


# ══════════════════════════════════════════════════════════════
# Layer 2: parsers_summary helper
# ══════════════════════════════════════════════════════════════


def test_parsers_summary_lists_the_open_falco_parser():
    out = parsers_summary()
    assert "falco" in out


# ══════════════════════════════════════════════════════════════
# Layer 3: CLI entrypoint via subprocess
# ══════════════════════════════════════════════════════════════


def _cli_cmd() -> list[str]:
    """Run the CLI as `python -m kya.runtime.cli` so we don't depend
    on `kya-runtime-collect` being on PATH (it isn't until pip
    install -e is re-run after the pyproject change). The behavior
    is identical -- argparse + main()."""
    return [sys.executable, "-m", "kya.runtime.cli"]


def test_cli_list_parsers_prints_falco_and_exits_zero():
    r = subprocess.run(
        _cli_cmd() + ["--list-parsers"],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0
    assert "falco" in r.stdout


def test_cli_stdin_mode_ingests_falco_lines_and_reports_stats():
    payload = "\n".join([_falco_line() for _ in range(3)]) + "\n"
    r = subprocess.run(
        _cli_cmd() + ["--tool", "falco", "--quiet"],
        input=payload, capture_output=True, text=True, timeout=15,
    )
    # No assertion on stderr -- --quiet suppresses INFO. Returncode 0
    # means no max-errors hit.
    assert r.returncode == 0


def test_cli_max_errors_hard_fails_with_exit_code_2(tmp_path: Path):
    """Five lines of garbage with --max-errors=2 -> exit 2 because
    we exceed the budget. Exit 2 is the CLI's hard-fail signal."""
    bad = "\n".join("{bad json}" for _ in range(5)) + "\n"
    r = subprocess.run(
        _cli_cmd() + ["--max-errors", "2", "--quiet"],
        input=bad, capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 2


def test_cli_help_includes_documented_flags():
    r = subprocess.run(
        _cli_cmd() + ["--help"],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0
    for flag in (
        "--tail", "--tool", "--invocation-id",
        "--max-errors", "--list-parsers", "--from-start",
    ):
        assert flag in r.stdout, flag
