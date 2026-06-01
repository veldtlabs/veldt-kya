"""Smoke test for ``scripts/mavlink_stability_long_run.py``.

The 1-hour stability workflow is OFF by default (manual-trigger
only). But the script should still parse, import its deps, and
run a tiny 3-second profile end-to-end -- otherwise the workflow
is a paper tiger that would fail the moment someone clicks "Run
workflow."

This test runs a 3-second / 10 Hz / 100-MB-cap profile via
subprocess so the script's CLI surface (env var parsing,
output JSON shape, exit code) is genuinely exercised.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


_SCRIPT = Path(__file__).parent.parent / "scripts" / "mavlink_stability_long_run.py"


def test_script_runs_end_to_end():
    """Run the stability script for 3 seconds. Verify it produces
    a profile JSON with the expected shape + passes the (very
    generous) growth caps."""
    if not _SCRIPT.exists():
        pytest.skip(f"script not present at {_SCRIPT}")
    try:
        import psutil  # noqa: F401
    except ImportError:
        pytest.skip("psutil not installed -- stability script needs it")

    out = Path(tempfile.NamedTemporaryFile(
        suffix=".stability.json", delete=False).name)
    env = {
        **os.environ,
        "DURATION_SECONDS": "3",
        "RATE_HZ": "10",
        "SAMPLE_EVERY_FRAMES": "5",  # plenty of samples in 3s
        "MEMORY_GROWTH_MB_CAP": "500",  # very generous; we want
                                         # to verify SHAPE not perf
        "FD_GROWTH_CAP": "50",
        "STABILITY_PROFILE_OUT": str(out),
    }
    result = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"stability script exited {result.returncode}\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )

    profile = json.loads(out.read_text())
    assert profile["duration_seconds"] == 3
    assert profile["rate_hz"] == 10
    assert profile["frames_processed"] > 0
    # At least baseline + final samples
    assert len(profile["samples"]) >= 2
    # Every sample carries the expected keys
    for s in profile["samples"]:
        assert "frame_count" in s
        assert "rss_mb" in s
        assert "fds" in s
    # Verdict block well-formed
    v = profile["verdict"]
    assert "rss_growth_mb" in v
    assert "fd_growth" in v
    assert v["passed"] is True
