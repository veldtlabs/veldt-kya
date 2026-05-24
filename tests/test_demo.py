"""Smoke test for the quick-demo module.

The hero install line on the kya landing page promises
`pip install veldt-kya && python -m kya.demo`. This test guarantees:

  1. The module imports cleanly
  2. main() runs without raising and returns 0
  3. Each declared scenario actually scores (no fixture goes stale)
  4. Output mentions all three scenario names so the breakdown is real
"""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout


def test_demo_module_imports():
    from kya import demo
    assert hasattr(demo, "main")
    assert hasattr(demo, "SCENARIOS")
    assert len(demo.SCENARIOS) >= 3


def test_demo_main_runs_clean():
    """main() must complete with exit code 0 and produce sensible output."""
    from kya import demo
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = demo.main()
    assert rc == 0, f"demo.main returned non-zero: {rc}"
    out = buf.getvalue()
    # Each scenario name must appear in the output
    for name, _ in demo.SCENARIOS:
        assert name in out, f"scenario '{name}' missing from demo output:\n{out}"
    # Three sentinel substrings that confirm structured output
    assert "score=" in out
    assert "additive" in out
    assert "concentration" in out


def test_demo_runnable_as_module():
    """`python -m kya.demo` must succeed end-to-end in a subprocess
    so we catch any regression in the __main__ entry point."""
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "kya.demo"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"python -m kya.demo failed (rc={result.returncode}):\n"
        f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    )
    assert "score=" in result.stdout
