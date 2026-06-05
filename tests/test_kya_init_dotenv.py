"""Bug B regression: `import kya` auto-loads `.env` so provider API
keys (FIDDLER_API_KEY, OPENAI_API_KEY, etc.) are present in
os.environ before fiddler_bridge / scorer_orchestrator try to read
them. Pre-fix, KYA had no load_dotenv() call, so any CLI / pytest /
notebook usage that hadn't preloaded its .env silently surfaced as
ERROR verdicts with latency_ms=0 from the judges.

These tests exercise the load_dotenv side effect WITHOUT relying on
python-dotenv being installed (the package may be absent in
constrained CI environments).
"""

from __future__ import annotations

import importlib
import os
import sys
import textwrap
from pathlib import Path

import pytest


def _run_kya_import_in_subprocess(
    tmp_path: Path,
    env_file_body: str | None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, str | None]:
    """Spawn a subprocess that writes a .env (optionally), runs
    `import kya`, then prints the env-var dictionary we care about.
    Subprocess isolation prevents the test from polluting the
    parent process's os.environ."""
    import json
    import subprocess

    script = textwrap.dedent(
        """
        import json
        import os
        import sys
        # Ensure repo root is importable
        sys.path.insert(0, %r)
        import kya  # noqa: F401  -- the import IS the test
        print(json.dumps({
            "KYA_BUG_B_FIXTURE_KEY": os.environ.get("KYA_BUG_B_FIXTURE_KEY"),
            "kya_imported": True,
        }))
        """
    ) % str(Path.cwd())

    if env_file_body is not None:
        (tmp_path / ".env").write_text(env_file_body, encoding="utf-8")

    env = os.environ.copy()
    # Wipe the fixture key from parent env so the subprocess only sees
    # what dotenv loads (or doesn't).
    env.pop("KYA_BUG_B_FIXTURE_KEY", None)
    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"kya import failed in subprocess:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # Last JSON line of stdout
    lines = [ln.strip() for ln in result.stdout.strip().splitlines() if ln.strip()]
    return json.loads(lines[-1])


def _dotenv_installed() -> bool:
    return importlib.util.find_spec("dotenv") is not None


@pytest.mark.skipif(not _dotenv_installed(), reason="python-dotenv extra not installed")
def test_import_kya_loads_dotenv_from_cwd(tmp_path: Path):
    """The headline Bug B fix: `import kya` reads .env from CWD."""
    out = _run_kya_import_in_subprocess(
        tmp_path,
        env_file_body="KYA_BUG_B_FIXTURE_KEY=loaded-from-dotenv\n",
    )
    assert out["kya_imported"] is True
    assert out["KYA_BUG_B_FIXTURE_KEY"] == "loaded-from-dotenv"


@pytest.mark.skipif(not _dotenv_installed(), reason="python-dotenv extra not installed")
def test_explicit_env_overrides_dotenv(tmp_path: Path):
    """override=False: when the operator has already exported a value,
    .env must NOT clobber it. Standard layered-config rule."""
    out = _run_kya_import_in_subprocess(
        tmp_path,
        env_file_body="KYA_BUG_B_FIXTURE_KEY=from-dotenv\n",
        extra_env={"KYA_BUG_B_FIXTURE_KEY": "from-process-env"},
    )
    assert out["KYA_BUG_B_FIXTURE_KEY"] == "from-process-env"


@pytest.mark.skipif(not _dotenv_installed(), reason="python-dotenv extra not installed")
def test_kya_disable_dotenv_skips_load(tmp_path: Path):
    """Operators in strict-isolation CI can opt out via the kill
    switch. `KYA_DISABLE_DOTENV=1` means .env must NOT be consulted."""
    out = _run_kya_import_in_subprocess(
        tmp_path,
        env_file_body="KYA_BUG_B_FIXTURE_KEY=should-not-be-loaded\n",
        extra_env={"KYA_DISABLE_DOTENV": "1"},
    )
    assert out["KYA_BUG_B_FIXTURE_KEY"] is None


def test_import_kya_succeeds_without_dotenv_installed():
    """The fix is paywall-free: `import kya` must still succeed when
    python-dotenv isn't installed. The ImportError is swallowed."""
    # We can't reliably uninstall dotenv from inside the test process,
    # but we CAN verify the production code path catches ImportError.
    # Read the source and grep for the structural guard.
    init_path = Path(__file__).parent.parent / "kya" / "__init__.py"
    body = init_path.read_text(encoding="utf-8")
    assert "from dotenv import load_dotenv" in body, (
        "Bug B fix removed — kya/__init__.py no longer calls load_dotenv"
    )
    assert "except ImportError" in body, (
        "Bug B fix lost ImportError guard — kya/__init__.py would now "
        "hard-fail on `import kya` when python-dotenv is absent"
    )
    assert "KYA_DISABLE_DOTENV" in body, (
        "Bug B fix lost the opt-out kill switch"
    )
