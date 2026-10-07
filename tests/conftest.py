"""Make the package under test unmissable.

``kya`` can resolve either to this working copy or to whatever is
installed in site-packages, and which one wins depends on the working
directory the run started from. A suite that does not say which copy it
loaded cannot support a claim about either.

So this prints the copy under test on every run, and fails the run when
it is not the copy the run was meant to exercise:

* inside a git working tree the expectation is the working copy, because
  that is what a developer running the suite is asking about;
* outside one -- a wheel installed into a clean venv, which is what CI
  does -- site-packages is correct and expected.

``KYA_TEST_EXPECT=working_copy|site_packages`` overrides the inference.
"""
from __future__ import annotations

import os
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _origin() -> tuple[str, str]:
    """Return (label, path) for the kya package actually imported."""
    import kya
    path = (getattr(kya, "__file__", "") or "").replace("\\", "/")
    label = "site_packages" if "site-packages" in path else "working_copy"
    return label, path


def _expected() -> str:
    explicit = os.environ.get("KYA_TEST_EXPECT", "").strip().lower()
    if explicit:
        return explicit
    # A .git directory means someone is testing a checkout, not a release.
    return "working_copy" if (_ROOT / ".git").exists() else "site_packages"


def pytest_report_header(config) -> list[str]:
    try:
        label, path = _origin()
    except Exception as exc:  # pragma: no cover - import failure is fatal below
        return [f"kya under test: UNIMPORTABLE ({exc})"]
    from importlib.metadata import version
    try:
        ver = version("veldt-kya")
    except Exception:
        ver = "unknown"
    # The absolute path is machine-specific, so report the label and the
    # tail only -- enough to tell the two apart without publishing a
    # directory layout.
    tail = "/".join(path.split("/")[-3:])
    return [f"kya under test: {label} (veldt-kya {ver}, .../{tail})"]


def pytest_configure(config) -> None:
    try:
        label, path = _origin()
    except Exception as exc:
        pytest.exit(f"kya is not importable: {exc}", returncode=4)
        return
    want = _expected()
    if label != want:
        pytest.exit(
            "refusing to run: this suite would test the wrong copy of kya.\n"
            f"  expected: {want}\n"
            f"  imported: {label} ({path})\n"
            "A pass here would say nothing about the code you changed. "
            "Run from the repository root, install it with "
            "'pip install -e . --no-deps', or set KYA_TEST_EXPECT to "
            "declare which copy you mean to exercise.",
            returncode=4,
        )
