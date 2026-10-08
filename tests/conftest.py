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
    extra = _backend_report()
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
    return [f"kya under test: {label} (veldt-kya {ver}, .../{tail})"] + extra


def pytest_configure(config) -> None:
    _install_connect_timeout()
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

# ── No test may block on an unreachable database ─────────────────────
#
# Over twenty call sites in this suite do create_engine(<network url>)
# with no connect timeout. SQLAlchemy's default is the driver's, which
# for psycopg is "wait forever", so a stale port in a local .env turns
# the whole run into a hang: pytest-timeout's thread method then kills
# the process, and a destroyed signal is not a pass.
#
# Patching create_engine once covers every existing call site and every
# future one, which per-site edits would not. It runs in
# pytest_configure because test modules do `from sqlalchemy import
# create_engine` at collection time, which is after this and so binds
# the wrapped version.

_CONNECT_TIMEOUT_S = 5

# psycopg, psycopg2 and pymysql all spell it connect_timeout. sqlite and
# duckdb are local files and take no such argument.
_NETWORK_PREFIXES = ("postgresql", "postgres", "mysql", "mariadb")


def _install_connect_timeout() -> None:
    import sqlalchemy

    real = getattr(sqlalchemy, "_kya_real_create_engine", None)
    if real is not None:
        return                      # already wrapped this session
    real = sqlalchemy.create_engine
    sqlalchemy._kya_real_create_engine = real

    def create_engine(url, *args, **kwargs):
        try:
            text = str(getattr(url, "render_as_string", lambda **_: url)(
                hide_password=False)) if not isinstance(url, str) else url
        except Exception:
            text = str(url)
        if text.split(":", 1)[0].split("+", 1)[0] in _NETWORK_PREFIXES:
            ca = dict(kwargs.get("connect_args") or {})
            ca.setdefault("connect_timeout", _CONNECT_TIMEOUT_S)
            kwargs["connect_args"] = ca
        return real(url, *args, **kwargs)

    sqlalchemy.create_engine = create_engine


def _backend_report() -> list[str]:
    """One line per optional backend, reachable or not.

    A test that silently skips and a test that silently hangs look the
    same in a summary line. Say which backends this run can actually
    reach before any of them is used.
    """
    import sqlalchemy
    lines = []
    for env in ("KYA_TEST_PG_URL", "KYA_TEST_MYSQL_URL"):
        url = os.environ.get(env, "").strip()
        if not url:
            lines.append(f"{env}: unset (that backend is skipped)")
            continue
        try:
            eng = sqlalchemy.create_engine(url)
            with eng.connect():
                pass
            lines.append(f"{env}: reachable")
        except Exception as exc:
            lines.append(
                f"{env}: UNREACHABLE ({type(exc).__name__}) — tests using "
                f"it will fail fast, not hang")
    url = os.environ.get("KYA_VALKEY_URL", "").strip()
    lines.append(
        f"KYA_VALKEY_URL: {'set' if url else 'unset (replay tests skip)'}")
    return lines
