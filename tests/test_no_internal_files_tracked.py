"""No local-tooling or internal artifact may be tracked in this repo.

This repository is public. Editor/agent state files, environment files
and internal documents must never be committed.

``.gitignore`` is not sufficient on its own: it only affects UNTRACKED
files, so anything already added stays tracked, and ``git add -f``
bypasses it entirely. This test inspects what git actually tracks, so a
mistake fails in CI rather than reaching a release.

Adding a genuinely public file that trips a pattern? Add it to
``ALLOWED`` with a reason. Do not loosen the pattern.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: (glob, why it must never be tracked)
FORBIDDEN = [
    (".claude/**", "local agent/editor state"),
    (".claude", "local agent/editor state"),
    ("**/.env", "environment file; may carry secrets"),
    (".env.*", "environment file; may carry secrets"),
    ("RELEASE_STEPS*", "internal release runbook"),
    ("TASK_*_HANDOFF.md", "internal handoff notes"),
    ("private/**", "private material"),
    ("internal/**", "internal material"),
    ("_internal/**", "internal material"),
    ("_private/**", "private material"),
    ("KYA_*.pptx", "private document"),
    ("KYA_*.docx", "private document"),
    ("STRATEGY_*", "private material"),
    ("FOUNDER_*", "private material"),
    ("FUNDING_*", "private material"),
    ("OPPORTUNITIES_*", "private material"),
    ("RESEARCH_*", "private material"),
    ("alice_*.py", "private demo"),
]

#: Tracked paths that match a pattern above but are legitimately public.
#: Each needs a reason. Empty is the correct steady state -- an entry
#: here is an exception to a rule that exists for a reason, so it should
#: be justified in review rather than added to make a run go green.
ALLOWED: dict[str, str] = {}


def _tracked_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO, capture_output=True, text=True, timeout=60, check=True,
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
        pytest.skip(f"git unavailable: {exc}")
    return [p for p in out.split("\0") if p]


def test_no_internal_artifacts_are_tracked() -> None:
    """Inspects what git TRACKS, not what is ignored."""
    tracked = _tracked_files()
    assert tracked, "git ls-files returned nothing — refusing to pass vacuously"

    offenders = []
    for path in tracked:
        if path in ALLOWED:
            continue
        p = pathlib.PurePosixPath(path)
        for pattern, why in FORBIDDEN:
            if p.match(pattern) or path.startswith(pattern.replace("**", "")):
                offenders.append(f"{path}  <- {pattern} ({why})")
                break

    assert not offenders, (
        "internal/local artifact(s) are TRACKED in this public repo:\n  "
        + "\n  ".join(sorted(offenders))
        + "\n\n.gitignore does NOT fix this — it only affects untracked "
        "files. Run:\n"
        "    git rm --cached <path>\n"
        "and move the file out of the repository. If the file is genuinely "
        "public, add it to ALLOWED with a reason rather than loosening the "
        "pattern."
    )


def test_gitignore_covers_local_agent_state() -> None:
    """Defence in depth: keep the ignore rule present too.

    The test above catches a file that is already tracked. This keeps it
    from being offered by ``git add .`` in the first place. The two fail
    independently.
    """
    gitignore = (REPO / ".gitignore").read_text(encoding="utf-8")
    assert any(
        line.strip() in (".claude/", ".claude")
        for line in gitignore.splitlines()
    ), ".claude/ is missing from .gitignore"


def test_forbidden_list_is_not_empty() -> None:
    """Guard the guard: an emptied FORBIDDEN list would pass silently."""
    assert len(FORBIDDEN) >= 10, (
        "FORBIDDEN was shortened — every removed pattern is a class of file "
        "that can now be committed unnoticed"
    )
