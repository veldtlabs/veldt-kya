"""Self-test: prove the guard catches every bypass it claims to.

A guard that has never been shown to fail is indistinguishable from one
that cannot fail. The first version of this file exercised exactly one
case -- a root-level ``.claude/`` -- and the guard shipped passing while
five real bypasses went straight through. So each case below is one that
was empirically verified to defeat the earlier implementation.

Also asserts the guard does NOT fire on legitimately-named paths, since
an over-matching guard gets disabled rather than fixed.

Stdlib only, mirrors test_principal_kind_guard.py.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile

GUARD = pathlib.Path(__file__).with_name("agent_artifact_guard.py")

#: Each was confirmed to pass the prefix-matching implementation.
BYPASSES = [
    (".claude/worktrees/notes.md", "root-level, the original case"),
    ("apps/web/.claude/settings.json", "NESTED -- prefix match missed it"),
    (".Claude/worktrees/notes.md", "case variant -- git tracks it"),
    (".aider.chat.history.md", "root dotfile, not a .aider/ directory"),
    (".vscode/settings.json", "editor dir named in the job title"),
    (".idea/workspace.xml", "editor dir named in the job title"),
    ("nested/deep/settings.local.json", "forbidden basename at depth"),
]

#: Must NOT trip the guard. An over-matching guard gets switched off.
LEGITIMATE = [
    "docs/claude/overview.md",
    "myclaude.py",
    "src/claude_helper.py",
    "src/settings.json",
]


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True)


def _run_guard(cwd):
    return subprocess.run([sys.executable, str(GUARD)], cwd=cwd,
                          capture_output=True, text=True)


def _new_repo(tmp: str) -> pathlib.Path:
    repo = pathlib.Path(tmp)
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "t@example.com", cwd=repo)
    _git("config", "user.name", "t", cwd=repo)
    (repo / ".gitignore").write_text(
        ".claude/\n.vscode/\n.idea/\n", encoding="utf-8")
    (repo / "real.py").write_text("x = 1\n", encoding="utf-8")
    _git("add", ".gitignore", "real.py", cwd=repo)
    _git("commit", "-q", "-m", "init", cwd=repo)
    return repo


def main() -> int:
    failures: list[str] = []

    # ── each bypass, in isolation, must be caught and NAMED ──────────
    for rel, why in BYPASSES:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _new_repo(tmp)
            art = repo / rel
            art.parent.mkdir(parents=True, exist_ok=True)
            art.write_text("payload\n", encoding="utf-8")
            add = _git("add", "-f", rel, cwd=repo)
            if add.returncode != 0:
                failures.append(f"could not stage {rel}: {add.stderr}")
                continue

            r = _run_guard(repo)
            if r.returncode == 0:
                failures.append(f"NOT CAUGHT: {rel}  ({why})")
            elif rel.split("/")[-1] not in r.stdout:
                failures.append(
                    f"caught {rel} but did not name it: {r.stdout!r}")

    # ── legitimate names must pass ───────────────────────────────────
    with tempfile.TemporaryDirectory() as tmp:
        repo = _new_repo(tmp)
        for rel in LEGITIMATE:
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("ok\n", encoding="utf-8")
            _git("add", rel, cwd=repo)
        r = _run_guard(repo)
        if r.returncode != 0:
            failures.append(
                f"FALSE POSITIVE on legitimate names: {r.stdout}")

    # ── removing from the index restores a pass ──────────────────────
    with tempfile.TemporaryDirectory() as tmp:
        repo = _new_repo(tmp)
        art = repo / ".claude" / "notes.md"
        art.parent.mkdir(parents=True, exist_ok=True)
        art.write_text("x\n", encoding="utf-8")
        _git("add", "-f", ".claude/notes.md", cwd=repo)
        if _run_guard(repo).returncode == 0:
            failures.append("guard passed with .claude/notes.md staged")
        _git("rm", "-r", "-q", "--cached", ".claude", cwd=repo)
        r = _run_guard(repo)
        if r.returncode != 0:
            failures.append(
                f"still failing after `git rm --cached`: {r.stdout}")

    # ── must not narrow when run from a subdirectory ─────────────────
    with tempfile.TemporaryDirectory() as tmp:
        repo = _new_repo(tmp)
        art = repo / ".claude" / "notes.md"
        art.parent.mkdir(parents=True, exist_ok=True)
        art.write_text("x\n", encoding="utf-8")
        _git("add", "-f", ".claude/notes.md", cwd=repo)
        sub = repo / "sub"
        sub.mkdir(exist_ok=True)
        (sub / "a.py").write_text("a = 1\n", encoding="utf-8")
        _git("add", "sub/a.py", cwd=repo)
        r = _run_guard(sub)
        if r.returncode == 0:
            failures.append(
                "guard PASSED when run from a subdirectory -- it only "
                "saw that subtree, which is a fail-open mode")

    if failures:
        print("FAIL: guard self-test found problems:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"OK: guard caught all {len(BYPASSES)} bypasses, passed "
          f"{len(LEGITIMATE)} legitimate names, and did not narrow "
          f"from a subdirectory")
    return 0


if __name__ == "__main__":
    sys.exit(main())
