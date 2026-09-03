"""Self-test: prove the guard catches a forced add.

A guard that has never been shown to fail is indistinguishable from one
that cannot fail. This builds a throwaway repo, force-adds an ignored
agent artifact exactly as `git add -f` would, and asserts the guard
rejects it -- then asserts it passes on a clean tree.

Stdlib only, mirrors test_principal_kind_guard.py.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

GUARD = pathlib.Path(__file__).with_name("agent_artifact_guard.py")


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True)


def _run_guard(cwd):
    return subprocess.run([sys.executable, str(GUARD)], cwd=cwd,
                          capture_output=True, text=True)


def main() -> int:
    failures = []

    with tempfile.TemporaryDirectory() as tmp:
        repo = pathlib.Path(tmp)
        _git("init", "-q", cwd=repo)
        _git("config", "user.email", "t@example.com", cwd=repo)
        _git("config", "user.name", "t", cwd=repo)
        (repo / ".gitignore").write_text(".claude/\n", encoding="utf-8")
        (repo / "real.py").write_text("x = 1\n", encoding="utf-8")
        _git("add", ".gitignore", "real.py", cwd=repo)
        _git("commit", "-q", "-m", "init", cwd=repo)

        # 1. clean tree -> pass
        r = _run_guard(repo)
        if r.returncode != 0:
            failures.append(f"clean tree rejected: {r.stdout}{r.stderr}")

        # 2. the bypass: ignored, but force-added anyway
        art = repo / ".claude" / "worktrees" / "notes.md"
        art.parent.mkdir(parents=True, exist_ok=True)
        art.write_text("prompt history\n", encoding="utf-8")
        add = _git("add", "-f", ".claude/worktrees/notes.md", cwd=repo)
        if add.returncode != 0:
            failures.append(f"could not stage the artifact: {add.stderr}")

        r = _run_guard(repo)
        if r.returncode == 0:
            failures.append(
                "guard PASSED on a force-added .claude artifact -- it "
                "does not defend the case it exists for")
        elif ".claude/worktrees/notes.md" not in r.stdout:
            failures.append(f"guard failed but did not name the file: "
                            f"{r.stdout}")

        # 3. removing it from the index restores a pass
        _git("rm", "-r", "-q", "--cached", ".claude", cwd=repo)
        r = _run_guard(repo)
        if r.returncode != 0:
            failures.append(
                f"guard still failing after `git rm --cached`: {r.stdout}")

        # 4. a forbidden basename anywhere in the tree
        s = repo / "sub" / "settings.local.json"
        s.parent.mkdir(parents=True, exist_ok=True)
        s.write_text("{}\n", encoding="utf-8")
        _git("add", "-f", "sub/settings.local.json", cwd=repo)
        r = _run_guard(repo)
        if r.returncode == 0:
            failures.append("guard missed a nested settings.local.json")

    if failures:
        print("FAIL: guard self-test found problems:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("OK: guard rejects force-added agent artifacts and passes clean trees")
    return 0


if __name__ == "__main__":
    sys.exit(main())
