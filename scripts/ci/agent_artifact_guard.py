"""Fail if agent/editor working directories are tracked in git.

``.gitignore`` stops accidental adds and nothing else. ``git add -f``
bypasses it outright, so does deleting the rule, and so does a nested
``.gitignore`` that re-includes a path. None of those are exotic: they
are what happens when someone is trying to commit one file inside an
ignored directory and reaches for ``-f``.

This checks what is actually TRACKED, which is the only thing that ends
up on the remote. It runs in CI, so a local bypass still fails the PR.

Kept dependency-free and stdlib-only so it can run as the first step of
any job without a package install.
"""
from __future__ import annotations

import subprocess
import sys

#: Path prefixes that must never be tracked. Prefix match on the
#: repo-relative POSIX path git reports.
FORBIDDEN_PREFIXES: tuple[str, ...] = (
    ".claude/",
    ".cursor/",
    ".aider/",
    ".continue/",
)

#: Exact filenames that must never be tracked at any depth. Session and
#: local-settings files carry machine paths, tokens and prompt history.
FORBIDDEN_BASENAMES: tuple[str, ...] = (
    ".claude_history",
    "settings.local.json",
)


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [p for p in out.split("\0") if p]


def main() -> int:
    violations: list[str] = []
    for path in tracked_files():
        if path.startswith(FORBIDDEN_PREFIXES):
            violations.append(path)
            continue
        if path.rsplit("/", 1)[-1] in FORBIDDEN_BASENAMES:
            violations.append(path)

    if violations:
        print("FAIL: agent/editor artifacts are TRACKED in git:")
        for v in sorted(violations)[:50]:
            print(f"  {v}")
        if len(violations) > 50:
            print(f"  ... and {len(violations) - 50} more")
        print()
        print("These directories hold prompt history, machine-local paths")
        print("and sometimes credentials. .gitignore does not prevent this")
        print("-- `git add -f` ignores it. Remove them from the index:")
        print()
        print("  git rm -r --cached <path>")
        print()
        return 1

    print(f"OK: no agent/editor artifacts tracked "
          f"({len(tracked_files())} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
