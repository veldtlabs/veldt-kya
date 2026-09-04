"""Fail if agent/editor working directories are tracked in git.

``.gitignore`` stops accidental adds and nothing else. ``git add -f``
bypasses it outright, so does deleting the rule, and so does a nested
``.gitignore`` that re-includes a path. None of those are exotic: they
are what happens when someone is trying to commit one file inside an
ignored directory and reaches for ``-f``.

This checks what is actually TRACKED, which is the only thing that ends
up on the remote. It runs in CI, so a local bypass still fails the PR.

Matching is on path SEGMENTS, casefolded, at any depth. An earlier
version prefix-matched ``".claude/"`` against the repo-root-relative
path, which let five real cases through -- verified by force-adding
them: a nested ``apps/web/.claude/settings.json``, a case variant
``.Claude/``
(git tracks it happily on Windows and macOS), ``.aider.chat.history.md``
(aider writes root-level files, never a ``.aider/`` directory), and
``.vscode`` / ``.idea``, which the job name claimed to cover.

Kept dependency-free and stdlib-only so it can run as the first step of
any job without a package install.
"""
from __future__ import annotations

import subprocess
import sys

#: Directory names that must not appear as ANY path segment, at any
#: depth. Compared casefolded.
FORBIDDEN_SEGMENTS: frozenset[str] = frozenset({
    ".claude",
    ".cursor",
    ".aider",
    ".continue",
    ".vscode",
    ".idea",
})

#: Segment prefixes, for tools that write root-level dotfiles rather
#: than a directory (aider) or numbered variants.
FORBIDDEN_SEGMENT_PREFIXES: tuple[str, ...] = (
    ".aider.",
    ".claude.",
    ".cursor.",
)

#: Exact filenames that must not be tracked at any depth. These carry
#: machine paths, prompt history and sometimes credentials.
FORBIDDEN_BASENAMES: frozenset[str] = frozenset({
    ".claude_history",
    "settings.local.json",
})


def repo_root() -> str:
    """Absolute repo root, so the check cannot silently narrow.

    ``git ls-files`` run from a subdirectory returns only that
    subtree, and relative to it -- so a guard invoked with a
    ``working-directory:`` would report a clean subset and pass. That
    is a fail-OPEN mode, which is the one a guard must never have.
    """
    return subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "-C", repo_root(), "ls-files", "-z", "--full-name"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [p for p in out.split("\0") if p]


def violations_in(path: str) -> bool:
    segments = path.replace("\\", "/").casefold().split("/")
    for seg in segments:
        if seg in FORBIDDEN_SEGMENTS:
            return True
        if seg.startswith(FORBIDDEN_SEGMENT_PREFIXES):
            return True
    return segments[-1] in FORBIDDEN_BASENAMES


def main() -> int:
    files = tracked_files()
    bad = sorted(p for p in files if violations_in(p))

    if bad:
        print("FAIL: agent/editor artifacts are TRACKED in git:")
        for v in bad[:50]:
            print(f"  {v}")
        if len(bad) > 50:
            print(f"  ... and {len(bad) - 50} more")
        print()
        print("These hold prompt history, machine-local paths and")
        print("sometimes credentials. .gitignore does not prevent this")
        print("-- `git add -f` ignores it. Remove them from the index:")
        print()
        print("  git rm -r --cached <path>")
        print()
        return 1

    print(f"OK: no agent/editor artifacts tracked ({len(files)} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
