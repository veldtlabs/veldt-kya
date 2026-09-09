"""Is this copy still the control?

    python baseline.py            # compare against the validated originals
    python baseline.py --capture  # accept the current differences as
                                  # deliberate, after making one

`llm_lab/` is a copy of the four validated experiments, kept so the LLM work
can break things freely. That only means something if the copy still behaves
identically to the originals when its actor is the scripted one -- otherwise
a difference in an LLM run cannot be attributed to the model rather than to
drift in the copy.

So: run every experiment here and in the parent directory, and diff. A
difference is either deliberate -- recorded in `baseline.json`, the ledger
of what this copy is allowed to do differently and why -- or it is the
reason a later result is not comparable, and the run fails.

One difference is already recorded. The originals count an action as harm
when it departs from the step's benign version; this copy counts the harm
the classifier calls intrinsic, so a bulk read of customers.csv is not harm
by itself -- `benign_reporting` performs exactly that read legitimately.

The comparison is on the DETERMINISTIC path only. `--actor llm` is expected
to differ; that is the experiment.
"""
from __future__ import annotations

import argparse
import difflib
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ORIGINAL = HERE.parent
SNAPSHOT = HERE / "baseline.json"

# (script, args) run in both directories and compared line for line.
CASES = [
    ("experiment.py", ["--check"]),
    ("experiment.py", ["--sweep"]),
    ("sabotage.py", []),
    ("propagation.py", ["--check"]),
    ("propagation.py", ["--sweep"]),
    ("propagation_sabotage.py", []),
    ("preview.py", ["--check"]),
    ("preview.py", ["--sweep"]),
    ("preview_sabotage.py", []),
    ("governor.py", ["--check"]),
    ("governor.py", ["--sweep"]),
    ("governor_sabotage.py", []),
]


# Exactly what these experiments write, including the sqlite sidecars a
# journalled database leaves behind. A `*.jsonl` / `*.db` glob swept up
# whatever else was in the directory -- an LLM run recording here, and, in
# the validated directory, files this tool has no business touching.
ARTIFACTS = ("results.jsonl", "propagation.jsonl", "preview.jsonl",
             "governor.jsonl", "fault_experiment.db",
             "fault_experiment.db-wal", "fault_experiment.db-shm",
             "fault_experiment.db-journal")
ASIDE = ".baseline-aside"


def clean(where):
    """Move this run's own artifacts aside, to be put back afterwards.

    A comparison needs each script to start from nothing, but the parent
    is the validated copy: its files are borrowed for the length of one
    run, never deleted. They are RENAMED rather than read into memory --
    a crash, or a kill that is not an exception at all, then leaves a
    recoverable file on disk instead of nothing.
    """
    moved = []
    for name in ARTIFACTS:
        path = where / name
        if path.exists():
            aside = path.with_name(path.name + ASIDE)
            aside.unlink(missing_ok=True)
            path.replace(aside)
            moved.append((path, aside))
    return moved


def discard(where):
    """Delete what this run itself produced. Never touches what was moved."""
    for name in ARTIFACTS:
        path = where / name
        if path.exists():
            path.unlink()


def restore(moved):
    for path, aside in moved:
        if aside.exists():
            aside.replace(path)


def run(where, script, args):
    """Output with the run-specific noise removed.

    Only the PATH in an "appended to" line is noise. Dropping the whole
    line took the row count with it, so a sweep that wrote nothing read as
    identical to one that wrote every row.
    """
    moved = clean(where)
    try:
        p = subprocess.run([sys.executable, script, *args], cwd=where,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=1800)
    finally:
        # Restoring is the obligation; discarding is housekeeping. If
        # discard() raises -- a file still mapped by a just-exited process
        # is the ordinary case on Windows -- the borrowed files must still
        # come back.
        try:
            discard(where)
        finally:
            restore(moved)
    out = re.sub(r"(appended to )\S+", r"\1<path>", p.stdout + p.stderr)
    out = out.replace(str(where), "<dir>").replace(str(where.resolve()),
                                                   "<dir>")
    return out, p.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--capture", action="store_true",
                    help="record this copy's output as the new baseline")
    args = ap.parse_args()

    accepted = (json.loads(SNAPSHOT.read_text(encoding="utf-8"))
                if SNAPSHOT.exists() else {})

    # A difference is accepted only if BOTH sides, and both exit codes,
    # still read as they did when it was recorded. Pinning this copy alone
    # let a change in the originals pass unnoticed, and comparing only
    # stdout let a script start exiting nonzero in silence.
    def is_recorded(label, theirs, their_code, mine, my_code):
        was = accepted.get(label)
        return bool(was) and (was["original"], was.get("original_code", 0),
                              was["mine"], was.get("mine_code", 0)) == (
                                  theirs, their_code, mine, my_code)

    drifted, known, broken = [], [], []
    for script, argv in CASES:
        label = f"{script} {' '.join(argv)}".strip()
        mine, my_code = run(HERE, script, argv)
        theirs, their_code = run(ORIGINAL, script, argv)
        if my_code and their_code:
            # Agreement is not success. A missing dependency or a typo in
            # CASES fails identically on both sides and read as "same".
            broken.append(label)
            print(f"  BROKEN   {label:34} both sides exited "
                  f"{my_code}/{their_code}")
        elif not mine.strip() and not theirs.strip():
            # The other agreement mode: exit 0 having done nothing, which
            # is what a silently swallowed argument looks like.
            broken.append(label)
            print(f"  SILENT   {label:34} both sides printed nothing")
        elif mine == theirs and my_code == their_code:
            print(f"  same     {label}")
        elif is_recorded(label, theirs, their_code, mine, my_code):
            known.append(label)
            print(f"  recorded {label:34} {accepted[label]['why']}")
        else:
            drifted.append((label, theirs, their_code, mine, my_code))
            print(f"  DIFFERS  {label}")

    if args.capture:
        for label, theirs, their_code, mine, my_code in drifted:
            # A label that was already recorded keeps its `why` only if it
            # still describes the same outputs. Carrying an old reason onto
            # new text is how a regression gets blessed.
            was = accepted.get(label, {})
            why = was.get("why", "DESCRIBE THIS")
            if was and (was["mine"], was["original"]) != (mine, theirs):
                why = f"DESCRIBE THIS (was: {why})"
            accepted[label] = {"why": why, "original": theirs,
                               "original_code": their_code, "mine": mine,
                               "mine_code": my_code}
        SNAPSHOT.write_text(json.dumps(accepted, indent=1), encoding="utf-8")
        for label, *_ in drifted:
            print(f"    recorded {label}")
        print(f"\n  {len(drifted)} difference(s) written to "
              f"{SNAPSHOT.name}. Write the reason into each `why`; an "
              f"unexplained\n  entry is drift with a note on it.")
        return 0

    # A ledger entry for a case nobody runs, or a case list that has
    # quietly shrunk, both hide coverage behind a clean N/N. These are
    # counted apart from `broken`, which is about the cases themselves.
    labels = {f"{s} {' '.join(a)}".strip() for s, a in CASES}
    ledger = []
    for stale in sorted(set(accepted) - labels):
        ledger.append(stale)
        print(f"  STALE    {stale:34} recorded, but no longer run")
    for label in sorted(accepted):
        if "DESCRIBE THIS" in accepted[label].get("why", ""):
            ledger.append(label)
            print(f"  UNSAID   {label:34} recorded with no reason given")

    print(f"\n  {len(CASES) - len(drifted) - len(known) - len(broken)}"
          f"/{len(CASES)} identical, {len(known)} recorded as deliberate")
    for label, theirs, their_code, mine, my_code in drifted:
        print(f"\n  --- {label}  (exit {their_code} -> {my_code})")
        for line in list(difflib.unified_diff(
                theirs.splitlines(), mine.splitlines(),
                "original", "llm_lab", lineterm=""))[:24]:
            print(f"    {line}")
    if drifted:
        print("\n  This copy is no longer a control. Revert the difference, "
              "or run\n  --capture and say in `why` what it is, so later LLM "
              "results are\n  read against the right baseline.")
    if broken:
        print("\n  These cases prove nothing either way -- fix them before "
              "reading\n  any result from this copy.")
    if ledger:
        print("\n  The ledger no longer describes what is run. Re-capture "
              "it, or\n  delete the entries that no longer apply.")
    return 1 if drifted or broken or ledger else 0


if __name__ == "__main__":
    sys.exit(main())
