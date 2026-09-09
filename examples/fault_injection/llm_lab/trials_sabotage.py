"""Does `--trials` actually fail when a trial is wrong?

`--check` and `--sweep` verified their invariants and returned nonzero on a
violation. `--trials N` -- the only mode that matters against a real model,
because one run of a model is an anecdote -- summarised the rate and
returned 0 no matter what the runs contained. A student could have run six
trials against GPT-4o, seen a clean exit, and published a rate computed
over runs that violated their own invariants.

Three scenarios per experiment:

    control       nothing removed. Must PASS: exit 0, no violations.
    forced        an invariant is made to fail. Must FAIL: exit nonzero.
    unchecked     the invariant fails AND the check is removed. Must be
                  caught here, because it is the state the code was in.

The third is the point. Without it this file would only prove that a
passing run passes.

    python trials_sabotage.py
"""
from __future__ import annotations

import contextlib
import io
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import trials                                              # noqa: E402
import experiment                                          # noqa: E402
import preview                                             # noqa: E402
import propagation                                         # noqa: E402

EXPERIMENTS = [("experiment", experiment), ("preview", preview),
               ("propagation", propagation)]
TRIALS = 2
RESULTS = []


def invoke(module, out):
    """Run `module.main()` as `--trials N`, quietly, and return its exit."""
    argv = sys.argv
    sys.argv = [module.__name__, "--trials", str(TRIALS), "--out", out]
    try:
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            code = module.main()
        return code, buf.getvalue()
    finally:
        sys.argv = argv


def note(caught, label, detail=""):
    RESULTS.append((caught, label))
    print(f"  {'CAUGHT ' if caught else 'MISSED '} {label:52} {detail}")


with tempfile.TemporaryDirectory() as tmp:
    for name, module in EXPERIMENTS:
        out = os.path.join(tmp, f"{name}.jsonl")
        real_invariants = module.invariants
        real_violations = trials.violations

        code, text = invoke(module, out)
        note(code == 0 and "trials clean" in text,
             f"{name}: control -- nothing removed (must PASS)",
             f"exit={code}")

        # An invariant that fails on every trial. The exit code has to
        # follow it.
        module.invariants = lambda r: ["forced_violation"]
        try:
            code, text = invoke(module, out)
        finally:
            module.invariants = real_invariants
        note(code != 0 and "VIOLATED" in text,
             f"{name}: a violated trial fails the run",
             f"exit={code}")

        # And with the check removed, as it was: the violation is still
        # there, and the run still reports success.
        module.invariants = lambda r: ["forced_violation"]
        trials.violations = lambda runs, inv: []
        try:
            code, _ = invoke(module, out)
        finally:
            module.invariants = real_invariants
            trials.violations = real_violations
        note(code == 0,
             f"{name}: without the check, a violated run passes",
             f"exit={code} -- which is the defect this guards")

print()
missed = [label for caught, label in RESULTS if not caught]
print(f"  {len(RESULTS) - len(missed)}/{len(RESULTS)} behaved as required")
if missed:
    print("  --trials DOES NOT REPORT A VIOLATED TRIAL:")
    for label in missed:
        print(f"    {label}")
sys.exit(1 if missed else 0)
