"""Prove Experiment 3 can fail.

    python preview_sabotage.py

The promotion criterion:

    if the preview decision, the shadow engine, its isolation, the no-op
    emitter or block-on-match is removed, the experiment must fail for the
    specific claim that mechanism supports.

The earlier version of this experiment passed every check with the shadow
engine deleted entirely -- a previewed-and-refused action cost two
principals 15 trust points, exactly the harm preview exists to prevent, and
the harness reported success. That is what these mutations exist to stop.

The last case removes nothing and requires the matrix to pass, so a script
that fails everything cannot be mistaken for one that detects everything.
"""
from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout

sys.argv = ["preview_sabotage"]

import preview as P  # noqa: E402


class Args:
    min_trust = 40


def matrix():
    with redirect_stdout(io.StringIO()):
        rows, failures = P.check(Args())
    names = sorted({n for r in rows for n in P.invariants(r)})
    return failures, names


RESULTS = []


def sabotage(label, expect, **mechanisms):
    P.MECH.reset()
    for k, v in mechanisms.items():
        assert hasattr(P.MECH, k), k
        setattr(P.MECH, k, v)
    failures, names = matrix()
    P.MECH.reset()

    broke = bool(failures)
    if expect and broke:
        broke = expect in names
    RESULTS.append((label, broke))
    detail = (f"{len(failures)} cell(s) failed"
              + (f"; invariants fired: {names}" if names else
                 "; no invariant fired (hypothesis mismatch only)"))
    print(f"  {'CAUGHT ' if broke else 'MISSED '} {label:46} {detail}")


print("  each mutation must make --check fail\n")

# The preview never runs: the harmful post commits and is detected after
# the fact, which is the baseline preview is supposed to improve on.
sabotage("preview never consulted", None, preview=False)

# Evaluate the proposal on the LIVE engine. The refused action advances
# real state and the full match emits a real signal, costing trust.
sabotage("no shadow (predict on the live engine)",
         "preview_leaves_live_state_untouched", shadow=False)

# Keep the shadow but write its state back afterwards -- the leak the copy
# exists to prevent.
sabotage("shadow state leaks back into the live store",
         "preview_leaves_live_state_untouched", isolate=False)

# Shadow with the real emitter: state stays clean, trust does not.
sabotage("shadow uses the real signal emitter",
         "preview_costs_no_trust", noop_emitter=False)

# Predict correctly, then commit anyway.
sabotage("prediction ignored (no block on match)",
         "a_predicted_match_is_refused", block_on_match=False)

# Control.
P.MECH.reset()
failures, names = matrix()
ok = not failures and not names
RESULTS.append(("control: nothing removed (must PASS)", ok))
print(f"  {'CAUGHT ' if ok else 'MISSED '} "
      f"{'control: nothing removed (must PASS)':46} "
      f"{len(failures)} cell(s) failed, invariants fired: {names or 'none'}")

print()
missed = [n for n, ok in RESULTS if not ok]
print(f"  {len(RESULTS) - len(missed)}/{len(RESULTS)} sabotages behaved as "
      f"required")
if missed:
    print("  NOT VALIDATED -- these mechanisms are not measured by the "
          "experiment:")
    for n in missed:
        print(f"    {n}")
sys.exit(1 if missed else 0)
