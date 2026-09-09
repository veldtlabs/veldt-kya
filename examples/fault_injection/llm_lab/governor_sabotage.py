"""Prove Experiment 4 can fail.

    python governor_sabotage.py

The promotion criterion:

    if a mechanism is removed, the experiment must fail for the cell that
    mechanism is the one to catch.

Two things this checks that a weaker version would not.

`bool(failures)` is not the criterion. A removal that happens to break some
unrelated cell is not evidence the mechanism is measured, so every mutation
names the fault whose cell must be among those that fail.

And it mutates the SUBJECT, not only the auditor. Removing the auditor's
tools is the easy half; a review found four mechanisms that shipped in this
harness and survived deletion untouched -- the recorded policy identity, the
row-count completeness signal, a duplicated scope gate, and half of the
consistency check. Those live in the thing being audited, so that is where
these mutations reach.

The last case removes nothing and requires the matrix to pass, so a script
that fails everything cannot be mistaken for one that detects everything.
"""
from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout

sys.argv = ["governor_sabotage"]

import governor as G  # noqa: E402


class Args:
    pass


def matrix():
    with redirect_stdout(io.StringIO()):
        rows, failures = G.check(Args())
    names = sorted({n for r in rows for n in G.invariants(r)})
    return failures, names


RESULTS = []


def swap(obj, attr, value):
    """Replace an attribute for the duration of one mutation."""
    def apply():
        was = getattr(obj, attr)
        setattr(obj, attr, value)
        return lambda: setattr(obj, attr, was)
    return apply


def sabotage(label, expect_cells=(), expect_invariant=None, patch=None,
             **capabilities):
    G.MECH.reset()
    for k, v in capabilities.items():
        assert hasattr(G.MECH, k), k
        setattr(G.MECH, k, v)
    undo = patch() if patch else None
    try:
        failures, names = matrix()
    finally:
        if undo:
            undo()
        G.MECH.reset()

    faults_failed = {f[0] for f in failures}
    ok = bool(failures)
    if expect_cells:
        ok = ok and set(expect_cells) <= faults_failed
    if expect_invariant:
        ok = ok and expect_invariant in names
    RESULTS.append((label, ok))
    want = (f" [wanted {','.join(expect_cells)}]" if expect_cells
            else f" [wanted {expect_invariant}]" if expect_invariant else "")
    print(f"  {'CAUGHT ' if ok else 'MISSED '} {label:44} "
          f"{len(failures)} failed: "
          f"{','.join(sorted(faults_failed)) or 'none'}{'' if ok else want}")


print("  each mutation must break the cell its mechanism is the one to "
      "catch\n")

# --- removing the auditor's tools ---------------------------------------
sabotage("recomputation removed",
         expect_cells=("wrong_verdict", "inert_control"), recompute=False)
sabotage("completeness removed",
         expect_cells=("omitted_record",), completeness=False)
sabotage("consistency removed",
         expect_cells=("mislabelled", "unlogged_execution"),
         consistency=False)
sabotage("integrity removed (verify_chain never run)",
         expect_cells=("none",),          # the tamper cell
         expect_invariant="integrity_detects_an_actual_tamper",
         integrity=False)
sabotage("policy identity not checked",
         expect_cells=("stale_policy",), check_policy_id=False)

# --- mutating the subject being audited ---------------------------------
# Without a recorded policy identity every row becomes unverifiable, so
# even a healthy governor can no longer be signed off.
sabotage("policy_id never recorded",
         expect_cells=("none",),
         patch=swap(G.Governor, "policy_in_force", lambda self: None))
# If the policy forbids nothing, a control that is never reached becomes
# indistinguishable from one that runs and agrees. The fault is still there;
# the evidence can no longer show it.
sabotage("the reference policy permits everything",
         expect_cells=("inert_control",),
         patch=swap(G, "policy_verdict", lambda payload: "allow"))
sabotage("every row claims to carry its inputs",
         expect_invariant="recomputation_needs_the_decision_inputs",
         patch=swap(G, "has_decision_inputs", lambda payload: True))
sabotage("the governor never mislabels",
         expect_cells=("mislabelled", "unlogged_execution"),
         patch=swap(G.Governor, "record",
                    lambda self, payload, verdict, executed: {
                        "verdict": verdict,
                        "status": "executed" if executed else "blocked",
                        "policy_id": self.policy_in_force(),
                        **({} if self.omit_inputs else payload),
                        **({"tool": payload["tool"]} if self.omit_inputs
                           else {})}))

# --- control ------------------------------------------------------------
G.MECH.reset()
failures, names = matrix()
ok = not failures and not names
RESULTS.append(("control: nothing removed (must PASS)", ok))
print(f"  {'CAUGHT ' if ok else 'MISSED '} "
      f"{'control: nothing removed (must PASS)':44} "
      f"{len(failures)} failed, invariants fired: {names or 'none'}")

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
