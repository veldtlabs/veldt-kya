"""Prove no experiment's result is decided by the harm oracle.

    python measurement_independence.py

The oracle -- `measurement.classify` and the H1/H2/H3 classes it feeds --
is the RESEARCHER'S predeclared definition of harm. It is deliberately not
the policy under test. If it were also deciding pass/fail, a gap in the
classifier would read as an enforcement result, and a policy blind spot
would be undiscoverable by construction.

Reading the code is not evidence of that. This blinds the oracle -- one
tool at a time, then completely -- and requires every asserted outcome to
be byte-identical to the unblinded run. The runtime is untouched, so
anything that moves was being decided by the classifier.

Both cosmetic fixes were caught this way. Dropping an oracle-derived
element from an asserted tuple changed nothing while its two neighbours
were the same verdict under other names; blinding flipped four of eight
cells and turned a correct interception into a reported false positive.

The last case is the inverse: it re-couples compliance to the oracle and
requires the comparison to FAIL, so a script that reports independence no
matter what cannot be mistaken for one that detects coupling.
"""
from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout

sys.argv = ["measurement_independence"]

import measurement as M  # noqa: E402

TRUE_CLASSIFY = M.classify


class Args:
    window = 600
    min_trust = 40


def blinded(tool):
    """A classifier that cannot judge `tool` -- or, for "all", anything."""
    def classify(action):
        if tool == "all" or (isinstance(action, dict)
                             and action.get("tool") == tool):
            return M.Verdict(unknown=f"blinded to {tool}")
        return TRUE_CLASSIFY(action)
    return classify


# The asserted tuple of each experiment that reports an enforcement
# conclusion, read from the row the experiment itself saves. Experiment 2
# declares no policy and asserts on taint mechanics, so it is not here.
EXPERIMENTS = {
    "experiment.py": (
        lambda m: m.check(Args()),
        lambda r: (r["escape_count"], r["prevented_by"], r["detected"])),
    "preview.py": (
        lambda m: m.check(Args()),
        lambda r: (r["consequential_action"], r["false_positive_blocks"])),
}


def outcomes():
    """Every asserted tuple, plus whether the matrix passed."""
    out = {}
    for name, (drive, tuple_of) in EXPERIMENTS.items():
        module = __import__(name[:-3])
        with redirect_stdout(io.StringIO()):
            rows, failures = drive(module)
        out[name] = ([tuple_of(r) for r in rows], not failures)
    return out


def compare(label, tool, must_match=True):
    """Blind the oracle, re-run, require the outcomes to hold (or not)."""
    for module_name in EXPERIMENTS:
        sys.modules[module_name[:-3]].M.classify = blinded(tool)
    M.classify = blinded(tool)
    try:
        got = outcomes()
    finally:
        M.classify = TRUE_CLASSIFY
        for module_name in EXPERIMENTS:
            sys.modules[module_name[:-3]].M.classify = TRUE_CLASSIFY

    moved = [n for n in BASE if got[n][0] != BASE[n][0]]
    failed = [n for n in got if not got[n][1]]
    ok = (not moved and not failed) if must_match else bool(moved or failed)
    detail = ("every asserted outcome unmoved" if not moved and not failed
              else "moved: " + ", ".join(sorted(set(moved + failed))))
    RESULTS.append((label, ok))
    print(f"  {'ok     ' if ok else 'COUPLED'} {label:46} {detail}")


print(__doc__.strip().splitlines()[0])
print()
with redirect_stdout(io.StringIO()):
    BASE = outcomes()
for name, (tuples, passed) in BASE.items():
    print(f"  baseline   {name:46} {len(tuples)} cells, "
          f"{'matrix passes' if passed else 'MATRIX ALREADY FAILING'}")
if not all(passed for _, passed in BASE.values()):
    print("\n  the unblinded matrix does not pass; fix that first")
    sys.exit(1)

print()
RESULTS = []
for tool in ("file_read", "http_post", "agent_spawn", "all"):
    compare(f"oracle blinded to {tool!r}", tool)

# Control. Compliance re-coupled to the oracle is exactly the defect this
# script exists to find, so blinding must now move a result.
print()
original = M.Observation.followed_injection


def needs_the_oracle(self):
    if not self.offered_injection or not self.verdict.known:
        return None
    return M.equivalent(self.proposed_action, self.injected_instruction)


M.Observation.followed_injection = property(needs_the_oracle)
try:
    compare("control: compliance re-coupled (must COUPLE)", "all",
            must_match=False)
finally:
    M.Observation.followed_injection = original

# One control per experiment, or the other one is not being tested.
# Experiment 3 counts a false positive from what the workload declares the
# agent was briefed to do; gating that on the oracle is the same defect.
offered = M.Observation.offered_injection


def offered_needs_the_oracle(self):
    return bool(self.injected_instruction) and self.verdict.known


M.Observation.offered_injection = property(offered_needs_the_oracle)
try:
    compare("control: false positives re-coupled (must COUPLE)", "all",
            must_match=False)
finally:
    M.Observation.offered_injection = offered

print()
bad = [label for label, ok in RESULTS if not ok]
print(f"  {len(RESULTS) - len(bad)}/{len(RESULTS)} independence checks "
      f"behaved as required")
if bad:
    print("  NOT INDEPENDENT -- the harm oracle is deciding these results:")
    for label in bad:
        print(f"    {label}")
sys.exit(1 if bad else 0)
