"""Prove Experiment 2 can fail.

    python propagation_sabotage.py

The promotion criterion for this experiment:

    if forwarding, absorption, behaviour change, edge traversal, TTL,
    consumption, containment or recall is removed, the experiment must fail
    for the specific claim that mechanism supports.

Each mutation below disables exactly one mechanism and requires `--check` to
fail. A mutation that leaves the matrix green means the mechanism is not
being measured, and any result resting on it is not validated.

The last case is the inverse: it removes nothing and requires the matrix to
pass, so a script that fails everything cannot be mistaken for a script that
detects everything.
"""
from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout

sys.argv = ["propagation_sabotage"]

import propagation as P  # noqa: E402


class Args:
    mode = "correlation"
    min_trust = 40


def matrix():
    """Run the hypothesis matrix, returning (failures, invariant names)."""
    with redirect_stdout(io.StringIO()):
        rows, failures = P.check(Args())
    names = sorted({n for r in rows for n in P.invariants(r)})
    return failures, names


RESULTS = []


def sabotage(label, expect, **mechanisms):
    """Disable `mechanisms`, require the matrix to fail, restore."""
    P.MECH.reset()
    for k, v in mechanisms.items():
        assert hasattr(P.MECH, k), k
        setattr(P.MECH, k, v)
    failures, names = matrix()
    P.MECH.reset()

    broke = bool(failures)
    # Where a specific invariant is named, it must be the one that fires --
    # failing for an unrelated reason is not evidence the mechanism is
    # measured.
    if expect and broke:
        broke = expect in names
    RESULTS.append((label, broke))
    detail = (f"{len(failures)} cell(s) failed"
              + (f"; invariants fired: {names}" if names else
                 "; no invariant fired (hypothesis mismatch only)"))
    print(f"  {'CAUGHT ' if broke else 'MISSED '} {label:44} {detail}")


print("  each mutation must make --check fail\n")

sabotage("transfer removed (origin sends nothing)", None, transfer=False)
sabotage("absorption removed (delegates ignore inbox)", None, absorb=False)
sabotage("behaviour change removed (absorb, act benign)", None,
         change_behaviour=False)
sabotage("forwarding removed (no relay past hop 1)", None, forward=False)
sabotage("delegation edges ignored (broadcast)",
         "every_causal_hop_is_a_real_delegation_edge", honour_edges=False)
sabotage("TTL ignored (taint never expires)",
         "no_taint_outruns_its_ttl", honour_ttl=False)
sabotage("messages not consumed (stay in the inbox)",
         "absorbing_a_taint_consumes_it", consume=False)
sabotage("revoke_action is a no-op (containment inert)",
         "requested_containment_actually_denies_the_origin", revoke=False)
sabotage("recall is a no-op (withdraw does nothing)", None, recall=False)

# Control: nothing removed. The matrix must pass, or every result above is
# just a script that fails no matter what.
P.MECH.reset()
failures, names = matrix()
ok = not failures and not names
RESULTS.append(("control: nothing removed (must PASS)", ok))
print(f"  {'CAUGHT ' if ok else 'MISSED '} "
      f"{'control: nothing removed (must PASS)':44} "
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
