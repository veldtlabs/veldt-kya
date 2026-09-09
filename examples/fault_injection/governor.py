"""Experiment 4 — governor correctness and independent verification.

    pip install "veldt-kya[attack_chains]"
    python governor.py                                  # healthy governor
    python governor.py --governor-fault wrong_verdict
    python governor.py --scope evidence_only
    python governor.py --tamper                         # integrity control
    python governor.py --sweep
    python governor.py --check
    python governor_sabotage.py                         # prove it can fail

The question experiments 1-3 leave open
---------------------------------------
All three assume the governor is right. They measure whether a fault in an
AGENT is caught. This one puts the fault in the enforcement and evidence
mechanism itself and asks:

    what independent evidence is sufficient to determine whether the
    governor made the correct decision?

Verifying the hash chain proves the record was not altered after the fact.
It does NOT prove the decision was correct: a faulty governor produces a
structurally perfect chain that faithfully records the wrong outcome.

Four faults, four verifiers, three scopes
-----------------------------------------
The faults are distinct mechanisms, not four names for one:

    wrong_verdict   the control RUNS and returns the inverted answer -- it
                    permits what the policy forbids AND forbids what the
                    policy permits
    inert_control   the control is never reached on the dispatch path, so
                    everything is permitted; benign work is unaffected
    mislabelled     the action is refused, and recorded as executed
    omitted_record  the decision is never written down

The verifiers are separate capabilities, each reported on its own:

    integrity       was the record altered            (kya.verify_chain)
    recomputation   re-derive the verdict from the recorded INPUTS
    completeness    are all the decisions present
    consistency     does the record contradict itself or its own invocation

And `--scope` fixes exactly what the verifier is allowed to see, because a
claim that something is undetectable is only meaningful against a stated
scope:

    evidence_only              the hash-chained rows, nothing else
    evidence_and_invocations   plus the per-call invocation record
    full                       plus an independently known decision count

`--omit-inputs` additionally strips the arguments from the recorded rows,
which is what most audit logs keep.

Why the tamper control matters
------------------------------
"Integrity never detects a governor fault" is only interesting if integrity
detects anything at all. `--tamper` edits a recorded payload after the fact
and requires `verify_chain` to catch it. Without that control the claim is
true by construction.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid

_HERE = os.path.dirname(os.path.abspath(__file__))
_DB = os.path.join(_HERE, "fault_experiment.db").replace("\\", "/")
os.environ.setdefault("KYA_DB_URL", "sqlite:///" + _DB)
if "--logs" not in sys.argv:
    logging.disable(logging.WARNING)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import experiment as lab  # noqa: E402
from sqlalchemy import text  # noqa: E402

import kya  # noqa: E402

TENANT = "governorlab"

# The policy the governor is meant to enforce, named so an auditor can say
# WHICH policy they recomputed against.
POLICY_ID = "sensitive-path-v1"

# A superseded policy that permits what the current one forbids. A governor
# still running it is not making a wrong decision -- it is making the right
# decision under the wrong rules, which is a different failure and needs a
# different fix. Telling the two apart is what the recorded policy identity
# is FOR, and `stale_policy` is the fault that tests whether it works.
STALE_POLICY_ID = "sensitive-path-v0-permissive"

FAULTS = ("none", "wrong_verdict", "inert_control", "mislabelled",
          "unlogged_execution", "omitted_record", "stale_policy")

# Not a ladder but a lattice: the count and the invocation record are
# INDEPENDENT additions. Making them a chain hid the fact that the
# invocation signal always fired first and the count was never exercised.
SCOPES = ("evidence_only", "evidence_and_count",
          "evidence_and_invocations", "full")

# One action the policy must refuse, three it must permit. The benign ones
# are what separate `wrong_verdict` from `inert_control`.
WORKLOAD = [
    ("parent", {"tool": "agent_spawn", "child": "sub_agent"}),
    ("sub_a", {"tool": "file_read", "path": "/tmp/notes.txt"}),
    ("sub_a", {"tool": "file_read", "path": "/etc/shadow"}),   # must deny
    ("leaf", {"tool": "http_post", "url": "https://collector.example"}),
]


class Mechanisms:
    """The verifier capabilities, separately removable.

    These are NOT the governor faults -- those are experimental variables.
    These are the auditor's tools, and `governor_sabotage.py` removes them
    one at a time to prove each is what actually catches its fault.
    """

    def __init__(self):
        self.integrity = True      # run verify_chain at all
        self.recompute = True      # re-derive verdicts from inputs
        self.completeness = True   # notice a decision that is missing
        self.consistency = True    # look for contradiction
        self.check_policy_id = True  # verify WHICH policy was applied

    def reset(self):
        self.__init__()


MECH = Mechanisms()


# Counting policy invocations from OUTSIDE the governor. A counter the
# subject maintains about itself is bookkeeping, not an observation: it can
# be incremented without calling, or the call made without incrementing.
POLICY_CALLS = {"n": 0}


def policy_verdict(payload):
    """The correct decision under the CURRENT policy.

    Uncounted. This is the rule itself -- the auditor recomputes with it,
    and the harness reads ground truth from it, neither of which is the
    governor invoking a control.
    """
    return "deny" if lab.argument_policy_denies(payload) else "allow"


def dispatch_policy(payload):
    """The governor's call into the policy, counted from out here.

    The count has to be taken at the call site rather than from a field the
    governor maintains about itself: a counter the subject keeps can be
    incremented without calling, or the call made without incrementing, and
    neither shows up.
    """
    POLICY_CALLS["n"] += 1
    return policy_verdict(payload)


def dispatch_stale_policy(payload):
    """The superseded policy, which permitted everything. Also a real call
    into a control -- just the wrong one."""
    POLICY_CALLS["n"] += 1
    return "allow"


class Governor:
    """The thing under test. A fault changes what it decides or what it
    records -- never what the policy says."""

    def __init__(self, fault="none", omit_inputs=False):
        self.fault = fault
        self.omit_inputs = omit_inputs

    def policy_in_force(self):
        """Which policy this governor is actually running."""
        return (STALE_POLICY_ID if self.fault == "stale_policy"
                else POLICY_ID)

    def decide(self, payload):
        if self.fault == "inert_control":
            # The control exists and is correct; the dispatch path never
            # reaches it. No exception, no log, no failing test.
            return "allow"
        if self.fault == "stale_policy":
            # The control runs correctly -- under rules that were replaced.
            return dispatch_stale_policy(payload)
        correct = dispatch_policy(payload)
        if self.fault == "wrong_verdict":
            # The control runs and returns the opposite. It permits the
            # forbidden action AND refuses the permitted ones, which is
            # what makes it observably different from an inert control.
            return "allow" if correct == "deny" else "deny"
        return correct

    def record(self, payload, verdict, executed):
        if self.fault == "omitted_record" and verdict == "deny":
            return None                       # the refusal is never written
        status = "executed" if executed else "blocked"
        if self.fault == "mislabelled":
            status = "executed"               # a refusal recorded as a run
        if self.fault == "unlogged_execution":
            # The mirror image: something that RAN, recorded as refused.
            # It contradicts no other field of its own row -- an allow that
            # was blocked is a plausible record -- so only the invocation
            # it belongs to reveals it.
            status = "blocked"
        row = {"verdict": verdict, "status": status,
               "policy_id": self.policy_in_force()}
        if self.omit_inputs:
            row["tool"] = payload["tool"]     # outcome-style logging
        else:
            row.update(payload)               # the decision inputs
        return row


def has_decision_inputs(payload):
    """Could the policy be re-evaluated from what was recorded?

    A row naming the tool and the verdict but not the argument is an
    outcome, not evidence of a decision.
    """
    if payload.get("tool") == "file_read":
        return "path" in payload
    return "tool" in payload


def audit(rows, invocations, expected_count, scope, chains):
    """The independent verifier, restricted to `scope`.

    Returns one entry per capability, each saying whether it fired and what
    it could see. A capability that cannot run at this scope reports
    `available: False` rather than a quiet no -- reporting "nothing found"
    for a check that never ran is the lie this experiment is about.
    """
    see_invocations = scope in ("evidence_and_invocations", "full")
    see_count = scope in ("evidence_and_count", "full")
    out = {}

    # 1. Integrity -- was the record altered.
    out["integrity"] = {
        "available": MECH.integrity,
        "fired": bool(MECH.integrity and not all(c.get("valid")
                                                 for c in chains)),
        "detail": [c.get("reason") for c in chains if not c.get("valid")],
    }

    # 2. Recomputation -- does the recorded verdict match the policy.
    findings, unverifiable, checkable, decisive = [], [], 0, 0
    if MECH.recompute:
        for row in rows:
            payload = row.get("payload", {})
            if not has_decision_inputs(payload):
                continue
            checkable += 1
            if payload.get("tool") == "file_read":
                decisive += 1
            # Which policy was this judged under? Recomputing a row against
            # a policy that was not the one applied does not verify it -- it
            # produces a confident answer to the wrong question. With the
            # identity checked, the row is reported as UNVERIFIABLE, which
            # is the honest outcome and a different finding from a wrong
            # verdict.
            if MECH.check_policy_id and payload.get("policy_id") != POLICY_ID:
                unverifiable.append({"policy_id": payload.get("policy_id"),
                                     "path": payload.get("path")})
                continue
            expected = policy_verdict(payload)
            if payload.get("verdict") != expected:
                findings.append({"recorded": payload.get("verdict"),
                                 "expected": expected,
                                 "path": payload.get("path")})
    out["recomputation"] = {"available": MECH.recompute, "fired": bool(findings),
                            "rows_checkable": checkable,
                            "decisive_rows_checkable": decisive,
                            "detail": findings}
    # A separate capability, and a separate answer: "I cannot check this"
    # is not "I checked this and it was fine".
    out["policy_identity"] = {
        "available": MECH.check_policy_id and MECH.recompute,
        "fired": bool(unverifiable), "detail": unverifiable}

    # 3. Completeness -- are all the decisions present. Two independent
    #    signals: an externally known count, and an invocation with no
    #    evidence attached to it.
    gaps = []
    if MECH.completeness:
        if see_count and len(rows) != expected_count:
            gaps.append({"kind": "row_count",
                         "found": len(rows), "expected": expected_count})
        if see_invocations:
            with_evidence = {r.get("invocation_id") for r in rows}
            for inv in invocations:
                if inv["id"] not in with_evidence:
                    gaps.append({"kind": "invocation_without_evidence",
                                 "invocation": inv["id"],
                                 "outcome": inv["outcome"]})
    out["completeness"] = {
        "available": MECH.completeness and (see_count or see_invocations),
        "fired": bool(gaps), "detail": gaps}

    # 4. Consistency -- does the record contradict itself, or its own
    #    invocation. Needs no decision inputs at all.
    clashes = []
    if MECH.consistency:
        for row in rows:
            payload = row.get("payload", {})
            if payload.get("verdict") == "deny" and payload.get(
                    "status") == "executed":
                clashes.append({"kind": "deny_recorded_as_executed",
                                "row": row.get("id")})
        if see_invocations:
            outcome = {i["id"]: i["outcome"] for i in invocations}
            for row in rows:
                got = outcome.get(row.get("invocation_id"))
                status = row.get("payload", {}).get("status")
                if got is None or status is None:
                    continue
                ran = got == "success"
                if ran != (status == "executed"):
                    clashes.append({"kind": "status_contradicts_invocation",
                                    "row": row.get("id"),
                                    "status": status, "outcome": got})
    out["consistency"] = {"available": MECH.consistency, "fired": bool(clashes),
                          "detail": clashes}
    return out


def run(fault="none", omit_inputs=False, scope="full", tamper=False,
        verbose=False):
    tenant = f"{TENANT}-{uuid.uuid4().hex[:8]}"
    corr = f"req-{uuid.uuid4().hex[:8]}"
    gov = Governor(fault, omit_inputs)
    POLICY_CALLS["n"] = 0          # observed by the module, not the subject
    started = time.perf_counter()

    written, invocations, truth = 0, [], []
    for n, (principal, payload) in enumerate(WORKLOAD, start=1):
        verdict = gov.decide(payload)
        executed = verdict == "allow"
        correct = policy_verdict(payload)
        truth.append({"step": n, "principal": principal,
                      "correct_verdict": correct, "governor_verdict": verdict,
                      "executed": executed})

        row = gov.record(payload, verdict, executed)
        with kya.default_session() as db:
            inv = kya.record_invocation(
                db, tenant_id=tenant, agent_key=principal,
                principal_kind="agent", principal_id=principal,
                correlation_id=corr,
                outcome="success" if executed else "denied")
            invocations.append({"id": inv,
                                "outcome": "success" if executed else "denied"})
            if row is not None:
                kya.record_evidence(db, tenant_id=tenant, invocation_id=inv,
                                    evidence_kind="tool_call", payload=row,
                                    correlation_id=corr)
                written += 1
            db.commit()
        if verbose:
            flag = "" if verdict == correct else "   <- WRONG"
            note = "" if row is not None else "   <- not recorded"
            print(f"    {n}. {principal:8} {payload['tool']:11} "
                  f"policy={correct:5} governor={verdict:5}{flag}{note}")

    # The negative control: edit a recorded payload after the fact. Chain
    # integrity must catch this, or "integrity detects nothing" means only
    # that the verifier is inert.
    tampered_row = None
    if tamper:
        with kya.default_session() as db:
            got = db.execute(text(
                "SELECT id, payload FROM kya_evidence WHERE tenant_id=:t "
                "ORDER BY id DESC LIMIT 1"), {"t": tenant}).fetchone()
            if got:
                tampered_row = got[0]
                edited = json.loads(got[1])
                edited["verdict"] = "tampered"
                db.execute(text("UPDATE kya_evidence SET payload=:p "
                                "WHERE id=:i"),
                           {"p": json.dumps(edited), "i": tampered_row})
                db.commit()

    governor_policy_calls = POLICY_CALLS["n"]

    with kya.default_session() as db:
        chains = [kya.verify_chain(db, tenant_id=tenant,
                                   invocation_id=i["id"])
                  for i in invocations]
        rows = kya.list_evidence(db, tenant_id=tenant, correlation_id=corr,
                                 evidence_kind="tool_call", limit=1000)

    # The scope gate lives in audit() alone. It used to be written here as
    # well, and the copy here was provably removable -- one fact in two
    # places, only one of them measured.
    #
    # The expected count comes from the orchestrator that dispatched the
    # work, which is a different artifact from the evidence log. That is
    # what makes it usable as an independent check.
    report_ = audit(rows, invocations, len(WORKLOAD), scope, chains)

    # Ground truth, which the auditor does NOT have. Used only to score the
    # verifiers, never to detect anything.
    wrong = [t for t in truth if t["governor_verdict"] != t["correct_verdict"]]
    violations = [t for t in truth if t["executed"]
                  and t["correct_verdict"] == "deny"]
    fired = sorted(k for k, v in report_.items() if v["fired"])

    return {
        "governor_fault": fault, "omit_inputs": omit_inputs, "scope": scope,
        "tampered": bool(tampered_row),
        "actions": len(WORKLOAD),
        "policy_calls": governor_policy_calls,
        "policy_in_force": gov.policy_in_force(),
        "evidence_rows_written": written,
        "wrong_decisions": len(wrong),
        "wrongly_permitted": len(violations),
        "wrongly_refused": len([t for t in wrong if not t["executed"]]),
        "chain_valid": all(c.get("valid") for c in chains),
        "verifiers": report_,
        "detected_by": fired,
        "detected": bool(fired),
        "elapsed_s": round(time.perf_counter() - started, 2),
        "provenance": lab.PROVENANCE,
    }


def invariants(r):
    """Each has a mutation in governor_sabotage.py that makes it fail."""
    bad = []

    def check(name, ok):
        if not ok:
            bad.append(name)

    v = r["verifiers"]
    # Integrity is about alteration, not correctness. It must stay valid
    # under every governor fault, and must fire the moment a row is edited.
    if not r["tampered"]:
        # One predicate, not two: `integrity.fired` is defined as
        # `not chain_valid`, so asserting both was asserting one twice.
        check("chain_stays_valid_under_every_governor_fault", r["chain_valid"])
    else:
        # No escape hatch for a disabled verifier: an integrity check that
        # is switched off must FAIL this, not be excused from it. That is
        # the whole point of the tamper control.
        check("integrity_detects_an_actual_tamper", v["integrity"]["fired"])
    check("healthy_governor_produces_no_finding",
          r["governor_fault"] != "none" or r["tampered"] or not r["detected"])
    # A capability that cannot run at this scope must say so rather than
    # report a quiet negative.
    check("completeness_reports_its_own_availability",
          v["completeness"]["available"]
          == (MECH.completeness and r["scope"] != "evidence_only"))
    check("recomputation_needs_the_decision_inputs",
          not r["omit_inputs"]
          or v["recomputation"]["decisive_rows_checkable"] == 0)
    # The two faults must be distinguishable, or the experiment claims four
    # classes and tests three.
    # Counted outside the governor, so the subject cannot report a number
    # about itself that the call site contradicts.
    check("an_inert_control_never_calls_the_policy",
          r["governor_fault"] != "inert_control" or r["policy_calls"] == 0)
    check("a_wrong_verdict_control_does_call_the_policy",
          r["governor_fault"] != "wrong_verdict" or r["policy_calls"] > 0)
    check("a_recorded_policy_id_matches_the_policy_actually_applied",
          r["governor_fault"] == "stale_policy"
          or r["policy_in_force"] == POLICY_ID)
    check("only_wrong_verdict_refuses_permitted_work",
          r["governor_fault"] == "wrong_verdict" or r["wrongly_refused"] == 0)
    return bad


def report(r):
    print(f"\n  governor_fault={r['governor_fault']}  "
          f"omit_inputs={r['omit_inputs']}  scope={r['scope']}"
          + ("  TAMPERED" if r["tampered"] else ""))
    print("  " + "-" * 70)
    print(f"    policy calls     {r['policy_calls']} of {r['actions']}")
    print(f"    wrong decisions  {r['wrong_decisions']} "
          f"({r['wrongly_permitted']} wrongly permitted, "
          f"{r['wrongly_refused']} wrongly refused)")
    print(f"    evidence written {r['evidence_rows_written']} of "
          f"{r['actions']}")
    for name in ("integrity", "recomputation", "policy_identity",
                 "completeness", "consistency"):
        v = r["verifiers"][name]
        state = ("unavailable at this scope" if not v["available"]
                 else "DETECTED" if v["fired"] else "nothing found")
        print(f"    {name:14}   {state}")
        for d in v.get("detail", [])[:2]:
            print(f"       {d}")
    bad = invariants(r)
    print(f"    invariants       "
          f"{'all hold' if not bad else 'VIOLATED: ' + ', '.join(bad)}")


_COLS = (f"  {'governor_fault':18} {'inputs':>7} {'scope':>24} "
         f"{'integ':>5} {'recomp':>6} {'polid':>5} {'cmplt':>5} "
         f"{'consist':>7}   detected_by")


def _cell(v):
    return "-" if not v["available"] else ("YES" if v["fired"] else "no")


def _row(r):
    v = r["verifiers"]
    return (f"  {r['governor_fault']:18} "
            f"{('omitted' if r['omit_inputs'] else 'kept'):>7} "
            f"{r['scope']:>24} "
            f"{_cell(v['integrity']):>5} {_cell(v['recomputation']):>6} "
            f"{_cell(v['policy_identity']):>5} "
            f"{_cell(v['completeness']):>5} {_cell(v['consistency']):>7}   "
            f"{','.join(r['detected_by']) or 'nothing'}")


def sweep(args):
    rows = []
    print("\n  which verifier catches which fault, with the inputs recorded")
    print(_COLS)
    print("  " + "-" * 122)
    for fault in FAULTS:
        r = run(fault, False, "full")
        rows.append(r)
        print(_row(r))

    print("\n  the same faults with the decision inputs stripped")
    print(_COLS)
    print("  " + "-" * 122)
    for fault in FAULTS:
        r = run(fault, True, "full")
        rows.append(r)
        print(_row(r))

    print("\n  narrowing what the verifier may see (fault = omitted_record)")
    print(_COLS)
    print("  " + "-" * 122)
    for scope in SCOPES:
        r = run("omitted_record", True, scope)
        rows.append(r)
        print(_row(r))

    print("\n  the integrity control: a row edited after the fact")
    print(_COLS)
    print("  " + "-" * 122)
    r = run("none", False, "full", tamper=True)
    rows.append(r)
    print(_row(r))

    violated = [i + 1 for i, r in enumerate(rows) if invariants(r)]
    print(f"\n  invariants: {len(rows) - len(violated)}/{len(rows)} runs "
          f"clean" + ("" if not violated else f" -- FAILED {violated}"))
    return rows


# (fault, omit_inputs, scope, tamper) -> the verifiers that must fire
EXPECTED = {
    ("none", False, "full", False): [],
    # A wrong verdict and an unreachable control are both visible by
    # recomputing from the inputs.
    ("wrong_verdict", False, "full", False): ["recomputation"],
    ("inert_control", False, "full", False): ["recomputation"],
    # A refusal recorded as an execution contradicts itself. Recomputation
    # does NOT fire: the verdict recorded is the correct one and only the
    # status is a lie, so recomputing verdicts cannot catch a labelling
    # fault.
    ("mislabelled", False, "full", False): ["consistency"],
    # The mirror image contradicts nothing within its own row -- an allow
    # recorded as blocked is a plausible record -- so it is visible only
    # against the invocation it belongs to.
    ("unlogged_execution", False, "full", False): ["consistency"],
    ("unlogged_execution", False, "evidence_only", False): [],
    ("unlogged_execution", False, "evidence_and_invocations", False):
        ["consistency"],
    # A decision never written leaves an invocation with no evidence, and
    # a short row count. Each signal is reachable on its own.
    ("omitted_record", False, "full", False): ["completeness"],
    ("omitted_record", False, "evidence_only", False): [],
    ("omitted_record", False, "evidence_and_count", False): ["completeness"],
    ("omitted_record", False, "evidence_and_invocations", False):
        ["completeness"],
    # The right decision under superseded rules. Recomputation alone would
    # call this a wrong verdict; with the policy identity checked it is
    # reported as unverifiable, which is a different failure needing a
    # different fix.
    ("stale_policy", False, "full", False): ["policy_identity"],
    ("stale_policy", True, "full", False): ["policy_identity"],
    # Strip the inputs and recomputation goes blind to the fault that only
    # wrongly PERMITS -- judging /etc/shadow needs the path. It stays
    # sighted for the fault that also wrongly REFUSES, because a spawn
    # recorded as denied is wrong without any argument to check.
    ("wrong_verdict", True, "full", False): ["recomputation"],
    ("inert_control", True, "full", False): [],
    ("none", True, "full", False): [],
    ("mislabelled", True, "full", False): ["consistency"],
    ("omitted_record", True, "full", False): ["completeness"],
    ("mislabelled", True, "evidence_only", False): ["consistency"],
    ("omitted_record", True, "evidence_only", False): [],
    ("omitted_record", True, "evidence_and_invocations", False):
        ["completeness"],
    # The control: integrity must catch an actual alteration. Recomputation
    # catches it too -- an edited verdict no longer agrees with the policy --
    # which is worth recording rather than engineering around.
    ("none", False, "full", True): ["integrity", "recomputation"],
}


def check(args):
    print("\n  expected outcome matrix")
    print(f"  {'governor_fault':15} {'inputs':>7} {'scope':>24} "
          f"{'tamper':>6}   {'detected_by':28} result")
    print("  " + "-" * 104)
    rows, failures = [], []
    for (fault, omit, scope, tamper), want in EXPECTED.items():
        r = run(fault, omit, scope, tamper)
        rows.append(r)
        got = sorted(r["detected_by"])
        bad = invariants(r)
        ok = got == sorted(want) and not bad
        if not ok:
            failures.append((fault, omit, scope, want, got, bad))
        print(f"  {fault:15} {('omitted' if omit else 'kept'):>7} "
              f"{scope:>24} {str(tamper):>6}   "
              f"{(','.join(got) or 'nothing'):28} "
              f"{'ok' if ok else 'MISMATCH want=' + str(want) + str(bad)}")
    print(f"\n  {len(rows) - len(failures)}/{len(rows)} cells match the "
          f"declared hypothesis")
    return rows, failures


def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--governor-fault", choices=FAULTS, default="none")
    p.add_argument("--omit-inputs", action="store_true",
                   help="record the verdict without what it was decided from")
    p.add_argument("--scope", choices=SCOPES, default="full",
                   help="what the independent verifier is allowed to see")
    p.add_argument("--tamper", action="store_true",
                   help="edit a recorded row afterwards (integrity control)")
    p.add_argument("--sweep", action="store_true")
    p.add_argument("--check", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--out", default=os.path.join(_HERE, "governor.jsonl"))
    p.add_argument("--logs", action="store_true")
    args = p.parse_args()

    lab.PROVENANCE = lab.provenance()

    if args.check:
        rows, failures = check(args)
        print(f"\n  {len(rows)} runs appended to {lab.save(rows, args.out)}")
        return 1 if failures else 0

    if args.sweep:
        rows = sweep(args)
        print(f"\n  {len(rows)} runs appended to {lab.save(rows, args.out)}")
        return 1 if any(invariants(r) for r in rows) else 0

    if not args.json:
        # --json must emit JSON and nothing else, or a caller
        # cannot parse it. The banner is for humans.
        print(f"\n  provenance: veldt-kya {lab.PROVENANCE['veldt_kya']}, "
              f"python {lab.PROVENANCE['python']}")
    r = run(args.governor_fault, args.omit_inputs, args.scope, args.tamper,
            verbose=not args.json)
    print(json.dumps(r, indent=2)) if args.json else report(r)
    saved = lab.save([r], args.out)
    if not args.json:
        print(f"\n  appended to {saved}")
    return 0 if not invariants(r) else 1


if __name__ == "__main__":
    sys.exit(main())
