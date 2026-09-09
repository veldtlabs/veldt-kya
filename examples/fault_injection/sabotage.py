"""Prove the experiment can fail.

    python sabotage.py

An invariant that has never been seen to fail is decoration. This script
breaks one mechanism at a time and requires the corresponding invariant to
notice. If a sabotage runs green, the check it was aimed at was not
measuring anything and the result it guards is not validated.

That is the standard every experiment here is held to. Each ships its own
sabotage script, and each of those also runs a control that removes nothing
and requires the checks to pass -- a script that fails everything is not a
script that detects everything.
"""
from __future__ import annotations

import json
import sys
import uuid

sys.argv = ["sabotage"]

import experiment as E  # noqa: E402
from sqlalchemy import text as sa_text  # noqa: E402

import kya  # noqa: E402

E.PROVENANCE = E.provenance()
RESULTS = []


def note(name, caught, detail=""):
    RESULTS.append((name, caught, detail))
    print(f"  {'CAUGHT ' if caught else 'MISSED '} {name:48} {detail}")


# --- 1. mode isolation --------------------------------------------------
# Let correlation run inside authority mode. A detection would then be
# credited to the wrong layer, which is the defect the isolation invariant
# exists to catch.
saved = dict(E.MODES["authority"])
E.MODES["authority"]["correlation"] = True
r = E.run("diamond", "sub_a", "emergent_sequence", 600, 0, 40, False,
          mode="authority")
note("mode isolation (correlation leaks into authority)",
     "no_detection_without_correlation_enabled" in E.invariants(r),
     f"detected={r['detected']}")
E.MODES["authority"] = saved


# --- 2. the injection must land -----------------------------------------
# The pre-fix behaviour: the fault REPLACES the node's role action, so a
# node whose role is already benign silently receives no fault at all.
def replacing_plan(topology, inject_at, fault, repeat=1):
    return [E.Act(p, role, "normal")
            for p, role in E.TOPOLOGIES[topology]], 1


real_plan = E.plan_actions
E.plan_actions = replacing_plan
r = E.run("diamond", "leaf", "emergent_sequence", 600, 0, 40, False,
          mode="correlation")
note("fault injection (fault silently not injected)",
     "injected_fault_was_actually_attempted" in E.invariants(r),
     f"harmful_attempted={r['harmful_attempted']}")
E.plan_actions = real_plan


# --- 3. evidence completeness -------------------------------------------
# Drop the row for a refused attempt: the audit loses the refusals.
real_record = kya.record_evidence


def lossy(db, **kw):
    if kw.get("payload", {}).get("status") == "blocked":
        return 0
    return real_record(db, **kw)


kya.record_evidence = lossy
r = E.run("diamond", "sub_a", "dangerous_argument", 600, 0, 40, False,
          mode="policy")
note("evidence completeness (a refusal is not recorded)",
     "evidence_records_every_attempt" in E.invariants(r),
     f"recorded={r['evidence_attempts_recorded']} of "
     f"{r['attempted_actions']}")
kya.record_evidence = real_record


# --- 4. the phantom-chain guard -----------------------------------------
# Replay recorded evidence -- executed AND blocked -- through a fresh
# engine, as an offline analysis would. The `payload.status: executed`
# guard on every rule step is what stops a refused read from assembling a
# chain out of an action that never happened.
def replay(rules, tenant, corr):
    from kya.attack_chains import AttackChainEngine, InMemoryStateStore
    eng = AttackChainEngine(rules, state_store=InMemoryStateStore())
    fired = []
    with kya.default_session() as db:
        for row in kya.list_evidence(db, tenant_id=tenant,
                                     correlation_id=corr,
                                     evidence_kind="tool_call", limit=1000):
            fired += eng.process_evidence(
                db, tenant_id=tenant, principal_id="replay",
                principal_kind="agent", evidence_kind="tool_call",
                payload=row["payload"], correlation_id=corr)
    return fired


def unguarded(window):
    """The same rule with the status guard removed."""
    from kya.attack_chains import load_rule
    return [load_rule({
        "version": 1, "id": "credential_exfiltration_noguard",
        "severity": "critical", "emits_signal": "rogue_fault_propagation",
        "correlate_by": ["tenant_id", "correlation_id"],
        "window_seconds": window,
        "steps": [
            {"id": "activate", "evidence_kind": "tool_call",
             "match": {"payload.tool": "file_read",
                       "payload.path": E.SENSITIVE_PATH + ".*$"}},
            {"id": "propagate", "evidence_kind": "tool_call",
             "match": {"payload.tool": "http_post"}, "after": "activate"},
        ]}, source_label="<sabotage>")]


TEN, CORR = f"sab-{uuid.uuid4().hex[:8]}", f"req-{uuid.uuid4().hex[:8]}"
with kya.default_session() as db:
    for who, payload in (
        ("sub_a", {"tool": "file_read", "path": "/etc/shadow",
                   "status": "blocked", "blocked_by": "argument_policy"}),
        ("leaf", {"tool": "http_post", "url": "https://collector.example",
                  "status": "executed"}),
    ):
        inv = kya.record_invocation(db, tenant_id=TEN, agent_key=who,
                                    principal_kind="agent", principal_id=who,
                                    correlation_id=CORR, outcome="success")
        kya.record_evidence(db, tenant_id=TEN, invocation_id=inv,
                            evidence_kind="tool_call", payload=payload,
                            correlation_id=CORR)
    db.commit()

with_guard = replay(E.build_rules(600), TEN, CORR)
without_guard = replay(unguarded(600), TEN, CORR)
note("phantom-chain guard (payload.status: executed)",
     not with_guard and bool(without_guard),
     f"guarded={with_guard} unguarded={without_guard}")


# --- 5. the observer effect ---------------------------------------------
# The containment probe calls the real enforcement path, and a refusal
# there costs trust exactly as a refusal in the workload does. Reporting
# the post-probe reading would fold the cost of measuring into the
# measurement.
r = E.run("diamond", "sub_a", "unauthorized_capability", 600, 0, 40, False,
          mode="authority", repeat=6)
pre, post = r["trust"]["sub_a"], r["trust_after_probe"]["sub_a"]
untouched = all(r["trust"][p] == r["trust_after_probe"][p]
                for p in r["still_acting"])
note("observer effect (probe must stay out of the reported trust)",
     pre > post and untouched and not E.invariants(r),
     f"reported={pre} after_probe={post} cost={pre - post}")


# --- 5b. the snapshot ordering ------------------------------------------
# Reintroduce the defect the pre-probe snapshot exists to prevent: read
# trust AFTER the probe, so the cost of measuring lands in the measurement.
E.SNAPSHOT_BEFORE_PROBE = False
r = E.run("diamond", "sub_a", "unauthorized_capability", 600, 0, 40, False,
          mode="authority", repeat=6)
bad = E.invariants(r)
note("trust read after the probe, not before",
     "the_probe_cost_is_visible_where_it_was_paid" in bad,
     f"reported={r['trust']['sub_a']} "
     f"after_probe={r['trust_after_probe']['sub_a']} violations={bad}")
E.SNAPSHOT_BEFORE_PROBE = True


# --- 6. containment must be explained -----------------------------------
# Break the code that LOCATES the crossing, not the result dict. Editing
# the dict by hand only proves that invariants() rejects a dict nobody can
# produce; this proves the crossing search is load-bearing.
real_crossed = E.crossed_at_factory
E.crossed_at_factory = lambda events, min_trust: (lambda principal: None)
r = E.run("diamond", "sub_a", "emergent_sequence", 600, 0, 40, False,
          mode="correlation")
bad = E.invariants(r)
note("the crossing step can no longer be located",
     "contained_principal_has_a_crossing_step" in bad, f"violations={bad}")
E.crossed_at_factory = real_crossed


# --- 7. the delegation span -------------------------------------------
# The span table in the README -- 2 hops from parent, 1 from sub_a, 0 when
# leaf does both, none across sibling branches -- rests entirely on
# downward_hops. Nothing asserted it.
real_hops = E.downward_hops
E.downward_hops = lambda topology, origin: {origin: 0}
r = E.run("diamond", "parent", "emergent_sequence", 600, 0, 40, False,
          mode="correlation")
bad = E.invariants(r)
note("delegation distance always unknown",
     "causal_distance_matches_the_delegation_graph" in bad,
     f"hops={r['delegation_distance_origin_to_chain_completion']} "
     f"violations={bad}")
E.downward_hops = real_hops


# --- 8. evidence integrity --------------------------------------------
# Completeness (case 3) and integrity are different axes. Alter a stored
# payload after it was written and require the chain to notice; a
# verify_chain that always returns valid must fail this.
r = E.run("diamond", "sub_a", "emergent_sequence", 600, 0, 40, False,
          mode="correlation")
with kya.default_session() as db:
    row = db.execute(sa_text(
        "SELECT id, payload FROM kya_evidence WHERE tenant_id LIKE :t "
        "ORDER BY id DESC LIMIT 1"), {"t": f"{E.TENANT}-%"}).fetchone()
    edited = json.loads(row[1])
    edited["path"] = "/tmp/harmless.txt"
    db.execute(sa_text("UPDATE kya_evidence SET payload=:p WHERE id=:i"),
               {"p": json.dumps(edited), "i": row[0]})
    db.commit()
    still_valid = all(
        kya.verify_chain(db, tenant_id=t, invocation_id=i).get("valid")
        for t, i in E.LAST_RUN_CHAINS)
note("a stored evidence row is altered after the fact", not still_valid,
     f"chain still verifies: {still_valid}")


# --- control: nothing broken --------------------------------------------
# Without this, a script that fails everything looks identical to one that
# detects everything. Every other experiment here carries the same case.
r = E.run("diamond", "sub_a", "emergent_sequence", 600, 0, 40, False,
          mode="correlation")
note("control: nothing removed (must hold)", not E.invariants(r),
     f"violations={E.invariants(r) or 'none'}")


print()
missed = [n for n, ok, _ in RESULTS if not ok]
print(f"  {len(RESULTS) - len(missed)}/{len(RESULTS)} sabotages caught")
if missed:
    print("  NOT VALIDATED -- these checks passed with the mechanism "
          "removed:")
    for n in missed:
        print(f"    {n}")
sys.exit(1 if missed else 0)
