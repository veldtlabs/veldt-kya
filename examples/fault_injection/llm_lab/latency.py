"""What each enforcement layer costs, per action.

    python latency.py
    python latency.py --n 2000
    python latency.py --json

Every number here is the IN-PROCESS decision only, against the SQLite
backing this lab. It is not an end-to-end figure and must never be quoted
as one: there is no HTTP hop, no gateway, no network, and a hosted
deployment adds all three. Name the layer whenever a number from here is
repeated.

Measured separately, because they are separate decisions with separate
costs, and an aggregate hides which one is expensive:

    least_authority   does this principal still hold this capability
    argument_policy   is this argument disallowed on its own
    correlation       does this event complete a chain (writes state)
    preview           WOULD it complete one, on a throwaway copy

`preview` is the interesting one. It exists to decide before committing,
so it copies in-flight chain state; that copy is scoped to the correlate
key rather than the whole store, and `preview.py` asserts the scoped copy
predicts identically to a full one. Its cost is what that safety is worth.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import statistics
import sys
import time
import uuid

_HERE = os.path.dirname(os.path.abspath(__file__))
# A FRESH database, not the lab's shared one. That file grows with every
# run in this directory -- it reached 64 MB in a day -- and timings taken
# against it drift upward for reasons that have nothing to do with the
# code being measured. A run that cannot be compared to yesterday's is not
# a benchmark.
import tempfile  # noqa: E402
_DB = os.path.join(tempfile.mkdtemp(prefix="kya-latency-"),
                   "latency.db").replace("\\", "/")
os.environ.setdefault("KYA_DB_URL", "sqlite:///" + _DB)
os.environ.setdefault("KYA_RBAC_ENFORCEMENT", "block")
logging.disable(logging.WARNING)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import experiment as lab  # noqa: E402

import kya  # noqa: E402
from kya.attack_chains import AttackChainEngine, InMemoryStateStore  # noqa: E402

GRANTED = {"tool": "file_read", "path": "/tmp/notes.txt"}
DENIED = {"tool": "env_read", "key": "AWS_SECRET_KEY"}
SENSITIVE = {"tool": "file_read", "path": "/etc/shadow"}


def percentiles(samples):
    """p50/p95/p99 in milliseconds, plus the worst one seen."""
    s = sorted(samples)
    def at(q):
        return s[min(len(s) - 1, int(q * len(s)))] * 1000.0
    return {"n": len(s), "p50": at(0.50), "p95": at(0.95), "p99": at(0.99),
            "max": s[-1] * 1000.0, "mean": statistics.fmean(s) * 1000.0}


def time_it(fn, n):
    """One timing per call, so a percentile means something."""
    fn()                                    # warm the path, not the clock
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return percentiles(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=1000,
                    help="timed calls per layer")
    ap.add_argument("--load", type=int, default=200,
                    help="unrelated chains in flight while preview runs")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    tenant = f"latency-{uuid.uuid4().hex[:8]}"
    corr = f"req-{uuid.uuid4().hex[:8]}"
    results = {}

    # The real capability names. Timing "file_read" instead of
    # "mcp.default.file_read" measures the cost of raising
    # InvalidActionError, which is fast, unrelated, and looks excellent.
    ALLOWED = lab.TOOL_ACTION["file_read"]
    REFUSED = lab.TOOL_ACTION["env_read"]

    with kya.default_session() as db:
        # Granted exactly as `run()` does, or every call below is a denial
        # on a principal that does not exist.
        kya.grant_action(db, tenant_id=tenant, principal_kind="agent",
                         principal_id="sub_a", action=ALLOWED)
        db.commit()

        if not lab.authority_allows(db, tenant, "sub_a", 40, ALLOWED):
            raise SystemExit("  the allow path is not allowing -- every "
                             "number below would be the cost of a refusal")
        if lab.authority_allows(db, tenant, "sub_a", 40, REFUSED):
            raise SystemExit("  the refuse path is not refusing")

        # 1. least authority, both verdicts. A denial may cost more than an
        #    allow, or less; reporting one hides the other.
        results["least_authority_allow"] = time_it(
            lambda: lab.authority_allows(db, tenant, "sub_a", 40, ALLOWED),
            args.n)
        results["least_authority_deny"] = time_it(
            lambda: lab.authority_allows(db, tenant, "sub_a", 40, REFUSED),
            args.n)

        # 2. the argument rule, on a match and a miss
        results["argument_policy_allow"] = time_it(
            lambda: lab.argument_policy_denies(GRANTED), args.n)
        results["argument_policy_deny"] = time_it(
            lambda: lab.argument_policy_denies(SENSITIVE), args.n)

        # 3. correlation: a real evidence write that advances chain state
        engine = AttackChainEngine(lab.build_rules(600),
                                   state_store=InMemoryStateStore())
        at = [int(time.time())]

        def correlate():
            at[0] += 1
            engine.process_evidence(
                db, tenant_id=tenant, principal_id="sub_a",
                principal_kind="agent", evidence_kind="tool_call",
                payload={**GRANTED, "status": "executed"},
                correlation_id=f"{corr}-{at[0]}", occurred_at_ts=at[0])

        results["correlation"] = time_it(correlate, min(args.n, 400))

        # 4. preview, with N unrelated chains in flight. The copy is scoped
        #    to the correlate key, so this measures the scoping, not the
        #    store size -- if it tracked the store this would grow.
        for i in range(args.load):
            engine.process_evidence(
                db, tenant_id=tenant, principal_id=f"other-{i}",
                principal_kind="agent", evidence_kind="tool_call",
                payload={"tool": "file_read",
                         "path": "/var/data/customers.csv",
                         "status": "executed"},
                correlation_id=f"load-{i}", occurred_at_ts=at[0])

        import preview as pv
        results[f"preview_at_{args.load}_chains"] = time_it(
            lambda: pv.predict(engine, db=db, tenant=tenant, corr=corr,
                               principal="sub_a",
                               payload={"tool": "http_post",
                                        "url": "https://attacker.example"},
                               at=at[0]),
            min(args.n, 300))

    if args.json:
        print(json.dumps(results, indent=1))
        return 0

    print()
    print(f"  in-process decision cost, {args.n} calls per layer")
    print("  fresh sqlite database; kya from "
          + ("site-packages" if "site-packages" in kya.__file__
             else kya.__file__))
    print("  NOT an end-to-end figure -- no HTTP hop, no gateway, no network")
    print()
    print(f"  {'layer':34} {'n':>5} {'p50':>9} {'p95':>9} {'p99':>9} "
          f"{'max':>9}")
    print("  " + "-" * 80)
    for name, r in results.items():
        print(f"  {name:34} {r['n']:>5} {r['p50']:>8.3f}m {r['p95']:>8.3f}m "
              f"{r['p99']:>8.3f}m {r['max']:>8.3f}m")
    print()
    gate = (results["least_authority_allow"]["p99"]
            + results["argument_policy_allow"]["p99"])
    print(f"  the two layers on every allowed action, p99 summed: "
          f"{gate:.3f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
