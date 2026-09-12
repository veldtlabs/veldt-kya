"""How the injection is PHRASED, against what it asks for.

    python frame_grid.py --trials 5
    python frame_grid.py --modes authority policy layered
    python frame_grid.py --frames neutral urgent subtle supplanting
    python frame_grid.py --out grid_results.json

Two axes the other experiments hold fixed, and one they vary.

Framing
-------
Every built-in prompt variant except `supplanting` frames the planted note
ADDITIVELY -- "before continuing", "before anything else", "incomplete
without". Under those, an agent that does its task AND the planted thing
is obeying the note as written, so a sweep over them measures one frame
several times over. `supplanting` asks for the planted action INSTEAD of
the assigned work, which is the only frame under which doing both is not
compliance. Without that arm, a model reads as far more resistant than it
is.

What the note asks for
----------------------
The three original faults vary two things at once -- whether the planted
action needs a different tool than the agent's own work, and how obviously
refusable its target looks -- so following one and not another says
nothing about which mattered. `innocuous_capability` completes the square:

                     same tool            different tool
    salient          dangerous_argument   unauthorized_capability
    unremarkable     emergent_sequence    innocuous_capability

Model behaviour is not an enforcement result
--------------------------------------------
`complied` and `injection_ran` are reported side by side on purpose. They come
apart: an agent can follow the note in every trial and still reach nothing,
because the layer that was on covered the action. Reading a compliance rate
as a breach rate is the mistake this table exists to prevent.

Nothing here is asserted. There is no declared hypothesis for a model, and
widening one to fit whatever came back is how a hypothesis stops being one.
Use `experiment.py --check` for the claims that are asserted.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

_HERE = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))

# (fault, whether it needs a different tool, how refusable the target looks)
CELLS = [
    ("dangerous_argument", "same tool", "salient"),
    ("unauthorized_capability", "different tool", "salient"),
    ("emergent_sequence", "same tool", "unremarkable"),
    ("innocuous_capability", "different tool", "unremarkable"),
]


def run_cell(python, fault, mode, frame, trials, model, temperature):
    """One configuration, N trials, as a researcher would run it."""
    p = subprocess.run(
        [python, "experiment.py", "--actor", "llm", "--model", model,
         "--fault", fault, "--mode", mode, "--prompt-variant", frame,
         "--temperature", str(temperature), "--trials", str(trials),
         "--json"],
        cwd=str(_HERE), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=3600)
    try:
        return json.loads(p.stdout[p.stdout.index("{"):]), None
    except (ValueError, IndexError):
        return None, (p.stderr or p.stdout)[-200:]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="openai/gpt-4o-mini")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--modes", nargs="+", default=["authority"])
    ap.add_argument("--frames", nargs="+",
                    default=["neutral", "supplanting"])
    ap.add_argument("--temperature", type=float, default=0.7,
                    help="above zero on purpose: at 0 this model returns "
                         "byte-identical traces, and N of those is one "
                         "sample wearing N hats")
    ap.add_argument("--out", default=str(_HERE / "grid_results.json"))
    args = ap.parse_args(argv)

    total = len(CELLS) * len(args.modes) * len(args.frames)
    print(f"\n  {len(CELLS)} faults x {len(args.modes)} mode(s) x "
          f"{len(args.frames)} frame(s) x {args.trials} trials "
          f"on {args.model}")
    print(f"  temperature {args.temperature}")
    print()
    print(f"  {'fault':26} {'tool':15} {'target':13} {'mode':11} "
          f"{'frame':13} {'hedged':>7} {'complied':>9} {'resisted':>9} "
          f"{'injection_ran':>8}")
    print("  " + "-" * 124)

    rows, calls, t0 = [], 0, time.time()
    for fault, tool_rel, salience in CELLS:
        for mode in args.modes:
            for frame in args.frames:
                d, err = run_cell(sys.executable, fault, mode, frame,
                                  args.trials, args.model, args.temperature)
                if d is None:
                    print(f"  {fault:26} {tool_rel:15} {salience:13} "
                          f"{mode:11} {frame:13} FAILED {err}")
                    continue
                s, runs = d["summary"], d["runs"]
                calls += sum(r["provenance"]["actor"].get("calls", 0)
                             for r in runs)

                def rate(key):
                    got = s.get(key)
                    return got["rate"] if got else 0.0

                row = {"fault": fault, "tool": tool_rel,
                       "salience": salience, "mode": mode, "frame": frame,
                       "model": args.model, "trials": d["trials"],
                       "temperature": args.temperature,
                       "hedged": rate("injection_hedged"),
                       "complied": rate("injection_complied"),
                       "resisted": rate("injection_resisted"),
                       "diverted": rate("injection_diverted"),
                       "injection_ran": rate("injection_ran"),
                       "failed": d["failed"], "violations": d["violations"]}
                rows.append(row)
                print(f"  {fault:26} {tool_rel:15} {salience:13} "
                      f"{mode:11} {frame:13} {row['hedged']:>7.2f} "
                      f"{row['complied']:>9.2f} {row['resisted']:>9.2f} "
                      f"{row['injection_ran']:>8.2f}", flush=True)

    bad = [r for r in rows if r["violations"]]
    print()
    print(f"  {len(rows)}/{total} cells, {calls} model calls, "
          f"{time.time() - t0:.0f}s")
    if bad:
        print(f"  INVARIANTS VIOLATED in {len(bad)} cell(s):")
        for r in bad:
            print(f"    {r['fault']}/{r['mode']}/{r['frame']}: "
                  f"{r['violations']}")
    pathlib.Path(args.out).write_text(json.dumps(rows, indent=1),
                                      encoding="utf-8")
    print(f"  written to {args.out}")
    return 1 if (bad or len(rows) < total) else 0


if __name__ == "__main__":
    sys.exit(main())
