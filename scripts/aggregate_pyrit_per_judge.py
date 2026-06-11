"""Aggregate one PyRIT sweep JSON into a per-judge-vs-PyRIT-scorer
breakdown. Same shape as Garak's per-judge-vs-ground-truth table.

For each conversation:
  - PyRIT verdict      = any turn with pyrit_scorer_verdict==BREACH
  - Per-judge verdict  = any turn with panel_judge_details[J].verdict==BREACH

Then per judge:
  - TP = panel-judge BREACH on PyRIT-BREACH convs
  - FP = panel-judge BREACH on PyRIT-OK    convs
  - Agree-on-attack = same as TP
  - Agree-on-clean  = panel-judge OK on PyRIT-OK convs
  - Disagree count  = TP-miss (panel-judge OK on PyRIT-BREACH) +
                      FP (panel-judge BREACH on PyRIT-OK)

Usage::

  python scripts/aggregate_pyrit_per_judge.py \\
      --pyrit-json bench_results/pyrit_novel_<UTC>.json \\
      --output bench_results/pyrit_per_judge_<UTC>.md
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path


def _conv_pyrit_verdict(conv: dict) -> str:
    """Any-turn BREACH → BREACH, else OK (matches the script's
    rec.pyrit_final_verdict)."""
    return "BREACH" if conv.get("pyrit_final_verdict") == "BREACH" else "OK"


def _conv_judge_verdict(conv: dict, judge: str) -> str:
    """Any-turn BREACH for this judge → BREACH, else OK. SPLIT and
    UNCLEAR are treated as not-BREACH for this binary comparison."""
    for turn in conv.get("turns", []):
        details = turn.get("panel_judge_details", {}) or {}
        verdict = (details.get(judge) or {}).get("verdict", "OK")
        if verdict == "BREACH":
            return "BREACH"
    return "OK"


def _conv_judge_any_unclear_or_err(conv: dict, judge: str) -> str:
    """Worst-case verdict for the judge: ERROR > UNCLEAR > BREACH > OK."""
    seen = set()
    for turn in conv.get("turns", []):
        details = turn.get("panel_judge_details", {}) or {}
        seen.add((details.get(judge) or {}).get("verdict", "OK"))
    for tier in ("ERROR", "UNCLEAR", "BREACH"):
        if tier in seen:
            return tier
    return "OK"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pyrit-json", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    src = Path(args.pyrit_json)
    d = json.load(open(src, encoding="utf-8"))
    convs = d.get("conversations", [])
    if not convs:
        print("no conversations to aggregate", file=sys.stderr)
        sys.exit(1)

    # Discover judges from any populated turn
    judge_names: set[str] = set()
    for c in convs:
        for t in c.get("turns", []):
            judge_names.update((t.get("panel_judge_details") or {}).keys())
    judges = sorted(judge_names)

    # Bucket convs by PyRIT verdict
    pyrit_breach = [c for c in convs if _conv_pyrit_verdict(c) == "BREACH"]
    pyrit_ok = [c for c in convs if _conv_pyrit_verdict(c) == "OK"]

    rows = []
    for j in judges:
        tp = sum(1 for c in pyrit_breach
                 if _conv_judge_verdict(c, j) == "BREACH")
        fp = sum(1 for c in pyrit_ok
                 if _conv_judge_verdict(c, j) == "BREACH")
        # Worst-case (any-turn UNCLEAR/ERROR) on each bucket — useful
        # to see judges that ABSTAINED rather than disagreed
        unclear_on_breach = sum(
            1 for c in pyrit_breach
            if _conv_judge_any_unclear_or_err(c, j) == "UNCLEAR"
        )
        err_on_breach = sum(
            1 for c in pyrit_breach
            if _conv_judge_any_unclear_or_err(c, j) == "ERROR"
        )
        rows.append({
            "judge": j,
            "tp": tp,
            "fp": fp,
            "miss_on_pyrit_breach": len(pyrit_breach) - tp,
            "agree_on_clean": sum(
                1 for c in pyrit_ok
                if _conv_judge_verdict(c, j) == "OK"
            ),
            "unclear_on_breach": unclear_on_breach,
            "err_on_breach": err_on_breach,
        })

    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = {
        "summary_timestamp_utc": ts,
        "source_json": str(src),
        "total_convs": len(convs),
        "pyrit_breach_count": len(pyrit_breach),
        "pyrit_ok_count": len(pyrit_ok),
        "per_judge": rows,
    }
    json_path = args.output.replace(".md", ".json")
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(json_path).write_text(
        json.dumps(payload, indent=2), encoding="utf-8")

    md = [
        f"# Per-judge vs PyRIT-scorer breakdown — {ts}",
        "",
        f"Source: `{src.name}`",
        f"Total conversations: **{len(convs)}**  "
        f"(PyRIT BREACH: **{len(pyrit_breach)}**, "
        f"PyRIT OK: **{len(pyrit_ok)}**)",
        "",
        "Verdict-per-conversation = any-turn BREACH for that judge "
        "(or PyRIT). SPLIT / UNCLEAR / ERROR shown as separate "
        "columns for the BREACH bucket so abstain ≠ disagree.",
        "",
        "| Judge | TP (agree on attack) | FP (panel BREACH on PyRIT-OK) "
        "| Miss (panel OK on PyRIT-BREACH) | Agree on clean | "
        "UNCLEAR/ERR on attack |",
        "|---|---|---|---|---|---|",
    ]
    nb = max(len(pyrit_breach), 1)
    nok = max(len(pyrit_ok), 1)
    for r in rows:
        md.append(
            f"| `{r['judge']}` | "
            f"**{r['tp']}/{len(pyrit_breach)}** "
            f"({100*r['tp']/nb:.0f}%) | "
            f"{r['fp']}/{len(pyrit_ok)} ({100*r['fp']/nok:.0f}%) | "
            f"{r['miss_on_pyrit_breach']}/{len(pyrit_breach)} "
            f"({100*r['miss_on_pyrit_breach']/nb:.0f}%) | "
            f"{r['agree_on_clean']}/{len(pyrit_ok)} "
            f"({100*r['agree_on_clean']/nok:.0f}%) | "
            f"unc={r['unclear_on_breach']}/{len(pyrit_breach)} "
            f"err={r['err_on_breach']}/{len(pyrit_breach)} |"
        )
    Path(args.output).write_text("\n".join(md), encoding="utf-8")

    print(f"Per-judge-vs-PyRIT summary written:")
    print(f"  MD:   {args.output}")
    print(f"  JSON: {json_path}")
    print()
    print(f"  Convs: {len(convs)} ({len(pyrit_breach)} PyRIT BREACH, "
          f"{len(pyrit_ok)} PyRIT OK)")
    for r in rows:
        agree = r['tp'] + r['agree_on_clean']
        print(f"  {r['judge']:28s} TP={r['tp']}/{len(pyrit_breach)} "
              f"FP={r['fp']}/{len(pyrit_ok)} "
              f"agree={agree}/{len(convs)}")


if __name__ == "__main__":
    main()
