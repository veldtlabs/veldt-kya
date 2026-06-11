"""Aggregate N independent Garak sweep JSONs into a median + IQR
summary across runs. Reads every garak_sweep_<UTC>.json file in the
specified directory, computes per-run stats (lenient TP, strict TP,
strict FP, lenient FP, landed-rate, attempt count), then reports
median + IQR + min/max across runs.

Usage::

  python scripts/aggregate_garak_runs.py \\
      --run-files bench_results/garak_sweep_20260605T*.json \\
      --output bench_results/garak_multirun_summary_<UTC>.md
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import statistics
import sys
from pathlib import Path


def _iqr(values: list[float]) -> float:
    """Interquartile range (P75 - P25). Uses the inclusive quantiles
    method for small N."""
    if len(values) < 2:
        return 0.0
    qs = statistics.quantiles(values, n=4, method="inclusive")
    return qs[2] - qs[0]  # P75 - P25


def _stat_block(name: str, values: list[float]) -> dict:
    if not values:
        return {"name": name, "n": 0}
    return {
        "name": name,
        "n": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "iqr": _iqr(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "values_pct": [f"{100*v:.1f}%" for v in values],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--run-files", nargs="+", required=True,
        help="Glob patterns for the per-run JSONs to aggregate.")
    parser.add_argument(
        "--output", required=True,
        help="Output MD path. JSON written alongside.")
    parser.add_argument(
        "--exclude", nargs="*", default=[],
        help="Substrings — any JSON whose path contains one of these "
             "is skipped (e.g. 'smoke' to drop smoke runs).")
    args = parser.parse_args()

    # Expand globs
    files = []
    for pattern in args.run_files:
        files.extend(glob.glob(pattern))
    files = sorted(set(files))
    files = [f for f in files
             if not any(ex in f for ex in args.exclude)]
    if not files:
        print("No matching files.", file=sys.stderr)
        sys.exit(1)

    per_run = []
    for f in files:
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception as exc:
            print(f"WARN: skipping {f}: {exc}", file=sys.stderr)
            continue
        rpt = d.get("report", {})
        agg = rpt.get("aggregate", {})
        total = agg.get("total_attempts", 0)
        landed = agg.get("garak_landed", 0)
        clean = agg.get("garak_clean", 0)
        if landed <= 0 or clean <= 0:
            print(f"WARN: degenerate run in {f}: "
                  f"landed={landed} clean={clean}", file=sys.stderr)
            continue
        per_run.append({
            "file": f,
            "timestamp_utc": rpt.get("timestamp_utc", "?"),
            "total_attempts": total,
            "garak_landed": landed,
            "garak_clean": clean,
            "panel_strict_tp_rate": agg["panel_strict_tp"] / landed,
            "panel_lenient_tp_rate": agg["panel_tp"] / landed,
            "panel_strict_fp_rate": agg["panel_strict_fp"] / clean,
            "panel_lenient_fp_rate": agg["panel_fp"] / clean,
            "garak_landing_rate": landed / total,
            "per_judge_tp": agg.get("per_judge_tp", {}),
            "per_judge_fp": agg.get("per_judge_fp", {}),
        })

    n = len(per_run)
    if n == 0:
        print("No valid runs to aggregate.", file=sys.stderr)
        sys.exit(2)

    # Aggregate distributions
    stats = {
        "panel_lenient_tp": _stat_block(
            "lenient TP (BREACH or SPLIT on landed)",
            [r["panel_lenient_tp_rate"] for r in per_run]),
        "panel_strict_tp": _stat_block(
            "strict TP (BREACH only on landed)",
            [r["panel_strict_tp_rate"] for r in per_run]),
        "panel_lenient_fp": _stat_block(
            "lenient FP (BREACH or SPLIT on clean)",
            [r["panel_lenient_fp_rate"] for r in per_run]),
        "panel_strict_fp": _stat_block(
            "strict FP (BREACH only on clean)",
            [r["panel_strict_fp_rate"] for r in per_run]),
        "garak_landing_rate": _stat_block(
            "Garak attack landing rate",
            [r["garak_landing_rate"] for r in per_run]),
    }

    # Per-judge across runs
    judge_names = set()
    for r in per_run:
        judge_names.update(r["per_judge_tp"].keys())
        judge_names.update(r["per_judge_fp"].keys())
    per_judge_stats = {}
    for j in sorted(judge_names):
        tp_rates = [r["per_judge_tp"].get(j, 0) / r["garak_landed"]
                    for r in per_run]
        fp_rates = [r["per_judge_fp"].get(j, 0) / r["garak_clean"]
                    for r in per_run]
        per_judge_stats[j] = {
            "tp": _stat_block(f"{j} TP", tp_rates),
            "fp": _stat_block(f"{j} FP", fp_rates),
        }

    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    summary = {
        "summary_timestamp_utc": ts,
        "n_runs": n,
        "per_run": per_run,
        "panel_stats": stats,
        "per_judge_stats": per_judge_stats,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    json_path = args.output.replace(".md", ".json")
    Path(json_path).write_text(json.dumps(summary, indent=2),
                               encoding="utf-8")

    # Human MD
    md = [
        f"# Garak multi-run summary — {ts}",
        "",
        f"Runs aggregated: **{n}**",
        f"Source files:",
        *[f"- `{r['file']}` (ts={r['timestamp_utc']}, "
          f"N={r['total_attempts']}, landed={r['garak_landed']})"
          for r in per_run],
        "",
        "## Panel-vs-Garak combined consensus (across runs)",
        "",
        "| Metric | Median | IQR | Min | Max | Per-run values |",
        "|---|---|---|---|---|---|",
    ]
    for key, s in stats.items():
        md.append(
            f"| {s['name']} | **{100*s['median']:.1f}%** | "
            f"{100*s['iqr']:.1f}pp | {100*s['min']:.1f}% | "
            f"{100*s['max']:.1f}% | {' '.join(s['values_pct'])} |"
        )
    md.append("")
    md.append("## Per-judge TP / FP (across runs)")
    md.append("")
    md.append("| Judge | TP median | TP IQR | FP median | FP IQR |")
    md.append("|---|---|---|---|---|")
    for j, s in per_judge_stats.items():
        tp, fp = s["tp"], s["fp"]
        md.append(
            f"| `{j}` | "
            f"**{100*tp['median']:.1f}%** | {100*tp['iqr']:.1f}pp | "
            f"**{100*fp['median']:.1f}%** | {100*fp['iqr']:.1f}pp |"
        )
    Path(args.output).write_text("\n".join(md), encoding="utf-8")

    print(f"Aggregated {n} runs → {args.output}")
    print(f"  + JSON: {json_path}")
    # Console headline
    lt = stats["panel_lenient_tp"]
    sf = stats["panel_strict_fp"]
    print(f"  Panel lenient TP: median {100*lt['median']:.1f}% "
          f"(IQR {100*lt['iqr']:.1f}pp, range {100*lt['min']:.1f}-"
          f"{100*lt['max']:.1f}%)")
    print(f"  Panel strict FP : median {100*sf['median']:.1f}% "
          f"(IQR {100*sf['iqr']:.1f}pp)")


if __name__ == "__main__":
    main()
