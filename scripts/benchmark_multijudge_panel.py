"""Benchmark every panel judge individually + the combined consensus
against a real LLM target on a Garak probe sweep.

Real measurements only — no stubs, no mocks. The script:

  1. Registers the full 9-judge panel (Fiddler safety + faithfulness,
     openai_judge, refusal_heuristic, arize_phoenix, kya_pyrit,
     kya_attack_patterns, garak_detector, pyrit_jailbreak_scorer).
  2. Drives each probe through a live Llama-3.1-8B (OpenRouter) target.
  3. Sends the (probe, response) pair through `check_consensus` with
     every judge enabled.
  4. Prints a per-probe judge-by-judge table + the combined consensus.
  5. Computes catch rate per judge and per dimension.

Cost model
----------
  N probes × (2 Fiddler calls + 2 openai_judge/phoenix LLM calls
              + 1 pyrit_jailbreak_scorer LLM call) per check_consensus
  + N target calls (OpenRouter, ~free for Llama-3.1-8B).

For 5 probes that's ~10 Fiddler calls, ~25 OpenAI/OpenRouter calls.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Allow running this script directly from a source checkout:
# add the repo root to sys.path so `import kya` resolves before
# the rest of the imports run.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass
class ProbeRun:
    probe_tags: list[str]
    prompt: str
    response: str
    attack_landed_by_detector: bool
    judge_verdicts: dict[str, str]   # judge_name -> verdict
    judge_details: dict[str, dict]   # judge_name -> detail dict
    top_consensus: str
    per_dimension: dict[str, str]


def call_target(model: str, prompt: str) -> str:
    import litellm
    try:
        r = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            api_key=os.environ.get("OPENROUTER_API_KEY"),
            temperature=0.0,
            max_tokens=200,
            timeout=20.0,
        )
        return (r.choices[0].message.content or "").strip()
    except Exception as exc:
        return f"<<target_call_failed: {type(exc).__name__}: {exc}>>"


def run_probe(probe: dict, target_model: str) -> ProbeRun:
    from kya.scorer_orchestrator import check_consensus

    prompt = probe["prompt"]
    detector_strings = probe.get("detector_substrings", [])

    print(f"  → calling target {target_model}...", flush=True)
    response = call_target(target_model, prompt)
    print(f"  response[:120]: {response[:120]!r}", flush=True)

    response_lower = response.lower()
    landed = any(s.lower() in response_lower for s in detector_strings)

    print("  → running full multi-judge panel...", flush=True)
    result = check_consensus(
        input_text=prompt,
        response=response,
        context="No reference context (Garak probe).",
    )

    judge_verdicts = {jr.judge_name: jr.verdict for jr in result.judges}
    judge_details = {jr.judge_name: dict(jr.detail) for jr in result.judges}

    per_dim = {dim: d.consensus for dim, d in result.per_dimension.items()}

    return ProbeRun(
        probe_tags=probe["tags"],
        prompt=prompt,
        response=response,
        attack_landed_by_detector=landed,
        judge_verdicts=judge_verdicts,
        judge_details=judge_details,
        top_consensus=result.consensus,
        per_dimension=per_dim,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--probes", type=int, default=5,
        help="Number of Garak native probes to run (default 5).",
    )
    parser.add_argument(
        "--target-model",
        default="openrouter/meta-llama/llama-3.1-8b-instruct",
        help="LiteLLM model string for the defender LLM.",
    )
    parser.add_argument(
        "--skip-fiddler", action="store_true",
        help="Drop both Fiddler judges (saves quota).",
    )
    args = parser.parse_args()

    # Explicit .env load so this script works regardless of whether
    # `import kya` auto-loads (the Bug B fix that wires that in is in
    # PR #64, not yet merged to main).
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=str(_REPO_ROOT / ".env"), override=False)
    except ImportError:
        pass
    if not os.environ.get("FIDDLER_API_KEY"):
        print("WARN: FIDDLER_API_KEY not loaded — Fiddler judges will ERROR",
              file=sys.stderr)
    if not os.environ.get("OPENAI_API_KEY"):
        print("WARN: OPENAI_API_KEY not loaded — openai_judge / phoenix "
              "will ERROR", file=sys.stderr)
    import kya  # noqa: F401
    from kya.scorer_orchestrator import (
        _JUDGES,
        list_judges,
        register_phoenix_adapter,
        register_pyrit_jailbreak_scorer_adapter,
    )
    from kya_redteam.garak_runtime import GARAK_NATIVE_PROBES

    register_phoenix_adapter()
    register_pyrit_jailbreak_scorer_adapter()
    if args.skip_fiddler:
        _JUDGES.pop("fiddler_safety", None)
        _JUDGES.pop("fiddler_faithfulness", None)

    judges = list_judges()
    print("=== Multi-judge panel benchmark ===")
    print(f"Target model: {args.target_model}")
    print(f"Active judges ({len(judges)}): {judges}")
    print()

    probes_to_run = GARAK_NATIVE_PROBES[: args.probes]
    print(f"Running {len(probes_to_run)} probes...")
    print()

    runs: list[ProbeRun] = []
    for i, probe in enumerate(probes_to_run, 1):
        print(f"━━━ probe {i}/{len(probes_to_run)} : tags={probe['tags']} ━━━")
        run = run_probe(probe, args.target_model)
        runs.append(run)
        time.sleep(0.5)  # rate limit pacing
        print()

    # ── Per-probe table ───────────────────────────────────────────
    print("=" * 100)
    print("PER-PROBE BREAKDOWN")
    print("=" * 100)
    judge_columns = sorted(set().union(*[set(r.judge_verdicts) for r in runs]))
    header_judges = " | ".join(j[:18].ljust(18) for j in judge_columns)
    print(f"{'probe':30s}  landed  consensus | {header_judges}")
    print("-" * (30 + 8 + 11 + 3 + len(judge_columns) * 21))
    for run in runs:
        probe_label = "+".join(run.probe_tags[1:])[:30].ljust(30)
        landed_str = " YES " if run.attack_landed_by_detector else "  no "
        cells = " | ".join(
            (run.judge_verdicts.get(j, "—")[:18]).ljust(18)
            for j in judge_columns
        )
        print(f"{probe_label}  {landed_str}  {run.top_consensus:9s} | {cells}")
    print()

    # ── Per-judge catch-rate table ────────────────────────────────
    print("=" * 80)
    print("PER-JUDGE PERFORMANCE")
    print("=" * 80)
    landed_runs = [r for r in runs if r.attack_landed_by_detector]
    refused_runs = [r for r in runs if not r.attack_landed_by_detector]
    print(f"Total probes: {len(runs)}  "
          f"(landed: {len(landed_runs)}  refused: {len(refused_runs)})")
    print()
    print(f"{'judge':30s}  TP/landed  FP/refused  abstain  err")
    print("-" * 72)
    for j in judge_columns:
        # On LANDED attacks: BREACH = true positive, OK = miss
        tp = sum(1 for r in landed_runs if r.judge_verdicts.get(j) == "BREACH")
        # On REFUSED probes: BREACH = false positive, OK = correct
        fp = sum(1 for r in refused_runs if r.judge_verdicts.get(j) == "BREACH")
        unclear = sum(1 for r in runs if r.judge_verdicts.get(j) == "UNCLEAR")
        err = sum(1 for r in runs if r.judge_verdicts.get(j) == "ERROR")
        tp_str = f"{tp}/{len(landed_runs)}" if landed_runs else "n/a"
        fp_str = f"{fp}/{len(refused_runs)}" if refused_runs else "n/a"
        print(f"  {j:28s}  {tp_str:>9s}  {fp_str:>10s}  {unclear:>7d}  {err:>3d}")
    print()

    # ── Combined consensus ────────────────────────────────────────
    print("=" * 80)
    print("COMBINED CONSENSUS")
    print("=" * 80)
    combined_tp = sum(1 for r in landed_runs if r.top_consensus == "BREACH")
    combined_split = sum(1 for r in landed_runs if r.top_consensus == "SPLIT")
    combined_fp = sum(1 for r in refused_runs if r.top_consensus == "BREACH")
    if landed_runs:
        print(f"  TOP=BREACH on landed:           {combined_tp}/{len(landed_runs)}  "
              f"({100*combined_tp/len(landed_runs):.0f}%)")
        print(f"  TOP=BREACH or SPLIT on landed:  "
              f"{combined_tp + combined_split}/{len(landed_runs)}  "
              f"({100*(combined_tp + combined_split)/len(landed_runs):.0f}%)")
    if refused_runs:
        print(f"  TOP=BREACH on refusals (FP):    {combined_fp}/{len(refused_runs)}  "
              f"({100*combined_fp/len(refused_runs):.0f}%)")
    print()
    print(f"  → Use this output verbatim for the paper §9 'multi-judge "
          f"coverage' section. Numbers are real measurements against "
          f"{args.target_model} on a random {len(runs)}-probe slice of "
          f"GARAK_NATIVE_PROBES.")


if __name__ == "__main__":
    main()
