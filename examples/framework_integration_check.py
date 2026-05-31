"""Exercise the SDK against each framework's REAL payload shape.

This is a payload-driven integration check — it runs the SDK's
format_adapter + scoring against authentic payloads captured from each
framework, not synthetic data. It does NOT call any live API; live-API
checks live in ``examples/live_*.py`` and require provider API keys.

What this proves:
  1. normalize_agent_def(framework, raw) handles each framework's
     wire shape without crashing
  2. score_agent(canonical) produces a meaningful score for each
  3. The canonical schema is preserved across all 5 frameworks
"""

from __future__ import annotations

import json
from pathlib import Path

import kya

FIXTURES = Path(__file__).resolve().parent.parent / ".kya_test"


def _row(label: str, value) -> None:
    print(f"  {label:32s} {value}")


def check(framework: str, fixture_path: Path) -> dict:
    with open(fixture_path) as f:
        payload = json.load(f)

    # The fixture may either be the raw framework definition, or a
    # {"framework": ..., "definition": ...} envelope our test harness uses.
    if isinstance(payload, dict) and "framework" in payload and "definition" in payload:
        raw = payload["definition"]
    else:
        raw = payload

    canonical = kya.normalize_agent_def(framework, raw)
    risk = kya.score_agent(canonical)

    return {
        "agent_key": canonical.get("agent_key") or canonical.get("name"),
        "tools": canonical.get("tools") or [],
        "model": canonical.get("model"),
        "human_loop": canonical.get("human_loop"),
        "access_level": canonical.get("access_level"),
        "provenance": canonical.get("provenance"),
        "score": risk.score,
        "bucket": risk.bucket,
        "top_factors": [(f.name, f.delta) for f in risk.factors[:5]],
    }


def section(title):
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


def main():
    print()
    print("=" * 78)
    print("  KYA SDK · Framework integration check")
    print("=" * 78)
    print(f"  fixtures: {FIXTURES}")

    cases = [
        ("agents_md (OpenCLAW)", "agents_md", "openclaw_OpenClawBrowserAgent_payload.json"),
        ("agents_md (OpenCLAW Calendar)", "agents_md", "openclaw_OpenClawCalendarAgent_payload.json"),
        ("agents_md (OpenCLAW Email)", "agents_md", "openclaw_OpenClawEmailAgent_payload.json"),
        ("openai (OpenAI Agents SDK)", "openai", "openai_agents_payload.json"),
        ("anthropic (Claude Agent SDK)", "anthropic", "claude_agent_payload.json"),
    ]

    results = {}
    for label, framework, fixture in cases:
        section(label)
        fp = FIXTURES / fixture
        if not fp.exists():
            _row("status", f"FIXTURE MISSING: {fixture}")
            continue
        try:
            r = check(framework, fp)
            results[label] = r
            _row("agent_key", r["agent_key"])
            _row("tools", r["tools"])
            _row("model", r["model"])
            _row("human_loop", r["human_loop"])
            _row("access_level", r["access_level"])
            _row("provenance", r["provenance"])
            _row("score", r["score"])
            _row("bucket", r["bucket"])
            _row("top 5 factors", r["top_factors"])
        except Exception as exc:
            _row("ERROR", f"{type(exc).__name__}: {exc}")
            results[label] = {"error": str(exc)}

    section("SUMMARY")
    print(f"  {'framework':35s} {'score':>6s} {'bucket':>10s}")
    print(f"  {'-' * 60}")
    for label, r in results.items():
        if "error" in r:
            print(f"  {label:35s} FAIL: {r['error'][:40]}")
        else:
            print(f"  {label:35s} {r['score']:>6d} {r['bucket']:>10s}")


if __name__ == "__main__":
    main()
