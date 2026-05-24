"""KYA quick-demo — `python -m kya.demo`.

Zero-config, zero-DB, < 2 seconds. Run after ``pip install veldt-kya``
to see the score-agent surface on 3 contrasting fixtures and the
two-axis breakdown that makes the score auditable.

The fixtures match what the landing page (veldtlabs.ai/kya) animates,
so what you see here is exactly what you see there — with the actual
numbers your local install produces, not pre-baked screenshots.
"""

from __future__ import annotations

import sys
from typing import Any

# Shared scaffold to keep secondary factors from saturating each fixture
# -- same pattern used by examples/interaction_multiplier_ablation.py.
_WELL_FORMED = {
    "owner_user_id": "00000000-0000-0000-0000-000000000001",
    "owner_team": "platform-eng",
    "on_call": "platform-eng-oncall",
    "escalation_chain": ["sre-l1", "sre-l2"],
    "model_trust": "enterprise",
    "input_sources": ["internal_api"],
    "provenance": "internal",
    "signed_at": "2026-01-01T00:00:00Z",
    "review_status": "approved",
    "red_team_score": 80,
    "bias_score": 80,
    "fairness_score": 80,
    "environment": "staging",
    "access_level": "read",
}


def _scenario(overrides: dict) -> dict:
    d = dict(_WELL_FORMED)
    d.update(overrides)
    return d


SCENARIOS: list[tuple[str, dict]] = [
    (
        "support_lookup",
        _scenario({
            "agent_key": "support_lookup",
            "human_loop": "in_the_loop",
            "tools": ["lookup_ticket"],
            "data_classes": ["public"],
        }),
    ),
    (
        "code_runner (HIL)",
        _scenario({
            "agent_key": "code_runner",
            "human_loop": "in_the_loop",
            "tools": ["execute_python"],
            "security_caps": ["code_execution"],
            "input_sources": ["user_prompt"],
            "data_classes": ["public"],
        }),
    ),
    (
        "loan_writer (autonomous)",
        _scenario({
            "agent_key": "loan_writer",
            "human_loop": "none",
            "tools": ["create_loan", "update_account", "delete_pending"],
            "environment": "prod",
            "data_classes": ["pii", "financial"],
            "access_level": "read",
        }),
    ),
]


# -- Tiny colored-terminal helpers ------------------------------------
# We only color if stdout is a real TTY — otherwise pipe-safe plain text.

_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if _USE_COLOR else text

def _bold(t: str) -> str:    return _c("1", t)
def _dim(t: str) -> str:     return _c("2", t)
def _red(t: str) -> str:     return _c("31", t)
def _green(t: str) -> str:   return _c("32", t)
def _yellow(t: str) -> str:  return _c("33", t)
def _cyan(t: str) -> str:    return _c("36", t)


_BUCKET_COLOR = {
    "low":      _green,
    "medium":   _yellow,
    "high":     _yellow,
    "critical": _red,
}


def _render_row(label: str, value: str, *, indent: int = 2) -> str:
    pad = " " * indent
    return f"{pad}{_dim(label):<28}{value}"


def _print_scenario(name: str, agent_def: dict, last: bool = False) -> None:
    from kya import score_agent
    r = score_agent(agent_def)

    bucket_colored = _BUCKET_COLOR.get(r.bucket, _yellow)(r.bucket.upper())
    print()
    print(f"  {_bold(name)}  {_dim('--')}  score={_bold(str(r.score))}  {bucket_colored}")
    print(_render_row("additive",        f"{r.additive_score}"))
    print(_render_row("concentration",   f"{r.interaction_multiplier:.2f}x"))
    print(_render_row("overrun",         f"{r.overrun}"))
    if r.interactions:
        print(_render_row("interactions fired",
                          ", ".join(i.get("code", "?") for i in r.interactions if isinstance(i, dict))))
    top = sorted([f for f in r.factors if f.delta != 0],
                 key=lambda f: -f.delta)[:3]
    if top:
        print(_render_row("top factors", ""))
        for f in top:
            print(_render_row(f"  {f.name}", f"+{f.delta}" if f.delta > 0 else f"{f.delta}", indent=4))
    if not last:
        print(f"  {_dim('-' * 64)}")


def _header() -> None:
    import kya as _kya
    line1 = _bold("KYA -- Know Your Agents")
    line2 = _dim(f"  v{_kya.__version__}  |  Apache 2.0  |  pure-function score_agent, no DB")
    print()
    print(f"  {line1}")
    print(line2)
    print()
    print(f"  {_dim('Scoring 3 contrasting agent definitions (matches veldtlabs.ai/kya):')}")


def _footer() -> None:
    print()
    print(f"  {_dim('-' * 64)}")
    print(f"  {_bold('Next:')}")
    print(f"  {_dim('docs:')}     https://github.com/veldtlabs/veldt-kya#readme")
    print(f"  {_dim('paper:')}    https://arxiv.org/abs/2512.xxxxx")
    print(f"  {_dim('frameworks:')} adapters for LangChain, OpenAI Agents, Claude SDK, MCP, +18 more")
    print()


def main(argv: Any = None) -> int:
    """Entry point: ``python -m kya.demo``."""
    _header()
    for i, (name, defn) in enumerate(SCENARIOS):
        _print_scenario(name, defn, last=(i == len(SCENARIOS) - 1))
    _footer()
    return 0


if __name__ == "__main__":
    sys.exit(main())
