"""Interaction-multiplier ablation against kya/risk.py.

For each scenario, score the agent definition TWICE:
  - additive-only (disable_interactions=True)
  - additive + interaction multipliers (default)

Report bucket boundary crossings to test whether the multiplier
amplification step changes operator-visible bucket assignments
relative to the AIVSS-shaped additive baseline.

Run: python examples/interaction_multiplier_ablation.py
"""

from __future__ import annotations

import sys


def _score(agent_def: dict, *, with_multipliers: bool):
    """Score agent_def. Returns (additive, final, mult, fired_codes, bucket)."""
    from kya.risk import score_agent
    d = dict(agent_def)
    if not with_multipliers:
        d["disable_interactions"] = True
    r = score_agent(d)
    fired = [i.get("code") if isinstance(i, dict) else getattr(i, "code", None)
             for i in (r.interactions or [])]
    return (
        int(r.additive_score),
        int(r.score),
        float(r.interaction_multiplier),
        [c for c in fired if c],
        r.bucket,
    )


# Common boilerplate so secondary factors (ownership/lifecycle/input-source/
# model-trust/audit-evidence) don't accidentally fire and saturate the
# additive baseline. We want moderate additive scores so the multiplier
# amplification is what crosses the bucket, not noise.
# Environment defaults to STAGING (not prod) to keep additive moderate;
# scenarios that need prod override it explicitly.
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
    """Build a well-formed agent_def with scenario-specific overrides."""
    d = dict(_WELL_FORMED)
    d.update(overrides)
    return d


SCENARIOS: list[tuple[str, dict]] = [
    # 1. Autonomous writer in prod (governance=none, env=prod, 3 write tools).
    # autonomous_writer_in_prod (1.3x) fires. Additive is already high
    # because governance=none is +30 alone; multiplier saturates at 100.
    ("autonomous_writer_in_prod", _scenario({
        "agent_key": "loan_writer",
        "human_loop": "none",
        "tools": ["create_loan", "update_account", "delete_pending"],
        "environment": "prod",
        "data_classes": ["public"],
    })),
    # 2. Code execution + user prompt — fires code_exec_with_user_input (1.5x).
    # human_loop=in_the_loop keeps additive low; multiplier crosses a boundary.
    ("code_exec_user_input_hil", _scenario({
        "agent_key": "code_runner_hil",
        "human_loop": "in_the_loop",
        "tools": ["execute_python"],
        "environment": "staging",
        "security_caps": ["code_execution"],
        "input_sources": ["user_prompt"],
        "data_classes": ["public"],
    })),
    # 3. Self-hosted with PII, human-in-loop — fires self_hosted_with_pii (1.2x).
    # HIL + low tool count = moderate additive; multiplier should push bucket.
    ("self_hosted_pii_hil", _scenario({
        "agent_key": "internal_chat",
        "human_loop": "in_the_loop",
        "tools": ["lookup_customer"],
        "environment": "staging",
        "model_trust": "self_hosted",
        "data_classes": ["pii"],
    })),
    # 4. Untrusted chain (marketplace agent fanning out to 3+ delegates) —
    # fires untrusted_chain (1.2x). Read-only HIL keeps additive moderate.
    ("untrusted_chain_hil", _scenario({
        "agent_key": "marketplace_router",
        "human_loop": "in_the_loop",
        "tools": ["delegate_call"],
        "environment": "staging",
        "provenance": "marketplace",
        "can_delegate_to": ["sub_a", "sub_b", "sub_c"],
        "data_classes": ["public"],
    })),
    # 5. Replit-style autonomous code agent in prod — fires both
    # autonomous_writer_in_prod (1.3x) and code_exec_with_user_input (1.5x).
    # Already at additive ceiling due to governance=none + multiple writes.
    ("replit_style_autonomous", _scenario({
        "agent_key": "code_assistant",
        "human_loop": "none",
        "tools": ["create_file", "update_file", "delete_file"],
        "environment": "prod",
        "security_caps": ["code_execution"],
        "input_sources": ["user_prompt"],
        "data_classes": ["internal"],
    })),
    # 6. Benign control: read-only, human-in-loop in staging. No multiplier
    # should fire.
    ("benign_readonly_hil", _scenario({
        "agent_key": "support_lookup",
        "human_loop": "in_the_loop",
        "tools": ["lookup_ticket"],
        "environment": "staging",
        "data_classes": ["public"],
    })),
]


def main():
    print("Interaction-Multiplier Ablation — kya/risk.py")
    print("=" * 92)
    print(f"{'Scenario':<32} {'Add':<5} {'AddBkt':<8} {'Mult':<5} {'Final':<6} "
          f"{'FinBkt':<8} {'Bucket Change':<16}")
    print("-" * 92)

    bucket_changes = 0
    fired_total = 0
    for name, agent_def in SCENARIOS:
        a_add, a_fin, a_mult, a_fired, _ = _score(agent_def, with_multipliers=False)
        b_add, b_fin, b_mult, b_fired, b_bkt = _score(agent_def, with_multipliers=True)
        from kya.risk import bucket_for
        add_bkt = bucket_for(a_add)
        fin_bkt = bucket_for(b_fin)
        change = f"{add_bkt}->{fin_bkt}" if add_bkt != fin_bkt else "--"
        if add_bkt != fin_bkt:
            bucket_changes += 1
        fired_total += len(b_fired)
        print(f"{name:<32} {a_add:<5} {add_bkt:<8} {b_mult:<5.2f} "
              f"{b_fin:<6} {fin_bkt:<8} {change:<16}")
        if b_fired:
            print(f"    fired: {', '.join(b_fired)}")
    print("-" * 92)
    print(f"Bucket boundary crossings: {bucket_changes} of {len(SCENARIOS)}")
    print(f"Total interactions fired:  {fired_total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
