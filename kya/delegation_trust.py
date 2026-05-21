"""
Delegation trust — Round 13.3.

When an agent A delegates to other agents (A -> B, A -> C, ...), and
those delegates have low principal trust, A inherits some of that risk
even when A itself is individually clean.

Why: lineage-based attribution catches a specific failure mode — an
"orchestrator" agent that's clean on its own metrics but consistently
hands work to compromised / risky downstream agents. The orchestrator
becomes the load-bearing point of the attack without ever directly
triggering a rogue signal.

How it works
------------
1. Look up the agent's `can_delegate_to` list.
2. For each delegate target, fetch its principal trust (kind="agent")
   from kya_principal_trust.
3. Compute a penalty per delegate that's below the trust threshold.
4. Cap the total at `DELEGATION_TRUST_CAP` so it can't dominate.

The factor only fires when the agent CAN delegate AND has a delegate
list AND any of those delegates have non-trivial principal trust data.
A brand-new agent with no observed downstream signals contributes 0.

Public API
----------
    delegation_trust_weight(db, tenant_id, agent_def) -> tuple[int, str, list[dict]]
"""

import logging

logger = logging.getLogger(__name__)


# Calibration — risk premium per below-threshold delegate.
DELEGATION_TRUST_CAP = 25
THRESHOLD_RISKY = 40  # delegates with trust < this contribute
PER_RISKY_DELEGATE = 4
PER_BLOCKED_DELEGATE = 10  # trust < 15 = blocked


def delegation_trust_weight(
    db,
    tenant_id: str,
    agent_def: dict,
) -> tuple[int, str, list[dict]]:
    """Compute the delegation-trust premium.

    Returns (delta, label, evidence_list). When the agent has no delegates
    or no DB session, returns (0, "", []). Exception-safe — never raises.
    """
    try:
        from .principals import get_principal_trust
    except ImportError:
        return 0, "", []

    delegates = agent_def.get("can_delegate_to") or []
    if not delegates or not db:
        return 0, "", []

    evidence: list[dict] = []
    delta = 0
    for target in delegates:
        if not isinstance(target, str):
            continue
        try:
            trust = get_principal_trust(db, tenant_id, "agent", target)
        except Exception as exc:
            logger.debug("[KYP] delegation_trust lookup failed for %s: %s", target, exc)
            continue
        # Only penalize when the delegate has BEEN observed (signal_counts
        # non-empty OR trust < starting). A brand-new clean delegate at
        # the default 50 contributes nothing.
        observed = bool(trust.signal_counts) or trust.trust_score < 50
        if not observed:
            continue
        if trust.trust_score < 15:
            delta += PER_BLOCKED_DELEGATE
            evidence.append(
                {
                    "delegate": target,
                    "trust": trust.trust_score,
                    "bucket": trust.bucket,
                    "penalty": PER_BLOCKED_DELEGATE,
                }
            )
        elif trust.trust_score < THRESHOLD_RISKY:
            delta += PER_RISKY_DELEGATE
            evidence.append(
                {
                    "delegate": target,
                    "trust": trust.trust_score,
                    "bucket": trust.bucket,
                    "penalty": PER_RISKY_DELEGATE,
                }
            )

    if delta == 0:
        return 0, "", []
    delta = min(DELEGATION_TRUST_CAP, delta)
    worst = min(evidence, key=lambda e: e["trust"]) if evidence else None
    label = f"delegates to {len(evidence)} risky agent(s)" + (
        f" — worst: {worst['delegate']} trust={worst['trust']}" if worst else ""
    )
    return delta, label, evidence
