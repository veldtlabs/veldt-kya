"""
Interaction multipliers — non-linear risk amplification for dangerous
factor combinations.

The additive scoring model in `risk.py` is auditable but treats every
factor as independent. Real risk is interaction-driven:

    autonomous + 3 write tools + prod environment  >>  (autonomous) + (3 writes) + (prod)

is exponentially worse than the sum alone, because the cascade of bad
things-each-rounded-down hits all at once with no human gate. This
module detects known-dangerous combinations and applies multipliers
to the final additive score.

Conservative design rules
-------------------------
- Multipliers ≥ 1.0 ONLY. Interactions amplify, never reduce — credit
  factors (citation, fresh audits) already provide downward delta.
- Capped product: total multiplier never exceeds `MAX_MULTIPLIER`
  (default 2.0) so a single agent can't break 100 from interactions alone.
- The final score still clamps to 0..100.
- Every fired interaction is surfaced with a stable `code` so an
  auditor / UI can render "why is this score amplified."

Public API
----------
    INTERACTIONS                                                — list[Interaction]
    detect_interactions(agent_def, factors) -> list[dict]      — which fired
    interaction_multiplier(agent_def, factors) -> float        — capped product
    register_interaction(code, name, condition, multiplier, description, severity)
"""

from collections.abc import Callable
from dataclasses import dataclass

MAX_MULTIPLIER = 2.0  # capped product across all fired interactions


@dataclass
class Interaction:
    code: str  # stable id e.g. "autonomous_writer_in_prod"
    name: str  # short human label
    condition: Callable[[dict, list], bool]  # (agent_def, factor_list) -> bool
    multiplier: float  # >= 1.0
    description: str  # why this combo is risky
    severity: str = "warning"  # "info" | "warning" | "critical"


# ── Helper predicates (kept local; tested via the public detect fn) ──────


def _factor(factors: list, name: str):
    """Pull a factor dict by name from the risk breakdown list."""
    for f in factors or []:
        if isinstance(f, dict) and f.get("name") == name:
            return f
        # Also support RiskFactor dataclass instances
        if hasattr(f, "name") and f.name == name:
            return {"name": f.name, "label": f.label, "delta": f.delta}
    return None


def _has_security_cap(agent_def: dict, *names: str) -> bool:
    caps = set(agent_def.get("security_caps") or [])
    return any(n in caps for n in names)


def _has_data_class(agent_def: dict, *names: str) -> bool:
    classes = set(agent_def.get("data_classes") or [])
    return any(n in classes for n in names)


def _has_input_source(agent_def: dict, *names: str) -> bool:
    sources = set(agent_def.get("input_sources") or [])
    return any(n in sources for n in names)


_CLASSIFIED_CLASSES = {
    "itar",
    "ear",
    "cdi",
    "cui",
    "classified",
    "us_confidential",
    "us_secret",
    "us_top_secret",
    "nato_restricted",
    "nato_confidential",
    "nato_secret",
    "restreint_ue",
    "confidentiel_ue",
    "secret_ue",
}


# ── Built-in interactions ────────────────────────────────────────────────

INTERACTIONS: list[Interaction] = [
    Interaction(
        code="autonomous_writer_in_prod",
        name="Autonomous writer in prod",
        condition=lambda d, f: (
            (d.get("human_loop") or "").lower() == "none"
            and len(
                [
                    t
                    for t in (d.get("tools") or [])
                    if any(t.startswith(p) for p in ("create_", "update_", "delete_", "override_"))
                ]
            )
            >= 3
            and (d.get("environment") or "").lower() == "prod"
        ),
        multiplier=1.3,
        description="Fully-autonomous agent with multiple write tools running in production. "
        "Compound failure mode: a single hallucination or jailbreak can chain "
        "into multiple irreversible writes before a human notices.",
        severity="critical",
    ),
    Interaction(
        code="code_exec_with_user_input",
        name="Code execution + user-supplied input",
        condition=lambda d, f: (
            _has_security_cap(d, "code_execution", "shell_access", "container_exec")
            and _has_input_source(d, "user_upload", "web_fetch", "user_prompt")
        ),
        multiplier=1.5,
        description="Agent has code-execution capability AND ingests untrusted user input. "
        "Classic RCE-via-prompt-injection setup. Treat as if attacker controls "
        "code execution on the host.",
        severity="critical",
    ),
    Interaction(
        code="classified_autonomous",
        name="Classified data + autonomous mode",
        condition=lambda d, f: (
            _has_data_class(d, *_CLASSIFIED_CLASSES)
            and (d.get("human_loop") or "").lower() == "none"
        ),
        multiplier=1.4,
        description="Classified or export-controlled data being handled by a fully-autonomous "
        "agent. EU AI Act Art. 14 and US classification regimes both require "
        "effective human oversight — this combo violates both spirit and letter.",
        severity="critical",
    ),
    Interaction(
        code="untrusted_chain",
        name="Untrusted provenance with deep delegation",
        condition=lambda d, f: (
            (d.get("provenance") or "").lower() in ("marketplace", "third_party", "imported")
            and len([t for t in (d.get("can_delegate_to") or []) if isinstance(t, str)]) >= 3
        ),
        multiplier=1.2,
        description="Marketplace / third-party agent that can fan out to multiple delegates. "
        "Risk compounds through the chain — every downstream agent inherits the "
        "trust assumptions of the imported root.",
        severity="warning",
    ),
    Interaction(
        code="unowned_high_risk",
        name="Unowned and already high-risk",
        condition=lambda d, f: (
            not any(
                d.get(k) for k in ("owner_user_id", "owner_team", "on_call", "escalation_chain")
            )
            and _factor(f, "ownership") is not None  # orphan factor fired
        ),
        multiplier=1.15,
        description="Orphan agent without owner / on-call. If this agent misbehaves nobody "
        "is pageable — already a +15 additive penalty; interaction makes the "
        "lack-of-accountability proportional to the rest of the risk.",
        severity="warning",
    ),
    Interaction(
        code="unaudited_classified",
        name="Classified data, no audit evidence",
        condition=lambda d, f: (
            _has_data_class(d, *_CLASSIFIED_CLASSES)
            and not all(
                isinstance(d.get(k), (int, float))
                for k in ("red_team_score", "bias_score", "fairness_score")
            )
        ),
        multiplier=1.25,
        description="Classified data being handled but no red-team / bias / fairness audit "
        "evidence on file. EU AI Act Art. 15 + NIST 800-53 both require "
        "demonstrable accuracy + robustness testing for high-stakes systems.",
        severity="critical",
    ),
    Interaction(
        code="prod_marketplace_writer",
        name="Marketplace import with write tools in prod",
        condition=lambda d, f: (
            (d.get("provenance") or "").lower() == "marketplace"
            and any(
                t
                for t in (d.get("tools") or [])
                if any(t.startswith(p) for p in ("create_", "delete_", "update_", "override_"))
            )
            and (d.get("environment") or "").lower() == "prod"
        ),
        multiplier=1.2,
        description="Imported agent given write tools in production. The marketplace "
        "publisher's threat model may not match yours — supply-chain attack "
        "surface is highest at the write boundary.",
        severity="warning",
    ),
    Interaction(
        code="self_hosted_with_pii",
        name="Self-hosted model handling PII / PHI",
        condition=lambda d, f: (
            (d.get("model_trust") or "").lower() == "self_hosted"
            and _has_data_class(d, "pii", "phi", "financial")
        ),
        multiplier=1.2,
        description="Self-hosted inference layer with regulated data. KYA can't see what "
        "the model does internally; combined with PII/PHI this means there's "
        "no contractual data-protection guarantee on the inference path.",
        severity="warning",
    ),
    Interaction(
        code="rejected_in_prod",
        name="Explicitly rejected agent running in production",
        condition=lambda d, f: (
            (d.get("review_status") or "").lower() == "rejected"
            and (d.get("environment") or "").lower() == "prod"
        ),
        multiplier=1.4,
        description="Security review marked this agent as REJECTED but it's running in "
        "prod. Either the rejection is a stale flag, or it's a deployment "
        "bypass — both demand immediate operator attention.",
        severity="critical",
    ),
    Interaction(
        code="orphan_writer_in_prod",
        name="Orphan agent with write tools in prod",
        condition=lambda d, f: (
            not any(
                d.get(k) for k in ("owner_user_id", "owner_team", "on_call", "escalation_chain")
            )
            and any(
                t.startswith(("create_", "delete_", "update_", "override_"))
                for t in (d.get("tools") or [])
            )
            and (d.get("environment") or "").lower() == "prod"
        ),
        multiplier=1.2,
        description="No owner + write tools + prod = nobody to call when it deletes the "
        "wrong thing. Often catches dev-team prototypes that leaked into prod.",
        severity="warning",
    ),
]


# ── Registry surface ─────────────────────────────────────────────────────


def register_interaction(
    code: str,
    name: str,
    condition: Callable[[dict, list], bool],
    multiplier: float,
    description: str,
    severity: str = "warning",
) -> None:
    """Register a custom interaction at runtime. Multipliers ≥ 1.0 only —
    a value <1.0 raises ValueError."""
    if multiplier < 1.0:
        raise ValueError(
            f"interaction multiplier must be >= 1.0 (got {multiplier}). "
            "Use credit factors (citation, audits) for downward deltas."
        )
    if not callable(condition):
        raise ValueError("condition must be callable(agent_def, factors) -> bool")
    INTERACTIONS.append(
        Interaction(
            code=code,
            name=name,
            condition=condition,
            multiplier=multiplier,
            description=description,
            severity=severity,
        )
    )


def list_interactions() -> list[dict]:
    """Return the registered interactions as serializable dicts."""
    return [
        {
            "code": i.code,
            "name": i.name,
            "multiplier": i.multiplier,
            "description": i.description,
            "severity": i.severity,
        }
        for i in INTERACTIONS
    ]


# ── Public API ───────────────────────────────────────────────────────────


def detect_interactions(agent_def: dict, factors: list | None = None) -> list[dict]:
    """Return the interactions that fire for this agent_def + factor list.

    `factors` is the `risk.factors` array (list of RiskFactor dataclasses
    or dicts). Conditions can inspect both the raw definition AND which
    factors already fired — useful when an interaction wants to gate on
    "orphan factor present" rather than re-checking owner_user_id itself.

    Returns: list of {code, name, multiplier, description, severity}.
    """
    out = []
    for ix in INTERACTIONS:
        try:
            if ix.condition(agent_def, factors or []):
                out.append(
                    {
                        "code": ix.code,
                        "name": ix.name,
                        "multiplier": ix.multiplier,
                        "description": ix.description,
                        "severity": ix.severity,
                    }
                )
        except Exception:
            # A buggy custom interaction must never break scoring.
            continue
    return out


def interaction_multiplier(
    agent_def: dict, factors: list | None = None
) -> tuple[float, list[dict]]:
    """Compute the capped product of all fired multipliers.

    Returns (multiplier, fired_list). Caller applies the multiplier to
    the final score; clamping to 0..100 happens in risk.score_agent.

    Example: two interactions fire at 1.3 and 1.2 -> raw 1.56 -> capped
    at MAX_MULTIPLIER (2.0 default). Single 1.5 fires -> returns 1.5.
    """
    fired = detect_interactions(agent_def, factors)
    if not fired:
        return 1.0, []
    product = 1.0
    for f in fired:
        product *= float(f["multiplier"])
    return min(MAX_MULTIPLIER, product), fired
