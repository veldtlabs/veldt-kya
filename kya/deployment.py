"""
Deployment environment (#21) — dev / staging / prod / etc.

Same agent definition in dev vs. prod has very different blast radius.
This module captures the environment as a first-class risk factor,
separate from `blast_radius` (which captures the AGENT's scale once
deployed). Dev environments score 0; prod adds a premium; air-gapped /
classified environments are special-cased.

Environments
------------
    dev           — local dev / personal sandbox             (0)
    test          — CI / unit test runs                       (0)
    staging       — pre-production, may touch shared data    (5)
    qa            — full-scale QA env                         (5)
    preprod       — final gate before prod                   (8)
    prod          — production, real users + real data       (15)
    enclave       — air-gapped classified / IL5 / IL6        (25)

`unknown` defaults to prod-equivalent — when in doubt, assume the worst.

Public API
----------
    DEPLOYMENT_WEIGHTS                          — env name → risk delta
    deployment_weight(agent_def) -> tuple[int, str]
    set_deployment_weights(weights, merge=True)
"""

DEPLOYMENT_WEIGHTS = {
    "dev": 0,
    "test": 0,
    "staging": 5,
    "qa": 5,
    "preprod": 8,
    "prod": 15,
    "enclave": 25,
    "unknown": 15,  # conservative — treat unspecified as prod
}


def set_deployment_weights(weights: dict, merge: bool = True) -> None:
    if not merge:
        DEPLOYMENT_WEIGHTS.clear()
    DEPLOYMENT_WEIGHTS.update(weights or {})


def deployment_weight(
    agent_def: dict, weights: dict | None = None,
) -> tuple[int, str]:
    """Read agent_def['environment'] (or 'deployment_env' alias).
    Default 'unknown' → prod-equivalent risk.

    ``weights`` — optional dict overriding DEPLOYMENT_WEIGHTS for the
    duration of this call. Enables tenant-scoped overrides via
    tenant_weights.set_override; missing keys fall through to module
    defaults. Signature mirrors sensitivity_weight."""
    env = (
        (agent_def.get("environment") or agent_def.get("deployment_env") or "unknown")
        .strip()
        .lower()
    )
    weight_source = weights if weights is not None else DEPLOYMENT_WEIGHTS
    delta = weight_source.get(env, weight_source.get("unknown", DEPLOYMENT_WEIGHTS["unknown"]))
    if delta == 0:
        return 0, ""
    return delta, f"environment={env}"
