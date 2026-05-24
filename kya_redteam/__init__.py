"""KYA Red-Team — adversarial testing for KYA-registered agents.

Sister module to kya_hooks (passive observation) and kya_otlp_bridge
(OTel ingestion). Where those modules score real production traffic,
this module runs synthetic attacks on agents and posts findings as
KYA events with source='pyrit' / 'garak' so the regulator pack can
distinguish observed vs adversarial signals.

Public surface
--------------
campaigns:
    ensure_tables(db)
    create_campaign(db, tenant_id, agent_key, name, *, ...)
    list_campaigns(db, tenant_id, agent_key=None)
    get_campaign(db, tenant_id, campaign_id)
    update_campaign(db, tenant_id, campaign_id, **patch)
    delete_campaign(db, tenant_id, campaign_id)
    record_finding(db, tenant_id, campaign_id, run_id, *, ...)
    list_findings(db, tenant_id, *, campaign_id=None, run_id=None,
                  agent_key=None, limit=50)

tenant policy:
    get_tenant_policy(db, tenant_id)
    set_tenant_policy(db, tenant_id, *, max_auto_incident_mode=...,
                      budget_monthly_prompts=..., redteam_tier=...)

PyRIT integration (Phase 2 — pyrit_target/pyrit_scorer/pyrit_orchestrator)
lazily imports `pyrit` so the module stays optional. KYA core remains
SDK-dep-free; install pyrit only on the kya-redteam sidecar.

Tiers (free / standard / premium) gate which orchestrators a campaign
can use. Free tier: PromptSendingOrchestrator only (single-shot probes,
no attacker LLM). Standard: + multi-turn. Premium: + Crescendo + TAP.
"""
from __future__ import annotations

from .attacker_llm import (
    ATTACKER_SYSTEM_PROMPT_CRESCENDO,
    ATTACKER_SYSTEM_PROMPT_REDTEAM,
    ATTACKER_SYSTEM_PROMPT_XPIA,
    AttackerCallResult,
    ConversationState,
    build_attacker_user_prompt,
    call_attacker,
    call_attacker_with_retry,
    describe_configuration,
    model_for_tier,
)
from .campaigns import (
    VALID_AUTO_INCIDENT_MODES,
    VALID_ORCHESTRATORS,
    VALID_SCORERS,
    VALID_SEVERITIES,
    VALID_TIERS,
    create_campaign,
    delete_campaign,
    effective_auto_incident_mode,
    ensure_tables,
    get_campaign,
    get_finding,
    get_tenant_policy,
    list_campaigns,
    list_findings,
    record_finding,
    set_tenant_policy,
    tier_allows_orchestrator,
    update_campaign,
)
from .datasets import list_builtin_datasets, load_dataset
from .multi_turn import (
    MultiTurnConfig,
    run_multi_turn,
)
from .multi_turn import (
    supported_orchestrators as multi_turn_orchestrators,
)
from .pyrit_orchestrator import RunReport, run_campaign, run_campaign_async
from .pyrit_runtime import (
    PyritStatus,
    maybe_route_to_pyrit,
    pyrit_available,
    pyrit_status,
    run_via_pyrit,
)
from .pyrit_scorer import (
    CompositeScorer,
    DataLeakScannerScorer,
    RefusalFailureScorer,
    RegexScorer,
    ScorerVerdict,
    SelfAskTrueFalseScorer,
    SubStringScorer,
    ToolHijackScorer,
    build_scorer,
)
from .pyrit_target import HttpAgentTarget, TargetResponse
from .runs import (
    VALID_STATUSES as RUN_STATUSES,
)
from .runs import (
    create_run,
    finalize_run,
    get_run,
    is_cancel_requested,
    list_runs,
    reconcile_stale_runs,
    request_cancel,
    submit_async_run,
)
from .runtime import (
    acquire_rate_token,
    check_budget,
    check_token_budget,
    consume_attacker_tokens,
    consume_budget,
    runtime_status,
)
from .sidecar_client import (
    SidecarConfig,
    SidecarUnavailable,
    load_sidecar_config,
)
from .sidecar_client import (
    cancel_run as sidecar_cancel_run,
)
from .sidecar_client import (
    healthcheck as sidecar_healthcheck,
)
from .sidecar_client import (
    submit_run as sidecar_submit_run,
)
from .targets import (
    VALID_AUTH_KINDS,
    VALID_PARSER_KINDS,
    SecretConfigError,
    create_target,
    delete_target,
    get_response_parser,
    get_target,
    is_encryption_configured,
    list_targets,
    materialize_target,
    rotate_encryption_key_for_tenant,
    rotate_target_secret,
    update_target,
    verify_target,
)
from .targets import (
    ensure_tables as ensure_target_tables,
)

__all__ = [
    # campaigns / policy
    "VALID_ORCHESTRATORS", "VALID_SCORERS", "VALID_TIERS",
    "VALID_AUTO_INCIDENT_MODES", "VALID_SEVERITIES",
    "ensure_tables",
    "create_campaign", "list_campaigns", "get_campaign",
    "update_campaign", "delete_campaign",
    "record_finding", "list_findings", "get_finding",
    "get_tenant_policy", "set_tenant_policy",
    "effective_auto_incident_mode", "tier_allows_orchestrator",
    # target + scorer + orchestrator
    "HttpAgentTarget", "TargetResponse",
    "ScorerVerdict", "CompositeScorer", "build_scorer",
    "SubStringScorer", "RegexScorer", "DataLeakScannerScorer",
    "RefusalFailureScorer", "ToolHijackScorer", "SelfAskTrueFalseScorer",
    "RunReport", "run_campaign", "run_campaign_async",
    "run_multi_turn", "multi_turn_orchestrators", "MultiTurnConfig",
    # runtime gates
    "check_budget", "consume_budget", "acquire_rate_token", "runtime_status",
    "check_token_budget", "consume_attacker_tokens",
    # PyRIT-backed wrapper (opt-in)
    "PyritStatus", "pyrit_status", "pyrit_available",
    "run_via_pyrit", "maybe_route_to_pyrit",
    # Sidecar client (vd-app -> vd-kya-redteam)
    "SidecarConfig", "SidecarUnavailable",
    "load_sidecar_config", "sidecar_submit_run",
    "sidecar_cancel_run", "sidecar_healthcheck",
    # runs / async / cancel
    "RUN_STATUSES", "create_run", "get_run", "list_runs",
    "request_cancel", "is_cancel_requested",
    "finalize_run", "reconcile_stale_runs", "submit_async_run",
    # persistent targets with encrypted secrets
    "VALID_AUTH_KINDS", "VALID_PARSER_KINDS",
    "SecretConfigError", "is_encryption_configured",
    "ensure_target_tables",
    "create_target", "get_target", "list_targets",
    "update_target", "delete_target", "verify_target",
    "materialize_target", "get_response_parser",
    "rotate_target_secret", "rotate_encryption_key_for_tenant",
    # attacker LLM (multi-turn driver)
    "AttackerCallResult", "ConversationState",
    "model_for_tier", "call_attacker", "call_attacker_with_retry",
    "build_attacker_user_prompt", "describe_configuration",
    "ATTACKER_SYSTEM_PROMPT_REDTEAM", "ATTACKER_SYSTEM_PROMPT_CRESCENDO",
    "ATTACKER_SYSTEM_PROMPT_XPIA",
    # datasets
    "list_builtin_datasets", "load_dataset",
]
