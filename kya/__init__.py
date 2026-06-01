"""
KYA — Know Your Agents.

A framework-agnostic agent governance + observability layer. Risk scoring,
version control, rogue-behavior detection, and anomaly surfacing for any
agent — Veldt-native, LangChain, CrewAI, OpenAI Assistants, or a hand-rolled
agent loop.

Version is single-sourced from the installed package metadata so the
in-source `__version__` always matches `pip show veldt-kya`. Falls back
to the editable-install dev string when metadata isn't available (e.g.
running from a source checkout without `pip install`).
"""

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        __version__ = _pkg_version("veldt-kya")
    except PackageNotFoundError:
        __version__ = "0.0.0+dev"
except ImportError:
    __version__ = "0.0.0+dev"


__doc__ = """KYA — Know Your Agents.

Public surface
--------------
Risk scoring (`risk.py`):
    score_agent(definition) -> AgentRiskScore
    bucket_for(score) -> "low"|"medium"|"high"|"critical"
    is_write_tool(name) -> bool
    is_admin_tool(name) -> bool

Versioning (`versioning.py`):
    snapshot_agent(db, tenant_id, agent_key, definition, ...)
    list_versions(db, tenant_id, agent_key)
    get_version(db, tenant_id, agent_key, vno)
    rollback_to(db, tenant_id, agent_key, vno, ...)

Rogue + governance + anomalies (`rogue.py`):
    record_oos_tool_attempt(agent, tool, tenant_id)
    record_cross_tenant_attempt(agent, expected_tid, actual_tid)
    get_rogue_signals(agent) -> RogueReport
    rogue_score(report) -> int (0..50)
    get_governance_summary(db, tenant_id, agent_key=None)
    get_anomalies(rogue, activity, governance=None) -> list[dict]

Format adapter (`format_adapter.py`):
    normalize_agent_def(framework, raw_def) -> dict
    SupportedFramework = "veldt" | "langchain" | "crewai" | "openai" | "generic"

Design rules
------------
- Core modules MUST stay free of Veldt-specific imports. They depend only
  on the standard library, `prometheus_client` (optional), `opentelemetry`
  (optional), and SQLAlchemy (only versioning + governance read helpers).
- All record_* helpers are exception-safe — observability never breaks the
  request path.
- HTTP ingestion lives in routes/admin_agents.py — KYA itself owns no
  framework code.
"""

from .blast_radius import (
    BlastRadiusBreakdown,
    blast_radius_breakdown,
    blast_radius_weight,
)
from .compliance import (
    REGIME_BREACH_NOTIFY,
    REGIME_RETENTION_DAYS,
    REGIMES,
    compliance_summary,
    elevated_severity,
    eu_ai_act_tier,
    max_retention_days,
    required_controls,
)
from .cost import cost_burn_weight
from .data_classes import (
    CLASS_WEIGHTS,
    DATA_CLASSES,
    DEFAULT_TOOL_CLASSIFICATIONS,
    classify_tool,
    infer_data_classes,
    sensitivity_weight,
    set_class_weights,
    set_tool_classifications,
)

# Register the four weight scopes this module manages. Done at import
# time so the registry is populated before any score lookup. Each
# default dict is mutable and module-global — register_scope captures a
# reference, not a snapshot, so live `set_*_weights()` calls still work
# for SDK users.
from .data_classes import CLASS_WEIGHTS as _CLASS_WEIGHTS
from .delegation import (
    delegation_chain,
    delegation_weight,
    max_delegation_depth,
)
from .delegation_trust import delegation_trust_weight
from .deployment import (
    DEPLOYMENT_WEIGHTS,
    deployment_weight,
    set_deployment_weights,
)
from .deployment import DEPLOYMENT_WEIGHTS as _DEPLOYMENT_WEIGHTS
from .fault_attribution import (
    DivergenceReport,
    agent_divergence_score,
)
from .feedback import (
    approve_suggestion,
    ensure_suggestions_table,
    list_suggestions,
    propose_from_incident,
    reject_suggestion,
)
from .input_sources import (
    INPUT_SOURCES,
    SOURCE_WEIGHTS,
    input_source_weight,
    set_source_weights,
)
from .input_sources import SOURCE_WEIGHTS as _SOURCE_WEIGHTS
from .integrity import (
    canonical_hash,
    detect_drift,
    lineage_chain,
    lineage_risk_inheritance,
    verify_signature,
)
from .interactions import (
    INTERACTIONS,
    MAX_MULTIPLIER,
    Interaction,
    detect_interactions,
    list_interactions,
    register_interaction,
)
from .interactions import (
    interaction_multiplier as compute_interaction_multiplier,
)
from .invocations import (
    VALID_MODES,
    VALID_OUTCOMES,
    active_parallel_invocations,
    ensure_invocations_table,
    ingest_lag_stats,
    list_invocations,
    mode_distribution,
    new_correlation_id,
    record_invocation,
)
from .lifecycle import approval_weight, lifecycle_weight, ownership_weight

# kya.llm_judge removed in the "KYA = governance, not detection"
# cleanup. Customers wanting an LLM-as-judge for faithfulness should
# use kya.scorer_orchestrator.check_consensus() with the
# arize_phoenix or openai_judge adapters (both via litellm), or
# plug in their own via register_judge(). See CHANGELOG.
from .phoenix_poll import (
    PollResult,
    poll_phoenix_evals,
    start_phoenix_poll_thread,
    stop_phoenix_poll_thread,
)
from .phoenix_poll import (
    is_enabled as phoenix_poll_enabled,
)
from .principal_edges import (
    DEFAULT_EDGE_KIND,
    PrincipalEdge,
    add_principal_edge,
    ensure_principal_edges_table,
    list_children,
    list_parents,
    remove_principal_edge,
    walk_ancestors,
    walk_descendants,
)
from .principals import (
    PRINCIPAL_KINDS,
    PrincipalTrust,
    detect_principal_burst_anomalies,
    ensure_principal_table,
    get_principal_trust,
    get_principal_window_counts,
    is_valid_principal_kind,
    list_principals,
    principal_fingerprint,
    record_principal_clean,
    record_principal_signal,
    register_principal_kind,
    registered_principal_kinds,
)
from .requests import (
    RequestSummary,
    list_recent_requests,
    request_score,
    summarize_request,
)
from .risk import (
    AgentRiskScore,
    RiskFactor,
    bucket_for,
    is_admin_tool,
    is_write_tool,
    score_agent,
    set_tool_catalog,
)
from .security_caps import (
    CAPABILITY_WEIGHTS,
    DEFAULT_TOOL_CAPABILITIES,
    SECURITY_CAPS,
    capability_weight,
    classify_tool_capabilities,
    infer_capabilities,
    set_capability_weights,
    set_tool_capabilities,
)
from .security_caps import CAPABILITY_WEIGHTS as _CAPABILITY_WEIGHTS
from .session import default_session, reset_default_session
from .skills import (
    DEFAULT_SKILL_CLASSIFICATIONS,
    classify_skill,
    flatten_to_tools,
    infer_skill_classifications,
    normalize_skills,
    set_skill_classifications,
)
from .supply_chain import parse_dependencies, supply_chain_weight
from .tenant_weights import (
    OverrideLoosensError,
    delete_override,
    get_effective_weights,
    known_scopes,
    list_overrides,
    list_recent_changes,
    register_scope,
    set_override,
)
from .tenant_weights import (
    ensure_tables as ensure_weight_tables,
)
from .trust_signals import citation_weight, trust_score_weight
from .users import (
    SIGNAL_DELTAS,
    STARTING_TRUST,
    UserTrust,
    bucket_for_trust,
    ensure_user_trust_table,
    get_user_trust,
    list_user_trust,
    record_user_clean,
    record_user_signal,
)

register_scope("class_weights", _CLASS_WEIGHTS)
register_scope("capability_weights", _CAPABILITY_WEIGHTS)
register_scope("source_weights", _SOURCE_WEIGHTS)
register_scope("deployment_weights", _DEPLOYMENT_WEIGHTS)
from ._inbound_signing import SignatureVerificationError
from ._redactor import Redactor as DualWriteRedactor
from ._session_factory import (
    has_factory as has_session_factory,
)
from ._session_factory import (
    set_session_factory,
)
from ._valkey import (
    get_valkey,
    register_valkey_factory,
    reset_valkey_cache,
)
from .assessment import (
    AssessmentReport,
    Finding,
    pillar_authority_mapping,
    pillar_delegation_analysis,
    pillar_evidence_chain_review,
    pillar_provenance_assessment,
    pillar_trust_scoring,
    run_assessment,
)
from .audit_export import (
    EXPORT_SCHEMA_VERSION,
    AuditExportError,
    SignatureVerificationFailed,
    signed_export,
    verify_signed_export,
)
from .auth import (
    bind_principal_from_token,
    claims_to_kya_principal,
    reset_jwks_cache,
    verify_jwt,
)
from .autoinstrument import (
    autoinstrument,
    deinstrument,
    patched_sdks,
)
from .delegation_analytics import (
    DEFAULT_SPIKE_THRESHOLD,
    DEFAULT_STABLE_DAYS_TO_PROMOTE,
    DEFAULT_WINDOW_DAYS,
    VALID_RECOMMENDATIONS,
    delegation_readiness_report,
)
from .delegation_overrides import (
    InvalidOverrideError,
    delete_delegation_override,
    ensure_delegation_overrides_table,
    list_delegation_overrides,
    resolve_effective_mode,
    set_delegation_override,
)
from .delegation_policy import (
    DELEGATION_POLICY_MODES,
    DelegationPolicyError,
    check_delegation,
    enforce_delegation_policy,
    ensure_delegation_violations_table,
)
from .dualwrite import (
    ALLOWED_TABLES as DUAL_WRITE_ALLOWED_TABLES,
)
from .dualwrite import (
    DualWriteAllowlistError,
    disable_dual_write,
    dual_write_status,
    enable_dual_write,
)
from .evidence import (
    VALID_EVIDENCE_KINDS,
    get_evidence,
    init_evidence_table,
    list_evidence,
    prune_expired_evidence,
    record_evidence,
    verify_chain,
)
from .external_id import (
    IDP_KINDS,
    InvalidIdpKindError,
    bind_principal_to_idp,
    bind_user_to_idp,
    list_principals_by_idp_kind,
    lookup_principal_by_idp,
    lookup_user_by_idp,
)
from .format_adapter import (
    SupportedFramework,
    list_adapters,
    normalize_agent_def,
    register_adapter,
)
from .inbound import (
    KNOWN_SCOPES as INBOUND_KNOWN_SCOPES,
)
from .inbound import (
    approve_recommendation,
    disable_inbound,
    enable_inbound,
    inbound_status,
    list_recommendations,
    reject_recommendation,
)
from .inbound import (
    fetch_now as fetch_inbound_now,
)
from .payload_caps import (
    DEFAULT_MAX_PAYLOAD_BYTES,
    PayloadTooLargeError,
    check_payload_size,
)
from .policy_config import (
    DEFAULT_MODE as DEFAULT_DELEGATION_MODE,
)
from .policy_config import (
    InvalidDelegationModeError,
    active_delegation_mode,
    configure_delegation_policy,
)
from .quality import (
    QualityReport,
    get_quality_signals,
    quality_score,
    record_hallucination,
    record_injection_attempt,
    record_qa_irrelevance,
)
from .rate_limit import (
    RateLimitExceededError,
    maybe_rate_limit,
    reset_rate_limit_state,
)
from .rbac import (
    ACTIONS as RBAC_ACTIONS,
)
from .rbac import (
    RBAC_MODES,
    AccessDeniedError,
    InvalidActionError,
    InvalidRbacModeError,
    active_rbac_mode,
    configure_rbac,
    ensure_rbac_table,
    grant_action,
    has_action,
    list_grants,
    require_action,
    revoke_action,
)
from .realtime import (
    ALLOWED_SIGNAL_KINDS,
    WINDOWS,
    detect_burst_anomalies,
    get_window_counts,
    record_signal,
    subscribe_alerts,
)
from .replay_protection import (
    ReplayDetectedError,
    generate_nonce,
    is_valid_nonce,
    reset_replay_state,
    verify_request_nonce,
)
from .rogue import (
    Anomaly,
    RogueReport,
    get_anomalies,
    get_governance_summary,
    get_rogue_signals,
    record_cross_tenant_attempt,
    record_data_leak,
    record_oos_tool_attempt,
    record_policy_violation,
    rogue_score,
)
from .spiffe import (
    SpiffeIdFormatError,
    SpiffeVerificationError,
    _reset_spiffe_warned_state,
    bind_principal_from_svid,
    bind_spiffe_id_to_principal,
    is_allowed_trust_domain,
    is_valid_spiffe_id,
    lookup_principal_by_spiffe_id,
    parse_spiffe_id,
    verify_jwt_svid,
)
from .storage import init_storage
from .telemetry import (
    disable_telemetry,
    enable_telemetry,
    telemetry_status,
)
from .tenant_budget import (
    budget_status,
    current_spend,
    delete_budget,
    forecast_spend,
    get_budget,
    get_forecaster,
    list_budgets,
    list_changes,
    record_cost_event,
    set_budget,
    set_forecaster,
    should_refuse,
)
from .tenant_budget import (
    ensure_tables as ensure_budget_tables,
)
from .tenant_budget import (
    health_check as budget_health_check,
)
from .versioning import (
    ensure_table,
    get_principal_version,
    get_version,
    list_principal_versions,
    list_versions,
    rollback_to,
    snapshot_agent,
    snapshot_on_first_sight,
    snapshot_principal,
)

__all__ = [
    # session
    "default_session",
    "reset_default_session",
    # risk
    "AgentRiskScore",
    "RiskFactor",
    "bucket_for",
    "score_agent",
    "is_write_tool",
    "is_admin_tool",
    "set_tool_catalog",
    # data classification
    "DATA_CLASSES",
    "CLASS_WEIGHTS",
    "DEFAULT_TOOL_CLASSIFICATIONS",
    "classify_tool",
    "infer_data_classes",
    "sensitivity_weight",
    "set_class_weights",
    "set_tool_classifications",
    # versioning + unified storage setup
    "ensure_table",
    "snapshot_agent",
    "snapshot_on_first_sight",
    "list_versions",
    "get_version",
    "rollback_to",
    "init_storage",
    # forensic evidence capture (HMAC-chained, tamper-evident)
    "VALID_EVIDENCE_KINDS",
    "init_evidence_table",
    "record_evidence",
    "list_evidence",
    "get_evidence",
    "verify_chain",
    "prune_expired_evidence",
    # Zero-config capture for custom agents + direct LLM SDK calls
    "autoinstrument",
    "deinstrument",
    "patched_sdks",
    # rogue + governance + anomalies
    "RogueReport",
    "Anomaly",
    "record_oos_tool_attempt",
    "record_cross_tenant_attempt",
    "record_data_leak",
    "record_policy_violation",
    "get_rogue_signals",
    "rogue_score",
    "get_governance_summary",
    "get_anomalies",
    # security capabilities
    "SECURITY_CAPS",
    "CAPABILITY_WEIGHTS",
    "DEFAULT_TOOL_CAPABILITIES",
    "classify_tool_capabilities",
    "infer_capabilities",
    "capability_weight",
    "set_capability_weights",
    "set_tool_capabilities",
    # adapter (pluggable registry)
    "normalize_agent_def",
    "SupportedFramework",
    "register_adapter",
    "list_adapters",
    # real-time monitoring (Valkey sliding windows + pub/sub alerts)
    "record_signal",
    "get_window_counts",
    "detect_burst_anomalies",
    "subscribe_alerts",
    "WINDOWS",
    # quality signals (hallucination, QA relevance, prompt injection)
    "QualityReport",
    "record_hallucination",
    "record_qa_irrelevance",
    "record_injection_attempt",
    "get_quality_signals",
    "quality_score",
    # delegation depth
    "max_delegation_depth",
    "delegation_chain",
    "delegation_weight",
    # blast radius
    "BlastRadiusBreakdown",
    "blast_radius_breakdown",
    "blast_radius_weight",
    # input sources (where the agent ingests from)
    "INPUT_SOURCES",
    "SOURCE_WEIGHTS",
    "input_source_weight",
    "set_source_weights",
    # Round 8 — lifecycle / supply chain / deployment / trust / cost
    "ownership_weight",
    "approval_weight",
    "lifecycle_weight",
    "supply_chain_weight",
    "parse_dependencies",
    "DEPLOYMENT_WEIGHTS",
    "deployment_weight",
    "set_deployment_weights",
    "citation_weight",
    "trust_score_weight",
    "cost_burn_weight",
    # compliance scope (GDPR, HIPAA, SOX, PCI, CCPA, GLBA, FERPA, EU AI Act, etc.)
    "REGIMES",
    "REGIME_RETENTION_DAYS",
    "REGIME_BREACH_NOTIFY",
    "eu_ai_act_tier",
    "required_controls",
    "elevated_severity",
    "max_retention_days",
    "compliance_summary",
    # integrity + lineage (cybersec primitives)
    "canonical_hash",
    "detect_drift",
    "lineage_chain",
    "lineage_risk_inheritance",
    "verify_signature",
    # Round 11.1 — tenant-scoped weight overrides
    "ensure_weight_tables",
    "register_scope",
    "known_scopes",
    "get_effective_weights",
    "set_override",
    "delete_override",
    "list_overrides",
    "list_recent_changes",
    "OverrideLoosensError",
    # Round 11.2 — interaction multipliers
    "INTERACTIONS",
    "Interaction",
    "MAX_MULTIPLIER",
    "detect_interactions",
    "compute_interaction_multiplier",
    "register_interaction",
    "list_interactions",
    # Round 11.3 — KYU (per-user trust)
    "UserTrust",
    "STARTING_TRUST",
    "SIGNAL_DELTAS",
    "bucket_for_trust",
    "ensure_user_trust_table",
    "record_user_signal",
    "record_user_clean",
    "get_user_trust",
    "list_user_trust",
    # Round 11.4 — incident feedback loop
    "ensure_suggestions_table",
    "propose_from_incident",
    "list_suggestions",
    "approve_suggestion",
    "reject_suggestion",
    # Round 12 — skills as first-class
    "DEFAULT_SKILL_CLASSIFICATIONS",
    "normalize_skills",
    "flatten_to_tools",
    "classify_skill",
    "infer_skill_classifications",
    "set_skill_classifications",
    # Round 13 — Principal generalization + delegation trust + invocation tracking
    "PRINCIPAL_KINDS",
    "PrincipalTrust",
    "ensure_principal_table",
    "record_principal_signal",
    "record_principal_clean",
    "get_principal_trust",
    "list_principals",
    "get_principal_window_counts",
    "detect_principal_burst_anomalies",
    "delegation_trust_weight",
    # v0.1.8 — extensible principal vocabulary
    "register_principal_kind",
    "is_valid_principal_kind",
    "registered_principal_kinds",
    # v0.1.8 — many-to-many principal DAG
    "PrincipalEdge",
    "DEFAULT_EDGE_KIND",
    "ensure_principal_edges_table",
    "add_principal_edge",
    "remove_principal_edge",
    "list_children",
    "list_parents",
    "walk_descendants",
    "walk_ancestors",
    # v0.1.8 — generalised definition versioning
    "snapshot_principal",
    "list_principal_versions",
    "get_principal_version",
    # v0.1.8 — hierarchical fingerprint middle layer
    "principal_fingerprint",
    # Invocation tracking (event-time vs ingest-time + parallel tree)
    "VALID_MODES",
    "VALID_OUTCOMES",
    "ensure_invocations_table",
    "record_invocation",
    "list_invocations",
    "mode_distribution",
    "active_parallel_invocations",
    "ingest_lag_stats",
    "new_correlation_id",
    # Priority 2 — request-level rollups (correlation_id aggregation)
    "RequestSummary",
    "summarize_request",
    "list_recent_requests",
    "request_score",
    # Priority 4 — fault attribution heuristic (per-agent divergence)
    "DivergenceReport",
    "agent_divergence_score",
    # Round 15 — LLM-judge for fault attribution: REMOVED in
    # "KYA = governance, not detection" cleanup. Use
    # kya.scorer_orchestrator.check_consensus() with arize_phoenix
    # or openai_judge adapters instead.
    # Round 16 — Phoenix evaluator polling
    "PollResult",
    "phoenix_poll_enabled",
    "poll_phoenix_evals",
    "start_phoenix_poll_thread",
    "stop_phoenix_poll_thread",
    # Dual-write (opt-in row mirroring) + aggregate telemetry (on by default,
    # counts only, no payloads — disable with disable_telemetry()).
    "enable_dual_write",
    "disable_dual_write",
    "dual_write_status",
    "DUAL_WRITE_ALLOWED_TABLES",
    "DualWriteAllowlistError",
    "DualWriteRedactor",
    "enable_telemetry",
    "disable_telemetry",
    "telemetry_status",
    # Inbound recommendations — cross-tenant feedback loop (opt-in pull;
    # Ed25519-signed; operator-gated apply via set_override).
    "enable_inbound",
    "disable_inbound",
    "inbound_status",
    "fetch_inbound_now",
    "list_recommendations",
    "approve_recommendation",
    "reject_recommendation",
    "INBOUND_KNOWN_SCOPES",
    "SignatureVerificationError",
    # Session-factory injection — lets SDK users plug their own
    # sessionmaker into rogue/inbound mirror-write paths without
    # depending on the platform's db.database.SessionLocal.
    "set_session_factory",
    "has_session_factory",
    # Delegation-policy enforcement (principal-of-least-privilege chain
    # for sub-agents). Honored automatically by record_invocation when
    # principal_kind=="agent". Mode via env KYA_DELEGATION_POLICY:
    # "observe" (default), "flag", or "block".
    "DELEGATION_POLICY_MODES",
    "DelegationPolicyError",
    "check_delegation",
    "enforce_delegation_policy",
    "ensure_delegation_violations_table",
    # One-line startup configurator for the delegation-policy mode.
    # configure_delegation_policy("observe") is the safe default; flip
    # to "flag" then "block" as the violations surface stabilizes.
    "configure_delegation_policy",
    "active_delegation_mode",
    "DEFAULT_DELEGATION_MODE",
    "InvalidDelegationModeError",
    # Readiness report — operator-facing aggregation over the
    # violations table with deterministic recommendations. Surfaces
    # only items needing review (noise suppression for high-volume
    # tenants); each recommendation carries rule_id + rationale.
    "delegation_readiness_report",
    "VALID_RECOMMENDATIONS",
    "DEFAULT_WINDOW_DAYS",
    "DEFAULT_STABLE_DAYS_TO_PROMOTE",
    "DEFAULT_SPIKE_THRESHOLD",
    # Phase 2 — per-scope delegation policy overrides. Operators
    # target specific agent pairs / violation kinds with different
    # modes; resolution is specificity-ordered (most-specific wins,
    # ties broken by created_at DESC). Falls back to global env.
    "set_delegation_override",
    "delete_delegation_override",
    "list_delegation_overrides",
    "resolve_effective_mode",
    "ensure_delegation_overrides_table",
    "InvalidOverrideError",
    # Phase 4b — external-ID binding for principals + users. Adds
    # idp_subject/idp_issuer/idp_kind/federated_id columns + lookup
    # helpers so KYA trust records can be linked back to the
    # upstream IdP user (Okta/Auth0/Keycloak/Google/Entra/Cognito/
    # SPIFFE). Independent of Phase 4a — caller can supply the
    # claims from any source.
    "bind_principal_to_idp",
    "bind_user_to_idp",
    "lookup_principal_by_idp",
    "lookup_user_by_idp",
    "list_principals_by_idp_kind",
    "IDP_KINDS",
    "InvalidIdpKindError",
    # Phase 4a — JWT introspection + claim extraction. Decodes
    # OIDC/OAuth bearer tokens against a JWKS endpoint, returns
    # claims dict, can auto-populate Phase 4b's external_id columns
    # via bind_principal_from_token(). Optional PyJWT dependency.
    "verify_jwt",
    "claims_to_kya_principal",
    "bind_principal_from_token",
    "reset_jwks_cache",
    # Phase 4a.1 — KYA-semantic rate limiting + payload size caps
    # on write primitives. Both OFF by default; operators opt in
    # via KYA_RATE_LIMIT_DEFAULT_RPS / KYA_MAX_<PRIM>_PAYLOAD_BYTES.
    # Used internally by record_invocation / record_evidence /
    # record_cost_event today; record_principal_signal /
    # set_delegation_override / set_budget will follow in future
    # commits as the surface stabilizes.
    "maybe_rate_limit",
    "RateLimitExceededError",
    "reset_rate_limit_state",
    "check_payload_size",
    "PayloadTooLargeError",
    "DEFAULT_MAX_PAYLOAD_BYTES",
    # Phase 5a — replay protection (Valkey-backed nonce table with
    # TTL). Off-by-default. Operators opt in via
    # KYA_REPLAY_PROTECTION=on. Each (tenant, principal, nonce)
    # combination is uniquely reserved for KYA_REPLAY_MAX_AGE_SECONDS
    # (default 300). Two-axis check: nonce uniqueness AND timestamp
    # freshness — both required to defeat replay attacks.
    "verify_request_nonce",
    "generate_nonce",
    "is_valid_nonce",
    "reset_replay_state",
    "ReplayDetectedError",
    # Phase 5b — RBAC tied to KYA-specific actions. Off by default
    # via KYA_RBAC_ENFORCEMENT=off; flip to "flag" then "block"
    # for staged rollout. ACTIONS is the closed set of valid
    # action strings — extending requires a code change so typos
    # in grants are caught at insert time.
    "grant_action",
    "revoke_action",
    "list_grants",
    "has_action",
    "require_action",
    "configure_rbac",
    "active_rbac_mode",
    "ensure_rbac_table",
    "RBAC_ACTIONS",
    "RBAC_MODES",
    "AccessDeniedError",
    "InvalidActionError",
    "InvalidRbacModeError",
    # Phase 5d — SDK-friendly Valkey accessor. Without redis-py
    # installed and KYA_VALKEY_URL / REDIS_URL set, every hardening
    # feature degrades to fail-open silently. With them, hardening
    # actually works for PyPI-installed standalone deployments.
    "get_valkey",
    "register_valkey_factory",
    "reset_valkey_cache",
    # Phase 5c — Signed audit-trail export. Composes the existing
    # HMAC-chained evidence with a customer-owned Ed25519 signature.
    # Auditors verify OFFLINE with only the export + public key —
    # no live KYA access needed. signed_export() produces, the
    # verify_signed_export() verifies; both are pure and stateless.
    "signed_export",
    "verify_signed_export",
    "EXPORT_SCHEMA_VERSION",
    "AuditExportError",
    "SignatureVerificationFailed",
    # Autonomous Systems Trust Assessment -- the 30-day productized
    # assessment offering. run_assessment() orchestrates the five
    # pillars (trust scoring, authority mapping, delegation analysis,
    # provenance, evidence chain review) and emits an AssessmentReport
    # with optional Ed25519-signed evidence artifact. Each pillar is
    # individually callable; orchestrator fails soft per pillar.
    "Finding",
    "AssessmentReport",
    "run_assessment",
    "pillar_trust_scoring",
    "pillar_authority_mapping",
    "pillar_delegation_analysis",
    "pillar_provenance_assessment",
    "pillar_evidence_chain_review",
    # Economic Control (tenant_budget primitive — was shipped in
    # the budget Phase 1 commit but not re-exported at the top
    # level; users were forced to import from kya.tenant_budget).
    # Exposed here so the public API is "from kya import X".
    "record_cost_event",
    "set_budget",
    "get_budget",
    "list_budgets",
    "delete_budget",
    "list_changes",
    "current_spend",
    "forecast_spend",
    "should_refuse",
    "budget_status",
    "budget_health_check",
    "ensure_budget_tables",
    "set_forecaster",
    "get_forecaster",
]
