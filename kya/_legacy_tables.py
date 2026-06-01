"""
Portable ORM definitions for the 12 remaining KYA tables that were raw
PG-only DDL. Each table is declared once here via the dialect-aware
helpers in `_portable.py`; the owning module imports its specific Table
and runs `metadata.create_all` in its `ensure_X` function.

Tables defined:
    1. kya_agent_aliases             (agent_aliases.py)
    2. kya_user_trust                (users.py)
    3. kya_weight_overrides          (tenant_weights.py)
    4. kya_weight_changes            (tenant_weights.py)
    5. kya_weight_suggestions        (feedback.py)
    6. kya_breach_notifications      (compliance_shim.py)
    7. kya_redteam_campaigns         (kya_redteam/campaigns.py)
    8. kya_redteam_findings          (kya_redteam/campaigns.py)
    9. kya_redteam_tenant_policy     (kya_redteam/campaigns.py)
   10. kya_redteam_runs              (kya_redteam/runs.py)
   11. kya_redteam_targets           (kya_redteam/targets.py)
   12. kya_redteam_target_secrets    (kya_redteam/targets.py)
   13. kya_inbound_recommendations   (inbound.py)
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Index,
    LargeBinary,
    MetaData,
    Numeric,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)

from ._portable import (
    autoinc_id,
    dialect_schema_qualifier,
    json_or_jsonb,
    portable_bigint,
    uuid_or_string,
)

# All legacy tables share one MetaData so create_all can be batched.
# Schema is set to whatever `dialect_schema_qualifier()` returns at
# import time; the actual dialect-aware retargeting happens at CALL
# TIME via the `create_legacy_tables()` helper below, which uses
# SQLAlchemy's `schema_translate_map`. This solves the previous bug
# where env vars set AFTER import had no effect.
_LEGACY_MD_IMPORT_SCHEMA = dialect_schema_qualifier()
_LEGACY_MD = MetaData(schema=_LEGACY_MD_IMPORT_SCHEMA)


def create_legacy_tables(db, tables: list) -> None:
    """Idempotent create_all for the legacy tables, with the right
    schema qualifier for the bound dialect.

    Behavior:
        PG  + KYA_VERSIONS_SCHEMA set    -> tables in that schema
        PG  + KYA_VERSIONS_SCHEMA unset  -> tables in default (public)
        SQLite / DuckDB / MySQL          -> tables in default namespace
                                            (schema_translate_map strips
                                            the import-time qualifier)

    Uses SQLAlchemy's `schema_translate_map` execution option which
    rewrites table-name qualifiers at SQL-emission time without rebuilding
    the Table objects.
    """
    bind = db.connection()
    schema = dialect_schema_qualifier()  # read env at CALL time
    dialect = bind.engine.dialect.name

    if dialect == "postgresql" and schema == _LEGACY_MD_IMPORT_SCHEMA:
        # PG with the same schema setting as at import — emit table
        # names as-is (no remap needed because _LEGACY_MD.schema
        # already matches).
        target_bind = bind
    else:
        # Non-PG OR the env value changed between import and call —
        # remap the import-time qualifier to the current target.
        target_schema = schema if dialect == "postgresql" else None
        # MERGE with any pre-existing schema_translate_map the caller
        # already set on the connection. Replacing it blindly would
        # (a) silently break the customer's own translation rules and
        # (b) trigger SA's "schema translate map which previously had
        # X present as a key now no longer has it present" error when
        # the key sets differ between successive maps. By merging,
        # our addition is additive and harmless to other entries.
        existing = (
            bind.get_execution_options().get("schema_translate_map") or {})
        merged = dict(existing)
        merged[_LEGACY_MD_IMPORT_SCHEMA] = target_schema
        target_bind = bind.execution_options(schema_translate_map=merged)
    _LEGACY_MD.create_all(bind=target_bind, tables=tables)


# 1. kya_agent_aliases — alias → canonical agent_key
kya_agent_aliases = Table(
    "kya_agent_aliases",
    _LEGACY_MD,
    autoinc_id("kya_agent_aliases_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    # String(255) instead of Text — MySQL can't index TEXT in UNIQUE
    # constraints without an explicit key length prefix.
    Column("alias", String(255), nullable=False),
    Column("canonical_agent_key", String(50), nullable=False),
    Column("note", Text, nullable=True),
    Column("created_by", uuid_or_string(), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_id", "alias", name="uq_kya_agent_aliases_tenant_alias"),
    Index("idx_kya_agent_aliases_canonical",
          "tenant_id", "canonical_agent_key"),
)


# 2. kya_user_trust — per-tenant user trust score.
# Phase 4b adds idp_subject / idp_issuer / idp_kind / federated_id —
# optional pointers to the upstream Identity Provider's view of the
# same user. Populated by bind_user_to_idp() or directly via the
# users.py API. All nullable; existing deployments pick them up via
# additive ALTER (kya/users.py ensure_user_trust_table).
kya_user_trust = Table(
    "kya_user_trust",
    _LEGACY_MD,
    autoinc_id("kya_user_trust_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("user_id", uuid_or_string(), nullable=False),
    Column("trust_score", BigInteger, nullable=False, default=50),
    Column("signal_counts", json_or_jsonb(), nullable=False, default=dict),
    Column("idp_subject", String(255), nullable=True),
    Column("idp_issuer", String(255), nullable=True),
    Column("idp_kind", String(50), nullable=True),
    Column("federated_id", String(500), nullable=True),
    Column("last_signal_at", DateTime(timezone=True), nullable=True),
    Column("last_clean_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_id", "user_id", name="uq_kya_user_trust_tenant_user"),
    # Phase 4d fix: the idx_kya_user_trust_tenant_score index
    # (trust_score column) and the idp_subject index are
    # INTENTIONALLY OMITTED from the Table() definition. DuckDB's
    # ART index rejects UPDATE on any indexed column, which would
    # break record_user_signal's INSERT ... ON CONFLICT DO UPDATE
    # path. The indexes are added back conditionally for non-DuckDB
    # dialects via ALTER TABLE in
    # kya.users.ensure_user_trust_table().
)


# 3. kya_weight_overrides — tenant-specific scoring weight overrides
kya_weight_overrides = Table(
    "kya_weight_overrides",
    _LEGACY_MD,
    autoinc_id("kya_weight_overrides_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=True),  # NULL = platform default
    Column("scope", String(50), nullable=False),
    Column("key", String(100), nullable=False),
    Column("value", BigInteger, nullable=False),
    Column("created_by", uuid_or_string(), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_id", "scope", "key",
                     name="uq_kya_weight_overrides_tenant_scope_key"),
    Index("idx_kya_weight_overrides_tenant_scope", "tenant_id", "scope"),
    # PG and SQLite (default) both treat NULL as DISTINCT in UNIQUE
    # indexes, so the constraint above does NOT coalesce platform-level
    # rows (tenant_id IS NULL). Without this partial index, repeated
    # platform-level writes accumulate duplicate rows for the same
    # (scope, key) — observed and documented in the three-channel
    # composition witness (May 2026). The WHERE clause is supported on
    # PG 9.0+ and SQLite 3.8+. MySQL ignores postgresql_where; on MySQL
    # the same-NULL-treats-as-distinct semantics persist (acceptable
    # known limit; multiple platform-level rows are caught read-side by
    # ORDER BY id DESC LIMIT 1).
    Index("uq_kya_weight_overrides_platform_scope_key",
          "scope", "key",
          unique=True,
          postgresql_where=text("tenant_id IS NULL"),
          sqlite_where=text("tenant_id IS NULL")),
)


# 4. kya_weight_changes — audit log for weight overrides
kya_weight_changes = Table(
    "kya_weight_changes",
    _LEGACY_MD,
    autoinc_id("kya_weight_changes_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=True),
    Column("scope", String(50), nullable=False),
    Column("key", String(100), nullable=False),
    Column("old_value", BigInteger, nullable=True),
    Column("new_value", BigInteger, nullable=True),
    Column("action", String(20), nullable=False),
    Column("changed_by", uuid_or_string(), nullable=True),
    Column("reason", Text, nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Index("idx_kya_weight_changes_tenant_created", "tenant_id", "created_at"),
)


# 5. kya_weight_suggestions — proposals for weight tuning
kya_weight_suggestions = Table(
    "kya_weight_suggestions",
    _LEGACY_MD,
    autoinc_id("kya_weight_suggestions_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=True),
    Column("incident_id", BigInteger, nullable=True),
    Column("agent_key", String(100), nullable=True),
    Column("scope", String(50), nullable=False),
    Column("key", String(100), nullable=False),
    Column("current_value", BigInteger, nullable=True),
    Column("suggested_value", BigInteger, nullable=False),
    Column("suggested_delta", BigInteger, nullable=False),
    Column("rationale", Text, nullable=True),
    Column("evidence", json_or_jsonb(), nullable=False, default=dict),
    Column("status", String(20), nullable=False, default="pending"),
    Column("suggested_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("decided_at", DateTime(timezone=True), nullable=True),
    Column("decided_by", uuid_or_string(), nullable=True),
    Column("decision_notes", Text, nullable=True),
    Index("idx_kya_suggestions_tenant_status",
          "tenant_id", "status", "suggested_at"),
)


# 6. kya_breach_notifications — outbound regulator notifications
kya_breach_notifications = Table(
    "kya_breach_notifications",
    _LEGACY_MD,
    autoinc_id("kya_breach_notifications_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("incident_id", BigInteger, nullable=False),
    # String(100) instead of Text — MySQL can't UNIQUE on TEXT without key length.
    Column("regime", String(100), nullable=False),
    Column("format", String(50), nullable=False),
    Column("notified_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("destinations", BigInteger, nullable=False, default=0),
    Column("payload_summary", json_or_jsonb(), nullable=True),
    UniqueConstraint("incident_id", "regime",
                     name="uq_kya_breach_notify_incident_regime"),
    Index("idx_kya_breach_notify_tenant", "tenant_id", "notified_at"),
)


# 7. kya_redteam_campaigns — scheduled red-team test definitions
kya_redteam_campaigns = Table(
    "kya_redteam_campaigns",
    _LEGACY_MD,
    autoinc_id("kya_redteam_campaigns_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("agent_key", String(50), nullable=False),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("orchestrator_kind", String(50), nullable=False),
    Column("scorer_kind", String(50), nullable=False),
    Column("dataset", String(200), nullable=True),
    Column("attacker_llm", String(100), nullable=True),
    Column("converters", json_or_jsonb(), nullable=True),
    Column("schedule_cron", Text, nullable=True),
    Column("budget_max_prompts", BigInteger, nullable=False, default=100),
    Column("threshold", Numeric(3, 2), nullable=False, default=0.5),
    Column("enabled", Boolean, nullable=False, default=True),
    Column("tier_required", Text, nullable=False, default="free"),
    Column("auto_incident_mode", Text, nullable=False, default="never"),
    Column("last_run_at", DateTime(timezone=True), nullable=True),
    Column("last_run_status", Text, nullable=True),
    Column("last_run_finding_count", BigInteger, nullable=True),
    Column("next_run_at", DateTime(timezone=True), nullable=True),
    Column("created_by", uuid_or_string(), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Index("idx_kya_redteam_campaigns_tenant_agent",
          "tenant_id", "agent_key"),
)


# 8. kya_redteam_findings — individual vulnerabilities found
kya_redteam_findings = Table(
    "kya_redteam_findings",
    _LEGACY_MD,
    autoinc_id("kya_redteam_findings_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("campaign_id", BigInteger, nullable=True),  # FK target lives in same metadata
    Column("run_id", uuid_or_string(), nullable=False),
    Column("agent_key", String(50), nullable=False),
    Column("orchestrator", Text, nullable=True),
    Column("attack_category", String(100), nullable=True),
    Column("finding_class", String(100), nullable=True),
    # severity indexed — must have explicit length for MySQL
    Column("severity", String(50), nullable=True),
    Column("score", Numeric(3, 2), nullable=True),
    Column("prompt_redacted", Text, nullable=True),
    Column("response_redacted", Text, nullable=True),
    Column("conversation_redacted", json_or_jsonb(), nullable=True),
    Column("pyrit_memory_id", Text, nullable=True),
    Column("evidence_source", Text, nullable=False, default="pyrit"),
    Column("posted_event_id", BigInteger, nullable=True),
    Column("promoted_incident_id", BigInteger, nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Index("idx_kya_redteam_findings_run", "tenant_id", "agent_key", "run_id"),
    Index("idx_kya_redteam_findings_severity", "tenant_id", "severity"),
)


# 9. kya_redteam_tenant_policy — per-tenant red-team tier + budget
kya_redteam_tenant_policy = Table(
    "kya_redteam_tenant_policy",
    _LEGACY_MD,
    Column("tenant_id", uuid_or_string(), primary_key=True),
    Column("max_auto_incident_mode", Text, nullable=False, default="never"),
    Column("budget_monthly_prompts", BigInteger, nullable=False, default=10000),
    Column("redteam_tier", Text, nullable=False, default="free"),
    Column("attacker_llm_model", Text, nullable=True),
    Column("attacker_tokens_monthly_cap", BigInteger, nullable=True),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("updated_by", uuid_or_string(), nullable=True),
)


# 10. kya_redteam_runs — campaign execution history
kya_redteam_runs = Table(
    "kya_redteam_runs",
    _LEGACY_MD,
    autoinc_id("kya_redteam_runs_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("run_id", uuid_or_string(), nullable=False, unique=True),
    Column("campaign_id", BigInteger, nullable=True),
    Column("agent_key", String(50), nullable=False),
    Column("orchestrator", Text, nullable=False),
    Column("target_id", BigInteger, nullable=True),
    Column("target_endpoint_redacted", Text, nullable=True),
    Column("status", Text, nullable=False, default="queued"),
    Column("cancel_requested", Boolean, nullable=False, default=False),
    Column("cancel_requested_by", uuid_or_string(), nullable=True),
    Column("cancel_requested_at", DateTime(timezone=True), nullable=True),
    Column("started_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("finished_at", DateTime(timezone=True), nullable=True),
    Column("last_heartbeat_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("prompts_sent", BigInteger, nullable=False, default=0),
    Column("findings_count", BigInteger, nullable=False, default=0),
    Column("severity_buckets", json_or_jsonb(), nullable=False, default=dict),
    Column("attacker_tokens_estimated", BigInteger, nullable=False, default=0),
    Column("target_errors", BigInteger, nullable=False, default=0),
    Column("posted_event_ids", json_or_jsonb(), nullable=False, default=list),
    Column("auto_incidents_created", BigInteger, nullable=False, default=0),
    Column("error_message", Text, nullable=True),
    Column("initiated_by", uuid_or_string(), nullable=True),
    Column("attestation_id", BigInteger, nullable=True),
    Index("idx_kya_redteam_runs_tenant_agent", "tenant_id", "agent_key"),
)


# 11. kya_redteam_targets — red-team execution targets (the agents under test)
kya_redteam_targets = Table(
    "kya_redteam_targets",
    _LEGACY_MD,
    autoinc_id("kya_redteam_targets_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("agent_key", String(50), nullable=False),
    # `name` is UNIQUE-constrained — must have explicit length for MySQL
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("endpoint_url", String(500), nullable=False),
    Column("auth_kind", String(50), nullable=False, default="bearer"),
    Column("auth_header_name", String(100), nullable=True),
    Column("body_template", json_or_jsonb(), nullable=True),
    Column("response_parser_kind", Text, nullable=False, default="standard"),
    Column("rate_limit_rps", Numeric(5, 2), nullable=False, default=1.0),
    Column("enabled", Boolean, nullable=False, default=True),
    Column("verified_at", DateTime(timezone=True), nullable=True),
    Column("verified_status", Text, nullable=False, default="never"),
    Column("verified_error", Text, nullable=True),
    Column("created_by", uuid_or_string(), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_id", "name", name="uq_kya_redteam_targets_tenant_name"),
    Index("idx_kya_redteam_targets_tenant_agent", "tenant_id", "agent_key"),
)


# 12. kya_redteam_target_secrets — encrypted credentials per target
kya_redteam_target_secrets = Table(
    "kya_redteam_target_secrets",
    _LEGACY_MD,
    # PK that's ALSO a FK target — explicit autoincrement=False prevents
    # SQLAlchemy from emitting BIGSERIAL (DuckDB rejects that keyword).
    # The id value comes from the parent kya_redteam_targets.id at insert.
    Column("target_id", portable_bigint(), primary_key=True, autoincrement=False),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("ciphertext", LargeBinary, nullable=False),
    Column("key_id", Text, nullable=False),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
)


# 13. kya_inbound_recommendations — signed weight-tightening recommendations
#     fetched from the Veldt collector. Pending until an operator approves
#     (default) or until they match a customer-configured auto-apply
#     allowlist. Apply step routes through tenant_weights.set_override(),
#     so the only-tighten constraint still gates final value.
kya_inbound_recommendations = Table(
    "kya_inbound_recommendations",
    _LEGACY_MD,
    autoinc_id("kya_inbound_recommendations_id_seq"),
    Column("external_id", String(64), nullable=False),
    Column("signing_key_id", String(64), nullable=False),
    Column("tenant_id", uuid_or_string(), nullable=True),
    Column("scope", String(50), nullable=False),
    Column("key", String(100), nullable=False),
    Column("current_value_at_issue", BigInteger, nullable=True),
    Column("recommended_value", BigInteger, nullable=False),
    Column("rationale", Text, nullable=True),
    Column("evidence_summary", json_or_jsonb(), nullable=True),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("fetched_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("status", String(20), nullable=False, server_default="pending"),
    Column("decided_at", DateTime(timezone=True), nullable=True),
    Column("decided_by", uuid_or_string(), nullable=True),
    Column("decision_notes", Text, nullable=True),
    UniqueConstraint("external_id", name="uq_kya_inbound_rec_external_id"),
    Index("idx_kya_inbound_rec_status", "status", "fetched_at"),
)


# 14. kya_tenant_cost_budgets — per-(tenant, scope, scope_key, window)
#     budget configuration with only-tighten composition.
kya_tenant_cost_budgets = Table(
    "kya_tenant_cost_budgets",
    _LEGACY_MD,
    autoinc_id("kya_tenant_cost_budgets_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=True),  # NULL = platform default
    Column("scope", String(20), nullable=False),
    Column("scope_key", String(200), nullable=False),
    # 'window' is a reserved word in PG / DuckDB / MySQL (OVER WINDOW
    # clause). Using 'time_window' avoids dialect-specific escaping.
    Column("time_window", String(10), nullable=False),
    Column("threshold_usd", Numeric(12, 4), nullable=False),
    Column("hard_refuse", Boolean, nullable=False, server_default=text("FALSE")),
    Column("forecast_horizon_sec", BigInteger, nullable=False,
           server_default=text("3600")),
    Column("created_by", uuid_or_string(), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_id", "scope", "scope_key", "time_window",
                     name="uq_kya_budgets_tenant_scope_key_window"),
    Index("idx_kya_budgets_tenant_scope", "tenant_id", "scope"),
)


# 15. kya_budget_changes — audit log for budget set/delete operations.
#     Mirrors kya_weight_changes; same shape for the same reason
#     (tenant-mutable config without an append-only audit becomes a
#     stealth-modification surface).
kya_budget_changes = Table(
    "kya_budget_changes",
    _LEGACY_MD,
    autoinc_id("kya_budget_changes_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=True),
    Column("scope", String(20), nullable=False),
    Column("scope_key", String(200), nullable=False),
    Column("time_window", String(10), nullable=False),
    Column("old_threshold_usd", Numeric(12, 4), nullable=True),
    Column("new_threshold_usd", Numeric(12, 4), nullable=True),
    Column("old_hard_refuse", Boolean, nullable=True),
    Column("new_hard_refuse", Boolean, nullable=True),
    Column("action", String(20), nullable=False),  # "set" / "delete"
    Column("changed_by", uuid_or_string(), nullable=True),
    Column("reason", Text, nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Index("idx_kya_budget_changes_tenant_created",
          "tenant_id", "created_at"),
)


# 16. kya_cost_events — append-only cost ledger paired with Valkey
#     running counters in tenant_budget.py. Analytics-ready: FinOps,
#     chargeback, cost-of-failure, cache-efficiency, latency/cost ratio
#     all answerable with a single GROUP BY query.
#
# Analytics dimensions (all kept lean — derived columns sit alongside
# raw inputs so dashboards never need a JOIN to interpret a row):
#   provider           : openai / anthropic / google / azure / cohere /
#                        bedrock / vertex / self_hosted / other
#                        (closed-set, derived from model_used at write
#                        time if not supplied)
#   outcome            : success / failure / refused / partial / unknown
#   cost_center        : org-level chargeback target (string, e.g.
#                        "platform-eng", "marketing-team")
#   business_unit      : revenue/cost attribution (string)
#   environment        : dev / staging / prod / enclave
#   invocation_id      : FK-shaped link to kya_invocations.id (no FK
#                        constraint to keep cross-backend portability;
#                        joins still work)
#   parent_request_id  : delegation-chain root → child cost attribution
#   latency_ms         : performance/cost ratio analysis
#   cached_tokens      : caching efficiency metric (separated from
#                        input_tokens because Anthropic and OpenAI
#                        bill cached tokens at a fraction of the rate)
#   tags               : open-ended dimensions for tenant-specific
#                        analytics (cost-tracking labels, A/B test IDs)
kya_cost_events = Table(
    "kya_cost_events",
    _LEGACY_MD,
    autoinc_id("kya_cost_events_id_seq"),
    # Identity columns
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("agent_key", String(200), nullable=False),
    Column("principal_kind", String(20), nullable=False),
    Column("principal_id", String(200), nullable=False),
    # Cost columns
    Column("usd_amount", Numeric(12, 6), nullable=False),
    Column("input_token_cost_usd", Numeric(12, 6), nullable=True),
    Column("output_token_cost_usd", Numeric(12, 6), nullable=True),
    # Token columns
    Column("input_tokens", BigInteger, nullable=True),
    Column("output_tokens", BigInteger, nullable=True),
    Column("cached_tokens", BigInteger, nullable=True),
    # Model + provider columns (analytics)
    Column("model_used", String(100), nullable=True),
    Column("provider", String(50), nullable=True),
    # Attribution columns (chargeback + business reporting)
    Column("cost_center", String(100), nullable=True),
    Column("business_unit", String(100), nullable=True),
    Column("environment", String(20), nullable=True),
    # Causal-chain linkage (cost ↔ audit)
    Column("invocation_id", BigInteger, nullable=True),
    Column("parent_request_id", String(200), nullable=True),
    # Performance
    Column("latency_ms", BigInteger, nullable=True),
    Column("outcome", String(20), nullable=True),
    # Flexible
    Column("tags", json_or_jsonb(), nullable=True),
    Column("request_id", String(200), nullable=True),
    Column("recorded_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    UniqueConstraint("request_id", name="uq_kya_cost_events_request_id"),
    # Analytics indexes — each maps to a high-frequency dashboard query.
    Index("idx_kya_cost_events_tenant_recorded",
          "tenant_id", "recorded_at"),
    Index("idx_kya_cost_events_tenant_provider_recorded",
          "tenant_id", "provider", "recorded_at"),
    Index("idx_kya_cost_events_tenant_agent_recorded",
          "tenant_id", "agent_key", "recorded_at"),
    Index("idx_kya_cost_events_tenant_cost_center_recorded",
          "tenant_id", "cost_center", "recorded_at"),
    Index("idx_kya_cost_events_tenant_outcome",
          "tenant_id", "outcome"),
    Index("idx_kya_cost_events_invocation",
          "invocation_id"),
)


# kya_delegation_violations — recorded breaches of the
# principal-of-least-privilege chain when one agent delegates to another.
# Mode-aware: env KYA_DELEGATION_POLICY controls whether a detected
# violation is observed (logged silently to this table), flagged (logged
# + warning), or blocks the delegation (raises). Either way the row is
# written so the audit surface is consistent.
#
# violation_kind values:
#   access_escalation   — sub.access_level > parent.access_level
#   data_class_widening — sub.data_classes ⊄ parent.data_classes
#   human_loop_relax    — sub.human_loop offers less oversight than parent
#   tool_widening       — sub.tools includes an admin/write tool the
#                          parent doesn't have (admin-tool subset check)
#   trust_low_under_parent — sub-agent score below threshold while parent
#                            is high-trust (anomalous spawn pattern)
kya_delegation_violations = Table(
    "kya_delegation_violations",
    _LEGACY_MD,
    autoinc_id("kya_delegation_violations_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("sub_invocation_id", BigInteger, nullable=False),
    Column("parent_invocation_id", BigInteger, nullable=True),
    Column("parent_agent_key", String(100), nullable=False),
    Column("sub_agent_key", String(100), nullable=False),
    Column("violation_kind", String(40), nullable=False),
    Column("detail", json_or_jsonb(), nullable=True),
    Column("mode_active", String(20), nullable=False),
    Column("blocked", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Index("idx_kya_deleg_viol_tenant_created",
          "tenant_id", "created_at"),
    Index("idx_kya_deleg_viol_parent",
          "parent_agent_key", "created_at"),
    Index("idx_kya_deleg_viol_kind",
          "tenant_id", "violation_kind", "created_at"),
)


# kya_delegation_policy_overrides — per-scope mode overrides for
# delegation policy enforcement. Lets operators target specific
# agent pairs (or violation kinds, or just an orchestrator's whole
# spawn surface) with different modes without affecting the global
# default.
#
# Resolution: at enforcement time, all rows matching the (parent,
# sub, kind) scope are filtered to ACTIVE (effective_at <= now AND
# (expires_at IS NULL OR expires_at > now)) then ranked by
# specificity score. NULL = wildcard.
#
# Specificity score = count of non-NULL match fields.
#   (X, Y, Z) > (X, Y, NULL) ~ (X, NULL, Z) ~ (NULL, Y, Z)
#   > (X, NULL, NULL) ~ (NULL, Y, NULL) ~ (NULL, NULL, Z)
#   > (NULL, NULL, NULL)
# Ties broken by created_at DESC (most recent wins).
#
# Audit semantics: rows are append-only. Updating an override means
# inserting a new row (with same scope, new mode, new changed_by).
# Soft-delete sets expires_at = now() on the row.
kya_delegation_policy_overrides = Table(
    "kya_delegation_policy_overrides",
    _LEGACY_MD,
    autoinc_id("kya_delegation_policy_overrides_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("parent_agent_key", String(100), nullable=True),
    Column("sub_agent_key", String(100), nullable=True),
    Column("violation_kind", String(40), nullable=True),
    Column("mode", String(20), nullable=False),
    Column("reason", Text, nullable=True),
    Column("changed_by", uuid_or_string(), nullable=True),
    Column("effective_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Index("idx_kya_delpol_ovr_tenant_scope",
          "tenant_id", "parent_agent_key",
          "sub_agent_key", "violation_kind"),
    Index("idx_kya_delpol_ovr_tenant_effective",
          "tenant_id", "effective_at"),
)


# kya_role_grants — Phase 5b RBAC. Direct (principal → action)
# grants per-tenant. Single-table model intentionally — operators
# who want role grouping can wrap a "deploy this role" function
# that fans out to multiple grant rows. Kept simple here; the
# resolver (has_action) only does index-backed equality lookups.
#
# Wildcard handling: a row with action="kya.*" grants every
# kya.* action for that principal — a super-user shortcut.
# No deeper wildcards (no "kya.budget.*") in v1 — keeps the
# resolver SQL to two equality checks instead of LIKE scans.
kya_role_grants = Table(
    "kya_role_grants",
    _LEGACY_MD,
    autoinc_id("kya_role_grants_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("principal_kind", String(20), nullable=False),
    Column("principal_id", String(200), nullable=False),
    Column("action", String(80), nullable=False),
    Column("granted_by", uuid_or_string(), nullable=True),
    Column("reason", Text, nullable=True),
    Column("effective_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_id", "principal_kind", "principal_id",
                     "action",
                     name="uq_kya_role_grants_principal_action"),
    Index("idx_kya_role_grants_tenant_principal",
          "tenant_id", "principal_kind", "principal_id"),
    Index("idx_kya_role_grants_tenant_action",
          "tenant_id", "action"),
)


# Convenience list — every legacy table for batch create_all().
ALL_LEGACY_TABLES = [
    kya_agent_aliases,
    kya_user_trust,
    kya_weight_overrides,
    kya_weight_changes,
    kya_weight_suggestions,
    kya_breach_notifications,
    kya_redteam_campaigns,
    kya_redteam_findings,
    kya_redteam_tenant_policy,
    kya_redteam_runs,
    kya_redteam_targets,
    kya_redteam_target_secrets,
    kya_inbound_recommendations,
    kya_tenant_cost_budgets,
    kya_budget_changes,
    kya_cost_events,
    kya_delegation_violations,
    kya_delegation_policy_overrides,
]
