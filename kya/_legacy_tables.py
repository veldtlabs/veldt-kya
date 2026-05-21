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
    Sequence,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)

from ._portable import (
    autoinc_id,
    dialect_schema_qualifier,
    json_or_jsonb,
    portable_bigint,
    uuid_or_string,
)

# All legacy tables share one MetaData so create_all can be batched.
# Schema is set to the default ("prov_schema") at import; the actual
# dialect-aware retargeting happens at CALL TIME via the
# `create_legacy_tables()` helper below, which uses SQLAlchemy's
# `schema_translate_map`. This solves the previous bug where env vars
# set AFTER import had no effect.
_LEGACY_MD = MetaData(schema=dialect_schema_qualifier())


def create_legacy_tables(db, tables: list) -> None:
    """Idempotent create_all for the legacy tables, with the right
    schema qualifier for the bound dialect.

    Behavior:
        PG  + KYA_VERSIONS_SCHEMA="prov_schema"  → tables in prov_schema
        PG  + KYA_VERSIONS_SCHEMA=""             → tables in default (public)
        SQLite / DuckDB / MySQL                   → tables in default ns
                                                     (schema_translate_map
                                                      strips "prov_schema")

    Uses SQLAlchemy's `schema_translate_map` execution option which
    rewrites table-name qualifiers at SQL-emission time without rebuilding
    the Table objects.
    """
    bind = db.connection()
    schema = dialect_schema_qualifier()  # read env at CALL time
    dialect = bind.engine.dialect.name

    if dialect == "postgresql" and schema:
        # PG with prov_schema set — emit table names as-is (no remap needed
        # because _LEGACY_MD.schema already matches).
        target_bind = bind
    else:
        # Non-PG OR PG with KYA_VERSIONS_SCHEMA="" — strip the schema
        # so tables land in the default namespace.
        target_bind = bind.execution_options(
            schema_translate_map={"prov_schema": None}
        )
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


# 2. kya_user_trust — per-tenant user trust score
kya_user_trust = Table(
    "kya_user_trust",
    _LEGACY_MD,
    autoinc_id("kya_user_trust_id_seq"),
    Column("tenant_id", uuid_or_string(), nullable=False),
    Column("user_id", uuid_or_string(), nullable=False),
    Column("trust_score", BigInteger, nullable=False, default=50),
    Column("signal_counts", json_or_jsonb(), nullable=False, default=dict),
    Column("last_signal_at", DateTime(timezone=True), nullable=True),
    Column("last_clean_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    UniqueConstraint("tenant_id", "user_id", name="uq_kya_user_trust_tenant_user"),
    Index("idx_kya_user_trust_tenant_score", "tenant_id", "trust_score"),
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
]
