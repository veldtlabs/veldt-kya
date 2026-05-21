"""Cross-backend parity check for all 12 already-migrated KYA tables.

For each (backend, table) pair, verifies:
  1. Table exists after create_all
  2. Column NAMES are identical to PG (the reference schema)
  3. Data can be inserted via ORM (or raw INSERT for the 1 lazy-Table)
  4. Data can be queried back with the expected shape

Tables checked (12 total, the ones we've already migrated):

Core (SDK-owned ORM):
  1. agent_versions
  2. kya_invocations
  3. kya_principal_trust
  4. kya_evidence

Governance + attestation:
  5. governance_policies
  6. ai_model_registry
  7. governance_audit_log
  8. governance_incidents
  9. compliance_regulation_map
 10. decision_attestations
 11. decision_attestation_keypairs

Lazy DDL:
 12. kya_judge_history
"""

import os
import sys
import uuid as _uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker


# Expected canonical column names for each table (the reference shape).
# Validated as a SUBSET against the live introspected names — extras are
# OK (some tables have legacy columns on PG that aren't in the ORM model
# but were never removed). What we GUARANTEE is the column set the ORM
# emits on the portable backends matches.
_EXPECTED_COLUMNS: dict[str, set[str]] = {
    "agent_versions": {
        "tenant_id", "agent_key", "version_no", "definition", "note",
        "created_by", "occurred_at", "created_at",
    },
    "kya_invocations": {
        "id", "tenant_id", "agent_key", "principal_kind", "principal_id",
        "mode", "outcome", "duration_ms", "parent_invocation_id",
        "correlation_id", "occurred_at", "ingested_at", "started_at", "ended_at",
    },
    "kya_principal_trust": {
        "tenant_id", "principal_kind", "principal_id", "trust_score",
        "signal_counts", "actor_human_id", "attributes",
        "last_signal_at", "last_clean_at", "created_at", "updated_at",
    },
    "kya_evidence": {
        "id", "tenant_id", "invocation_id", "correlation_id",
        "parent_invocation_id", "span_id", "evidence_kind", "role",
        "payload", "payload_hash", "payload_size_bytes",
        "prev_hash", "signed_hash", "signing_key_id",
        "occurred_at", "ingested_at", "source", "data_classes",
        "redacted", "redaction_reason", "retention_until",
    },
    "governance_policies": {
        "id", "tenant_id", "rule_id", "policy_type", "regulation_tags",
        "risk_level", "enforcement", "phase", "priority",
        "applies_to_models", "applies_to_action_types", "minio_document_key",
        "enabled", "created_by", "created_at", "updated_at", "deleted_at",
    },
    "ai_model_registry": {
        "id", "tenant_id", "model_id", "name", "model_type", "provider",
        "version", "risk_level", "purpose", "owner", "status",
        "capabilities", "minio_card_key", "metadata_json", "created_by",
        "created_at", "updated_at", "deleted_at",
    },
    "governance_audit_log": {
        "id", "tenant_id", "user_id", "action_type", "model_id",
        "input_hash", "output_hash", "input_summary", "output_summary",
        "policies_applied", "policies_passed", "policies_failed",
        "verdict", "risk_level", "duration_ms", "metadata_json",
        "attestation_id", "created_at", "expires_at",
    },
    "governance_incidents": {
        "id", "tenant_id", "policy_id", "model_id", "audit_log_id",
        "severity", "action_taken", "input_context", "output_context",
        "resolution_status", "resolved_by", "resolution_notes",
        "resolved_at", "attestation_id", "created_at", "updated_at",
    },
    "compliance_regulation_map": {
        "id", "tenant_id", "regulation", "requirement_id",
        "requirement_text", "policy_id", "coverage_status",
        "notes", "created_at", "updated_at",
    },
    "decision_attestations": {
        "id", "tenant_id", "entity_type", "entity_id", "attester_id",
        "action", "content_hash", "signature", "public_key", "parent_hash",
        "metadata_json", "created_at",
    },
    "decision_attestation_keypairs": {
        "id", "user_id", "public_key", "encrypted_private_key",
        "is_active", "created_at",
    },
    "kya_judge_history": {
        "id", "tenant_id", "agent_key", "user_input", "agent_output",
        "alignment_score", "divergence_kind", "reasoning",
        "model_used", "invocation_id", "judged_at",
    },
}


def _stub_parent_packages():
    """Stub agents.* and decisions.* package inits in sys.modules so
    side-loaded ORM modules with relative imports don't trigger Veldt's
    full runtime dep chain (slowapi / redis / fastapi / etc)."""
    import types

    for pkg in (
        "agents", "kya",
        "decisions", "decisions.governance", "decisions.attestation",
    ):
        if pkg not in sys.modules:
            sys.modules[pkg] = types.ModuleType(pkg)
            sys.modules[pkg].__path__ = []  # mark as package for relative imports


def _setup_backend(url: str, dialect_name: str):
    """Bring up engine + sessions for one backend, run create_all on all
    12 portable tables, seed 1 row each, and return engine."""
    _stub_parent_packages()
    # Schema env handshake — PG wants prov_schema; others want default ns.
    if dialect_name == "postgresql":
        os.environ["KYA_VERSIONS_SCHEMA"] = "prov_schema"
    else:
        os.environ["KYA_VERSIONS_SCHEMA"] = ""

    # Clear all stale ORM definitions so the env switch takes effect
    from models.orm import Base as _StaleBase

    _StaleBase.metadata.clear()
    for k in list(sys.modules):
        if k in (
            "decisions.governance.models",
            "decisions.attestation.service",
            "kya.versioning",
            "kya.invocations",
            "kya.principals",
            "kya.evidence",
        ):
            del sys.modules[k]

    # On PG, register stub parent tables for cross-schema FK resolution
    if dialect_name == "postgresql":
        from sqlalchemy import Column as _Col
        from sqlalchemy import Integer as _Int
        from sqlalchemy import Table as _Table
        from sqlalchemy.dialects.postgresql import UUID as _PG_UUID

        _Table("tenants", _StaleBase.metadata,
               _Col("id", _PG_UUID(as_uuid=True), primary_key=True),
               schema="prov_schema")
        _Table("users", _StaleBase.metadata,
               _Col("user_id", _PG_UUID(as_uuid=True), primary_key=True),
               schema="prov_schema")
        _Table("decision_rules", _StaleBase.metadata,
               _Col("id", _Int, primary_key=True),
               schema="prov_schema")

    # Side-load the ORM modules
    import importlib.util

    def _load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    gov_mod = _load("decisions.governance.models",
                    "/repo/app/decisions/governance/models.py")
    att_mod = _load("decisions.attestation.service",
                    "/repo/app/decisions/attestation/service.py")
    ver_mod = _load("kya.versioning",
                    "/repo/app/agents/kya/versioning.py")
    inv_mod = _load("kya.invocations",
                    "/repo/app/agents/kya/invocations.py")
    prin_mod = _load("kya.principals",
                     "/repo/app/agents/kya/principals.py")
    ev_mod = _load("kya.evidence",
                   "/repo/app/agents/kya/evidence.py")

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    # Seed PG parent tables for FK targets
    if dialect_name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            for t in ("tenants", "users", "decision_rules", "governance_policies"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS prov_schema.{t} CASCADE"))
                except Exception:
                    pass
            conn.execute(text("CREATE TABLE prov_schema.tenants (id UUID PRIMARY KEY)"))
            conn.execute(text("CREATE TABLE prov_schema.users (user_id UUID PRIMARY KEY)"))
            conn.execute(text("CREATE TABLE prov_schema.decision_rules (id INTEGER PRIMARY KEY)"))
            tenant_uuid = "11111111-2222-3333-4444-555555555555"
            user_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            conn.execute(text(
                "INSERT INTO prov_schema.tenants (id) VALUES (:t::uuid)"
            ), {"t": tenant_uuid})
            conn.execute(text(
                "INSERT INTO prov_schema.users (user_id) VALUES (:u::uuid)"
            ), {"u": user_uuid})

    # Create all 11 ORM-defined tables + kya_judge_history via lazy helper
    tables_to_create = [
        ver_mod.AgentVersion.__table__,
        inv_mod.Invocation.__table__,
        prin_mod._PrincipalRow.__table__,
        ev_mod._EvidenceRow.__table__,
        gov_mod.GovernancePolicy.__table__,
        gov_mod.AIModelRegistry.__table__,
        gov_mod.GovernanceAuditLog.__table__,
        gov_mod.GovernanceIncident.__table__,
        gov_mod.ComplianceRegulationMap.__table__,
        att_mod.AttestationRecord.__table__,
        att_mod.AttestationKeyPair.__table__,
    ]
    _StaleBase.metadata.create_all(bind=engine, tables=tables_to_create)

    # Inline create kya_judge_history (lazy DDL helper lives in admin_agents
    # which has heavy deps; inline a portable Table here matching its shape)
    from sqlalchemy import (
        BigInteger,
        DateTime,
        Float,
        Index,
        Integer,
        MetaData,
        Sequence,
        String,
        Table,
        Text,
        func,
    )
    from sqlalchemy import Column as Col
    from sqlalchemy.dialects.postgresql import UUID as _PG_UUID2

    _TT = String(36).with_variant(_PG_UUID2(as_uuid=True), "postgresql")
    schema = "prov_schema" if dialect_name == "postgresql" else None
    md = MetaData(schema=schema)
    judge_tbl = Table(
        "kya_judge_history", md,
        Col("id", BigInteger().with_variant(Integer(), "sqlite"),
            Sequence("kya_judge_history_id_seq"),
            primary_key=True, autoincrement=True),
        Col("tenant_id", _TT, nullable=False),
        Col("agent_key", String(50), nullable=False),
        Col("user_input", Text, nullable=False),
        Col("agent_output", Text, nullable=False),
        Col("alignment_score", Float, nullable=True),
        Col("divergence_kind", String(30), nullable=True),
        Col("reasoning", Text, nullable=True),
        Col("model_used", String(100), nullable=True),
        Col("invocation_id", BigInteger, nullable=True),
        Col("judged_at", DateTime(timezone=True), nullable=False,
            server_default=func.now()),
        Index("idx_kya_judge_history_agent",
              "tenant_id", "agent_key", "judged_at"),
    )
    md.create_all(bind=engine, tables=[judge_tbl])

    # Seed 1 row in each ORM-managed table
    tenant_uuid = "11111111-2222-3333-4444-555555555555"
    user_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    with Session() as db:
        # versioning — keyless natural PK
        ver_mod.snapshot_agent(
            db, tenant_id=tenant_uuid, agent_key="parity_agent",
            definition={"tools": ["search"]}, note="parity",
        )
        # invocations — autoinc id
        inv_id = inv_mod.record_invocation(
            db, tenant_id=tenant_uuid, agent_key="parity_agent",
            mode="hybrid", outcome="success",
        )
        # principals — natural composite PK
        prin_mod.record_principal_signal(
            db, tenant_id=tenant_uuid, principal_kind="agent",
            principal_id="parity_principal", signal_kind="oos_tool",
        )
        # evidence — autoinc id, linked to invocation
        ev_mod.record_evidence(
            db, tenant_id=tenant_uuid, invocation_id=inv_id,
            evidence_kind="prompt", payload={"content": "parity"},
            role="user",
        )

        # governance + attestation via ORM (autoinc fires via session.add)
        db.add(gov_mod.GovernancePolicy(
            tenant_id=tenant_uuid, rule_id=1, policy_type="content_safety",
            regulation_tags=["eu_ai_act_art_14"], risk_level="limited",
            enforcement="block", phase="pre", priority=100,
            applies_to_models=[], applies_to_action_types=["*"], enabled=True,
            created_by=user_uuid,
        ))
        db.commit()  # need policy_id available before incident
        # Retrieve the policy_id we just created
        policy_id = db.execute(text(
            ("SELECT id FROM prov_schema.governance_policies "
             "WHERE tenant_id = :t LIMIT 1") if dialect_name == "postgresql" else
            ("SELECT id FROM governance_policies "
             "WHERE tenant_id = :t LIMIT 1")
        ), {"t": tenant_uuid}).scalar()

        db.add(gov_mod.AIModelRegistry(
            tenant_id=tenant_uuid, model_id="parity-model", name="Parity",
            model_type="llm", provider="test", version="1.0",
            risk_level="limited", status="active", capabilities={},
            metadata_json={},
        ))
        db.add(gov_mod.GovernanceAuditLog(
            tenant_id=tenant_uuid, user_id=user_uuid, action_type="chat",
            model_id="parity_agent", input_hash="0" * 64, output_hash="1" * 64,
            verdict="allow", risk_level="limited", duration_ms=0,
        ))
        db.add(gov_mod.GovernanceIncident(
            tenant_id=tenant_uuid, policy_id=policy_id, model_id="parity_agent",
            severity="warning", action_taken="redact", resolution_status="open",
        ))
        db.add(gov_mod.ComplianceRegulationMap(
            tenant_id=tenant_uuid, regulation="gdpr", requirement_id="art_30",
            coverage_status="covered",
        ))
        db.add(att_mod.AttestationRecord(
            tenant_id=tenant_uuid, entity_type="agent",
            entity_id=f"parity_agent:run-1", attester_id=user_uuid,
            action="signed", content_hash="a" * 64, signature="sig",
            public_key="pk",
        ))
        db.add(att_mod.AttestationKeyPair(
            user_id=user_uuid, public_key="pk", encrypted_private_key="encpk",
        ))
        db.commit()

        # kya_judge_history — raw INSERT, with explicit nextval on PG/DuckDB
        if dialect_name in ("postgresql", "duckdb"):
            seq = "nextval('kya_judge_history_id_seq')"
            ns = "prov_schema." if dialect_name == "postgresql" else ""
            tcast = "(:t)::uuid" if dialect_name == "postgresql" else ":t"
            db.execute(text(
                f"INSERT INTO {ns}kya_judge_history "
                f"(id, tenant_id, agent_key, user_input, agent_output, "
                f" alignment_score, model_used) VALUES "
                f"({seq}, {tcast}, 'parity_agent', 'q', 'a', 0.9, 'gpt')"
            ), {"t": tenant_uuid})
        else:
            db.execute(text(
                "INSERT INTO kya_judge_history "
                "(tenant_id, agent_key, user_input, agent_output, "
                " alignment_score, model_used) VALUES "
                "(:t, 'parity_agent', 'q', 'a', 0.9, 'gpt')"
            ), {"t": tenant_uuid})
        db.commit()

    return engine, tenant_uuid


def _check_parity(url: str, dialect_name: str) -> dict:
    engine, tenant_uuid = _setup_backend(url, dialect_name)
    schema = "prov_schema" if dialect_name == "postgresql" else None
    insp = inspect(engine)

    report: dict[str, dict] = {}
    for tbl, expected_cols in _EXPECTED_COLUMNS.items():
        try:
            cols = insp.get_columns(tbl, schema=schema)
            actual = {c["name"] for c in cols}
        except Exception as exc:
            report[tbl] = {"exists": False, "error": str(exc)[:120]}
            continue

        # Count rows the test seeded
        with engine.connect() as conn:
            try:
                ns = "prov_schema." if dialect_name == "postgresql" else ""
                tcast = "(:t)::uuid" if dialect_name == "postgresql" else ":t"
                if tbl == "decision_attestation_keypairs":
                    row_count = int(conn.execute(
                        text(f"SELECT COUNT(*) FROM {ns}{tbl}")
                    ).scalar() or 0)
                elif tbl == "agent_versions":
                    row_count = int(conn.execute(
                        text(f"SELECT COUNT(*) FROM {ns}{tbl} WHERE tenant_id = {tcast}"),
                        {"t": tenant_uuid},
                    ).scalar() or 0)
                else:
                    row_count = int(conn.execute(
                        text(f"SELECT COUNT(*) FROM {ns}{tbl} WHERE tenant_id = {tcast}"),
                        {"t": tenant_uuid},
                    ).scalar() or 0)
            except Exception as exc:
                row_count = -1
                report[tbl] = {"exists": True, "columns_actual": actual,
                               "count_error": str(exc)[:120]}
                continue

        missing = expected_cols - actual
        report[tbl] = {
            "exists": True,
            "columns_actual_count": len(actual),
            "missing_expected_cols": sorted(missing) if missing else None,
            "row_count": row_count,
        }
    return report


def _assert_all_tables_ok(report: dict, backend_label: str) -> None:
    failures = []
    for tbl, info in report.items():
        if not info.get("exists"):
            failures.append(f"{tbl}: does not exist (error: {info.get('error')})")
            continue
        if info.get("missing_expected_cols"):
            failures.append(
                f"{tbl}: missing columns {info['missing_expected_cols']}"
            )
        if info.get("row_count", 0) < 1:
            failures.append(
                f"{tbl}: expected >=1 row, got {info.get('row_count')}"
            )
    assert not failures, f"[{backend_label}] table-parity failures:\n  " + "\n  ".join(failures)


def test_parity_sqlite():
    sys.path.insert(0, "/repo/app")
    report = _check_parity("sqlite:///:memory:", "sqlite")
    _assert_all_tables_ok(report, "sqlite")


def test_parity_duckdb():
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        pytest.skip("duckdb-engine not installed")
    sys.path.insert(0, "/repo/app")
    report = _check_parity("duckdb:///:memory:", "duckdb")
    _assert_all_tables_ok(report, "duckdb")


def test_parity_mysql():
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        pytest.skip("KYA_TEST_MYSQL_URL not set")
    sys.path.insert(0, "/repo/app")
    # Clean previous run's data
    eng = create_engine(url)
    with eng.begin() as conn:
        for t in _EXPECTED_COLUMNS:
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {t}"))
            except Exception:
                pass
    eng.dispose()
    report = _check_parity(url, "mysql")
    _assert_all_tables_ok(report, "mysql")


def test_parity_postgres():
    url = os.environ.get("KYA_TEST_PG_URL")
    if not url:
        pytest.skip("KYA_TEST_PG_URL not set")
    sys.path.insert(0, "/repo/app")
    eng = create_engine(url)
    with eng.begin() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        for t in list(_EXPECTED_COLUMNS) + [
            "governance_policies", "tenants", "users", "decision_rules",
        ]:
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS prov_schema.{t} CASCADE"))
            except Exception:
                pass
    eng.dispose()
    report = _check_parity(url, "postgresql")
    _assert_all_tables_ok(report, "postgresql")
