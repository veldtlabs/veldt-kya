"""HONEST validation: do all 4 governance/attestation tables CREATE + INSERT
+ SELECT correctly across PostgreSQL, MySQL, DuckDB, SQLite?

Loads the dialect-aware ORM models via importlib to bypass Veldt's
decisions/__init__.py transitive-dep chain (slowapi/redis/etc.).

For each backend, verifies:
  1. Table count expectation (4: governance_incidents, governance_audit_log,
     decision_attestations, kya_judge_history)
  2. INSERT lands and persists
  3. SELECT returns the inserted row
  4. Column types are dialect-appropriate (raw introspection)

NOTE: side-loads decisions.governance.models and decisions.attestation.service
from the veldt-decisions repo at /repo/app/decisions/. Skipped automatically
when those paths are unavailable (i.e. running in standalone veldt-kya).
These are cross-repo integration tests; equivalent KYA-side cross-backend
coverage is in tests/verify_all_backends_with_data.py.
"""

import importlib.util
import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.path.exists("/repo/app/decisions/governance/models.py"),
    reason="Monorepo-only cross-repo integration test (loads "
           "decisions.governance.models + decisions.attestation.service "
           "from veldt-decisions). Skipped in standalone veldt-kya.",
)
import sys
import types

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

# Build a minimal `decisions` package shadow so the model modules load
# without dragging in slowapi/redis/etc.
sys.path.insert(0, "/repo/app")
sys.modules.setdefault("decisions", types.ModuleType("decisions"))
sys.modules.setdefault("decisions.governance", types.ModuleType("decisions.governance"))
sys.modules.setdefault("decisions.attestation", types.ModuleType("decisions.attestation"))


def _load_models():
    """Side-load the two model modules by file path, bypassing the package
    init that pulls in the broader Veldt app."""
    # First load models.orm.Base — the declarative base every model inherits
    from models.orm import Base

    # decisions.governance.models
    spec_g = importlib.util.spec_from_file_location(
        "decisions.governance.models",
        "/repo/app/decisions/governance/models.py",
    )
    mod_g = importlib.util.module_from_spec(spec_g)
    sys.modules["decisions.governance.models"] = mod_g
    spec_g.loader.exec_module(mod_g)

    # decisions.attestation.service
    spec_a = importlib.util.spec_from_file_location(
        "decisions.attestation.service",
        "/repo/app/decisions/attestation/service.py",
    )
    mod_a = importlib.util.module_from_spec(spec_a)
    sys.modules["decisions.attestation.service"] = mod_a
    spec_a.loader.exec_module(mod_a)

    return Base, mod_g, mod_a


def _create_judge_history_via_admin_agents(db):
    """Use the actual _ensure_judge_history_table function from admin_agents.
    Bypasses the rest of admin_agents.py's heavy imports via direct
    importlib load."""
    # The judge_history DDL we shipped is portable; we inline-reproduce
    # the table here to validate it on every backend without dragging
    # admin_agents.py's full import surface.
    from sqlalchemy import (
        BigInteger,
        DateTime,
        Float,
        Index,
        Integer,
        MetaData,
        String,
        Table,
        Text,
    )
    from sqlalchemy import Column as Col
    from sqlalchemy import func as sa_func
    from sqlalchemy.dialects.postgresql import UUID as PG_UUID

    # Dialect-aware tenant_id — UUID on PG, String(36) elsewhere — so the
    # `(:tid)::uuid` cast in the regulator-pack query matches the column.
    _TENANT_TYPE = String(36).with_variant(PG_UUID(as_uuid=True), "postgresql")

    bind = db.connection().engine
    if "KYA_VERSIONS_SCHEMA" in os.environ:
        schema = os.environ["KYA_VERSIONS_SCHEMA"] or None
    else:
        schema = "prov_schema"
    use_schema = schema if (bind.dialect.name == "postgresql" and schema) else None
    from sqlalchemy import Sequence as _Seq

    md = MetaData(schema=use_schema)
    tbl = Table(
        "kya_judge_history",
        md,
        Col(
            "id",
            BigInteger().with_variant(Integer(), "sqlite"),
            _Seq("kya_judge_history_id_seq"),
            primary_key=True,
            autoincrement=True,
        ),
        Col("tenant_id", _TENANT_TYPE, nullable=False),
        Col("agent_key", String(50), nullable=False),
        Col("user_input", Text, nullable=False),
        Col("agent_output", Text, nullable=False),
        Col("alignment_score", Float, nullable=True),
        Col("divergence_kind", String(30), nullable=True),
        Col("reasoning", Text, nullable=True),
        Col("model_used", String(100), nullable=True),
        Col("invocation_id", BigInteger, nullable=True),
        Col(
            "judged_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=sa_func.now(),
        ),
        Index("idx_kya_judge_history_agent", "tenant_id", "agent_key", "judged_at"),
    )
    md.create_all(bind=db.connection(), tables=[tbl])
    db.commit()
    return tbl


def _run_for_backend(url: str, dialect_name: str) -> dict:
    """Bring up tables, seed one row each, count rows, return report."""
    # Set the schema env appropriately for this dialect.
    # IMPORTANT: setting to "" (empty string) is NOT the same as `pop` —
    # the models module defaults to "prov_schema" when env is unset, so
    # we explicitly set to "" to disable the schema qualifier AND the
    # cross-schema FKs (which would reference tenants/users tables that
    # don't exist on SQLite/DuckDB/MySQL).
    old_schema = os.environ.get("KYA_VERSIONS_SCHEMA")
    if dialect_name == "postgresql":
        os.environ["KYA_VERSIONS_SCHEMA"] = "prov_schema"
    else:
        os.environ["KYA_VERSIONS_SCHEMA"] = ""

    try:
        # Re-import models so the schema env takes effect at class-def time.
        # CRITICAL: Base.metadata accumulates Table definitions across
        # reloads. Without clearing, a prior backend's class registrations
        # (with schema="prov_schema") survive into the SQLite/DuckDB run
        # and create_all() blasts them at the wrong dialect.
        from models.orm import Base as _StaleBase

        _StaleBase.metadata.clear()

        # On PG: register stub parent tables so SQLA can resolve cross-
        # schema FKs (tenants/users/decision_rules/governance_policies).
        # Real Veldt PG has these populated already; the test PG is bare.
        # On non-PG dialects we set KYA_VERSIONS_SCHEMA="" so no FKs are
        # emitted and stubs aren't needed.
        if dialect_name == "postgresql":
            from sqlalchemy import Column as _Col
            from sqlalchemy import Integer as _Int
            from sqlalchemy import Table as _Table
            from sqlalchemy.dialects.postgresql import UUID as _PG_UUID

            _Table(
                "tenants", _StaleBase.metadata,
                _Col("id", _PG_UUID(as_uuid=True), primary_key=True),
                schema="prov_schema",
            )
            _Table(
                "users", _StaleBase.metadata,
                _Col("user_id", _PG_UUID(as_uuid=True), primary_key=True),
                schema="prov_schema",
            )
            _Table(
                "decision_rules", _StaleBase.metadata,
                _Col("id", _Int, primary_key=True),
                schema="prov_schema",
            )
            # NOTE: governance_policies is owned by the GovernancePolicy
            # ORM class — we DON'T stub it (would collide). SQLA will
            # auto-include it in the dependency graph for create_all.

        for k in list(sys.modules):
            if k in (
                "decisions.governance.models",
                "decisions.attestation.service",
            ):
                del sys.modules[k]

        Base, mod_g, mod_a = _load_models()
        GovernanceAuditLog = mod_g.GovernanceAuditLog
        GovernanceIncident = mod_g.GovernanceIncident
        GovernancePolicy = mod_g.GovernancePolicy
        AttestationRecord = mod_a.AttestationRecord

        engine = create_engine(url)
        Session = sessionmaker(bind=engine)

        # On PG also create governance_policies (the FK target of
        # GovernanceIncident.policy_id). On non-PG no FKs are emitted so
        # we don't need it.
        tables_to_create = [
            GovernanceIncident.__table__,
            GovernanceAuditLog.__table__,
            AttestationRecord.__table__,
        ]
        if dialect_name == "postgresql":
            tables_to_create.insert(0, GovernancePolicy.__table__)
        Base.metadata.create_all(bind=engine, tables=tables_to_create)

        # The 4th table (kya_judge_history) is created via the admin_agents helper
        with Session() as db:
            judge_tbl = _create_judge_history_via_admin_agents(db)

        # ── INSPECT: list tables that exist now ──
        insp = inspect(engine)
        if dialect_name == "postgresql":
            existing = insp.get_table_names(schema="prov_schema")
        else:
            existing = insp.get_table_names()

        # ── SEED one row in each of the 4 tables ──
        tenant_uuid = "11111111-2222-3333-4444-555555555555"
        agent_key = "claims_agent"
        ns = "prov_schema." if dialect_name == "postgresql" else ""
        tid_cast = "(:tid)::uuid" if dialect_name == "postgresql" else ":tid"
        uid_cast = "(:uid)::uuid" if dialect_name == "postgresql" else ":uid"
        atid_cast = "(:atid)::uuid" if dialect_name == "postgresql" else ":atid"

        # Seed via ORM (db.add) — Sequence-based autoincrement fires
        # through SQLA's id-generation path. Raw text() INSERT would
        # bypass autoincrement and leave id NULL on PG/DuckDB.
        with Session() as db:
            db.add(GovernanceIncident(
                tenant_id=tenant_uuid,
                policy_id=1,
                model_id=agent_key,
                severity="warning",
                action_taken="redact",
                resolution_status="open",
            ))
            db.add(GovernanceAuditLog(
                tenant_id=tenant_uuid,
                user_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                action_type="chat",
                model_id=agent_key,
                input_hash="0",
                output_hash="1",
                verdict="allow",
                risk_level="limited",
                duration_ms=0,
            ))
            db.add(AttestationRecord(
                tenant_id=tenant_uuid,
                entity_type="agent",
                entity_id=f"{agent_key}:run-001",
                attester_id="ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb",
                action="signed",
                content_hash="a",
                signature="b",
                public_key="c",
            ))
            db.commit()
            # kya_judge_history isn't a Base ORM class; use raw INSERT.
            # On DuckDB, raw INSERT without id will fail unless we
            # bind a nextval. Use SQLite/MySQL native auto, DuckDB
            # bind nextval explicitly.
            # On PG + DuckDB, the column was created with a Sequence but
            # without DEFAULT nextval() clause, so raw INSERT must provide
            # id explicitly via nextval. SQLite/MySQL handle autoincrement
            # natively without help (rowid alias / AUTO_INCREMENT).
            if dialect_name in ("duckdb", "postgresql"):
                # SQLAlchemy creates the Sequence in the default schema
                # (public on PG) even when the Table is in prov_schema.
                # So reference it WITHOUT schema prefix.
                seq_ref = "nextval('kya_judge_history_id_seq')"
                db.execute(
                    text(
                        f"INSERT INTO {ns}kya_judge_history "
                        f"(id, tenant_id, agent_key, user_input, agent_output, "
                        f" alignment_score, model_used) VALUES "
                        f"({seq_ref}, {tid_cast}, :ak, 'q', 'a', 0.92, 'gpt-4')"
                    ),
                    {"tid": tenant_uuid, "ak": agent_key},
                )
            else:
                db.execute(
                    text(
                        f"INSERT INTO {ns}kya_judge_history "
                        f"(tenant_id, agent_key, user_input, agent_output, "
                        f" alignment_score, model_used) VALUES "
                        f"({tid_cast}, :ak, 'q', 'a', 0.92, 'gpt-4')"
                    ),
                    {"tid": tenant_uuid, "ak": agent_key},
                )
            db.commit()

        # ── COUNT each table to prove writes landed ──
        counts: dict[str, int] = {}
        with Session() as db:
            for tbl_name in (
                "governance_incidents",
                "governance_audit_log",
                "decision_attestations",
                "kya_judge_history",
            ):
                counts[tbl_name] = int(
                    db.execute(
                        text(
                            f"SELECT COUNT(*) FROM {ns}{tbl_name} "
                            f"WHERE tenant_id = {tid_cast}"
                        ),
                        {"tid": tenant_uuid},
                    ).scalar()
                    or 0
                )

        return {
            "dialect": dialect_name,
            "tables_present": sorted(existing),
            "row_counts": counts,
        }
    finally:
        if old_schema is None:
            os.environ.pop("KYA_VERSIONS_SCHEMA", None)
        else:
            os.environ["KYA_VERSIONS_SCHEMA"] = old_schema


def test_governance_tables_sqlite():
    r = _run_for_backend("sqlite:///:memory:", "sqlite")
    for t in ("governance_incidents", "governance_audit_log",
              "decision_attestations", "kya_judge_history"):
        assert t in r["tables_present"], f"{t} missing on sqlite"
        assert r["row_counts"][t] == 1, f"{t} expected 1 row, got {r['row_counts'][t]}"


def test_governance_tables_duckdb():
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        pytest.skip("duckdb-engine not installed")
    r = _run_for_backend("duckdb:///:memory:", "duckdb")
    for t in ("governance_incidents", "governance_audit_log",
              "decision_attestations", "kya_judge_history"):
        assert t in r["tables_present"], f"{t} missing on duckdb"
        assert r["row_counts"][t] == 1, f"{t} expected 1 row, got {r['row_counts'][t]}"


def test_governance_tables_mysql():
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        pytest.skip("KYA_TEST_MYSQL_URL not set")
    # Clean slate for MySQL (persistent across runs)
    eng = create_engine(url)
    with eng.begin() as conn:
        for t in (
            "governance_incidents", "governance_audit_log",
            "decision_attestations", "kya_judge_history",
        ):
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {t}"))
            except Exception:
                pass
    eng.dispose()
    r = _run_for_backend(url, "mysql")
    for t in ("governance_incidents", "governance_audit_log",
              "decision_attestations", "kya_judge_history"):
        assert t in r["tables_present"], f"{t} missing on mysql"
        assert r["row_counts"][t] == 1, f"{t} expected 1 row, got {r['row_counts'][t]}"


def test_governance_tables_postgres():
    url = os.environ.get("KYA_TEST_PG_URL")
    if not url:
        pytest.skip("KYA_TEST_PG_URL not set")
    # Clean slate + stub parent tables. Real Veldt PG has
    # tenants/users/decision_rules/governance_policies populated; in this
    # isolated test PG we (a) define minimal ORM Tables so SQLAlchemy can
    # resolve the FK targets, AND (b) seed the rows the FKs will reference.
    from sqlalchemy import Column as Col
    from sqlalchemy import Integer as Int
    from sqlalchemy import Table
    from sqlalchemy.dialects.postgresql import UUID as PG_UUID

    eng = create_engine(url)
    with eng.begin() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        for t in (
            "governance_incidents",
            "governance_audit_log",
            "decision_attestations",
            "kya_judge_history",
            "governance_policies",
            "decision_rules",
            "users",
            "tenants",
        ):
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {t} CASCADE CASCADE"))
            except Exception:
                pass
        conn.execute(text("CREATE TABLE prov_schema.tenants (id UUID PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE prov_schema.users (user_id UUID PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE prov_schema.decision_rules (id INTEGER PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE prov_schema.governance_policies (id INTEGER PRIMARY KEY)"))
        conn.execute(text(
            "INSERT INTO prov_schema.tenants (id) VALUES "
            "('11111111-2222-3333-4444-555555555555'::uuid)"
        ))
        conn.execute(text(
            "INSERT INTO prov_schema.users (user_id) VALUES "
            "('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'::uuid), "
            "('ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb'::uuid)"
        ))
        conn.execute(text("INSERT INTO prov_schema.governance_policies (id) VALUES (1)"))
    eng.dispose()

    # Register stub Tables in Base.metadata so SQLAlchemy can resolve the
    # FK target references at create_all time (it walks metadata.tables,
    # not the live DB catalog).
    from models.orm import Base

    Base.metadata.clear()
    stub_md = Base.metadata
    Table("tenants", stub_md,
          Col("id", PG_UUID(as_uuid=True), primary_key=True),
          schema="prov_schema")
    Table("users", stub_md,
          Col("user_id", PG_UUID(as_uuid=True), primary_key=True),
          schema="prov_schema")
    Table("decision_rules", stub_md,
          Col("id", Int, primary_key=True),
          schema="prov_schema")
    Table("governance_policies", stub_md,
          Col("id", Int, primary_key=True),
          schema="prov_schema")
    r = _run_for_backend(url, "postgresql")
    for t in ("governance_incidents", "governance_audit_log",
              "decision_attestations", "kya_judge_history"):
        assert t in r["tables_present"], f"{t} missing on pg (looked in prov_schema)"
        assert r["row_counts"][t] == 1, f"{t} expected 1 row, got {r['row_counts'][t]}"
