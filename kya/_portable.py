"""
Shared dialect-aware ORM primitives for KYA tables.

Every KYA table that's not the original 4 (agent_versions, kya_invocations,
kya_principal_trust, kya_evidence) gets ported to ORM via these helpers.
Same pattern proven on those 4 tables + the governance/attestation set.

Usage in a module that owns a raw DDL table:

    from ._portable import (
        portable_bigint, autoinc_id, schema_args, json_or_jsonb,
        uuid_or_string, dialect_schema_qualifier, build_table,
    )

    _TABLE = build_table(
        "kya_my_thing",
        autoinc_id("kya_my_thing_id_seq"),
        Column("tenant_id", uuid_or_string(), nullable=False),
        Column("payload", json_or_jsonb(), nullable=False, default=dict),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
        Index("idx_kya_my_thing", "tenant_id"),
    )

    def ensure_table(db):
        bind = db.connection()
        _TABLE.metadata.create_all(bind=bind, tables=[_TABLE])
        db.commit()

Behavior contracts (v0.1.6+):
- `KYA_VERSIONS_SCHEMA` env unset → KYA tables (kya_*, agent_versions)
  land in the dialect's default schema (public on PG). Set to
  "prov_schema" to keep the legacy v0.1.5 location.
- `KYA_DECISIONS_SCHEMA` env unset → veldt-decisions tables
  (governance_*, decision_approvals, tenants, custom_agents) land in
  "prov_schema". Set to a different value or "" to override.
- All ID columns become BIGINT on PG/MySQL/DuckDB, INTEGER on SQLite.
- Sequences are created on PG/DuckDB; ignored on SQLite/MySQL (which
  fall back to their native autoincrement).
- JSONB on PG; JSON elsewhere.
- UUID on PG; String(36) elsewhere.
"""

from __future__ import annotations

import os

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    Integer,
    MetaData,
    Sequence,
    String,
    Table,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


def dialect_schema_qualifier() -> str | None:
    """Return the schema name to use for KYA-owned tables (every
    table named ``kya_*`` or ``agent_versions``).

    Default: None -- KYA tables land in the dialect's default schema
    (``public`` on PostgreSQL, ``main`` on SQLite, the active
    database on MySQL/DuckDB). Customers who want to isolate KYA
    tables under a named schema set ``KYA_VERSIONS_SCHEMA`` in their
    environment.

    BREAKING CHANGE in 0.1.6: prior versions defaulted to
    ``"prov_schema"`` (a legacy from when KYA was packaged inside
    the veldt-decisions monorepo). Upgraders running on the same
    database instance should set
    ``KYA_VERSIONS_SCHEMA=prov_schema`` to keep their existing KYA
    tables addressable.
    """
    if "KYA_VERSIONS_SCHEMA" in os.environ:
        return os.environ["KYA_VERSIONS_SCHEMA"] or None
    return None


def decisions_schema_qualifier() -> str | None:
    """Return the schema name for **non-KYA** veldt-decisions tables
    that KYA reads from (``governance_incidents``,
    ``governance_audit_log``, ``governance_policies``,
    ``decision_approvals``, ``tenants``, ``custom_agents``,
    ``kya_redteam_*``, ``decision_attestations``).

    These tables aren't owned by KYA -- they live in veldt-decisions
    deployments and KYA's compliance / rogue / fleet-metrics readers
    just FROM them. Splitting this from ``dialect_schema_qualifier``
    means a customer running KYA tables under one schema and the
    decisions tables under another won't silently break.

    Default: ``"prov_schema"`` (the historical veldt-decisions
    deployment location). Override with ``KYA_DECISIONS_SCHEMA``.
    Set to empty string to land in the dialect's default.
    """
    if "KYA_DECISIONS_SCHEMA" in os.environ:
        return os.environ["KYA_DECISIONS_SCHEMA"] or None
    return "prov_schema"


def schema_args(extra: dict | None = None) -> dict:
    """For __table_args__ on declarative classes."""
    args: dict = dict(extra or {})
    schema = dialect_schema_qualifier()
    if schema:
        args["schema"] = schema
    return args


def qual_for_raw_sql(db_or_bind) -> str:
    """Return the schema prefix (with trailing dot, e.g. ``"prov_schema."``)
    to splice into raw ``text(...)`` SQL on the bound dialect.

    Raw ``text("FROM prov_schema.kya_X")`` does NOT honor SQLAlchemy's
    ``schema_translate_map`` execution option — that option only
    rewrites schemas on Table objects. So functions that build raw
    SQL must qualify the table name dynamically per dialect.

    Use:

        from ._portable import qual_for_raw_sql
        qual = qual_for_raw_sql(db)         # "prov_schema." on PG; "" elsewhere
        db.execute(text(f"SELECT ... FROM {qual}kya_user_trust ..."))

    Returns:
        - "prov_schema." on PostgreSQL when KYA_VERSIONS_SCHEMA is set
          (or default "prov_schema").
        - "" on SQLite, MySQL, DuckDB, or when
          KYA_VERSIONS_SCHEMA="" disables qualification on PG.
    """
    # Accept a Session or an Engine/Connection.
    bind = (
        db_or_bind.get_bind()
        if hasattr(db_or_bind, "get_bind") else db_or_bind
    )
    dialect = bind.dialect.name if hasattr(bind, "dialect") else None
    if dialect != "postgresql":
        return ""
    schema = dialect_schema_qualifier()
    return f"{schema}." if schema else ""


def qual_for_raw_sql_decisions(db_or_bind) -> str:
    """Like ``qual_for_raw_sql`` but for **veldt-decisions** monorepo
    tables (``governance_incidents``, ``governance_audit_log``,
    ``governance_policies``, ``decision_approvals``, ``tenants``,
    ``custom_agents``, ``decision_attestations``, etc.) that KYA's
    compliance / rogue / fleet-metrics readers join against.

    Reads ``KYA_DECISIONS_SCHEMA`` env var (default ``"prov_schema"``)
    instead of ``KYA_VERSIONS_SCHEMA``, so a customer can put KYA
    tables in one schema and the legacy decisions tables in another.

    Use:

        from ._portable import qual_for_raw_sql_decisions
        dq = qual_for_raw_sql_decisions(db)
        db.execute(text(f"FROM {dq}governance_incidents WHERE ..."))
    """
    bind = (
        db_or_bind.get_bind()
        if hasattr(db_or_bind, "get_bind") else db_or_bind
    )
    dialect = bind.dialect.name if hasattr(bind, "dialect") else None
    if dialect != "postgresql":
        return ""
    schema = decisions_schema_qualifier()
    return f"{schema}." if schema else ""


def portable_bigint():
    """Fresh BigInteger().with_variant(Integer(), 'sqlite') per call.
    Each column should get its own instance — sharing across columns
    occasionally confuses the dialect compiler."""
    return BigInteger().with_variant(Integer(), "sqlite")


def json_or_jsonb():
    """Fresh JSON().with_variant(JSONB(), 'postgresql') per call."""
    return JSON().with_variant(JSONB(), "postgresql")


def uuid_or_string():
    """Fresh String(36).with_variant(PG_UUID, 'postgresql') per call."""
    return String(36).with_variant(PG_UUID(as_uuid=True), "postgresql")


def autoinc_id(seq_name: str, name: str = "id") -> Column:
    """Build a portable autoincrement primary-key column.

    Uses the Sequence-based pattern proven on the ORM-modeled tables
    (kya_invocations, kya_evidence). Works on all 4 supported backends:

       PG (10+) — Sequence becomes a PG SEQUENCE; nextval() default.
       MySQL    — Sequence ignored; BIGINT AUTO_INCREMENT does the job.
       SQLite   — Sequence ignored; INTEGER PRIMARY KEY rowid alias
                  (needs Integer, not BigInteger — handled by variant).
       DuckDB   — Sequence becomes CREATE SEQUENCE + nextval() default
                  (DuckDB rejects the IDENTITY keyword used by SA's
                  Identity() construct, but accepts explicit sequences).

    `seq_name` matters here — DuckDB and PG use it to name the
    underlying sequence; SQLite/MySQL ignore it.
    """
    return Column(
        name,
        BigInteger().with_variant(Integer(), "sqlite"),
        Sequence(seq_name),
        primary_key=True,
        autoincrement=True,
    )


def build_table(name: str, *columns_and_constraints, schema: str | None = "auto") -> Table:
    """Create a portable Table with the right schema qualifier.

    `schema="auto"` picks the env-driven default; pass `None` to force
    default-schema; pass a string to force a specific schema.
    """
    if schema == "auto":
        schema = dialect_schema_qualifier()
    md = MetaData(schema=schema)
    return Table(name, md, *columns_and_constraints)
