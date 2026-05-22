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

Behavior contracts:
- `KYA_VERSIONS_SCHEMA` env unset → schema defaults to "prov_schema"
  (Veldt prod). Set to "" (empty) on SDK installs to disable.
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
    """Return the schema name to use for KYA tables.

    Veldt prod default: "prov_schema". SDK consumers disable by setting
    KYA_VERSIONS_SCHEMA="" (empty string).
    """
    if "KYA_VERSIONS_SCHEMA" in os.environ:
        return os.environ["KYA_VERSIONS_SCHEMA"] or None
    return "prov_schema"


def schema_args(extra: dict | None = None) -> dict:
    """For __table_args__ on declarative classes."""
    args: dict = dict(extra or {})
    schema = dialect_schema_qualifier()
    if schema:
        args["schema"] = schema
    return args


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
