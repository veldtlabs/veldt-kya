"""Test that kya_invocations.agent_key can hold a DID URI.

Originally agent_key was `String(100)` — too small for did:jwk URIs
(~175 chars) and arbitrary did:web URIs. This caused production
deployments using DID identity to have SILENT audit-row loss when
record_invocation hit `value too long for type character varying(100)`
on PostgreSQL or MySQL (SQLite silently truncates without complaint,
hiding the bug locally).

The fix widens agent_key to String(512). This test surfaces the bug
by inserting a row with a 200-char agent_key. RED on the old schema,
GREEN after widening.
"""
from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import init_storage, record_invocation


def _backends():
    """Backends to test. Excludes DuckDB (single-writer; not relevant for
    a column-width test) and is opt-in for PG/MySQL via env vars."""
    out = [("sqlite", "sqlite:///:memory:")]
    pg = os.environ.get("KYA_TEST_PG_URL")
    if pg:
        out.append(("postgresql", pg))
    my = os.environ.get("KYA_TEST_MYSQL_URL")
    if my:
        out.append(("mysql", my))
    return out


@pytest.fixture(params=_backends(), ids=lambda p: p[0])
def db(request):
    label, url = request.param
    eng = create_engine(url)
    if label == "postgresql":
        with eng.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS kya_invocations CASCADE"))
    elif label == "mysql":
        with eng.begin() as conn:
            try:
                conn.execute(text("DROP TABLE IF EXISTS kya_invocations"))
            except Exception:
                pass
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


def test_migration_widens_existing_old_schema_column(db):
    """The migration must widen a PRE-EXISTING VARCHAR(100) column.

    The fresh-install test below would pass even if the migration was
    silently broken because `metadata.create_all` would create new
    tables at VARCHAR(512). This test forces the old schema first by
    DROPping and creating with VARCHAR(100), then calls init_storage
    and asserts the column is now wide enough.

    SQLite is skipped because it doesn't enforce VARCHAR width.
    """
    from sqlalchemy import inspect
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        pytest.skip("SQLite does not enforce VARCHAR widths — N/A")
    if os.environ.get("KYA_VERSIONS_SCHEMA"):
        # Production migration honors KYA_VERSIONS_SCHEMA; this test's raw
        # CREATE/DROP would land in the default schema, decoupling it from
        # the migration runner's schema-qualified introspection. Skip
        # rather than mask a silent migration no-op.
        pytest.skip("KYA_VERSIONS_SCHEMA set — schema-qualified raw SQL needed")

    # Drop the freshly-created table, then re-create at the OLD width
    # to simulate a pre-0.2.4 deployment.
    db.execute(text("DROP TABLE IF EXISTS kya_invocations CASCADE"
                    if dialect == "postgresql"
                    else "DROP TABLE IF EXISTS kya_invocations"))
    if dialect == "postgresql":
        db.execute(text(
            "CREATE TABLE kya_invocations ("
            "  id BIGSERIAL PRIMARY KEY, "
            "  tenant_id VARCHAR(36) NOT NULL, "
            "  agent_key VARCHAR(100) NOT NULL, "
            "  mode VARCHAR(20) NOT NULL, "
            "  outcome VARCHAR(20) NOT NULL, "
            "  occurred_at TIMESTAMP WITH TIME ZONE NOT NULL, "
            "  ingested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()"
            ")"
        ))
    elif dialect == "mysql":
        db.execute(text(
            "CREATE TABLE kya_invocations ("
            "  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, "
            "  tenant_id VARCHAR(36) NOT NULL, "
            "  agent_key VARCHAR(100) NOT NULL, "
            "  mode VARCHAR(20) NOT NULL, "
            "  outcome VARCHAR(20) NOT NULL, "
            "  occurred_at DATETIME(6) NOT NULL, "
            "  ingested_at DATETIME(6) NOT NULL"
            ")"
        ))
    db.commit()

    # Pre-check: agent_key is VARCHAR(100).
    insp = inspect(db.get_bind())
    pre = {c["name"]: c for c in insp.get_columns("kya_invocations")}
    assert pre["agent_key"]["type"].length == 100, (
        f"pre-condition not met: {pre['agent_key']['type'].length}"
    )

    # Now call the migration explicitly (init_storage would call this too).
    from kya.invocations import _migrate_agent_key_width
    _migrate_agent_key_width(db.connection())
    db.commit()

    # Re-inspect — must be widened to 512.
    insp2 = inspect(db.get_bind())
    post = {c["name"]: c for c in insp2.get_columns("kya_invocations")}
    assert post["agent_key"]["type"].length == 512, (
        f"migration did NOT widen agent_key — still "
        f"{post['agent_key']['type'].length}. Likely a NameError or "
        f"missing import being silently swallowed."
    )


def test_record_invocation_accepts_did_length_agent_key(db):
    """A 200-char agent_key must fit. did:jwk URIs are ~175 chars.

    On the OLD schema (String(100)), Postgres raises
    StringDataRightTruncation and MySQL raises a similar truncation
    error. SQLite silently accepts (no length enforcement), hiding the
    bug — which is why the production E2E was the only way it surfaced.
    """
    tenant = str(uuid.uuid4())
    long_did_agent_key = "did:jwk:" + "x" * 200  # 208 chars total

    inv_id = record_invocation(
        db,
        tenant_id=tenant,
        agent_key=long_did_agent_key,
        principal_kind="agent",
        principal_id=long_did_agent_key,
        mode="observed",
        outcome="success",
    )
    assert inv_id is not None

    # Round-trip to confirm the row landed with the full agent_key (not
    # silently truncated).
    row = db.execute(text(
        "SELECT agent_key FROM kya_invocations WHERE id = :i"
    ), {"i": inv_id}).first()
    assert row is not None, "row not found"
    assert row[0] == long_did_agent_key, (
        f"agent_key was truncated from {len(long_did_agent_key)} chars "
        f"to {len(row[0])}: {row[0]!r}"
    )
