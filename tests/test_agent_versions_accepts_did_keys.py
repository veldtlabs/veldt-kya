"""A DID-identified agent must be able to register in the catalogue.

The fault
---------
``agent_versions.agent_key`` was ``VARCHAR(50)``. A ``did:key:`` is 56
characters and a ``did:jwk:`` is ~175, so ``snapshot_on_first_sight``
raised on every DID-identified principal. That call is what registers an
agent on first sight, so those agents never appeared in the catalogue,
got no version snapshot, and had no rollback history.

Governance was unaffected -- invocations, evidence, verdicts and
containment all use wider columns -- which is exactly why it went
unnoticed. Measured on a live database: 80 distinct DID principals with
239 invocations and 33 kill-switch rows between them, and 0 rows in
``agent_versions``.

Why no test caught it
---------------------
SQLite does not enforce ``VARCHAR`` lengths. It accepted the 56-char key
happily, so the default sqlite suite was green while Postgres and MySQL
both raised ``DataError``. That is the reason this file is parametrised
across backends rather than trusting the default one.

The table was simply never added to ``_AGENT_KEY_MIGRATIONS``; the
widening mechanism already existed for six sibling columns.
"""
from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from kya.invocations import _AGENT_KEY_MIGRATIONS
from kya.versioning import AgentVersion, ensure_table, snapshot_on_first_sight

# 56 chars. The shortest DID method in common use -- if this one fails,
# every longer one does too.
DID_KEY = "did:key:z6Mkf7n4fvfVJJQs1WXy1HjvrdjxPPq16qhZjbRqscw89a25"
# ~175 chars, the width the 512 target was actually sized for.
DID_JWK = "did:jwk:" + ("e" * 170)

_BACKENDS = {
    "postgres": os.environ.get(
        "KYA_TEST_POSTGRES_URL",
        "postgresql+psycopg2://veldt:veldt_kya_2026@localhost:18432/veldt_kya_pending_test",
    ),
    "mysql": os.environ.get(
        "KYA_TEST_MYSQL_URL",
        "mysql+pymysql://root:kya_test_2026@localhost:13306/kya_test",
    ),
}

# How a deployed install regresses to the pre-fix shape.
_NARROW = {
    "postgres": "ALTER TABLE agent_versions ALTER COLUMN agent_key TYPE VARCHAR(50)",
    "mysql": "ALTER TABLE agent_versions MODIFY agent_key VARCHAR(50) NOT NULL",
}


def _engine(url):
    try:
        eng = create_engine(url)
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
        return eng
    except Exception as exc:
        pytest.skip(f"backend unavailable ({type(exc).__name__})")


def _width(engine):
    with engine.connect() as c:
        return c.execute(text(
            "SELECT character_maximum_length FROM information_schema.columns "
            "WHERE table_name = 'agent_versions' AND column_name = 'agent_key'"
        )).scalar()


# -- the declaration ---------------------------------------------------

def test_the_model_is_wide_enough_for_a_did():
    """The model is the source of truth: a fresh install builds from it,
    so widening only the database would let the bug back in on every
    new deployment."""
    width = AgentVersion.__table__.c.agent_key.type.length
    assert width >= len(DID_JWK), (
        f"agent_key is VARCHAR({width}); did:jwk is {len(DID_JWK)} chars "
        f"and did:key is {len(DID_KEY)}"
    )


def test_the_table_is_registered_for_widening():
    """An existing install is only fixed by the migration list. The
    model change alone helps new deployments and nobody else."""
    tables = {t for t, _c, _n in _AGENT_KEY_MIGRATIONS}
    assert "agent_versions" in tables, (
        "agent_versions is not in _AGENT_KEY_MIGRATIONS, so a deployed "
        "install keeps its VARCHAR(50) column and DID agents still "
        "cannot register"
    )


# -- the behaviour, per backend ----------------------------------------

@pytest.mark.parametrize("did", [DID_KEY, DID_JWK],
                         ids=["did:key", "did:jwk"])
def test_sqlite_registers_a_did(tmp_path, did):
    """Included deliberately: sqlite passed BEFORE the fix too, because
    it ignores VARCHAR lengths. Keeping it documents that a green sqlite
    run is not evidence for this bug either way."""
    eng = create_engine(f"sqlite:///{(tmp_path / 'v.db').as_posix()}")
    with Session(eng) as db:
        ensure_table(db)
        db.commit()
        snapshot_on_first_sight(
            db=db, tenant_id=f"t-{uuid.uuid4().hex[:8]}", agent_key=did,
            definition={"agent_key": did}, created_by="test")
        db.commit()


@pytest.mark.parametrize("backend", sorted(_BACKENDS))
@pytest.mark.parametrize("did", [DID_KEY, DID_JWK],
                         ids=["did:key", "did:jwk"])
def test_an_UPGRADED_install_registers_a_did(backend, did):
    """The load-bearing case: an install that already has the narrow
    column, upgraded in place.

    Built from the real model then narrowed, rather than hand-written --
    an earlier hand-rolled CREATE TABLE omitted a column and failed for
    an unrelated reason, which looked like the fix not working.
    """
    eng = _engine(_BACKENDS[backend])
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    try:
        with eng.begin() as c:
            c.execute(text("DROP TABLE IF EXISTS agent_versions"))
        with Session(eng) as db:          # real schema
            ensure_table(db)
            db.commit()
        with eng.begin() as c:            # regress to the deployed shape
            c.execute(text(_NARROW[backend]))
        assert _width(eng) == 50, "the narrow precondition did not apply"

        with Session(eng) as db:          # the upgrade
            ensure_table(db)
            db.commit()
        assert _width(eng) >= len(DID_JWK), (
            f"agent_key is still VARCHAR({_width(eng)}) after upgrade"
        )

        with Session(eng) as db:
            snapshot_on_first_sight(
                db=db, tenant_id=tenant, agent_key=did,
                definition={"agent_key": did}, created_by="test")
            db.commit()

        with eng.connect() as c:
            found = c.execute(text(
                "SELECT agent_key FROM agent_versions WHERE tenant_id = :t"
            ), {"t": tenant}).scalar()
        assert found == did, (
            f"stored key does not round-trip: {found!r} != {did!r}. A "
            f"truncated key would silently merge two distinct agents "
            f"into one catalogue row."
        )
    finally:
        with eng.begin() as c:
            c.execute(text("DELETE FROM agent_versions WHERE tenant_id = :t"),
                      {"t": tenant})
        eng.dispose()


# -- the MySQL index-limit case ----------------------------------------

def test_MYSQL_widening_survives_an_over_wide_index():
    """MySQL caps an index key at 3072 bytes.

    At utf8mb4 an AGENT_KEY_LEN column is 2048, so
    `idx_kya_delpol_ovr_tenant_scope` -- which spans two of them --
    exceeded the cap and the ALTER failed with errno 1071. It failed
    SOFT, so the columns silently stayed narrow and DID principals kept
    being rejected there while the log carried a warning nobody read.

    The migration now re-creates such an index with 64-char prefixes and
    retries.
    """
    from kya.invocations import _migrate_agent_key_width

    eng = _engine(_BACKENDS["mysql"])
    table = "kya_delegation_policy_overrides"
    try:
        with eng.begin() as c:
            c.execute(text(f"DROP TABLE IF EXISTS {table}"))
            c.execute(text(
                f"CREATE TABLE {table} ("
                " id BIGINT AUTO_INCREMENT PRIMARY KEY,"
                " tenant_id VARCHAR(36) NOT NULL,"
                " parent_agent_key VARCHAR(100),"
                " sub_agent_key VARCHAR(100),"
                " violation_kind VARCHAR(40),"
                " mode VARCHAR(20) NOT NULL)"))
            # the unprefixed index a deployed install already has
            c.execute(text(
                "CREATE INDEX idx_kya_delpol_ovr_tenant_scope "
                f"ON {table} (tenant_id, parent_agent_key, "
                "sub_agent_key, violation_kind)"))

        with eng.connect() as conn:
            _migrate_agent_key_width(conn)
            conn.commit()

        with eng.connect() as c:
            widths = dict(c.execute(text(
                "SELECT COLUMN_NAME, CHARACTER_MAXIMUM_LENGTH "
                "FROM information_schema.COLUMNS "
                f"WHERE TABLE_NAME = '{table}' "
                "AND COLUMN_NAME LIKE '%agent_key'")).fetchall())
            prefixes = {
                r._mapping["Column_name"]: r._mapping["Sub_part"]
                for r in c.execute(text(f"SHOW INDEX FROM {table}"))
                if r._mapping["Key_name"] != "PRIMARY"
            }

        assert widths.get("parent_agent_key") == 512, widths
        assert widths.get("sub_agent_key") == 512, (
            f"sub_agent_key is still VARCHAR({widths.get('sub_agent_key')}) "
            f"-- the 1071 recovery did not run, so long DIDs are still "
            f"rejected on MySQL"
        )
        assert prefixes.get("parent_agent_key") == 64, prefixes
        assert prefixes.get("sub_agent_key") == 64, prefixes
    finally:
        with eng.begin() as c:
            c.execute(text(f"DROP TABLE IF EXISTS {table}"))
        eng.dispose()
