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

from kya.invocations import (
    AGENT_KEY_LEN,
    _AGENT_KEY_MIGRATIONS,
    _migrate_agent_key_width,
)
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


#: Set in CI to turn "backend absent" from a skip into a failure.
#:
#: Without it this file reports GREEN on four assertions when Postgres
#: and MySQL are missing -- and the four that actually prove the fix are
#: the ones that vanish. That is the same "sqlite is not evidence"
#: failure the module docstring warns about, one layer up.
_REQUIRE_BACKENDS = os.environ.get("KYA_REQUIRE_BACKENDS", "").strip() in (
    "1", "true", "yes", "on")


def _engine(url):
    try:
        eng = create_engine(url)
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
        return eng
    except Exception as exc:
        msg = f"backend unavailable ({type(exc).__name__}): {url}"
        if _REQUIRE_BACKENDS:
            pytest.fail(
                f"{msg}. KYA_REQUIRE_BACKENDS is set, so a missing "
                f"backend is a failure: skipping here would report "
                f"green while the tests that prove this fix never ran."
            )
        pytest.skip(msg)


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
    # Bound to the constant, not a literal. Shrinking AGENT_KEY_LEN to
    # 256 left eight of nine tests green -- the upgrade tests only
    # assert >= len(DID_JWK) (178), which 256 satisfies.
    assert width == AGENT_KEY_LEN, (
        f"the model says VARCHAR({width}) but AGENT_KEY_LEN is "
        f"{AGENT_KEY_LEN}; the two have drifted"
    )


def test_the_table_is_registered_for_widening():
    """An existing install is only fixed by the migration list. The
    model change alone helps new deployments and nobody else."""
    pairs = {(t, c) for t, c, _n in _AGENT_KEY_MIGRATIONS}
    # The whole set, not just agent_versions: with only that one
    # asserted, any of the other eleven could be dropped silently.
    expected = {
        ("kya_invocations", "agent_key"),
        ("agent_versions", "agent_key"),
        ("kya_agent_aliases", "canonical_agent_key"),
        ("kya_redteam_campaigns", "agent_key"),
        ("kya_redteam_findings", "agent_key"),
        ("kya_redteam_runs", "agent_key"),
        ("kya_redteam_targets", "agent_key"),
        ("kya_weight_suggestions", "agent_key"),
        ("kya_delegation_violations", "parent_agent_key"),
        ("kya_delegation_violations", "sub_agent_key"),
        ("kya_delegation_policy_overrides", "parent_agent_key"),
        ("kya_delegation_policy_overrides", "sub_agent_key"),
    }
    missing = expected - pairs
    assert not missing, (
        f"dropped from _AGENT_KEY_MIGRATIONS: {sorted(missing)}. Those "
        f"columns stay VARCHAR(50) on a deployed install and long "
        f"identifiers keep being rejected there."
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


# -- gaps found by independent sabotage --------------------------------

def test_the_composite_primary_key_is_intact():
    """S7, the most severe miss.

    Dropping ``primary_key=True`` from ``agent_key`` collapses the PK to
    (tenant_id, version_no). Every test above uses one agent per tenant,
    so the collision is unreachable and all nine stayed green -- while
    the SECOND DID agent in any tenant would fail to register. That is
    the exact class of bug this file exists to prevent.
    """
    assert [c.name for c in AgentVersion.__table__.primary_key] == [
        "tenant_id", "agent_key", "version_no"
    ], "the composite primary key changed shape"


def test_two_distinct_agents_coexist_in_one_tenant(tmp_path):
    """The behavioural half of the same gap."""
    eng = create_engine(f"sqlite:///{(tmp_path / 'pk.db').as_posix()}")
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    with Session(eng) as db:
        ensure_table(db)
        db.commit()
        for key in (DID_KEY, DID_JWK):
            snapshot_on_first_sight(
                db=db, tenant_id=tenant, agent_key=key,
                definition={"agent_key": key}, created_by="test")
        db.commit()
        n = db.execute(text(
            "SELECT COUNT(DISTINCT agent_key) FROM agent_versions "
            "WHERE tenant_id = :t"), {"t": tenant}).scalar()
    assert n == 2, (
        f"expected 2 distinct agents in one tenant, found {n} -- a "
        f"collapsed primary key merges them"
    )


def test_widening_is_idempotent_across_boots():
    """S4: without the ``cur_len >= AGENT_KEY_LEN`` guard the migration
    re-ALTERs eleven columns on EVERY process start. On MySQL that is a
    table rebuild under lock, per boot."""
    eng = _engine(_BACKENDS["postgres"])
    statements: list[str] = []

    from sqlalchemy import event

    def _record(conn, cursor, stmt, params, ctx, many):
        if "ALTER TABLE" in stmt.upper():
            statements.append(stmt)

    try:
        with eng.connect() as conn:
            _migrate_agent_key_width(conn)     # first boot: may ALTER
            conn.commit()
        event.listen(eng, "before_cursor_execute", _record)
        with eng.connect() as conn:
            _migrate_agent_key_width(conn)     # second boot: must not
            conn.commit()
    finally:
        try:
            event.remove(eng, "before_cursor_execute", _record)
        except Exception:
            pass
        eng.dispose()

    assert statements == [], (
        f"the second pass issued {len(statements)} ALTER statement(s) "
        f"though every column was already wide: {statements[:2]}"
    )


def test_the_index_rebuild_stays_behind_the_ddl_gate(monkeypatch):
    """S6: the inner ``schema_init_enabled()`` check.

    Both current callers are gated, so this is defence in depth -- but
    this very file calls ``_migrate_agent_key_width`` directly, which is
    exactly the ungated entry point a saas deployment must be able to
    switch off.
    """
    from kya.invocations import _reprefix_mysql_indexes

    monkeypatch.setenv("KYA_SKIP_SCHEMA_INIT", "1")
    executed: list[str] = []

    class _Conn:
        def execute(self, stmt, *a, **k):
            executed.append(str(stmt))
            raise AssertionError("DDL issued with schema init disabled")

    import logging
    _reprefix_mysql_indexes(_Conn(), "t", "t", "agent_key",
                            logging.getLogger("test"))
    assert executed == [], executed


def test_MYSQL_a_unique_index_is_never_silently_downgraded():
    """The critical finding: a rebuilt index must not lose UNIQUE.

    The rebuild read SHOW INDEX, skipped only PRIMARY, and issued a
    plain CREATE INDEX -- so a UNIQUE index came back ordinary and
    duplicate rows were accepted where they previously raised 1062.
    A prefix index would also enforce uniqueness on the PREFIX, a
    weaker guarantee than the operator declared.

    The migration now refuses and says so, leaving the column narrow.
    Narrow-and-loud is recoverable; a lost constraint is not.
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
            c.execute(text(
                "CREATE UNIQUE INDEX uq_delpol_ovr_pair "
                f"ON {table} (tenant_id, parent_agent_key, sub_agent_key)"))

        with eng.connect() as conn:
            _migrate_agent_key_width(conn)
            conn.commit()

        with eng.connect() as c:
            still_unique = any(
                int(r._mapping["Non_unique"]) == 0
                for r in c.execute(text(f"SHOW INDEX FROM {table}"))
                if r._mapping["Key_name"] == "uq_delpol_ovr_pair"
            )
        assert still_unique, (
            "uq_delpol_ovr_pair came back non-unique -- duplicate rows "
            "are now accepted where they previously raised 1062"
        )

        # And the constraint still bites.
        with eng.begin() as c:
            c.execute(text(f"INSERT INTO {table} (tenant_id, "
                           "parent_agent_key, sub_agent_key, mode) "
                           "VALUES ('t','p','s','observe')"))
        with pytest.raises(Exception):
            with eng.begin() as c:
                c.execute(text(f"INSERT INTO {table} (tenant_id, "
                               "parent_agent_key, sub_agent_key, mode) "
                               "VALUES ('t','p','s','observe')"))
    finally:
        with eng.begin() as c:
            c.execute(text(f"DROP TABLE IF EXISTS {table}"))
        eng.dispose()


def test_every_migration_log_line_actually_formats():
    """A malformed log call shipped in this very commit.

    The Postgres success branch was changed to say ``-> VARCHAR(%s)``
    without extending the argument list: four placeholders, three
    arguments. ``logging`` swallows that into a stderr traceback rather
    than raising, so a SUCCESSFUL widening emitted no success line and a
    logging error instead -- on the primary backend, inverting the one
    signal an operator has for "did the fix take?".

    Asserting on log output is unusual, but a migration's log IS its
    interface: there is no return value to check.
    """
    import logging

    eng = _engine(_BACKENDS["postgres"])
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger("kya.invocations")
    handler = _Capture()
    logger.addHandler(handler)
    prev = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        # Narrow one column so the success branch genuinely runs.
        with eng.begin() as c:
            c.execute(text("DROP TABLE IF EXISTS agent_versions"))
        with Session(eng) as db:
            ensure_table(db)
            db.commit()
        with eng.begin() as c:
            c.execute(text(_NARROW["postgres"]))
        with eng.connect() as conn:
            _migrate_agent_key_width(conn)
            conn.commit()
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prev)
        eng.dispose()

    assert records, "the migration logged nothing at all"
    for r in records:
        try:
            r.getMessage()
        except Exception as exc:  # noqa: BLE001
            pytest.fail(
                f"log call does not format: {r.msg!r} with {r.args!r} "
                f"-> {type(exc).__name__}: {exc}"
            )
