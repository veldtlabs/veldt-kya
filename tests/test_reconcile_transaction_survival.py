"""A fail-soft schema step must not poison the caller's transaction.

Postgres aborts the ENTIRE transaction on any failed statement; sqlite
does not. So a reconciler that probes for a column, fails, and swallows
the error leaves every later statement failing with
InFailedSqlTransaction -- and the caller's own write is lost.

Measured before the fix: 32 "Current transaction is aborted" lines in a
full suite run, 0 after.

The load-bearing assertion in every case below is the CALLER'S WRITE
AFTER the reconciler. Asserting only that the reconciler "did not
raise" passes even when the transaction is dead, which is exactly how
this shipped: a sabotage reverting the savepoint wholesale left the ten
most relevant test files green.
"""
from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text


def _pg_url() -> str:
    return os.environ.get(
        "KYA_TEST_POSTGRES_URL",
        "postgresql+psycopg2://veldt:veldt_kya_2026@localhost:18432"
        "/veldt_kya_pending_test",
    )


@pytest.fixture()
def pg_schema():
    """A private schema: these deliberately break DDL, and the shared
    tables are used by ~44 other files."""
    url = _pg_url()
    assert "_test" in url.rsplit("/", 1)[-1], "refusing a non-test database"
    try:
        admin = create_engine(url)
        with admin.connect() as c:
            c.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"postgres unreachable: {exc}")
    schema = f"recon_{uuid.uuid4().hex[:10]}"
    with admin.begin() as c:
        c.execute(text(f'CREATE SCHEMA "{schema}"'))
    eng = create_engine(url, connect_args={
        "options": f"-csearch_path={schema}"})
    try:
        yield eng
    finally:
        eng.dispose()
        with admin.begin() as c:
            c.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()


def test_a_failing_reconcile_leaves_the_caller_able_to_write(pg_schema):
    """The whole point of the savepoint.

    Drive a reconciler against a table shaped so its probe fails, then
    assert the caller can still COMMIT. Without containment the INSERT
    dies with InFailedSqlTransaction and the row is silently lost.
    """
    from sqlalchemy.orm import Session
    from kya.invocations import ensure_invocations_table

    eng = pg_schema
    # A table that exists but is missing everything the reconcilers
    # probe for -- the pre-anchor schema shape.
    with eng.begin() as c:
        c.execute(text("""
            CREATE TABLE kya_invocations (
                id BIGSERIAL PRIMARY KEY,
                tenant_id VARCHAR(64),
                agent_key VARCHAR(512))"""))
        c.execute(text("""
            CREATE TABLE probe_target (id SERIAL PRIMARY KEY, note TEXT)"""))

    with Session(eng) as db:
        ensure_invocations_table(db)
        # THE assertion: the caller's own write, after the reconcilers
        # ran. A poisoned transaction fails here, not above.
        db.execute(text("INSERT INTO probe_target (note) VALUES ('after')"))
        db.commit()

    with eng.connect() as c:
        n = c.execute(text("SELECT COUNT(*) FROM probe_target")).scalar()
    assert n == 1, (
        "the caller's write was lost: a fail-soft schema step aborted "
        "the transaction and every later statement failed"
    )


def test_no_reconcile_failure_is_logged_on_a_healthy_table(pg_schema, caplog):
    """Guard the guard: containment must not become a false alarm.

    The reconcile-failed log is the tamper-detection channel -- its own
    comment says operators diagnose from it "before customers see
    verify failures". If it fires on a healthy deployment it is
    worthless. That is exactly what a savepoint around MySQL's
    implicitly-committing DDL caused.
    """
    import logging

    from sqlalchemy.orm import Session
    from kya.invocations import ensure_invocations_table

    eng = pg_schema
    with Session(eng) as db:
        ensure_invocations_table(db)
        db.commit()

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="kya.invocations"):
        with Session(eng) as db:
            ensure_invocations_table(db)
            db.commit()

    noisy = [r.getMessage() for r in caplog.records
             if "reconcile FAILED" in r.getMessage()]
    assert not noisy, (
        f"the tamper-detection channel fired on a healthy table: {noisy}"
    )


def test_savepoint_dialects_excludes_mysql():
    """MySQL DDL implicitly commits, which destroys an open savepoint.

    Wrapping a reconciler there made RELEASE SAVEPOINT fail on the happy
    path, firing the operator alert on every MySQL deployment forever.
    MySQL does not abort on error, so it never needed containment.
    """
    from kya.invocations import _SAVEPOINT_DIALECTS
    assert "mysql" not in _SAVEPOINT_DIALECTS, (
        "MySQL DDL implicitly commits; a savepoint around it fails on "
        "RELEASE and turns the tamper-detection log into a false alarm"
    )
    assert "postgresql" in _SAVEPOINT_DIALECTS
