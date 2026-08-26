"""``kya_invocations.id`` must be assignable by the server, not just the ORM.

The model passes an explicit ``Sequence``, and the comment above it used
to claim Postgres got BIGSERIAL behaviour and DuckDB a ``nextval()``
default. Neither was true: with an explicit Sequence, SQLAlchemy creates
the sequence separately and pre-fetches ``nextval`` CLIENT-SIDE, emitting
a bare ``id BIGINT NOT NULL``.

That is why it went unnoticed for 49k rows -- the ORM supplies ``id``
itself, so every application write worked. Nothing else could write at
all, and the schema quietly permitted a SECOND id source. There is no FK
on ``parent_invocation_id``; the delegation chain is walked hop-by-hop in
application code, so a duplicate id mis-parents an invocation in signed
evidence rather than raising.
"""
from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine, text          # noqa: E402
from sqlalchemy.orm import Session                  # noqa: E402


def test_emitted_ddl_names_every_dialect_honestly() -> None:
    """Guard the comment against the code.

    A dialect that autoincrements natively must NOT be reconciled, and
    one that does not must BE reconciled. If this list and the emitted
    DDL ever disagree, the reconciler silently targets the wrong set.
    """
    from sqlalchemy.dialects import mysql, postgresql, sqlite
    from sqlalchemy.schema import CreateTable

    from kya.invocations import Invocation, _SEQUENCE_DIALECTS

    ddl = {
        name: str(CreateTable(Invocation.__table__).compile(dialect=d))
        for name, d in [
            ("postgresql", postgresql.dialect()),
            ("sqlite", sqlite.dialect()),
            ("mysql", mysql.dialect()),
        ]
    }
    id_line = {
        k: next(ln.strip() for ln in v.splitlines() if ln.strip().startswith("id "))
        for k, v in ddl.items()
    }

    assert "AUTO_INCREMENT" in id_line["mysql"], id_line["mysql"]
    assert "mysql" not in _SEQUENCE_DIALECTS, (
        "MySQL autoincrements natively; reconciling it would be wrong"
    )
    assert "sqlite" not in _SEQUENCE_DIALECTS, (
        "SQLite autoincrements via the rowid alias"
    )
    assert "postgresql" in _SEQUENCE_DIALECTS, (
        f"PG emits {id_line['postgresql']!r} — no DEFAULT — so it must be "
        "reconciled"
    )
    assert "DEFAULT" not in id_line["postgresql"].upper(), (
        "PG now emits a DEFAULT on its own; the reconciler may be "
        f"redundant: {id_line['postgresql']!r}"
    )


def test_sqlite_still_autoincrements_untouched() -> None:
    """The reconciler must be a no-op on dialects that already work."""
    from kya.invocations import ensure_invocations_table

    eng = create_engine("sqlite+pysqlite:///:memory:")
    try:
        with Session(eng) as db:
            ensure_invocations_table(db)
            db.execute(text(
                "INSERT INTO kya_invocations "
                "(tenant_id, agent_key, mode, outcome, occurred_at) "
                "VALUES ('t','a','auto','success',CURRENT_TIMESTAMP)"
            ))
            db.commit()
            got = db.execute(text("SELECT id FROM kya_invocations")).scalar()
        assert got is not None and int(got) >= 1, got
    finally:
        eng.dispose()


def _pg_engine():
    import os

    url = os.environ.get(
        "KYA_TEST_PG_URL",
        "postgresql+psycopg2://veldt:veldt_kya_2026@localhost:18432/veldt_kya",
    )
    try:
        eng = create_engine(url, future=True)
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
        return eng
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"postgres unavailable: {str(exc)[:80]}")


def _id_default(eng):
    with eng.connect() as c:
        return c.execute(text(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_name='kya_invocations' AND column_name='id'"
        )).scalar()


def _drive_drift(eng):
    """Put the column back into the state the emitted DDL produces.

    Without this the test is vacuous: a database that was already
    reconciled satisfies every assertion below whether or not the
    reconciler runs. Sabotaging the reconciler proved exactly that --
    three separate breakages went undetected.
    """
    with eng.begin() as c:
        c.execute(text("ALTER TABLE kya_invocations ALTER COLUMN id DROP DEFAULT"))
        c.execute(text("ALTER SEQUENCE kya_invocations_id_seq OWNED BY NONE"))


@pytest.mark.parametrize("_run", [1, 2], ids=["first", "idempotent"])
def test_postgres_id_is_server_assignable(_run) -> None:
    """The real proof, on real Postgres. Skips when unavailable.

    Drives the drift first, then reconciles, so the assertions can only
    pass because the reconciler did the work.

    Parametrized twice because this runs on every boot: the second pass
    must be a no-op, not a second ALTER or a sequence reset.
    """
    from kya.invocations import ensure_invocations_table

    eng = _pg_engine()
    try:
        _drive_drift(eng)
        assert _id_default(eng) is None, "precondition: drift not applied"

        with Session(eng) as db:
            ensure_invocations_table(db)
            db.commit()

        default = _id_default(eng)
        with eng.connect() as c:
            owned = c.execute(text(
                "SELECT pg_get_serial_sequence('kya_invocations','id')"
            )).scalar()

        assert default and "nextval" in default, (
            "the reconciler did not attach a server-side DEFAULT — only "
            f"the ORM can insert into this table (got {default!r})"
        )
        assert owned, (
            "the sequence is not OWNED BY the column, so dropping the "
            "column would strand it"
        )

        with eng.begin() as c:
            c.execute(text(
                "INSERT INTO kya_invocations "
                "(tenant_id, agent_key, principal_kind, mode, outcome, "
                " occurred_at) VALUES "
                "('00000000-0000-0000-0000-000000000000','id-default-test',"
                " 'agent','auto','success',CURRENT_TIMESTAMP)"
            ))
            rows = c.execute(text(
                "SELECT id FROM kya_invocations WHERE agent_key='id-default-test'"
            )).fetchall()
            assert len(rows) == 1 and rows[0][0] is not None, rows
            dupes = c.execute(text(
                "SELECT count(*) FROM (SELECT id FROM kya_invocations "
                "GROUP BY id HAVING count(*) > 1) d"
            )).scalar()
            assert dupes == 0, (
                f"{dupes} duplicate id(s) — a second id source would "
                "mis-parent invocations, and there is no FK to catch it"
            )
            c.execute(text(
                "DELETE FROM kya_invocations WHERE agent_key='id-default-test'"
            ))
    finally:
        # Never leave a shared dev database drifted, even on failure.
        try:
            with Session(eng) as db:
                ensure_invocations_table(db)
                db.commit()
        except Exception:  # noqa: BLE001
            pass
        eng.dispose()
