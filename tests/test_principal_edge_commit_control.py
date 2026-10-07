"""``add_principal_edge(commit=False)`` — the caller owns the transaction.

Why this parameter exists.

A caller that needs the edge to be ATOMIC with its own writes cannot get
that while the primitive commits internally. Two measured failures drove
it:

1. Without a SAVEPOINT, a failing edge write aborts the whole Postgres
   transaction, so the caller's other writes are lost -- an invocation
   row ended up with ``verdict = NULL`` while the API still answered
   201. Silent corruption of the audit record.

2. With a SAVEPOINT but an internal commit, the commit DEASSOCIATES the
   savepoint, so the block raises on SUCCESS. An inverted alarm: the
   caller logs a failure every time the write actually worked.

``commit=False`` + ``begin_nested()`` fixes both. The edge lands in the
caller's transaction (atomic, no visibility window) and a bad edge rolls
back to the savepoint without taking the caller's work with it.

The default stays ``True`` so every existing caller is unaffected.
"""
from __future__ import annotations

import uuid

import pytest

sa = pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from kya.principal_edges import (  # noqa: E402
    add_principal_edge,
    ensure_principal_edges_table,
)


@pytest.fixture
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/edges.db")
    with Session(eng) as db:
        ensure_principal_edges_table(db)
        db.commit()
    return eng


def _edge_count(eng, tenant, child):
    with eng.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM kya_principal_edges "
                 "WHERE tenant_id = :t AND child_id = :c"),
            {"t": tenant, "c": child},
        ).scalar() or 0


def _add(db, tenant, child, **kw):
    return add_principal_edge(
        db, tenant_id=tenant, parent_kind="agent", parent_id="p",
        child_kind="agent", child_id=child, **kw,
    )


def test_default_still_commits(engine):
    """Every existing caller depends on this. The parameter must be
    additive, so the default has to keep committing on its own."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    with Session(engine) as db:
        _add(db, tenant, "committed-by-default")
        # No db.commit() here on purpose.
    assert _edge_count(engine, tenant, "committed-by-default") == 1, (
        "the default no longer commits; every existing caller that "
        "relies on it now silently loses its edge"
    )


def test_commit_false_defers_to_the_caller(engine):
    """With commit=False the row must NOT be durable until the caller
    commits -- that is the whole point: one commit for both writes."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    with Session(engine) as db:
        _add(db, tenant, "deferred", commit=False)
        # Visible inside the transaction...
        inside = db.execute(
            text("SELECT count(*) FROM kya_principal_edges "
                 "WHERE tenant_id = :t AND child_id = 'deferred'"),
            {"t": tenant},
        ).scalar()
        assert inside == 1, "the INSERT was not even flushed"
        db.rollback()
    assert _edge_count(engine, tenant, "deferred") == 0, (
        "commit=False still committed: the caller rolled back and the "
        "edge survived, so the edge is not atomic with the caller's "
        "own writes"
    )


def test_commit_false_lands_on_the_callers_commit(engine):
    """The other half: when the caller DOES commit, the edge is there."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    with Session(engine) as db:
        _add(db, tenant, "carried", commit=False)
        db.commit()
    assert _edge_count(engine, tenant, "carried") == 1


def test_commit_false_does_not_break_a_savepoint(engine):
    """The inverted-alarm case.

    An internal commit deassociates the caller's ``begin_nested()``
    SAVEPOINT, which made the block raise on SUCCESS -- so the caller
    logged a containment failure every time the write worked. With
    commit=False the savepoint survives and no exception is raised.
    """
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    with Session(engine) as db:
        with db.begin_nested():
            _add(db, tenant, "savepointed", commit=False)
        db.commit()
    assert _edge_count(engine, tenant, "savepointed") == 1, (
        "the edge did not survive the savepoint + commit"
    )


def test_a_failed_edge_inside_a_savepoint_spares_the_caller(engine):
    """The reason the parameter exists at all.

    A bad edge must cost the edge, not the caller's work. Without the
    savepoint this was measured losing an invocation's verdict while
    the request still returned success.
    """
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    with Session(engine) as db:
        db.execute(
            text("CREATE TABLE caller_work (id INTEGER PRIMARY KEY, v TEXT)")
        )
        db.execute(text("INSERT INTO caller_work (id, v) VALUES (1, 'kept')"))

        # An over-long child id: rejected by the column, so the write
        # raises inside the savepoint.
        try:
            with db.begin_nested():
                _add(db, tenant, "z" * 4000, commit=False)
        except Exception:
            pass

        db.commit()

    with engine.connect() as conn:
        survived = conn.execute(
            text("SELECT v FROM caller_work WHERE id = 1")
        ).scalar()
    assert survived == "kept", (
        "a failed edge write destroyed the caller's own committed work "
        "-- the savepoint did not contain it"
    )
