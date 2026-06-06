"""Regression test for the DuckDB BIGSERIAL portability bug caught
by the v0.4.0 Pro E2E pipeline.

Before the fix, `ensure_principal_edges_table(db)` emitted
`BIGSERIAL` for DuckDB which raised:

    duckdb.CatalogException: Type with name BIGSERIAL does not exist!

The fix wires the same explicit `Sequence("kya_principal_edges_id_seq")`
pattern already proven on `kya_invocations` / `kya_evidence` so DuckDB
emits CREATE SEQUENCE + nextval() instead of BIGSERIAL.

This test creates the table on a real DuckDB engine and asserts the
table exists. If anyone reintroduces the BIGSERIAL pattern, the
CREATE TABLE call raises and this test fails.
"""
from __future__ import annotations

import tempfile
from pathlib import Path


def test_ensure_principal_edges_table_works_on_duckdb():
    """The table must create cleanly on DuckDB. Pre-fix this raised
    `Type with name BIGSERIAL does not exist` because SQLAlchemy
    emitted BIGSERIAL for BigInteger().with_variant(Integer, 'sqlite')
    on the DuckDB dialect, and DuckDB rejects BIGSERIAL."""
    duckdb_engine = __import__("duckdb_engine")  # ImportError == skip
    assert duckdb_engine is not None

    from sqlalchemy import create_engine, inspect
    from sqlalchemy.orm import Session

    from kya.principal_edges import (
        add_principal_edge,
        ensure_principal_edges_table,
        walk_ancestors,
    )

    # File-based DuckDB so the CREATE TABLE statement exercises the
    # full DDL pipeline (in-memory paths short-circuit some checks).
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "regression.duckdb"
        engine = create_engine(f"duckdb:///{db_path}", future=True)
        with Session(engine) as db:
            # The DDL call that used to fail
            ensure_principal_edges_table(db)
            db.commit()

            # Confirm the table actually landed
            ins = inspect(engine)
            assert "kya_principal_edges" in ins.get_table_names()

            # And a real round-trip — add an edge, walk it back.
            # This proves the autoincrement default actually works
            # on DuckDB (not just the DDL).
            add_principal_edge(
                db, tenant_id="00000000-0000-0000-0000-000000000001",
                parent_kind="user", parent_id="alice",
                child_kind="agent", child_id="bot1",
                edge_kind="delegation",
            )
            db.commit()
            ancestors = walk_ancestors(
                db, tenant_id="00000000-0000-0000-0000-000000000001",
                leaf_kind="agent", leaf_id="bot1",
            )
            assert len(ancestors) == 1
            depth, edge = ancestors[0]
            assert depth == 1
            assert edge.parent_id == "alice"


def test_principal_edges_id_column_uses_explicit_sequence():
    """White-box: the column definition must carry an explicit
    Sequence so the BIGSERIAL-rejection path can't reintroduce.
    Catches a future refactor that drops the Sequence."""
    from sqlalchemy import Sequence

    from kya.principal_edges import _PrincipalEdgeRow

    id_col = _PrincipalEdgeRow.__table__.c.id
    # The Sequence is attached to the column's `default` and `server_default`
    # via the SA Sequence machinery. Cheapest detection: walk the
    # column's foreign-construct list.
    seqs = [
        c for c in id_col.proxy_set
        if hasattr(c, "default") and isinstance(c.default, Sequence)
    ]
    # Fallback: SA stores the Sequence as `column.default`.
    if not seqs and isinstance(id_col.default, Sequence):
        seqs = [id_col]
    assert seqs, (
        "kya_principal_edges.id is missing the explicit "
        "Sequence(...) — re-introducing this is the DuckDB "
        "BIGSERIAL bug. See "
        "tests/test_principal_edges_duckdb_regression.py."
    )
