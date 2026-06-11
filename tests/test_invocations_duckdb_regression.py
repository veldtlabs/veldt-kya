"""Regression test for the DuckDB agent_key widening migration bug
caught by the Phase 10 4-backend matrix.

Two related bugs poisoned the connection's transaction context on
DuckDB, causing every subsequent statement on the same conn to fail
with `TransactionContext Error: Current transaction is aborted`:

1. `insp.get_columns("missing_table", schema=None)` raises
   CatalogException on DuckDB (PG/MySQL return []). The exception
   is caught by the per-table try/except, but the DuckDB connection
   is now in an aborted-transaction state.

2. `ALTER TABLE kya_invocations ALTER COLUMN agent_key TYPE VARCHAR(512)`
   fails on DuckDB with "Cannot change the type of this column: an
   index depends on it!" because `idx_kya_inv_tenant_agent_occurred`
   includes the column. Same poisoning effect.

Both are no-ops on DuckDB anyway: DuckDB does not enforce VARCHAR
length, so a VARCHAR(100) column happily accepts a 500-char string.

This test creates the table on a fresh DuckDB, runs the migration,
then inserts a 308-char DID-shaped agent_key. Before the fix,
record_invocation raised TransactionException; after the fix it
returns a valid invocation id.
"""
from __future__ import annotations


def test_ensure_invocations_table_then_insert_long_did_on_duckdb():
    """The migration must not poison the DuckDB connection. A long
    DID-shaped agent_key must insert cleanly."""
    duckdb_engine = __import__("duckdb_engine")  # ImportError == skip
    assert duckdb_engine is not None

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from kya.invocations import ensure_invocations_table, record_invocation

    # In-memory DuckDB avoids the Windows tempfile-cleanup race where
    # the engine still holds an open file handle when TemporaryDirectory
    # tries to unlink it.
    engine = create_engine("duckdb:///:memory:")
    try:
        Session = sessionmaker(bind=engine)
        with Session() as db:
            ensure_invocations_table(db)
            long_did = "did:jwk:" + "X" * 300
            inv = record_invocation(
                db,
                tenant_id="00000000-0000-0000-0000-000000000001",
                agent_key="k1",
                principal_kind="admin",
                principal_id=long_did,
                mode="hybrid",
                outcome="success",
            )
            db.commit()
            assert inv is not None and int(inv) >= 1
            n = db.execute(
                text("SELECT COUNT(*) FROM kya_invocations")
            ).scalar()
            assert n == 1
    finally:
        engine.dispose()
