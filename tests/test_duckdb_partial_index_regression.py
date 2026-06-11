"""DuckDB partial-index regression test.

DuckDB's SQLAlchemy dialect (duckdb_engine) inherits from postgresql,
so `Index(..., postgresql_where=...)` would be honored — but DuckDB
itself rejects partial indexes:

    NotSupportedError: (_duckdb.NotImplementedException) Not implemented
    Error: Creating partial indexes is not supported currently

`kya._legacy_tables.create_legacy_tables` detaches any partial indexes
for the duration of a DuckDB create_all call and re-attaches them
afterward, so PG/SQLite sessions in the same process still get them.

This test asserts:
  1. ensure_tables() succeeds on DuckDB (both kya_weight_overrides
     and kya_weight_changes exist after the call)
  2. The partial index is restored on the Table object after the
     DuckDB call returns (subsequent PG sessions would still get it)
  3. Re-calling ensure_tables() on a fresh DuckDB connection still
     works (the restore step doesn't leave state that breaks idempotency)
  4. PG / SQLite paths still emit the partial index (cross-session
     isolation works correctly)
"""
from __future__ import annotations

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from kya._legacy_tables import (
    kya_weight_overrides,
)
from kya.tenant_weights import ensure_tables


def _has_partial_index(table) -> bool:
    """Does this Table carry a partial index (postgresql_where set)?"""
    for idx in table.indexes:
        pg_opts = idx.dialect_options.get("postgresql", {})
        if pg_opts.get("where") is not None:
            return True
    return False


def test_duckdb_ensure_tables_succeeds():
    """ensure_tables on DuckDB must create both weight tables."""
    e = create_engine("duckdb:///:memory:")
    with Session(e) as db:
        ensure_tables(db)
        names = set(inspect(db.connection()).get_table_names())
    assert "kya_weight_overrides" in names, (
        f"kya_weight_overrides missing on DuckDB; have: {sorted(names)}"
    )
    assert "kya_weight_changes" in names, (
        f"kya_weight_changes missing on DuckDB; have: {sorted(names)}"
    )


def test_partial_index_restored_after_duckdb_call():
    """After a DuckDB call returns, the Table object MUST still carry
    its partial index. Otherwise the next PG session would silently
    lose the constraint."""
    # Sanity precondition — the partial index IS defined before any call
    assert _has_partial_index(kya_weight_overrides), (
        "test setup invariant broken — kya_weight_overrides should have "
        "a partial index in its definition"
    )

    e = create_engine("duckdb:///:memory:")
    with Session(e) as db:
        ensure_tables(db)

    # Post-call: the partial index MUST be back on the shared Table
    assert _has_partial_index(kya_weight_overrides), (
        "partial index was NOT restored after DuckDB create_all — "
        "subsequent PG sessions would lose the platform-row dedup"
    )


def test_duckdb_ensure_tables_idempotent():
    """Re-calling ensure_tables on a fresh DuckDB engine MUST still
    succeed (restore logic doesn't poison subsequent calls)."""
    for _ in range(3):
        e = create_engine("duckdb:///:memory:")
        with Session(e) as db:
            ensure_tables(db)
            names = set(inspect(db.connection()).get_table_names())
        assert "kya_weight_overrides" in names
        assert "kya_weight_changes" in names


def test_sqlite_still_creates_partial_index():
    """The DuckDB-only detach MUST NOT regress SQLite — the partial
    index is what dedups platform-level rows on SQLite + PG."""
    e = create_engine("sqlite:///:memory:")
    with Session(e) as db:
        ensure_tables(db)
        insp = inspect(db.connection())
        names = set(insp.get_table_names())
        assert "kya_weight_overrides" in names
        # SQLite reports indexes including the partial one.
        idx_names = {ix["name"] for ix in
                     insp.get_indexes("kya_weight_overrides")}
    assert (
        "uq_kya_weight_overrides_platform_scope_key" in idx_names
    ), (
        f"partial index missing on SQLite; have: {idx_names}. "
        "The DuckDB fix should be DuckDB-only."
    )


def test_concurrent_duckdb_and_sqlite_ensure_tables():
    """Stress: many threads × DuckDB and SQLite engines concurrently.

    The fix mutates the SHARED module-level Table.indexes set during
    the DuckDB detach. Without `_DUCKDB_DETACH_LOCK` this races with
    concurrent SQLite/PG `create_all` calls iterating the same
    `Table.indexes`, producing either:

      - RuntimeError: Set changed size during iteration
      - The original NotSupportedError: 'Creating partial indexes is
        not supported' (the index gets re-attached mid-create_all by
        another worker, so DuckDB sees the WHERE clause again)
      - Silently lost partial index on SQLite (detached + never
        restored because the racing thread observed it as 'already
        absent' in its re-attach loop)
    """
    import concurrent.futures as cf
    import random

    def _one_iteration(seed: int) -> str:
        backend = "duckdb" if (seed % 2 == 0) else "sqlite"
        url = f"{backend}:///:memory:"
        e = create_engine(url)
        try:
            with Session(e) as db:
                ensure_tables(db)
                names = set(inspect(db.connection()).get_table_names())
            assert "kya_weight_overrides" in names
            assert "kya_weight_changes" in names
            return f"{backend}:ok"
        finally:
            e.dispose()

    n_threads = 16
    iterations = 40
    random.seed(0xC0FFEE)
    with cf.ThreadPoolExecutor(max_workers=n_threads) as ex:
        futs = [ex.submit(_one_iteration, i) for i in range(iterations)]
        results = [f.result() for f in cf.as_completed(futs)]

    assert len(results) == iterations
    assert all(r.endswith(":ok") for r in results), results

    # Critical post-condition: the partial index MUST still be present
    # on the shared Table after all the racing detach/re-attach cycles.
    # If the lock fails, this is where the regression surfaces.
    assert _has_partial_index(kya_weight_overrides), (
        "partial index was LOST after concurrent DuckDB + SQLite "
        "ensure_tables calls — _DUCKDB_DETACH_LOCK is not holding"
    )


def test_duckdb_writes_to_weight_tables_work():
    """End-to-end smoke: after ensure_tables on DuckDB, writes succeed."""
    e = create_engine("duckdb:///:memory:")
    with Session(e) as db:
        ensure_tables(db)
        db.execute(kya_weight_overrides.insert().values(
            tenant_id=None,  # platform-level
            scope="class_weights",
            key="pii",
            value=10,
            created_by=None,
        ))
        db.commit()
        rows = db.execute(kya_weight_overrides.select()).fetchall()
    assert len(rows) == 1
    assert rows[0].scope == "class_weights"
    assert rows[0].key == "pii"
    assert rows[0].value == 10
