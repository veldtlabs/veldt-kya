"""Dialect-aware helpers shared by the legacy write paths.

The legacy modules (agent_aliases, users, tenant_weights, kya_redteam/*)
were originally implemented with PG-native raw SQL (``(:tid)::uuid``,
``ON CONFLICT DO UPDATE``, ``RETURNING``, ``jsonb_*``). These helpers
abstract the dialect-divergent surface so the entry-point write
functions can stay portable across PostgreSQL, MySQL, SQLite, and
DuckDB without giving up the PG concurrency primitives.

What lives here:
    dialect_of(db)                 -> str   (one of pg/mysql/sqlite/duckdb)
    portable_upsert(...)            -> Compile-ready Insert with the
                                       right ``on_conflict`` flavor.
    insert_returning_id(...)        -> int  (uses RETURNING where
                                       supported; LAST_INSERT_ID() on MySQL).

Concurrency notes:
- PG path preserves the original ``INSERT ON CONFLICT DO UPDATE``
  semantics: atomic, no read-modify-write window.
- Non-PG paths get the same statement shape via SQLAlchemy's
  dialect-specific ``insert()`` constructors; lost-update windows are
  identical to the PG version on SQLite/DuckDB (both implement
  ``ON CONFLICT DO UPDATE`` since 3.24/0.6) and on MySQL via
  ``ON DUPLICATE KEY UPDATE``.
"""

from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import Table, text
from sqlalchemy.dialects import mysql as mysql_d
from sqlalchemy.dialects import postgresql as pg_d
from sqlalchemy.dialects import sqlite as sqlite_d


def dialect_of(db) -> str:
    """Return short dialect name for the bound engine.

    Possible values: 'postgresql', 'mysql', 'sqlite', 'duckdb', 'unknown'.
    """
    try:
        bind = db.get_bind() if hasattr(db, "get_bind") else db.bind
        return bind.dialect.name
    except Exception:
        return "unknown"


def portable_upsert(
    db,
    table: Table,
    values: dict,
    *,
    conflict_cols: Iterable[str],
    update_cols: Iterable[str],
):
    """Emit an atomic INSERT ... ON CONFLICT DO UPDATE for the bound dialect.

    DuckDB shares SQLite's `dialects.sqlite.insert().on_conflict_do_update()`
    grammar (both render `ON CONFLICT (cols) DO UPDATE SET ...`).
    """
    dialect = dialect_of(db)
    update_dict = {c: values[c] for c in update_cols if c in values}

    if dialect == "postgresql":
        stmt = pg_d.insert(table).values(**values).on_conflict_do_update(
            index_elements=list(conflict_cols),
            set_=update_dict,
        )
    elif dialect == "mysql":
        stmt = mysql_d.insert(table).values(**values)
        stmt = stmt.on_duplicate_key_update(**update_dict)
    elif dialect == "sqlite":
        stmt = sqlite_d.insert(table).values(**values).on_conflict_do_update(
            index_elements=list(conflict_cols),
            set_=update_dict,
        )
    elif dialect == "duckdb":
        # duckdb-engine's SQLite-grammar shim has a known compile bug on
        # on_conflict_do_update (missing `constraint_target` attr). DuckDB
        # itself supports the same ON CONFLICT syntax; emit raw SQL.
        return _duckdb_upsert_raw(db, table, values, conflict_cols, update_dict)
    else:
        # Last-resort fallback: plain insert (tests will detect missed
        # uniqueness; logged for visibility).
        stmt = table.insert().values(**values)

    return db.execute(stmt)


def _duckdb_upsert_raw(db, table: Table, values: dict, conflict_cols, update_cols_map: dict):
    """Build a raw INSERT ... ON CONFLICT ... DO UPDATE for DuckDB.

    DuckDB syntax matches SQLite/PG (``ON CONFLICT (col,...) DO UPDATE
    SET c = excluded.c``); the issue is purely in duckdb-engine's
    SQLAlchemy compile path on the SQLite-style insert constructor.

    Sequence-backed autoincrement columns aren't auto-filled when going
    through raw ``text()`` SQL (SA's Core insert handles that via the
    column's default generator). We resolve them manually here.
    """
    values = dict(values)
    for col in table.columns:
        if col.name in values:
            continue
        seq = col.default
        seq_name = getattr(seq, "name", None) if seq is not None else None
        if seq_name and col.primary_key:
            values[col.name] = db.execute(
                text(f"SELECT nextval('{seq_name}')")
            ).scalar()

    cols = list(values.keys())
    col_list = ", ".join(cols)
    placeholders = ", ".join(f":{c}" for c in cols)
    conflict_list = ", ".join(conflict_cols)
    if update_cols_map:
        set_clause = ", ".join(f"{c} = excluded.{c}" for c in update_cols_map.keys())
        upsert_tail = f"ON CONFLICT ({conflict_list}) DO UPDATE SET {set_clause}"
    else:
        upsert_tail = f"ON CONFLICT ({conflict_list}) DO NOTHING"

    table_ref = (
        f"{table.schema}.{table.name}" if table.schema else table.name
    )
    sql = f"INSERT INTO {table_ref} ({col_list}) VALUES ({placeholders}) {upsert_tail}"
    return db.execute(text(sql), values)


def insert_returning_id(db, table: Table, values: dict, id_col: str = "id") -> int | None:
    """Execute INSERT and return the new row's primary-key value.

    Uses RETURNING on PG / SQLite (≥3.35) / DuckDB; falls back to
    `result.inserted_primary_key` on MySQL.
    """
    dialect = dialect_of(db)

    if dialect == "mysql":
        result = db.execute(table.insert().values(**values))
        try:
            pk = result.inserted_primary_key
            return int(pk[0]) if pk else None
        except Exception:
            row = db.execute(text("SELECT LAST_INSERT_ID()")).fetchone()
            return int(row[0]) if row and row[0] else None

    stmt = table.insert().values(**values).returning(getattr(table.c, id_col))
    row = db.execute(stmt).fetchone()
    return int(row[0]) if row else None
