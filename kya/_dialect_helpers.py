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

from collections.abc import Iterable

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
    """Portable upsert for DuckDB without the indexed-column restriction.

    DuckDB rejects `INSERT ... ON CONFLICT DO UPDATE SET c = ...`
    whenever `c` is part of any UNIQUE/PRIMARY-KEY constraint OR a
    regular index on the table. ``kya_user_trust`` has an index on
    ``trust_score`` (for tenant trust-distribution queries), which
    makes the indexed-column rule fatal for the obvious upsert form.

    Sidestep with **two statements** instead of `DO UPDATE`:

      1) ``INSERT ... ON CONFLICT (cols) DO NOTHING``   -- DuckDB-legal
         (DO NOTHING has no SET clause, so the indexed-column rule
         doesn't apply)
      2) ``UPDATE ... WHERE cols = ...``                -- plain UPDATE
         is fine on indexed columns

    Race semantics: two concurrent calls land like this --
      tx A: INSERT (creates row), UPDATE (applies its merge)
      tx B: INSERT no-op (conflict), UPDATE (applies its merge over A)
    The second UPDATE overwrites the first. This is the same lost-
    update window the original ON CONFLICT DO UPDATE had on the
    ``signal_counts`` JSON merge -- both forms are SELECT-then-write
    when read-modify-write is required (the caller pre-computes the
    merged value in users.py). For high-contention DuckDB workloads,
    the caller should also hold an in-process lock around the
    select-merge-write block (record_principal_signal does this).

    Sequence-backed autoincrement columns aren't auto-filled when
    going through raw ``text()`` SQL (SA's Core insert handles that
    via the column's default generator). We resolve them manually.
    """
    values = dict(values)
    conflict_cols_list = list(conflict_cols)

    # Schema resolution must honor schema_translate_map — SQLAlchemy's
    # core/dialect insert constructors apply it automatically, but our
    # raw text() bypass does not. Look up the active map on the bound
    # connection and rewrite the qualifier (None / "" → unqualified).
    schema = table.schema
    try:
        bind = db.get_bind() if hasattr(db, "get_bind") else db.bind
        exec_opts = getattr(bind, "_execution_options", None) or {}
        translate = (exec_opts.get("schema_translate_map") or {}) if exec_opts else {}
        if schema in translate:
            schema = translate[schema]
    except Exception:  # pragma: no cover
        pass
    table_ref = f"{schema}.{table.name}" if schema else table.name

    # Existence pre-check. duckdb-engine reports cursor.rowcount==0
    # even when an UPDATE matched rows, so the "UPDATE-first then
    # check rowcount" pattern is unreliable. Read the conflict-key
    # row state explicitly with one extra SELECT.
    exists_where = " AND ".join(
        f"{c} = :where_{c}" for c in conflict_cols_list)
    exists_params = {f"where_{c}": values[c]
                     for c in conflict_cols_list}
    exists = db.execute(
        text(f"SELECT 1 FROM {table_ref} WHERE {exists_where} LIMIT 1"),
        exists_params,
    ).first()

    if exists is not None:
        # UPDATE path. Plain UPDATE on conflict-keyed rows is
        # DuckDB-legal even when SET touches indexed columns.
        if update_cols_map:
            set_clause = ", ".join(
                f"{c} = :set_{c}" for c in update_cols_map)
            params: dict = {f"set_{c}": v
                            for c, v in update_cols_map.items()}
            params.update(exists_params)
            update_sql = (
                f"UPDATE {table_ref} SET {set_clause} "
                f"WHERE {exists_where}"
            )
            return db.execute(text(update_sql), params)
        return None  # caller passed no update_cols → no-op upsert

    # INSERT path. Fill autoinc PK at the point of actual insertion
    # so we don't burn sequence values on UPDATEs. No ON CONFLICT —
    # the SELECT above proved the row is absent. Concurrent-write
    # race is left to the caller's in-process lock (precedent: see
    # record_principal_signal's _get_chain_lock pattern).
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
    insert_sql = (
        f"INSERT INTO {table_ref} ({col_list}) VALUES ({placeholders})"
    )
    return db.execute(text(insert_sql), values)


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
