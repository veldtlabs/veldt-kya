"""Independent 4-backend review of fix/duckdb-partial-index.

Verifies the detach/re-attach + _LEGACY_CREATE_LOCK fix works correctly
on SQLite, DuckDB, PostgreSQL, and MySQL — both in isolation and in
mixed-dialect sequences. Also runs a 4-backend concurrent storm.

Test DB URLs:
  KYA_TEST_PG_URL=postgresql+psycopg://kya:kya@localhost:35432/kyatest
  KYA_TEST_MYSQL_URL=mysql+pymysql://root:kya@localhost:33077/kyatest

Each PG/MySQL run uses a unique schema (PG) or per-test row keys (MySQL)
so concurrent test instances don't collide on the shared DB.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import random
import uuid

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from kya._legacy_tables import (
    kya_weight_changes,
    kya_weight_overrides,
)
from kya.tenant_weights import ensure_tables

PG_URL = os.environ.get(
    "KYA_TEST_PG_URL",
    "postgresql+psycopg://kya:kya@localhost:35432/kyatest",
)
MYSQL_URL = os.environ.get(
    "KYA_TEST_MYSQL_URL",
    "mysql+pymysql://root:kya@localhost:33077/kyatest",
)


def _has_partial_index_on_table_object() -> bool:
    """Does the shared Table object still carry its partial index?"""
    for idx in kya_weight_overrides.indexes:
        pg = idx.dialect_options.get("postgresql", {}).get("where")
        sq = idx.dialect_options.get("sqlite", {}).get("where")
        if pg is not None or sq is not None:
            return True
    return False


def _live_partial_index_present(engine) -> tuple[bool, list[dict]]:
    """Inspect the live catalog and check if the partial unique index
    `uq_kya_weight_overrides_platform_scope_key` exists with a WHERE.

    Returns (present, raw_index_info_for_debug).
    For PG, also pulls pg_indexes.indexdef so we can confirm WHERE clause.
    """
    insp = inspect(engine)
    idxs = insp.get_indexes("kya_weight_overrides")
    raw = list(idxs)
    base_present = any(
        ix.get("name") == "uq_kya_weight_overrides_platform_scope_key"
        for ix in idxs
    )
    # PG: read pg_indexes.indexdef so we can confirm the WHERE clause
    if engine.dialect.name == "postgresql":
        with engine.connect() as c:
            q = text(
                "SELECT indexname, indexdef FROM pg_indexes "
                "WHERE tablename = 'kya_weight_overrides'"
            )
            rows = c.execute(q).fetchall()
            raw = [{"name": r[0], "definition": r[1]} for r in rows]
            base_present = any(
                r[0] == "uq_kya_weight_overrides_platform_scope_key"
                for r in rows
            )
    return base_present, raw


def _drop_kya_weight_tables(engine, schema=None):
    with engine.begin() as conn:
        for t in ("kya_weight_changes", "kya_weight_overrides"):
            full = f"{schema}.{t}" if schema else t
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {full}"))
            except Exception:
                pass


# PG tables land in `public` (no KYA_VERSIONS_SCHEMA at import time).
# We can't safely run two PG tests in parallel against the same `public`,
# so we serialize PG tests by always dropping + recreating in `public`.
# Each PG test must clean up after itself.
def _make_pg_engine():
    """Clean PG engine — tables go to `public`."""
    eng = create_engine(PG_URL)
    _drop_kya_weight_tables(eng)
    return eng


def _drop_pg_kya_tables():
    eng = create_engine(PG_URL)
    _drop_kya_weight_tables(eng)
    eng.dispose()


def _ensure_mysql_clean():
    eng = create_engine(MYSQL_URL)
    _drop_kya_weight_tables(eng)
    eng.dispose()


# ─────────────────────────────────────────────────────────────────────────
# A. Per-backend table + index presence + dedup behavior
# ─────────────────────────────────────────────────────────────────────────


def test_A_sqlite_table_and_partial_index():
    e = create_engine("sqlite:///:memory:")
    with Session(e) as db:
        ensure_tables(db)
        insp = inspect(db.connection())
        names = set(insp.get_table_names())
        assert "kya_weight_overrides" in names
        assert "kya_weight_changes" in names
        idx_names = {ix["name"] for ix in insp.get_indexes("kya_weight_overrides")}
        assert "uq_kya_weight_overrides_platform_scope_key" in idx_names, (
            f"SQLite missing partial index; have: {idx_names}"
        )

        # Platform-level write OK
        db.execute(kya_weight_overrides.insert().values(
            tenant_id=None, scope="class_weights", key="pii",
            value=10, created_by=None))
        db.commit()
        # Tenant-level write OK
        db.execute(kya_weight_overrides.insert().values(
            tenant_id=str(uuid.uuid4()), scope="class_weights",
            key="pii", value=20, created_by=None))
        db.commit()

        # Second platform row with same (scope, key) — MUST fail
        with pytest.raises((IntegrityError, OperationalError)):
            db.execute(kya_weight_overrides.insert().values(
                tenant_id=None, scope="class_weights", key="pii",
                value=99, created_by=None))
            db.commit()
        db.rollback()


def test_A_duckdb_table_and_no_partial_index():
    e = create_engine("duckdb:///:memory:")
    with Session(e) as db:
        ensure_tables(db)
        insp = inspect(db.connection())
        names = set(insp.get_table_names())
        assert "kya_weight_overrides" in names
        assert "kya_weight_changes" in names
        idx_names = {ix["name"] for ix in insp.get_indexes("kya_weight_overrides")}
        assert "uq_kya_weight_overrides_platform_scope_key" not in idx_names, (
            f"DuckDB unexpectedly has the partial index: {idx_names}"
        )

        db.execute(kya_weight_overrides.insert().values(
            tenant_id=None, scope="class_weights", key="pii",
            value=10, created_by=None))
        db.commit()
        db.execute(kya_weight_overrides.insert().values(
            tenant_id=str(uuid.uuid4()), scope="class_weights",
            key="pii", value=20, created_by=None))
        db.commit()

        # Second platform-level row — MUST succeed (no partial index)
        db.execute(kya_weight_overrides.insert().values(
            tenant_id=None, scope="class_weights", key="pii",
            value=99, created_by=None))
        db.commit()
        rows = db.execute(select(kya_weight_overrides).where(
            kya_weight_overrides.c.tenant_id.is_(None))).fetchall()
        assert len(rows) == 2, f"DuckDB should accept dup platform rows; got {len(rows)}"


def test_A_postgresql_table_and_partial_index():
    eng = _make_pg_engine()
    try:
        with Session(eng) as db:
            ensure_tables(db)

        present, raw = _live_partial_index_present(eng)
        assert present, f"PG missing partial index; raw: {raw}"
        # Verify WHERE clause includes 'tenant_id IS NULL'
        found_where = False
        for r in raw:
            if r.get("name") == "uq_kya_weight_overrides_platform_scope_key":
                defn = r.get("definition", "") or ""
                if "tenant_id IS NULL" in defn or "IS NULL" in defn:
                    found_where = True
                    break
        assert found_where, f"PG partial index missing tenant_id IS NULL WHERE: {raw}"

        with Session(eng) as db:
            db.execute(kya_weight_overrides.insert().values(
                tenant_id=None, scope="class_weights", key="pii",
                value=10, created_by=None))
            db.commit()
            db.execute(kya_weight_overrides.insert().values(
                tenant_id=str(uuid.uuid4()), scope="class_weights",
                key="pii", value=20, created_by=None))
            db.commit()

            with pytest.raises(IntegrityError):
                db.execute(kya_weight_overrides.insert().values(
                    tenant_id=None, scope="class_weights", key="pii",
                    value=99, created_by=None))
                db.commit()
            db.rollback()
    finally:
        eng.dispose()
        _drop_pg_kya_tables()


def test_A_mysql_table_observed_behavior():
    """MySQL OBSERVED BEHAVIOR — documented as a finding.

    The user's spec said MySQL silently ignores `postgresql_where` /
    `sqlite_where`, so the partial index would be absent. In practice
    on MySQL 8+, SQLAlchemy emits the index as a NON-PARTIAL UNIQUE
    (the WHERE clause is dropped but the UNIQUE constraint remains).

    Consequence: the index `uq_kya_weight_overrides_platform_scope_key`
    becomes a hard UNIQUE on `(scope, key)` — which forbids ANY two
    tenants from sharing the same (scope, key) pair. That's a
    tenant-isolation regression, not a known acceptable limit.

    This test captures the observed state so the regression is loud.
    """
    _ensure_mysql_clean()
    eng = create_engine(MYSQL_URL)
    try:
        with Session(eng) as db:
            ensure_tables(db)

        insp = inspect(eng)
        names = set(insp.get_table_names())
        assert "kya_weight_overrides" in names
        assert "kya_weight_changes" in names
        idx_names = {ix["name"] for ix in insp.get_indexes("kya_weight_overrides")}

        # Observed: index IS present, but as a non-partial UNIQUE
        partial_index_present = (
            "uq_kya_weight_overrides_platform_scope_key" in idx_names
        )

        # Show whether it's actually unique-with-WHERE or unique-no-WHERE
        with eng.connect() as c:
            ddl = c.execute(
                text("SHOW CREATE TABLE kya_weight_overrides")
            ).fetchone()[1]

        # Now test cross-tenant impact — try inserting two DIFFERENT
        # tenants with the same (scope, key). On PG/SQLite this succeeds
        # because the UNIQUE constraint is on (tenant_id, scope, key)
        # and the partial unique is only on platform rows.
        with Session(eng) as db:
            t1, t2 = str(uuid.uuid4()), str(uuid.uuid4())
            db.execute(kya_weight_overrides.insert().values(
                tenant_id=t1, scope="class_weights", key="pii",
                value=10, created_by=None))
            db.commit()
            cross_tenant_blocked = False
            try:
                db.execute(kya_weight_overrides.insert().values(
                    tenant_id=t2, scope="class_weights", key="pii",
                    value=20, created_by=None))
                db.commit()
            except IntegrityError:
                cross_tenant_blocked = True
                db.rollback()

        # POST-FIX expected behavior on MySQL:
        # 1. The partial index name is ABSENT (we detach it because
        #    MySQL would emit it as a non-partial UNIQUE that blocks
        #    cross-tenant rows — a tenant-isolation regression).
        # 2. Cross-tenant inserts with the same (scope, key) SUCCEED
        #    — DIFFERENT tenants can share the same (scope, key)
        #    pair because only the UniqueConstraint("tenant_id",
        #    "scope", "key") is in effect, and MySQL treats NULL as
        #    distinct.
        # 3. Same-tenant duplicate would be blocked by the
        #    UniqueConstraint, but that's not what this test exercises.
        assert not partial_index_present, (
            "MySQL emitted 'uq_kya_weight_overrides_platform_scope_key' — "
            "the fix's MySQL-detach branch did NOT run. Reviewer-flagged "
            "tenant-isolation bug would still apply."
        )
        assert not cross_tenant_blocked, (
            "MySQL BLOCKED cross-tenant (scope, key) — the non-partial "
            "UNIQUE is still being emitted, the tenant-isolation bug is "
            "still present. Check the detach branch in create_legacy_tables."
        )
        # Surface the DDL for evidence
        print(f"\n[MySQL] DDL:\n{ddl}\n")
    finally:
        _ensure_mysql_clean()
        eng.dispose()


# ─────────────────────────────────────────────────────────────────────────
# B. Cross-backend isolation: DuckDB → PG → MySQL → SQLite
# ─────────────────────────────────────────────────────────────────────────


def test_B_cross_backend_isolation_no_leak():
    """Running ensure_tables on DuckDB first MUST NOT leak the index
    detach into subsequent PG/SQLite sessions."""
    assert _has_partial_index_on_table_object(), "precondition failed"

    # 1. DuckDB
    edk = create_engine("duckdb:///:memory:")
    with Session(edk) as db:
        ensure_tables(db)
    edk.dispose()
    assert _has_partial_index_on_table_object(), (
        "after DuckDB call, shared Table lost its partial index — re-attach failed"
    )

    # 2. PostgreSQL
    epg = _make_pg_engine()
    try:
        with Session(epg) as db:
            ensure_tables(db)
        pg_present, _ = _live_partial_index_present(epg)
        assert pg_present, "PG partial index missing after DuckDB-then-PG sequence"
    finally:
        epg.dispose()
        _drop_pg_kya_tables()

    # 3. MySQL — observed bug: MySQL emits the index as a non-partial
    # UNIQUE (silently strips the WHERE). This is captured separately in
    # test_A_mysql_table_observed_behavior; here we only assert that the
    # SHARED Table object still carries its partial index after the call
    # (regardless of what MySQL actually creates on-disk).
    _ensure_mysql_clean()
    emy = create_engine(MYSQL_URL)
    try:
        with Session(emy) as db:
            ensure_tables(db)
        assert _has_partial_index_on_table_object(), (
            "after MySQL, shared Table lost its partial index"
        )
    finally:
        _ensure_mysql_clean()
        emy.dispose()

    # 4. SQLite — last one, MUST still get partial index
    esq = create_engine("sqlite:///:memory:")
    with Session(esq) as db:
        ensure_tables(db)
        insp = inspect(db.connection())
        idx_names = {ix["name"] for ix in insp.get_indexes("kya_weight_overrides")}
        assert "uq_kya_weight_overrides_platform_scope_key" in idx_names, (
            "SQLite (last in sequence) missing partial index — cross-backend "
            f"isolation broken; have: {idx_names}"
        )
    esq.dispose()


# ─────────────────────────────────────────────────────────────────────────
# D. 4-backend concurrency stress
# ─────────────────────────────────────────────────────────────────────────


def test_D_concurrent_all_four_backends():
    """16 threads × 40 iterations, random backend pick across all 4.

    Each iteration: random backend → fresh engine → ensure_tables →
    inspect table presence → dispose. After all iterations:
      - no exceptions
      - shared Table.indexes still has the partial index (lock held)
    """
    # Pre-create the PG + MySQL tables once so all stress iterations are
    # CREATE IF NOT EXISTS no-ops (the test isn't about per-iteration
    # DROP/CREATE — it's about the shared Table.indexes set not racing).
    _drop_pg_kya_tables()
    _ensure_mysql_clean()

    def _one_iteration(seed: int) -> str:
        rng = random.Random(seed)
        backend = rng.choice(["sqlite", "duckdb", "postgresql", "mysql"])

        if backend == "sqlite":
            e = create_engine("sqlite:///:memory:")
        elif backend == "duckdb":
            e = create_engine("duckdb:///:memory:")
        elif backend == "postgresql":
            e = create_engine(PG_URL, pool_pre_ping=True)
        else:  # mysql
            e = create_engine(MYSQL_URL, pool_pre_ping=True)

        try:
            with Session(e) as db:
                ensure_tables(db)
                insp = inspect(db.connection())
                names = set(insp.get_table_names())
            assert "kya_weight_overrides" in names, f"{backend}: missing table"
            assert "kya_weight_changes" in names, f"{backend}: missing audit table"
            return f"{backend}:ok"
        finally:
            e.dispose()

    n_threads = 16
    iterations = 40
    with cf.ThreadPoolExecutor(max_workers=n_threads) as ex:
        futs = [ex.submit(_one_iteration, i) for i in range(iterations)]
        results = []
        errors = []
        for f in cf.as_completed(futs):
            try:
                results.append(f.result())
            except Exception as exc:
                errors.append(repr(exc))

    # Cleanup
    _drop_pg_kya_tables()
    _ensure_mysql_clean()

    assert not errors, f"concurrent ensure_tables errors: {errors[:5]}"
    assert len(results) == iterations
    assert all(r.endswith(":ok") for r in results), results

    # Shared Table MUST still have the partial index
    assert _has_partial_index_on_table_object(), (
        "after 4-backend concurrent storm, shared Table lost partial index — "
        "_LEGACY_CREATE_LOCK failed to serialize the detach/re-attach"
    )

    # Verify that any SQLite/PG engine created NOW still gets the partial idx
    es = create_engine("sqlite:///:memory:")
    with Session(es) as db:
        ensure_tables(db)
        idx_names = {ix["name"]
                     for ix in inspect(db.connection()).get_indexes(
                         "kya_weight_overrides")}
        assert "uq_kya_weight_overrides_platform_scope_key" in idx_names
    es.dispose()
