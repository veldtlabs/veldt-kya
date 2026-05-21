"""Validation: all 12 newly-migrated legacy tables × 4 backends.

For each backend (SQLite, DuckDB, MySQL, PostgreSQL), verifies:
  - All 12 tables CREATE successfully via the shared _LEGACY_MD.create_all
  - Catalog inspection confirms each table exists
"""

import os
import sys
import types

import pytest
from sqlalchemy import create_engine, inspect, text


def _stub_parents():
    """Stub the agents.* package init so side-loading _legacy_tables.py
    doesn't drag in fastapi/redis/etc."""
    for pkg in ("agents", "kya"):
        if pkg not in sys.modules:
            mod = types.ModuleType(pkg)
            mod.__path__ = []
            sys.modules[pkg] = mod


def _load_legacy_tables(dialect_name: str):
    """Side-load _portable and _legacy_tables fresh each backend."""
    if dialect_name == "postgresql":
        os.environ["KYA_VERSIONS_SCHEMA"] = "prov_schema"
    else:
        os.environ["KYA_VERSIONS_SCHEMA"] = ""

    sys.path.insert(0, "/repo/app")
    _stub_parents()

    # Force fresh load every call
    for k in ("kya._portable", "kya._legacy_tables"):
        sys.modules.pop(k, None)

    import importlib.util

    def _load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod

    _load("kya._portable", "/repo/app/agents/kya/_portable.py")
    legacy = _load(
        "kya._legacy_tables", "/repo/app/agents/kya/_legacy_tables.py"
    )
    return legacy


_TABLE_NAMES = [
    "kya_agent_aliases",
    "kya_user_trust",
    "kya_weight_overrides",
    "kya_weight_changes",
    "kya_weight_suggestions",
    "kya_breach_notifications",
    "kya_redteam_campaigns",
    "kya_redteam_findings",
    "kya_redteam_tenant_policy",
    "kya_redteam_runs",
    "kya_redteam_targets",
    "kya_redteam_target_secrets",
]


def _verify(url: str, dialect_name: str) -> dict:
    legacy = _load_legacy_tables(dialect_name)
    engine = create_engine(url)

    # Drop any leftovers (for persistent backends)
    schema = "prov_schema" if dialect_name == "postgresql" else None
    with engine.begin() as conn:
        if dialect_name == "postgresql":
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        for t in _TABLE_NAMES:
            try:
                if schema:
                    conn.execute(text(f"DROP TABLE IF EXISTS {schema}.{t} CASCADE"))
                else:
                    conn.execute(text(f"DROP TABLE IF EXISTS {t}"))
            except Exception:
                pass

    # Batch create_all on every legacy table
    legacy._LEGACY_MD.create_all(bind=engine, tables=legacy.ALL_LEGACY_TABLES)

    # Inspect
    insp = inspect(engine)
    present = set(insp.get_table_names(schema=schema))
    missing = [t for t in _TABLE_NAMES if t not in present]
    return {"dialect": dialect_name, "missing": missing, "present_count": len(present)}


def _assert_all_present(report: dict) -> None:
    assert not report["missing"], (
        f"[{report['dialect']}] missing tables: {report['missing']}"
    )


def test_legacy_tables_sqlite():
    _assert_all_present(_verify("sqlite:///:memory:", "sqlite"))


def test_legacy_tables_duckdb():
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        pytest.skip("duckdb-engine not installed")
    _assert_all_present(_verify("duckdb:///:memory:", "duckdb"))


def test_legacy_tables_mysql():
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        pytest.skip("KYA_TEST_MYSQL_URL not set")
    _assert_all_present(_verify(url, "mysql"))


def test_legacy_tables_postgres():
    url = os.environ.get("KYA_TEST_PG_URL")
    if not url:
        pytest.skip("KYA_TEST_PG_URL not set")
    _assert_all_present(_verify(url, "postgresql"))
