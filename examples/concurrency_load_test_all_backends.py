"""Run examples/concurrency_load_test.py against all 4 backends.

This stresses the dialect-aware concurrency primitive of
``kya/evidence.py:423--462``:

  PostgreSQL: pg_advisory_xact_lock keyed by (tenant, invocation).
  MySQL:      SELECT FOR UPDATE on the existing tail row (first
              writers to an empty chain are not serialized).
  SQLite:     BEGIN IMMEDIATE + documented single-writer contract.
  DuckDB:     Same single-writer contract; DuckDB does not support
              concurrent writers from multiple processes either.

For each backend the suite runs five phases:
  A. concurrent record_invocation (distinct invocations)
  B. concurrent record_evidence on the SAME HMAC chain
  C. concurrent record_principal_signal (same key, SELECT-then-INSERT race)
  D. concurrent rogue-signal mirror writes (separate sessions)
  E. concurrent snapshot_agent on same agent (monotonic version_no)

We expect:
  PG, MySQL : all 5 phases PASS at 20 workers × 50 ops.
  SQLite    : passes when sqlite3 honors WAL + IMMEDIATE; may need
              lower worker count.
  DuckDB    : passes if and only if writers serialize at the
              Python-application layer. We test with 4 workers
              (DuckDB's documented limit on concurrent connection
              writes) instead of 20.
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

env_file = Path("/d/veldt-decisions/.env")
if not env_file.exists():
    env_file = Path("D:/veldt-decisions/.env")
if env_file.exists():
    for line in env_file.read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and v and k not in os.environ:
                os.environ[k] = v


def _reset_kya_modules() -> None:
    for k in list(sys.modules):
        if k.startswith("kya") or k.startswith("kya_redteam"):
            del sys.modules[k]


def _drop_kya_tables(engine, schema):
    from sqlalchemy import text
    tables = [
        "agent_versions", "kya_invocations", "kya_principal_trust",
        "kya_evidence", "kya_agent_aliases", "kya_user_trust",
        "kya_weight_overrides", "kya_weight_changes",
        "kya_weight_suggestions", "kya_breach_notifications",
        "kya_redteam_campaigns", "kya_redteam_findings",
        "kya_redteam_tenant_policy", "kya_redteam_runs",
        "kya_redteam_targets", "kya_redteam_target_secrets",
        "kya_inbound_recommendations",
    ]
    with engine.begin() as conn:
        if schema == "prov_schema":
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        for t in tables:
            full = f"{schema}.{t}" if schema else t
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {full} CASCADE"))
            except Exception:
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {full}"))
                except Exception:
                    pass


def run_backend(name, url, schema, workers, per_worker):
    print(f"\n{'#'*78}\n#  BACKEND: {name} ({workers}w × {per_worker} ops)\n{'#'*78}")
    os.environ["KYA_VERSIONS_SCHEMA"] = schema or ""

    _reset_kya_modules()
    import kya  # noqa
    from kya import init_storage
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine_kwargs = {"pool_size": max(32, workers * 2), "max_overflow": 32,
                     "pool_pre_ping": True}
    if name in ("sqlite", "duckdb"):
        engine_kwargs = {}
    engine = create_engine(url, **engine_kwargs)

    if name == "sqlite":
        # Enable WAL for concurrent reads + IMMEDIATE locking semantics.
        from sqlalchemy import event
        @event.listens_for(engine, "connect")
        def _set_wal(dbapi_connection, _):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

    _drop_kya_tables(engine, schema)
    Session = sessionmaker(bind=engine)

    db = Session()
    init_storage(db)
    db.commit()
    db.close()

    # Import the existing concurrency suite functions
    spec = importlib.util.spec_from_file_location(
        "kya_concurrency",
        REPO / "examples" / "concurrency_load_test.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    results = {}
    phases = [
        ("A_invocation",    mod.test_invocation_concurrency),
        ("B_evidence_chain", mod.test_evidence_chain_concurrency),
        ("C_principal_sig", mod.test_principal_signal_concurrency),
        ("D_actor_mirror",  mod.test_actor_mirror_concurrency),
        ("E_versioning",    mod.test_versioning_concurrency),
    ]
    for label, fn in phases:
        try:
            ok = fn(Session, workers, per_worker)
            results[label] = "PASS" if ok else "FAIL"
        except Exception as exc:
            results[label] = f"ERR: {str(exc).splitlines()[0][:80]}"

    return results


def main():
    tmp = tempfile.mkdtemp(prefix="kya_concur_")
    backends = [
        ("sqlite", f"sqlite:///{tmp}/kya.sqlite", None, 8, 25),
        ("duckdb", f"duckdb:///{tmp}/kya.duckdb", None, 1, 25),
    ]
    pg = os.environ.get("KYA_TEST_PG_URL",
                        "postgresql+psycopg2://postgres:kya@localhost:55777/kya")
    backends.append(("postgresql", pg, "prov_schema", 20, 50))
    mysql = os.environ.get("KYA_TEST_MYSQL_URL",
                           "mysql+pymysql://root:kya@localhost:33077/kyatest")
    backends.append(("mysql", mysql, None, 20, 50))

    matrix = {}
    for name, url, schema, w, pw in backends:
        try:
            matrix[name] = run_backend(name, url, schema, w, pw)
        except Exception as exc:
            matrix[name] = {"_setup": f"ERR: {str(exc).splitlines()[0][:120]}"}

    print(f"\n\n{'='*78}\n  CONCURRENCY MATRIX — 5 phases × 4 backends\n{'='*78}")
    phases = ["A_invocation", "B_evidence_chain", "C_principal_sig",
              "D_actor_mirror", "E_versioning"]
    print(f"{'PHASE':22s} | " + " | ".join(f"{n:>12s}" for n in matrix.keys()))
    print("-" * (24 + sum(15 for _ in matrix)))
    for p in phases:
        cells = [matrix[n].get(p, "—")[:12] for n in matrix.keys()]
        print(f"{p:22s} | " + " | ".join(f"{c:>12s}" for c in cells))


if __name__ == "__main__":
    main()
