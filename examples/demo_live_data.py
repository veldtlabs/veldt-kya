"""Live data demo — populates real SQLite + DuckDB files and reads them
back via raw SQL to prove KYA's persistence works end-to-end on both
backends with `init_storage()`.

Run:
    pip install veldt-kya[all] duckdb duckdb-engine pytz
    python demo_live_data.py
"""

import os

import duckdb
from kya import init_storage, rollback_to, snapshot_agent
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

SEP = "=" * 70


def banner(title):
    print()
    print(SEP)
    print(f"  {title}")
    print(SEP)


def demo_sqlite():
    banner("SQLite backend — file on disk")
    db_path = "/tmp/kya_demo.sqlite"
    if os.path.exists(db_path):
        os.remove(db_path)

    engine = create_engine(f"sqlite:///{db_path}")
    Session = sessionmaker(bind=engine)

    with Session() as db:
        report = init_storage(db)
        print(f"  dialect    : {report['dialect']}")
        print(f"  succeeded  : {report['succeeded']}")
        print(f"  skipped    : {len(report['skipped'])} (PG-only DDL, expected)")

        print()
        print("  Tables actually created:")
        insp = inspect(engine)
        for t in insp.get_table_names():
            cols = [c["name"] for c in insp.get_columns(t)]
            print(f"    {t}: {cols}")

        print()
        print("  Populating 3 agent versions + rollback...")
        snapshot_agent(
            db,
            "tenant_alpha",
            "fraud_detector",
            {"tools": ["search_records"]},
            created_by="alice",
            note="v1: minimal",
        )
        snapshot_agent(
            db,
            "tenant_alpha",
            "fraud_detector",
            {"tools": ["search_records", "send_alert"]},
            created_by="alice",
            note="v2: added alerting",
        )
        snapshot_agent(
            db,
            "tenant_alpha",
            "fraud_detector",
            {"tools": ["search_records", "send_alert", "freeze_account"]},
            created_by="bob",
            note="v3: ESCALATION RISK",
        )
        rolled = rollback_to(db, "tenant_alpha", "fraud_detector", version_no=1, created_by="alice")
        print(f"  Rolled back to v1, produced v{rolled['version_no']}")

    print()
    file_size = os.path.getsize(db_path)
    print(f"  /tmp/kya_demo.sqlite = {file_size} bytes on disk (persisted)")
    print()
    print("  RAW ROWS (plain SQL, not ORM):")

    engine2 = create_engine(f"sqlite:///{db_path}")
    with engine2.connect() as conn:
        rows = conn.execute(
            text("""
                SELECT version_no, agent_key, tenant_id, note, created_by,
                       json_extract(definition, '$.tools') AS tools, created_at
                FROM agent_versions
                ORDER BY version_no
            """)
        ).fetchall()
        header = f"  {'v#':3s} {'agent_key':18s} {'tenant':15s} {'by':6s} {'note':28s} tools"
        print(header)
        print(f"  {'-' * (len(header) - 2)}")
        for r in rows:
            v, ak, tid, note, by, tools, _ts = r
            print(f"  {v:<3d} {ak:18s} {tid:15s} {by:6s} {note:28s} {tools}")


def demo_duckdb():
    banner("DuckDB backend — file on disk")
    db_path = "/tmp/kya_demo.duckdb"
    if os.path.exists(db_path):
        os.remove(db_path)

    engine = create_engine(f"duckdb:///{db_path}")
    Session = sessionmaker(bind=engine)

    with Session() as db:
        report = init_storage(db)
        print(f"  dialect    : {report['dialect']}")
        print(f"  succeeded  : {report['succeeded']}")
        print(f"  skipped    : {len(report['skipped'])}")

        print()
        print("  Populating real data through KYA SDK...")
        snapshot_agent(
            db,
            "tenant_beta",
            "claims_triager",
            {"tools": ["search_policy"]},
            created_by="carol",
            note="v1: read-only",
        )
        snapshot_agent(
            db,
            "tenant_beta",
            "claims_triager",
            {"tools": ["search_policy", "approve_claim"]},
            created_by="dave",
            note="v2: ADDED WRITE",
        )
        snapshot_agent(
            db,
            "tenant_beta",
            "claims_triager",
            {"tools": ["search_policy", "approve_claim", "issue_payment"]},
            created_by="dave",
            note="v3: payment authority",
        )

    # Release the SQLA pool so the raw duckdb cli can attach below
    engine.dispose()

    # Verify via raw duckdb (proves data is real, not ORM-cached)
    file_size = os.path.getsize(db_path)
    print()
    print(f"  /tmp/kya_demo.duckdb = {file_size} bytes on disk (persisted)")
    print()
    print("  RAW ROWS via duckdb-cli library (not SQLA):")
    conn = duckdb.connect(db_path, read_only=True)
    rows = conn.execute("""
        SELECT version_no, agent_key, tenant_id, created_by, note,
               definition->>'$.tools' AS tools
        FROM agent_versions
        ORDER BY version_no
    """).fetchall()
    header = f"  {'v#':3s} {'agent_key':18s} {'tenant':14s} {'by':6s} {'note':22s} tools"
    print(header)
    print(f"  {'-' * (len(header) - 2)}")
    for r in rows:
        v, ak, tid, by, note, tools = r
        print(f"  {v:<3d} {ak:18s} {tid:14s} {by:6s} {note:22s} {tools}")
    conn.close()


if __name__ == "__main__":
    demo_sqlite()
    demo_duckdb()
    banner("Both backends populated + queried via raw SQL — data is real")
