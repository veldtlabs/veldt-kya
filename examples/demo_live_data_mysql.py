"""Live data demo against MySQL — proves the ORM-modeled versioning table
works on MySQL 8.0+ and that data is queryable via raw MySQL.

Run with KYA_TEST_MYSQL_URL pointing at a running MySQL, e.g.:

    docker run -d --name kya-mysql -p 3306:3306 \\
        -e MYSQL_ROOT_PASSWORD=test \\
        -e MYSQL_DATABASE=kya_test \\
        mysql:8.0
    pip install veldt-kya[all] pymysql cryptography
    KYA_TEST_MYSQL_URL=mysql+pymysql://root:test@localhost:3306/kya_test \\
        python demo_live_data_mysql.py
"""

import os

import pymysql
from kya import init_storage, rollback_to, snapshot_agent
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker


def main():
    url = os.environ["KYA_TEST_MYSQL_URL"]
    print("=" * 70)
    print("  MySQL backend — live data demo")
    print(f"  URL: {url}")
    print("=" * 70)

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    with Session() as db:
        # Idempotent — drop pre-existing rows so the demo is reproducible
        from sqlalchemy import text

        db.execute(text("DROP TABLE IF EXISTS agent_versions"))
        db.commit()

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
            "tenant_gamma",
            "loan_underwriter",
            {"tools": ["pull_credit_report"]},
            created_by="eve",
            note="v1: credit pull only",
        )
        snapshot_agent(
            db,
            "tenant_gamma",
            "loan_underwriter",
            {"tools": ["pull_credit_report", "compute_dti"]},
            created_by="eve",
            note="v2: added DTI calc",
        )
        snapshot_agent(
            db,
            "tenant_gamma",
            "loan_underwriter",
            {"tools": ["pull_credit_report", "compute_dti", "approve_loan"]},
            created_by="frank",
            note="v3: APPROVAL AUTHORITY",
        )
        rolled = rollback_to(db, "tenant_gamma", "loan_underwriter", version_no=1, created_by="eve")
        print(f"  Rolled back to v1, produced v{rolled['version_no']}")

    engine.dispose()

    # Read back via raw pymysql (proves data is real, not ORM-cached)
    print()
    print("  RAW ROWS via pymysql (not SQLA):")
    # Parse URL to get connection params
    from urllib.parse import urlparse

    parsed = urlparse(url.replace("mysql+pymysql://", "mysql://"))
    conn = pymysql.connect(
        host=parsed.hostname,
        port=parsed.port or 3306,
        user=parsed.username,
        password=parsed.password,
        database=parsed.path.lstrip("/"),
    )
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT version_no, agent_key, tenant_id, created_by, note,
                   JSON_EXTRACT(definition, '$.tools') AS tools, created_at
            FROM agent_versions
            ORDER BY version_no
        """)
        rows = cur.fetchall()
        header = f"  {'v#':3s} {'agent_key':18s} {'tenant':15s} {'by':7s} {'note':30s} tools"
        print(header)
        print(f"  {'-' * (len(header) - 2)}")
        for r in rows:
            v, ak, tid, by, note, tools, _ts = r
            print(f"  {v:<3d} {ak:18s} {tid:15s} {by:7s} {note:30s} {tools}")
    finally:
        conn.close()

    print()
    print("=" * 70)
    print("  MySQL backend populated + queried via raw SQL — data is real")
    print("=" * 70)


if __name__ == "__main__":
    main()
