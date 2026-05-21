"""Live demo: KYP (Know Your Principal) trust scoring + signal merge +
event-time on SQLite + DuckDB + MySQL.

Shows the upsert path (signal_counts JSON merge across multiple writes),
trust score arithmetic, and raw SQL inspection of the resulting row.

Run:
    pip install veldt-kya[all] duckdb duckdb-engine pytz
    python demo_principals.py
"""

import os
from datetime import datetime, timedelta, timezone

from kya import (
    get_principal_trust,
    list_principals,
    record_principal_clean,
    record_principal_signal,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

SEP = "=" * 78


def banner(t):
    print()
    print(SEP)
    print(f"  {t}")
    print(SEP)


def demo(label: str, url: str):
    banner(f"{label} backend — KYP trust scoring + signal merge")

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    # Scope cleanup
    with Session() as db:
        from kya import ensure_principal_table

        ensure_principal_table(db)
        db.execute(
            text("DELETE FROM kya_principal_trust WHERE tenant_id = :t"), {"t": f"t_{label}"}
        )
        db.commit()

    now = datetime.now(timezone.utc)

    with Session() as db:
        print("  Recording signals against agent 'data_exfil':")
        s1 = record_principal_signal(
            db,
            tenant_id=f"t_{label}",
            principal_kind="agent",
            principal_id="data_exfil",
            signal_kind="oos_tool",
            occurred_at=now - timedelta(minutes=10),
            attributes={"team": "ops", "origin": "us-east"},
        )
        print(f"    +oos_tool (10 min ago)              -> trust={s1}")

        s2 = record_principal_signal(
            db,
            tenant_id=f"t_{label}",
            principal_kind="agent",
            principal_id="data_exfil",
            signal_kind="data_leak",
            occurred_at=now - timedelta(minutes=2),
            attributes={"sensitivity": "pii"},  # merges with prior attrs
        )
        print(f"    +data_leak (2 min ago)              -> trust={s2}")

        s3 = record_principal_signal(
            db,
            tenant_id=f"t_{label}",
            principal_kind="agent",
            principal_id="data_exfil",
            signal_kind="cross_tenant",
            occurred_at=now,
        )
        print(f"    +cross_tenant (just now)            -> trust={s3}")

        # Compare with a well-behaved principal
        record_principal_clean(
            db,
            tenant_id=f"t_{label}",
            principal_kind="user",
            principal_id="alice@acme",
        )
        c2 = record_principal_clean(
            db,
            tenant_id=f"t_{label}",
            principal_kind="user",
            principal_id="alice@acme",
        )
        print(f"    user alice@acme: 2 clean events     -> trust={c2}")

    print()
    print("  Fetching trust dossier for data_exfil:")
    with Session() as db:
        trust = get_principal_trust(
            db,
            tenant_id=f"t_{label}",
            principal_kind="agent",
            principal_id="data_exfil",
        )
    print(f"    trust_score    : {trust.trust_score}")
    print(f"    bucket         : {trust.bucket}")
    print(f"    signal_counts  : {trust.signal_counts}  (3 distinct kinds merged)")
    print(f"    attributes     : {trust.attributes}  (multi-write merge)")
    print(f"    last_signal_at : {trust.last_signal_at}  (event-time, not insert-time)")

    print()
    print("  Tenant rollup — riskiest first:")
    with Session() as db:
        rows = list_principals(db, tenant_id=f"t_{label}")
    print(f"    {'principal':25s}  {'kind':18s}  {'score':>6s}  {'bucket':10s}  signal_counts")
    print(f"    {'-' * 90}")
    for r in rows:
        sigs = ",".join(f"{k}={v}" for k, v in r["signal_counts"].items())
        print(
            f"    {r['principal_id']:25s}  {r['principal_kind']:18s}  "
            f"{r['trust_score']:>6d}  {r['bucket']:10s}  {sigs}"
        )


def main():
    demo("sqlite", "sqlite:///:memory:")
    try:
        import duckdb_engine  # noqa: F401

        demo("duckdb", "duckdb:///:memory:")
    except ImportError:
        print("(duckdb-engine not installed — skipping DuckDB demo)")

    mysql_url = os.environ.get("KYA_TEST_MYSQL_URL")
    if mysql_url:
        demo("mysql", mysql_url)
    else:
        print("(KYA_TEST_MYSQL_URL not set — skipping MySQL demo)")

    banner("Principal trust + signal merge + event-time on all 3 backends")


if __name__ == "__main__":
    main()
