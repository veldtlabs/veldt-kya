"""Live demo of event-time vs ingest-time forensics on kya_invocations.

Simulates pipeline lag (an event that "happened" 30s ago and only now lands
in KYA), then dumps the raw rows so you see both timestamps + the computed
ingest-lag in milliseconds.

Run:
    pip install veldt-kya[all] duckdb duckdb-engine pytz
    python demo_event_vs_ingest_time.py
"""

import os
from datetime import datetime, timedelta, timezone

from kya import (
    ingest_lag_stats,
    list_invocations,
    new_correlation_id,
    record_invocation,
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
    banner(f"{label} backend — event-time vs ingest-time")

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    cid = new_correlation_id()
    now = datetime.now(timezone.utc)

    # Three invocations across simulated pipeline lags
    scenarios = [
        (now - timedelta(seconds=120), "hybrid", "success", "v old (2-min lag)"),
        (now - timedelta(seconds=12), "autonomous", "success", "moderate lag"),
        (now - timedelta(milliseconds=50), "autonomous", "blocked", "near-real-time"),
    ]

    with Session() as db:
        for occ, mode, outcome, note in scenarios:
            record_invocation(
                db,
                tenant_id=f"t_{label}",
                agent_key="claims_agent",
                mode=mode,
                outcome=outcome,
                occurred_at=occ,
                correlation_id=cid,
                principal_id=note,  # using principal_id to label the scenario
            )

    with Session() as db:
        rows = list_invocations(db, tenant_id=f"t_{label}", correlation_id=cid)
        stats = ingest_lag_stats(
            db, tenant_id=f"t_{label}", agent_key="claims_agent", window_days=1
        )

    print(f"  rows recorded: {len(rows)}")
    print()
    print(
        f"  {'id':4s} {'mode':12s} {'outcome':9s} "
        f"{'occurred_at':28s} {'ingested_at':28s} {'lag_ms':>10s}"
    )
    print(f"  {'-' * 96}")
    for r in rows:
        occ = r["occurred_at"][:26]
        ing = r["ingested_at"][:26]
        print(
            f"  {r['id']:<4d} {r['mode']:12s} {r['outcome']:9s} "
            f"{occ:28s} {ing:28s} {r['ingest_lag_ms']:>10d}"
        )

    print()
    print("  Ingest-lag rollup (last 1 day):")
    print(f"    samples : {stats['samples']}")
    print(f"    p50_ms  : {stats['p50_ms']:>10,}")
    print(f"    p95_ms  : {stats['p95_ms']:>10,}")
    print(f"    p99_ms  : {stats['p99_ms']:>10,}")
    print(f"    max_ms  : {stats['max_ms']:>10,}")
    print()
    print("  Interpretation:")
    print("    occurred_at = caller's wall-clock when the event happened")
    print("    ingested_at = KYA server clock at INSERT")
    print("    lag = pipeline delay; a sudden spike = pipeline lag, clock skew,")
    print("          or — combined with OTel span correlation — tampering signal.")


def cleanup_sqlite():
    p = "/tmp/kya_invocations_demo.sqlite"
    if os.path.exists(p):
        os.remove(p)
    return f"sqlite:///{p}"


def cleanup_duckdb():
    p = "/tmp/kya_invocations_demo.duckdb"
    if os.path.exists(p):
        os.remove(p)
    return f"duckdb:///{p}"


if __name__ == "__main__":
    demo("sqlite", cleanup_sqlite())
    try:
        import duckdb_engine  # noqa: F401

        demo("duckdb", cleanup_duckdb())
    except ImportError:
        print("(duckdb-engine not installed — skipping DuckDB demo)")

    mysql_url = os.environ.get("KYA_TEST_MYSQL_URL")
    if mysql_url:
        # Scope-clean MySQL since it's persistent
        engine = create_engine(mysql_url)
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM kya_invocations WHERE tenant_id = 't_mysql'"))
        engine.dispose()
        demo("mysql", mysql_url)
    else:
        print("(KYA_TEST_MYSQL_URL not set — skipping MySQL demo)")

    banner("event-time vs ingest-time forensics demonstrated end-to-end")
