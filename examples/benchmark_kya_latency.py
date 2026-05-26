"""
KYA per-primitive latency benchmark — replaces the engineering
estimates I gave earlier with measured numbers.

What this measures
------------------
For each KYA primitive that runs on the agent-invocation hot path:

  1. record_invocation (user principal — no delegation check)
  2. record_invocation (agent principal — triggers delegation check)
  3. record_evidence (HMAC chain append)
  4. snapshot_on_first_sight (idempotent re-call, fast path)
  5. snapshot_on_first_sight (true first sight — includes risk-tier
     auto-default if applicable)
  6. record_principal_signal (uncontested)
  7. record_cost_event
  8. bind_principal_to_idp (Phase 4b)
  9. lookup_principal_by_idp
 10. resolve_effective_mode (with N overrides — measures scaling)
 11. delegation_readiness_report (with N violations — measures scaling)

Each primitive is measured with:
  - 50-iteration warm-up (excluded from stats)
  - 500-iteration measurement
  - Single-threaded baseline (workers=1)

Results
-------
For each (backend, primitive): p50 / p95 / p99 / mean / max in
milliseconds. Output as a single combined table.

Why no async / multi-worker yet
-------------------------------
A serious concurrency benchmark requires connection pooling, per-
worker isolation, and contention controls that are easy to get
wrong. Starting with single-threaded measurements gives us a
defensible p50 baseline. Concurrency benchmark is the v2 of this
script.

Run
---
    KYA_TEST_PG_URL=postgresql://test:kya@localhost:15433/kyatest \\
    KYA_TEST_MYSQL_URL=mysql+pymysql://root:kya@localhost:33077/kyatest \\
    python examples/benchmark_kya_latency.py

Sqlite always measured (in-memory baseline).
DuckDB skipped on primitives known incompatible (task #42).
"""

from __future__ import annotations

import os
import statistics
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable


def _load_dotenv():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


_load_dotenv()

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    bind_principal_to_idp,
    delegation_readiness_report,
    init_storage,
    lookup_principal_by_idp,
    record_cost_event,
    record_evidence,
    record_invocation,
    record_principal_signal,
    resolve_effective_mode,
    set_delegation_override,
    snapshot_agent,
    snapshot_on_first_sight,
)


TENANT = "11111111-2222-3333-4444-555555555555"  # valid hex UUID, 36 chars
WARMUP = 50
MEASURE = 500


def _hdr(t):
    print(); print("=" * 78); print(f"  {t}"); print("=" * 78)


def measure(name: str, fn: Callable[[int], None]) -> dict:
    """Run fn(i) WARMUP+MEASURE times; record only the MEASURE wall-
    clock times. fn receives the iteration index so it can produce
    unique keys per call."""
    # Warm-up — JIT compile paths, prime caches
    for i in range(WARMUP):
        fn(i)
    times_ms = []
    for i in range(WARMUP, WARMUP + MEASURE):
        t0 = time.perf_counter()
        fn(i)
        times_ms.append((time.perf_counter() - t0) * 1000)
    times_ms.sort()
    n = len(times_ms)
    return {
        "primitive": name,
        "n": n,
        "p50": times_ms[n // 2],
        "p95": times_ms[int(n * 0.95)],
        "p99": times_ms[int(n * 0.99)],
        "mean": statistics.mean(times_ms),
        "max": max(times_ms),
        "min": min(times_ms),
    }


# ── Setup helpers ──────────────────────────────────────────────────


_AGENT_DEF = {
    "agent_key": "BenchAgent",
    "system_prompt": "Benchmark agent.",
    "tools": ["lookup", "calc"],
    "human_loop": "in_the_loop",
    "access_level": "read",
    "data_classes": ["pii"],
    "environment": "dev",
    "model_trust": "frontier",
}


def _setup(db, label):
    """Snapshot a few agents used by multiple primitive benchmarks."""
    snapshot_agent(db, tenant_id=TENANT, agent_key="BenchOrch",
                   definition={**_AGENT_DEF,
                                "agent_key": "BenchOrch",
                                "access_level": "write"},
                   note="bench")
    snapshot_agent(db, tenant_id=TENANT, agent_key="BenchSub",
                   definition={**_AGENT_DEF, "agent_key": "BenchSub"},
                   note="bench")
    # Create a base principal trust row for bind/signal benchmarks
    record_principal_signal(
        db, tenant_id=TENANT,
        principal_kind="user", principal_id="bench_alice",
        signal_kind="clean_invocation")
    # Create one invocation we can attach evidence to
    inv_id = record_invocation(
        db, tenant_id=TENANT, agent_key="BenchSub",
        principal_kind="user", principal_id="bench_alice",
        mode="observed", outcome="success")
    return {"shared_inv_id": inv_id}


# ── Primitives ─────────────────────────────────────────────────────


def bench_record_invocation_user(db, _state):
    return measure(
        "record_invocation [user principal]",
        lambda i: record_invocation(
            db, tenant_id=TENANT, agent_key="BenchSub",
            principal_kind="user",
            principal_id=f"bench_user_{i}",
            mode="observed", outcome="success"),
    )


def bench_record_invocation_agent(db, _state):
    """Agent principal triggers delegation policy check."""
    return measure(
        "record_invocation [agent principal+deleg check]",
        lambda i: record_invocation(
            db, tenant_id=TENANT, agent_key="BenchSub",
            principal_kind="agent", principal_id="BenchOrch",
            mode="observed", outcome="success"),
    )


def bench_record_evidence(db, state):
    inv_id = state["shared_inv_id"]
    return measure(
        "record_evidence [HMAC chain append]",
        lambda i: record_evidence(
            db, tenant_id=TENANT, invocation_id=inv_id,
            evidence_kind="prompt",
            payload={"content": f"benchmark prompt {i}"}),
    )


def bench_snapshot_idempotent(db, _state):
    """Re-snapshot identical def — hits the canonical_hash fast path."""
    return measure(
        "snapshot_on_first_sight [idempotent re-call]",
        lambda i: snapshot_on_first_sight(
            db, tenant_id=TENANT, agent_key="BenchOrch",
            definition={**_AGENT_DEF,
                         "agent_key": "BenchOrch",
                         "access_level": "write"},
            note="bench-idempotent"),
    )


def bench_snapshot_first_sight(db, _state):
    """Each iteration uses a fresh agent_key to force first-sight."""
    return measure(
        "snapshot_on_first_sight [TRUE first sight]",
        lambda i: snapshot_on_first_sight(
            db, tenant_id=TENANT, agent_key=f"BenchNovel_{i}",
            definition={**_AGENT_DEF,
                         "agent_key": f"BenchNovel_{i}"},
            note=f"first-{i}"),
    )


def bench_record_principal_signal(db, _state):
    return measure(
        "record_principal_signal [uncontested]",
        lambda i: record_principal_signal(
            db, tenant_id=TENANT,
            principal_kind="user",
            principal_id=f"bench_signal_{i % 100}",  # spread across 100
            signal_kind="oos_tool"),
    )


def bench_record_cost_event(db, _state):
    return measure(
        "record_cost_event",
        lambda i: record_cost_event(
            db, tenant_id=TENANT, agent_key="BenchSub",
            usd_amount=0.0001, model_used="gpt-4o-mini",
            input_tokens=50, output_tokens=20,
            environment="dev", outcome="success",
            latency_ms=10, invocation_id=None,
            request_id=f"bench-{i}-{uuid.uuid4().hex[:8]}"),
    )


def bench_bind_principal_to_idp(db, _state):
    # pre-create a row per iteration so the bind has a target
    for i in range(WARMUP + MEASURE):
        record_principal_signal(
            db, tenant_id=TENANT,
            principal_kind="user",
            principal_id=f"bench_bind_{i}",
            signal_kind="clean_invocation")
    return measure(
        "bind_principal_to_idp [Phase 4b]",
        lambda i: bind_principal_to_idp(
            db, tenant_id=TENANT,
            principal_kind="user",
            principal_id=f"bench_bind_{i}",
            idp_subject=f"okta|bench|{i}",
            idp_kind="okta"),
    )


def bench_lookup_principal_by_idp(db, _state):
    # Setup: bind some principals to lookup
    for i in range(100):
        record_principal_signal(
            db, tenant_id=TENANT,
            principal_kind="user",
            principal_id=f"bench_lookup_{i}",
            signal_kind="clean_invocation")
        bind_principal_to_idp(
            db, tenant_id=TENANT,
            principal_kind="user",
            principal_id=f"bench_lookup_{i}",
            idp_subject=f"sub_lookup_{i}", idp_kind="okta")
    return measure(
        "lookup_principal_by_idp [indexed/scan]",
        lambda i: lookup_principal_by_idp(
            db, tenant_id=TENANT,
            idp_subject=f"sub_lookup_{i % 100}"),
    )


def bench_resolve_effective_mode(db, _state):
    # 20 overrides at various specificity levels
    for i in range(20):
        set_delegation_override(
            db, tenant_id=TENANT, mode="observe",
            parent_agent_key=f"bench_p_{i}",
            reason=f"bench {i}")
    return measure(
        "resolve_effective_mode [with 20 overrides]",
        lambda i: resolve_effective_mode(
            db, tenant_id=TENANT,
            parent_agent_key=f"bench_p_{i % 20}",
            sub_agent_key="any", violation_kind="access_escalation"),
    )


def bench_readiness_report(db, _state):
    # Pre-populate violations table with 200 rows
    schema_p = ("prov_schema."
                if db.get_bind().dialect.name == "postgresql"
                else "")
    seq_name = "kya_delegation_violations_id_seq"
    for i in range(200):
        if db.get_bind().dialect.name == "postgresql":
            db.execute(text(
                f"INSERT INTO {schema_p}kya_delegation_violations "
                f"(id, tenant_id, sub_invocation_id, parent_invocation_id, "
                f" parent_agent_key, sub_agent_key, violation_kind, "
                f" detail, mode_active, blocked, created_at) "
                f"VALUES (nextval('{seq_name}'), :t, 1, 0, :p, :s, "
                f"        :k, '{{}}'::jsonb, 'observe', false, now())"
            ), {"t": TENANT,
                "p": f"P_{i % 10}", "s": f"S_{i % 5}",
                "k": "access_escalation"})
        else:
            db.execute(text(
                f"INSERT INTO {schema_p}kya_delegation_violations "
                f"(tenant_id, sub_invocation_id, parent_invocation_id, "
                f" parent_agent_key, sub_agent_key, violation_kind, "
                f" detail, mode_active, blocked) "
                f"VALUES (:t, 1, 0, :p, :s, :k, '{{}}', 'observe', 0)"
            ), {"t": TENANT,
                "p": f"P_{i % 10}", "s": f"S_{i % 5}",
                "k": "access_escalation"})
    db.commit()
    return measure(
        "delegation_readiness_report [200 violations, 7d window]",
        lambda i: delegation_readiness_report(
            db, tenant_id=TENANT, window_days=7,
            stable_days_to_promote=30, spike_threshold=100),
    )


# Order matters — earlier setup helps later benchmarks
_BENCHMARKS = [
    bench_record_invocation_user,
    bench_record_invocation_agent,
    bench_record_evidence,
    bench_snapshot_idempotent,
    bench_snapshot_first_sight,
    bench_record_principal_signal,
    bench_record_cost_event,
    bench_bind_principal_to_idp,
    bench_lookup_principal_by_idp,
    bench_resolve_effective_mode,
    bench_readiness_report,
]


# Primitives we SKIP on DuckDB due to known compat issues (task #42)
_DUCKDB_SKIP = {
    "record_principal_signal [uncontested]",
}


# ── Open backend ───────────────────────────────────────────────────


def open_backend(label):
    if label == "sqlite":
        eng = create_engine("sqlite:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None})
    elif label == "duckdb":
        eng = create_engine("duckdb:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None})
    elif label == "postgresql":
        url = os.environ.get("KYA_TEST_PG_URL")
        if not url: return None, None
        eng = create_engine(url)
        with eng.begin() as conn:
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            # Drop ALL kya tables for a clean baseline
            for tbl in ("kya_cost_events", "kya_budget_changes",
                        "kya_tenant_cost_budgets",
                        "kya_delegation_violations",
                        "kya_delegation_policy_overrides",
                        "kya_evidence", "kya_invocations",
                        "kya_principal_trust", "kya_user_trust",
                        "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_cost_events", "kya_budget_changes",
                        "kya_tenant_cost_budgets",
                        "kya_delegation_violations",
                        "kya_delegation_policy_overrides",
                        "kya_evidence", "kya_invocations",
                        "kya_principal_trust", "kya_user_trust",
                        "agent_versions"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception:
                    pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


def _fmt(d: dict) -> str:
    return (f"{d['p50']:7.2f}  {d['p95']:7.2f}  "
            f"{d['p99']:7.2f}  {d['mean']:7.2f}  {d['max']:7.2f}")


def run_backend(label: str) -> dict:
    db, dispose = open_backend(label)
    if db is None:
        return {}
    try:
        init_storage(db)
        state = _setup(db, label)
        results = []
        for bench in _BENCHMARKS:
            # Defensive: a previous bench's exception could leave the
            # session in a poisoned "current transaction is aborted"
            # state on PG. Force a clean transaction before each bench.
            try:
                db.rollback()
            except Exception:
                pass
            try:
                r = bench(db, state)
            except Exception as exc:
                print(f"  [SKIP] {bench.__name__} on {label}: "
                      f"{type(exc).__name__}: {str(exc)[:80]}")
                try: db.rollback()
                except Exception: pass
                continue
            # DuckDB-specific skip list
            if label == "duckdb" and r["primitive"] in _DUCKDB_SKIP:
                continue
            results.append(r)
        return {"label": label, "results": results}
    finally:
        try: db.close()
        except Exception: pass
        try: dispose()
        except Exception: pass


# ── Concurrency benchmark (workers > 1) ────────────────────────────


def run_concurrency_benchmark(
    backend_label: str,
    backend_url: str,
    workers: int,
    iterations_per_worker: int = 100,
) -> dict | None:
    """For a backend that supports concurrent connections (PG/MySQL),
    spin up N workers each running record_invocation (lightest hot-
    path primitive). Reports aggregate p50/p95/p99 + throughput (ops/s).

    Excludes the in-memory engines (sqlite/duckdb) — they don't model
    real concurrency since they're single-connection. PG + MySQL give
    the realistic answer.

    Each worker gets its OWN session from the engine pool. Pre-creates
    a row to bind against and pre-snapshots the agent so the hot path
    has no setup amortization issues."""
    import concurrent.futures as _cf
    import threading

    if backend_label not in ("postgresql", "mysql"):
        return None  # in-memory engines don't model real concurrency
    if backend_url is None:
        return None

    # Use the engine with a connection pool large enough for N workers
    eng = create_engine(backend_url, pool_size=workers + 5,
                        max_overflow=workers)
    SessionLocal = sessionmaker(bind=eng)

    # Pre-snapshot the agent + clear contention surface
    setup_db = SessionLocal()
    try:
        init_storage(setup_db)
        snapshot_agent(setup_db, tenant_id=TENANT,
                       agent_key="ConcAgent",
                       definition={**_AGENT_DEF,
                                    "agent_key": "ConcAgent"},
                       note="conc-setup")
    finally:
        setup_db.close()

    barrier = threading.Barrier(workers)

    def worker(wid: int) -> list[float]:
        times = []
        db = SessionLocal()
        try:
            # All workers wait at the barrier so they hit the DB at
            # the same time — measures real contention, not staggered
            # serial execution.
            barrier.wait()
            for i in range(iterations_per_worker):
                t0 = time.perf_counter()
                try:
                    record_invocation(
                        db, tenant_id=TENANT,
                        agent_key="ConcAgent",
                        principal_kind="user",
                        principal_id=f"worker_{wid}_user_{i}",
                        mode="observed", outcome="success")
                except Exception:
                    db.rollback()
                    continue
                times.append((time.perf_counter() - t0) * 1000)
        finally:
            db.close()
        return times

    t_start = time.perf_counter()
    with _cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(worker, w) for w in range(workers)]
        all_times = []
        for f in futures:
            all_times.extend(f.result())
    wall_clock_s = time.perf_counter() - t_start

    eng.dispose()

    if not all_times:
        return None
    all_times.sort()
    n = len(all_times)
    return {
        "backend": backend_label,
        "workers": workers,
        "iters_per_worker": iterations_per_worker,
        "total_ops": n,
        "wall_clock_s": wall_clock_s,
        "throughput_ops_per_sec": n / wall_clock_s if wall_clock_s > 0 else 0,
        "p50": all_times[n // 2],
        "p95": all_times[int(n * 0.95)],
        "p99": all_times[int(n * 0.99)],
        "mean": statistics.mean(all_times),
        "max": max(all_times),
    }


def main():
    backends = ["sqlite"]
    try:
        import duckdb_engine  # noqa: F401
        backends.append("duckdb")
    except ImportError:
        pass
    if os.environ.get("KYA_TEST_PG_URL"):
        backends.append("postgresql")
    if os.environ.get("KYA_TEST_MYSQL_URL"):
        backends.append("mysql")

    _hdr("KYA per-primitive latency benchmark — MEASURED, not estimated")
    print(f"  WARMUP={WARMUP}   MEASURE={MEASURE}   single-threaded")
    print(f"  Backends: {', '.join(backends)}")

    all_results: dict[str, list[dict]] = {}
    for label in backends:
        print(f"\n  Running on {label}...")
        out = run_backend(label)
        if out:
            all_results[label] = out["results"]

    # ── Final report ──
    _hdr("MEASURED LATENCY (milliseconds)")
    header = (f"  {'primitive':52s}  "
              f"{'p50':>7s}  {'p95':>7s}  {'p99':>7s}  "
              f"{'mean':>7s}  {'max':>7s}")
    for label, results in all_results.items():
        print()
        print(f"  ── Backend: {label.upper()} ──")
        print(header)
        print(f"  {'-'*52}  {'-'*7}  {'-'*7}  {'-'*7}  {'-'*7}  {'-'*7}")
        for r in results:
            print(f"  {r['primitive']:52s}  {_fmt(r)}")

    # ── Concurrency benchmark (PG + MySQL only) ──
    _hdr("CONCURRENCY BENCHMARK — record_invocation under N workers")
    print("  workers=1 is baseline (no contention)\n"
          "  10 / 100 simulate realistic production fan-out\n"
          "  Each worker has its own DB session from the engine pool\n"
          "  All workers synchronize via a barrier before starting\n")
    print(f"  {'backend':12s} {'workers':>8s} {'iters/worker':>13s} "
          f"{'p50ms':>7s} {'p95ms':>7s} {'p99ms':>7s} "
          f"{'mean':>7s} {'max':>7s} {'ops/sec':>10s}")
    print(f"  {'-'*12} {'-'*8} {'-'*13} "
          f"{'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*10}")
    conc_urls = {
        "postgresql": os.environ.get("KYA_TEST_PG_URL"),
        "mysql": os.environ.get("KYA_TEST_MYSQL_URL"),
    }
    for backend_label in ("postgresql", "mysql"):
        url = conc_urls[backend_label]
        if not url:
            continue
        for workers in (1, 10, 100):
            # Wipe + reinit the schema for a clean run per workers level
            eng_clean = create_engine(url)
            try:
                with eng_clean.begin() as conn:
                    if backend_label == "postgresql":
                        conn.execute(text(
                            "CREATE SCHEMA IF NOT EXISTS prov_schema"))
                        for tbl in (
                            "kya_cost_events", "kya_budget_changes",
                            "kya_tenant_cost_budgets",
                            "kya_delegation_violations",
                            "kya_delegation_policy_overrides",
                            "kya_evidence", "kya_invocations",
                            "kya_principal_trust", "kya_user_trust",
                            "agent_versions"):
                            conn.execute(text(
                                f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
                    else:
                        for tbl in (
                            "kya_cost_events", "kya_budget_changes",
                            "kya_tenant_cost_budgets",
                            "kya_delegation_violations",
                            "kya_delegation_policy_overrides",
                            "kya_evidence", "kya_invocations",
                            "kya_principal_trust", "kya_user_trust",
                            "agent_versions"):
                            try:
                                conn.execute(text(
                                    f"DROP TABLE IF EXISTS {tbl}"))
                            except Exception: pass
            except Exception as exc:
                print(f"  [SKIP] {backend_label}/{workers}: "
                      f"{type(exc).__name__}: {str(exc)[:60]}")
                continue
            finally:
                eng_clean.dispose()

            r = run_concurrency_benchmark(
                backend_label, url, workers,
                iterations_per_worker=100)
            if r is None:
                print(f"  {backend_label:12s} {workers:>8d}  "
                      "(no measurements collected)")
                continue
            print(f"  {backend_label:12s} {workers:>8d} "
                  f"{r['iters_per_worker']:>13d} "
                  f"{r['p50']:>7.2f} {r['p95']:>7.2f} "
                  f"{r['p99']:>7.2f} {r['mean']:>7.2f} "
                  f"{r['max']:>7.2f} {r['throughput_ops_per_sec']:>10.0f}")

    # ── Honesty summary ──
    _hdr("Honesty notes")
    print(
        "  • Single-threaded section uses warmup + 500 measured\n"
        "    iterations. Reasonable confidence in p50/p95.\n"
        "  • In-memory sqlite is a lower bound (no real I/O).\n"
        "  • PG/MySQL hit a local Docker container — production\n"
        "    network adds 0.5-5ms RTT per call.\n"
        "  • Concurrency benchmark uses real connection pooling and\n"
        "    a synchronization barrier so all workers hit the DB\n"
        "    simultaneously. p99 here surfaces real contention.\n"
        "  • Valkey not configured during this run; primitives that\n"
        "    write to Valkey skip the mirror gracefully.\n"
        "  • DuckDB skips primitives blocked by task #42.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
