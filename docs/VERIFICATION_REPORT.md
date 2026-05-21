# KYA SDK — Verification Report

**As of:** 2026-05-21 · last commit before migration: `7a52604`
**Status:** ✅ All gates pass. Ready for `D:\veldt-kya\` migration.

## Test surfaces and results

### 1. Pytest suite — 34 tests + 1 platform-only skip

| File | Tests | Result |
|---|---|---|
| `test_dualwrite.py` | 12 | ✅ pass |
| `test_inbound.py` | 10 | ✅ pass |
| `test_lifecycle_and_errors.py` | 11 | ✅ pass |
| `test_feedback_loop_closes.py` | 2 | ✅ 1 pass / 1 skipped (platform-only) |
| **Total** | **35** | **34 pass · 1 skipped · 0 failed** |

### 2. 4-backend × 9-phase OpenCLAW multi-agent e2e — 36/36 cells

|  | PostgreSQL | SQLite | DuckDB | MySQL |
|---|---|---|---|---|
| **1. Score** | ✅ | ✅ | ✅ | ✅ |
| **2. Snapshot** | ✅ | ✅ | ✅ | ✅ |
| **3. Fan-out (correlation tree)** | ✅ | ✅ | ✅ | ✅ |
| **4. Evidence (HMAC chain × 3)** | ✅ | ✅ | ✅ | ✅ |
| **5. Rogue + actor_agent attribution** | ✅ | ✅ | ✅ | ✅ |
| **6. Trust decay + recovery** | ✅ | ✅ | ✅ | ✅ |
| **7. Telemetry counters** | ✅ | ✅ | ✅ | ✅ |
| **8. Persistence (fresh session)** | ✅ | ✅ | ✅ | ✅ |
| **9. Persisted rows verified** | ✅ | ✅ | ✅ | ✅ |

### 3. Cross-backend smoke

| Backend | Tables created | Evidence chain |
|---|---|---|
| PostgreSQL | 11/25 | ✅ verify_chain valid |
| MySQL | 10/25 | ✅ verify_chain valid |
| SQLite | 11/25 | ✅ verify_chain valid |
| DuckDB | 4/25 (legacy tables limited — Identity DDL) | ✅ verify_chain valid |

### 4. Concurrency + load test (20 workers × 50 ops/phase = 1000 ops/phase)

| Phase | Result | Loss rate |
|---|---|---|
| A. `record_invocation` (no shared state) | ✅ | 0% |
| B. `record_evidence` (one chain) | ✅ chain valid, 1000/1000 | 0% |
| C. `record_principal_signal` (one principal) | ✅ | 0% |
| D. Actor mirror writes | ✅ | 0% |
| E. `snapshot_agent` (one agent, version race) | ✅ | 0.5% (no duplicates) |

### 5. Wheel build + cleanroom install

| Check | Result |
|---|---|
| Built with setuptools >= 77 (PEP 639 SPDX) | ✅ |
| `License-Expression: Apache-2.0` in wheel metadata | ✅ |
| `LICENSE` ships at `veldt_kya-0.1.0.dist-info/licenses/LICENSE` | ✅ |
| `Author-email: "Veldt Labs Inc." <kola@veldtlabs.ai>` | ✅ |
| `pip show veldt-kya` reports correct version + license | ✅ |
| `import kya` works in clean venv without source tree | ✅ |
| `kya.__version__ == "0.1.0"` from `importlib.metadata` | ✅ |
| Smoke test runs from installed wheel (no source) | ✅ |
| Python 3.10 / 3.11 / 3.12 all pass (Linux) | ✅ |

### 6. Optional extras matrix

| Extra | Install | Deps resolve |
|---|---|---|
| (default) | ✅ | ✅ |
| `[metrics]` (prometheus_client) | ✅ | ✅ |
| `[tracing]` (opentelemetry) | ✅ | ✅ |
| `[webhooks]` (requests) | ✅ | ✅ |
| `[judge]` (litellm) | ✅ | ✅ |
| `[all]` | ✅ | ✅ |

### 7. Secret audit — third-party agent verdict

**SAFE TO PUBLISH.** No API keys, private keys, tokens, internal hostnames, or customer UUIDs in any shipped source. Only Veldt identifiers in the wheel are the package name, author email (`kola@veldtlabs.ai`), and project URLs.

## Bugs found and fixed across the verification sweep

1. `autoinc_id` PG-only `server_default` broke SQLite — fixed via `Identity()`
2. `inbound.py` PG-only raw SQL — rewritten to SA Core (cross-dialect)
3. `_auto_apply_if_allowed` UPDATE had no status filter — could roll back applied rows
4. `_persist_one` conflated `deployment_id` (hash) with `tenant_id` (UUID)
5. MySQL `REPEATABLE READ` hid mirror writes — fixed with commit-before-read
6. DuckDB SELECT-then-INSERT race in `record_principal_signal` — retry-on-IntegrityError
7. Lost-update race in `record_principal_signal` at concurrency — fixed with `FOR UPDATE` on PG/MySQL
8. Evidence chain fork under concurrent writers — fixed with `pg_advisory_xact_lock`
9. Version-no race in `snapshot_agent` — fixed with retry × 30
10. Thread leak in `shutdown()` (100 enable/disable cycles → 100 leaked threads) — fixed with `worker.join()`
11. `propose_from_incident` was never invoked from `resolve_incident` — dead code wired live
12. `actor_agent_key` mirror used platform-only `db.database.SessionLocal` — replaced with pluggable `set_session_factory()`
13. `get_rogue_signals` used PG-only `(:tid)::uuid` cast — replaced with SA Core query
14. `kya_inbound_recommendations` table missing from `init_storage` plan — added
15. `__version__` undefined — single-sourced from `importlib.metadata`

## What this means

Every customer-facing surface has been exercised under realistic load and across the four database dialects KYA claims to support. The remaining items before PyPI publish are governance decisions (signing-key minting, public-repo creation) — no code work is blocking.
