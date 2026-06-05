# Changelog

All notable changes to **veldt-kya** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the version
scheme follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-06-05

### Added
- `garak_real_detector` panel judge — opt-in via
  `register_garak_real_detector_adapter()` (`pip install garak`).
  Probe family propagates across `ThreadPoolExecutor` workers via
  `attack_context()` (ContextVar).
- Multi-LLM judge ensemble — `register_multi_llm_judge_adapter(models=[…])`
  registers one `llm_judge::<sanitized>` judge per model.
- `[dotenv]` extra — loads `Path.cwd()/".env"` at `import kya` so API
  keys reach judges in CLI / pytest / notebook processes. Opt-out via
  `KYA_DISABLE_DOTENV=1`.

### Changed
- **Breaking:** `refusal_heuristic` and `kya_attack_patterns` removed
  from the default panel. Re-enable via
  `register_refusal_heuristic_adapter()` /
  `register_kya_attack_patterns_adapter()`.

### Fixed
- Bundled judges no longer return `UNCLEAR` when `context=None`; they
  score on `input_text` + `response` alone.
- Fiddler failures record specific reasons (`no_api_key`,
  `requests_not_installed`, `http_request_exception:<cls>`,
  `http_non_2xx:<code>`, `json_parse_failed`) on
  `JudgeResult.detail["failure_reason"]`. Read via
  `kya.fiddler_bridge.get_last_failure_reason(fn_name)`.
- **Bug B — auto-load `.env` so API keys reach the LLM judges.**
  Without this fix, `import kya` in a CLI / pytest / notebook process
  that hadn't already preloaded its environment surfaced as
  `verdict=ERROR, latency_ms=0` on the Fiddler / OpenAI / Phoenix
  judges — even though the underlying cause was just "the API key never
  loaded into `os.environ`". `kya/__init__.py` now soft-imports
  `python-dotenv` and calls
  `load_dotenv(dotenv_path=Path.cwd()/".env", override=False)` at module
  load; the call is a no-op when the package isn't installed (no hard
  dependency added to the wheel), pinned to CWD to avoid surprise
  ancestor-walk loads from site-packages, and opt-out-able via
  `KYA_DISABLE_DOTENV=1` for strict-isolation deployments.

## [0.1.9]

### Added
- **Real-Garak v0.15 adapter** in `kya_redteam.garak_runtime`. Replaces the
  stub `run_probe_via_garak` with a production implementation that loads
  Garak probe families via `_plugins.load_plugin`, wraps any KYA HTTP
  target as a Garak Generator subclass, runs `probe.probe()` under an
  in-memory `reportfile` buffer (closes a CLI-only side-channel crash),
  and scores attempts via the probe's `primary_detector`.
- Multi-generation support: `KyaHttpGenerator._call_model` honors
  `generations_this_call` and Garak's `supports_multiple_generations=True`
  contract (prevents N² calls). Operator cost cap via the
  `KYA_REDTEAM_GARAK_MAX_GENS` env var (default 10) — pads with `None` up
  to `n_requested` so Garak's harness contract still holds.
- `GARAK_NATIVE_PROBES` entries now carry a `garak_probe` field mapping
  each native prompt to its Garak family (`dan`, `encoding`,
  `sysprompt_extraction`, `promptinject`, `latentinjection`, or `None`
  for native-only). The orchestrator dispatches by family when
  real-garak is enabled and emits one finding per Garak hit.
- **PyRIT adapter observability**: `KyaWrappedChatTarget` tracks
  `http_sends_total` and `http_send_failures` per instance; counters
  surface via `run_via_pyrit`'s return dict and feed
  `report.target_calls` / `report.target_errors` so silent target
  outages and CrescendoAttack backtracks no longer hide.
- Regression suites: `tests/test_garak_runtime.py` (22 tests) and
  `tests/test_pyrit_runtime.py` (14 tests) — covers probe-family
  resolution, counter semantics, cost-cap padding, RLock concurrency,
  budget-integration source-level guards.

### Changed
- **Budget accounting now at real-HTTP granularity** for both Garak and
  PyRIT paths. Previously `consume_budget` was debited at the dataset-
  entry or transcript-turn granularity, which under-counted target HTTP
  calls by the `generations_per_call` factor (Garak) and by Crescendo
  backtrack rewrites (PyRIT). Both paths now use atomic
  `consume_budget(tenant_id, limit, n=total_http_sends)`.
- `_garak_io_lock` upgraded from `threading.Lock` to `threading.RLock`
  for defensive reentrancy across `probe.probe(generator)` callbacks.
- PyRIT path now serializes the full attack lifecycle (`set_memory_instance`
  → `execute_async` → transcript extraction) under
  `_pyrit_central_memory_lock` (RLock). Closes a cross-run data corruption
  hole where concurrent workers in `runs.submit_async_run`'s
  ThreadPoolExecutor would race the `CentralMemory` singleton.

### Fixed
- **Garak caller bug** in `pyrit_orchestrator.py`: was passing
  `prompt[:60]` truncated text where a Garak probe spec was required,
  causing every real-garak call to hit a RuntimeError and silently fall
  back to native — entire Layer-2 dead code in production. Caller now
  dispatches by `entry["garak_probe"]` and iterates `gres["hits"]` as
  typed dicts.
- `pyrit_orchestrator.py` budget-debit loop collapsed to a single atomic
  `consume_budget(n=extra)` (was N `INCR` round-trips per dispatch).
- Silent target-failure observability: `http_target.send` exceptions /
  `response.error` / empty responses now surface via
  `http_send_failures` counters rather than being absorbed into a
  misleading "0 hits = clean" finding count.

### Fixed
- **Bug A — judge `context=None` short-circuit.** `_judge_openai_direct`
  and `register_phoenix_adapter()._phoenix` no longer auto-vote `UNCLEAR`
  when the caller passes no reference context. Red-team probes drive
  these judges with a target response but no ground-truth context;
  pre-fix the entire judge panel collapsed to UNCLEAR, hiding the actual
  signal. `llm_judge_refusal_or_hallucination` now accepts `context=None`
  (treated as `""`) — the underlying LLM judge still distinguishes
  REFUSAL from HALLUCINATION using the response alone.
- **Bug A — modern refusal phrases.** `_REFUSAL_PHRASES` extended with
  GPT-4-family / Claude / Llama-3+ refusal patterns ("I can't assist",
  "I cannot assist", "I'm sorry, I can't", "I am not able to",
  "I won't", "I will not provide", "I can't provide", etc.). Without
  these, well-aligned models surfaced as UNCLEAR rather than as
  legitimate refusals (OK) during red-team scoring.

## [0.1.8]

### Added
- **MAVLink parser** for drone / autonomous-systems telemetry
  (`kya.runtime.parsers.mavlink`). Canonicalizes six core MAVLink
  message families (HEARTBEAT, COMMAND_LONG, COMMAND_ACK, MISSION_*,
  PARAM_*, SYS_STATUS) into `AutonomyEvent` records. ArduPilot SITL
  harness ships in `tests/live/test_mavlink_sitl.py` with hardened CI
  (port-wait, SHA-pin, drift guard, cross-process replay).
- **Principal extension** to fourteen typed kinds: `agent`,
  `service_account`, `user`, `machine_identity`, `automated_workload`,
  `controller`, `drone`, `robot`, `vehicle`, `plc`, `scada`, `sensor`,
  `actuator`, `autonomous_system`. Custom kinds register via
  `register_principal_kind()`.
- `kya.snapshot_principal(db, *, tenant_id, principal_kind, principal_id,
  definition, ...)` — immutable definition snapshot for any typed
  principal. Same storage path as `snapshot_agent` (composed
  `<kind>:<id>` key) so existing indexes / replication pipelines cover
  drones / robots / PLCs without forking schema.
- `kya.principal_fingerprint(db, *, tenant_id, principal_kind,
  principal_id, ...)` — composite identity hash binding a principal's
  definition to its delegation lineage. Same definition + different
  lineage = different fingerprint. Read-only, deterministic.
- `KYA_HASH_STRICT_KIND` env var: when set, raises on unknown
  `principal_kind` values instead of silently treating them as `agent`.
- Many-to-many `kya_principal_edges` table + cycle-safe ancestor /
  descendant walks (`walk_ancestors`, `walk_descendants`) carrying typed
  edge kinds (`operates`, `member_of`, `supervises`, `delegates_to`).

### Changed
- Threading lock added to `_HASHED_FIELDS_BY_KIND` and
  `_REGISTERED_PRINCIPAL_KINDS` for concurrent custom-kind registration.
- `canonical_hash` now rejects `principal_id` values containing `:`
  since `<kind>:<id>` is the storage key composition delimiter.
- Batch-fetch optimization for `fleet_fingerprint` removes the N+1 query
  pattern when fingerprinting large fleets.

### Fixed
- `_discover_principals` cross-source deduplication (the same
  controller declared by two parsers is now collapsed to one principal).
- `canonical_hash` datetime nondeterminism (mixed naive / aware values
  with the same epoch now hash identically).
- Bridge dispatch source_kind / class mismatch on `RuntimeEvent` vs
  `AutonomyEvent` routing.

### Docs
- README refreshed for cross-domain (cyber + physical) positioning. New
  "Across cyber & physical" example showing `mission_controller →
  planner_agent → uav_001` chain using `snapshot_principal` +
  `principal_fingerprint` + `verify_chain`. Hierarchy diagram
  (`human → controller → agent → drone → actuator`) added near the
  opener. Financial-domain example names renamed to mission /
  autonomous-systems wording. `CONTRIBUTING.md` gains a Live SITL run
  step for MAVLink-touching changes.

## [0.1.7]

### Added
- `canonical_hash(agent_def, *, include_ownership=...)` — opt-in flag
  that folds the ownership / accountability fields (`owner`, `on_call`,
  `escalation`, `review_status`) into the identity hash. Default `False`:
  most customers should leave it off, because `tenant_id` is unchanged,
  prompt / tools / permissions / policies / model are unchanged, and a
  pure ownership transfer is **operational metadata, not governance**.
  Opt-in is intended for the small set of regulated programs (defense,
  intel, highly regulated government) where transferring an agent to a
  new accountable team is itself a re-approval event.
- `detect_drift(declared_hash, agent_def, *, include_ownership=...)` —
  matching kwarg so opt-in customers compare like with like.
- `KYA_HASH_OWNER_FIELDS` env var — cluster-wide default for the same
  flag; explicit kwarg overrides it. Lets ops enable strict mode across
  a deployment without per-call code changes.

### Notes
- Pure addition; no semantics change at the default. Existing
  `definition_hash` values continue to match.
- Required by `veldt-kya-pro>=0.1.6` for its `fleet_fingerprint`
  strict-mode and the `assert_fingerprint_mode` guardrail.

## [0.1.6]

### Changed (BREAKING)
- **Default schema for KYA tables flipped from `prov_schema` to `None`**
  (= dialect's default; `public` on PostgreSQL). Customers running on the
  same database instance as v0.1.5 must export
  `KYA_VERSIONS_SCHEMA=prov_schema` to keep their existing KYA tables
  addressable, or migrate the tables into `public`.
- New env var `KYA_DECISIONS_SCHEMA` (default `prov_schema`) controls the
  schema for non-KYA tables that KYA's compliance / rogue / fleet-metrics
  helpers read (`governance_incidents`, `governance_audit_log`,
  `decision_approvals`, `tenants`, `custom_agents`). Lets customers run
  KYA tables and veldt-decisions tables in separate schemas without
  conflict.

### Added
- `since_ts` / `until_ts` keyword arguments on `kya.list_invocations()` and
  `kya.list_evidence()`. Server-side window filter (half-open:
  `since_ts <= occurred_at < until_ts`) so callers building time-bounded
  packs no longer have to filter post-fetch.
- `kya._portable.decisions_schema_qualifier()` and
  `qual_for_raw_sql_decisions()` helpers — symmetric to the KYA-schema
  ones, for any code that joins veldt-decisions tables.
- CI guard test `tests/test_no_hardcoded_schemas.py` that scans the open
  SDK source for hardcoded `prov_schema.<table>` strings (catches
  single-quoted, double-quoted, AND triple-quoted SQL) and fails the
  build if a future PR re-introduces a hardcode.

### Fixed
- Refactored every hardcoded `prov_schema.<table>` raw SQL string across
  the wheel's full package set (kya + kya_redteam) to use
  `qual_for_raw_sql(db)` (KYA tables) or `qual_for_raw_sql_decisions(db)`
  (veldt-decisions tables). The CI guard in
  `tests/test_no_hardcoded_schemas.py` now scans every shipped package
  (kya, kya_redteam, kya_hooks, kya_otlp_bridge) so a future regression
  in any of them fails the build.
- `kya._legacy_tables.create_legacy_tables()` no longer silently
  overwrites a customer's pre-existing `schema_translate_map` entry for
  the same key. When the customer's mapping differs from what KYA would
  set, the customer's value is preserved and a `[KYA-LEGACY]` warning
  is logged so split-schema deployments can diagnose "KYA tables not
  visible" cases.
- Module-level `_PG_SCHEMA` constants in `evidence.py`, `invocations.py`,
  `principals.py`, `versioning.py` no longer hardcode `prov_schema` as
  the fallback.
- `KYA_VERSIONS_SCHEMA` is validated to be a SQL-legal identifier before
  being interpolated into `CREATE SCHEMA IF NOT EXISTS` (defense against
  operator-typo-induced SQL injection on misconfigured deployments).

### Upgrade

If your deployment relied on the v0.1.5 default of `prov_schema`:

```bash
export KYA_VERSIONS_SCHEMA=prov_schema
export KYA_DECISIONS_SCHEMA=prov_schema  # only if you join decisions tables
```

Starting fresh on v0.1.6 needs no env vars — tables land in `public`.

## [0.1.0] — 2026-05-21

Initial public release on PyPI.

### Added — core SDK (`kya/`)
- **Risk scoring** — pure-function `score_agent(definition) → AgentRiskScore`
  with attributable factor breakdown across base, tools, governance mode,
  data sensitivity, provenance, model trust, ownership, approval, deployment,
  trust audits, blast radius, interactions.
- **Versioning** — `snapshot_agent` writes immutable agent-definition
  versions; `rollback_to` creates a new snapshot from an older version.
- **HMAC-chained evidence** — `record_evidence` builds a tamper-evident
  per-invocation chain (each row signs `prev_hash || payload_hash`);
  `verify_chain` validates the full chain after the fact.
- **Principal trust ledger** — `record_principal_signal` /
  `record_principal_clean` maintain per-principal trust scores with
  signal-count breakdown.
- **Format adapter** — `normalize_agent_def(framework, raw_def)` canonicalises
  agent definitions from five frameworks: agents_md (OpenCLAW),
  langchain, crewai, openai (Assistants), generic.
- **Aggregate telemetry** — anonymous counter rollups (no payloads, no tenant
  IDs); off by default for transmission, on by default for in-process
  counters; `enable_telemetry(url=...)` to ship aggregates to a collector.
- **Dual-write outbound** — opt-in row mirroring to a configurable Veldt
  collector with PII redaction by default, allowlist-controlled tables,
  circuit breaker, exponential backoff.
- **Inbound recommendations fetcher** — pulls Ed25519-signed weight
  recommendations from a Veldt collector, verifies signature against pinned
  trust anchor (with `KYA_INBOUND_PUBLIC_KEY` env override), persists to
  pending queue; operator approves via `approve_recommendation()` which
  routes through `set_override()` (only-tighten enforced).
- **In-tenant feedback loop** — `propose_from_incident()` generates weight-
  tightening suggestions from critical incidents; `approve_suggestion()`
  applies them via `set_override()`.
- **Autoinstrument** — zero-config patching of Anthropic / OpenAI / LiteLLM
  SDKs to capture invocation + evidence automatically.
- **Compliance helpers** — GDPR / HIPAA / SOX / PCI / CCPA / GLBA / FERPA
  scope tagging, retention windows, breach-notification SLAs.
- **Pluggable session factory** — `set_session_factory(sessionmaker)` lets
  SDK consumers wire their own engine without depending on platform globals.

### Added — supporting components (in repo, not in PyPI wheel)
- `kya_hooks/` — framework adapters (Claude Agent SDK, LangChain,
  OpenAI Agents SDK).
- `kya_otlp_bridge/` — OTel → KYA signal sidecar.
- `kya_redteam/` — PyRIT / Garak adversarial-testing harness (framework
  only; curated attack corpus is sold as a separate "Pro Pack" by
  Veldt Labs Inc.).
- `scripts/generate_kya_signing_key.py` — Ed25519 keypair generator
  for self-hosted KYA gateways.

### Compatibility
- Python 3.10, 3.11, 3.12
- PostgreSQL, MySQL, SQLite, DuckDB (see
  `docs/storage_backends.md` for backend selection guidance)
- Optional deps via extras: `[metrics]`, `[tracing]`, `[webhooks]`,
  `[judge]`, `[all]`

### Verified
- 34 pytests + 1 platform-only skip
- 4-backend × 9-phase OpenCLAW multi-agent e2e (36/36 cells)
- 5-phase concurrency load test (20 workers × 50 ops/phase)
- Cleanroom `pip install` on Python 3.10 / 3.11 / 3.12 (Linux)

### License
Apache-2.0. © 2026 Veldt Labs Inc.
