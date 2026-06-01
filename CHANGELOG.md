# Changelog

All notable changes to **veldt-kya** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the version
scheme follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Dedicated `veldt-kya` repo separated from the upstream `veldt-decisions`
  monorepo (open-core split).

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
