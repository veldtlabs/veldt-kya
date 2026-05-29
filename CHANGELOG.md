# Changelog

All notable changes to **veldt-kya** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the version
scheme follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Dedicated `veldt-kya` repo separated from the upstream `veldt-decisions`
  monorepo (open-core split).

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
- PostgreSQL, MySQL, SQLite, DuckDB (with caveats — see
  `docs/storage_backends.md`)
- Optional deps via extras: `[metrics]`, `[tracing]`, `[webhooks]`,
  `[judge]`, `[all]`

### Verified
- 34 pytests + 1 platform-only skip
- 4-backend × 9-phase OpenCLAW multi-agent e2e (36/36 cells)
- 5-phase concurrency load test (20 workers × 50 ops/phase)
- Cleanroom `pip install` on Python 3.10 / 3.11 / 3.12 (Linux)

### License
Apache-2.0. © 2026 Veldt Labs Inc.

## [0.1.1] — 2026-05-27

### Changed
- **PyPI package description** — expanded summary to "KYA — Know Your Agent +
  Know Your Principal. Open control plane for trust + governance of autonomous
  systems (LLM agents, multi-agent systems, agentic RAG, autonomous SQL,
  AutoML, RPA bots, service accounts)." Surfaces KYP as the primary
  differentiator and matches the search terms practitioners actually use.
- **README judge section** — restructured into three honest buckets so
  first-time installers have accurate expectations:
  - *Bundled* (zero setup, works after `pip install veldt-kya`):
    `openai_judge`, `refusal_heuristic`, `kya_pyrit`, `kya_attack_patterns`.
  - *Optional extras* (one install command, no external service):
    `kya_presidio` via `[presidio]`; `arize_phoenix` via `[recommended]`.
  - *BYOC bridges* (wrap an existing paid account — no-op without credentials):
    `fiddler_safety` + `fiddler_faithfulness` require `FIDDLER_API_KEY`.

### Added
- **arXiv preprint link** in README — points to the framework paper
  "KYA: A Framework-Agnostic Trust Layer for Autonomous Systems with
  Verifiable Provenance and Hierarchical Policy Composition" (Quadri, 2026,
  arXiv:2605.25376).

## [0.1.2] — 2026-05-27

### Added
- **`min_trust` kwarg on `require_action`** — `kya.rbac.require_action(...,
  min_trust=N)` now gates access on principal trust score in addition to the
  RBAC grant check. Trust ≥ `min_trust` allows; trust below threshold raises
  `AccessDeniedError` with reason `"trust_below_threshold"`. Unseen principals
  default to `STARTING_TRUST` (50). `min_trust=None` is a no-op (backward
  compatible). Emits distinct security-event reasons so SOC tooling can
  separate RBAC misses from trust-decay blocks. 14 new test cases; 33/33 rbac
  tests pass.

### Fixed
- **Cross-backend `prov_schema` in raw SQL** — several public-API primitives
  (`get_user_trust`, `list_user_trust`, `summarize_request`,
  `list_recent_requests`, `agent_divergence_score`,
  `migrate_principals_for_aliases`) hardcoded `prov_schema.kya_*` in raw
  `text()` SQL strings that SQLAlchemy's `schema_translate_map` does not
  rewrite. Introduced `kya._portable.qual_for_raw_sql()` (returns `"prov_schema."` on
  PostgreSQL, `""` elsewhere) and routed all affected queries through it.
  Fixes silent breakage on SQLite, DuckDB, and MySQL. `migrate_principals_for_aliases`
  now returns an explicit `skipped_reason` on non-PostgreSQL backends.
  10 new cross-backend regression tests; 618 tests pass repo-wide.

[0.1.0]: https://github.com/veldtlabs/veldt-kya/releases/tag/v0.1.0
[0.1.1]: https://github.com/veldtlabs/veldt-kya/releases/tag/v0.1.1
[0.1.2]: https://github.com/veldtlabs/veldt-kya/releases/tag/v0.1.2