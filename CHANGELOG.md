# Changelog

All notable changes to **veldt-kya** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the version
scheme follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] — 2026-05-29

### Added — attack chains
- **ValkeyStateStore** — cross-process, cross-worker multi-step attack-chain
  detection. Drops in as a `state_store=` to `AttackChainEngine` so multiple
  KYA workers share partial-match state without coordination. JSON
  serialization; ZSET-backed TTL expiry; fail-soft contract; full backward
  compatibility with `InMemoryStateStore`.
- **Cross-agent delegation-graph-aware correlation** — `correlate_by` now
  supports `correlation_id`; `correlation_id_for_invocation` walks the
  `parent_invocation_id` chain (configurable max-hop) so an attack chain
  can span multiple cooperating agents on the same delegated task. New
  example rule: `cross_agent_data_exfiltration.yml`.
- **DAG step grammar** — rules can declare `mode: "dag"` with multi-parent
  `after: [step_a, step_b]` to express AND-joins (diamond patterns, fan-in).
  `within_seconds` measures from the latest predecessor. Linear rules remain
  the default and behave identically to v0.1.3. New example rule:
  `delegated_credential_exfil_diamond.yml`.
- **Sigma → KYA rule adapter** — `load_sigma_rule`, `load_sigma_rules_from_dir`,
  `translate_sigma_to_kya_dict` translate SigmaHQ-format rules
  (single-selection + AND-chain conditions, `|contains`, `|startswith`,
  `|endswith`, `|re`/`|regex`, list values) into KYA `AttackChainRule`s.
  MITRE technique IDs + tactic names preserved as metadata. Unsupported
  constructs (OR, NOT, quantifiers, parens, keyword-only) raise
  `SigmaTranslateError` with named offender so operators can split rules.
  Configurable `field_prefix` (defaults to `"payload."` matching KYA's
  evidence convention).

### Added — assessment
- **Autonomous Systems Trust Assessment orchestrator** — `run_assessment`
  computes a 5-pillar `AssessmentReport` (RiskScore, Provenance, Lineage,
  TrustScoring, RBAC) returning structured `Finding` rows with severity,
  evidence, and remediation hints. Designed for periodic governance
  reporting against any agent or service-account principal.

### Notes
- **Zero new database surface across all five features.** All new state
  lives in the existing tables (kya_attack_partial_matches via the state
  store, kya_evidence via the chain attach, kya_principal_trust via the
  scoring update); no migrations required.
- All five features are independently optional; nothing in this release
  introduces a hard runtime dependency.

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
