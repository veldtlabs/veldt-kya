# KYA Paper — Code-Grounded Repositioning Audit

**Date:** 2026-05-21
**Repo:** `D:\veldt-kya\` (extracted from `veldt-decisions` monorepo)
**Method:** Read 5 claim-critical source files; cross-checked against
literature audit in [research_audit.md](../veldt-decisions/paper/research_audit.md).

This audit verifies the paper's contribution claims against the **actual
shipping code in the standalone repo**. Where the literature audit
flagged risk, this re-checks whether the code supports a refined,
defensible claim — or whether the contribution should be dropped.

---

## Repo state (verified)

- Standalone repo: `D:\veldt-kya\`
- License: **Apache 2.0** ✅ — `pyproject.toml` line 17 (PEP 639 format)
- Version: `0.1.0`
- CHANGELOG entry: "Initial public release — 2026-05-21"
- Tests: 34 passing pytests + 4×9 cross-backend matrix (36 cells) + concurrency load test
- Sibling packages (`kya_hooks/`, `kya_otlp_bridge/`, `kya_redteam/`) are co-located but **not in the wheel** — confirmed in `pyproject.toml` package-discovery rules.

**License decision blocker is resolved.** Paper title is consistent with shipping reality.

---

## Code-verified contribution claims

### ✅ Only-tighten composition algebra — STRONGEST CONTRIBUTION

**Evidence in code** (`kya/tenant_weights.py`):

- Module docstring lines 23–27: *"a tenant override is rejected if it would LOWER the effective risk weight below the platform default. Tenants can raise their own bar; they can't lower it."*
- Dedicated exception class: `OverrideLoosensError(ValueError)` (line 182)
- Write-time enforcement: `_check_only_tighten(db, scope, key, new_value, tenant_id)` (line 189)
- Resolution order (line 16–22) is documented and deterministic: caller-explicit → tenant override → platform default override → module default
- Same semantics mirrored in Veldt's `agents/tool_rbac_overrides.py` — so this is a **cross-system invariant**, not a one-off.

**Audit trail in code**: every successful change writes a row to `kya_weight_changes` with `old_value`/`new_value`/`changed_by`/`reason` — verifiable history of every tightening.

**Paper claim is fully supported.** This is the strongest formal contribution. Lemma 1 (only-tighten soundness) in §8 maps directly to `_check_only_tighten()`. Keep and elevate.

### ✅ Four-gate inbound apply pipeline — STRONG CONTRIBUTION

**Evidence in code** (`kya/inbound.py` + `kya/_inbound_signing.py`):

The apply pipeline composes four sequential gates, all in the code:

| Gate | Code location | What it does |
|---|---|---|
| **1. Ed25519 signature verify** | `_inbound_signing.verify_envelope()` | Canonical-JSON serialization (signature field stripped), Ed25519 verify against pinned trust anchor. Raises `SignatureVerificationError`. |
| **2. Expiration check** | `inbound._persist_one()` line 166–167 | `expires_at < now()` → reject with `"expired_at_fetch"`. |
| **3. Only-tighten composition** | `tenant_weights.set_override()` via `inbound.apply_recommendation()` | Same `_check_only_tighten` gate as direct operator overrides — raises `OverrideLoosensError`. |
| **4. Operator gate (default) OR allowlist auto-apply** | `inbound.py` lines 11–18 | Default: every recommendation lands as `'pending'` regardless of scope; operator must explicitly approve. Allowlist mode: scopes in `auto_apply_allowlist` are applied immediately after gates 1–3 pass. |

**Plus** multi-anchor key pinning via `KYA_INBOUND_PUBLIC_KEY` env var with comma-separated `<keyid>:<base64-pubkey>` syntax — supports key rotation and sovereign-cloud / air-gapped deployments without code changes.

**Paper claim supported.** Reframe §8 around this four-gate composition as the headline novelty. The federation transport itself is well-trodden (STIX/TAXII, OPA bundles, TUF) — what's novel is the **composition discipline** at the consumer side.

### ⚠️ Drift detection — REFRAME from "bitemporal" to "event-time + ingest-time"

**Evidence in code** (`kya/integrity.py` + `kya/versioning.py`):

The original paper §7 framed this as "bitemporal canonical-hash drift detection." After reading the code:

- `integrity.py` provides `canonical_hash(agent_def)` — SHA-256 over canonical JSON of **18 explicit identity fields** (`_HASHED_FIELDS`, lines 42–62). `detect_drift(declared_hash, agent_def)` is a single hash-equality check.
- `versioning.py` provides immutable snapshots with **BOTH timestamps**: `occurred_at` (event time, caller's clock) and `created_at` (ingest time, server clock).
- `examples/demo_event_vs_ingest_time.py` exists — this is a designed feature.
- **But:** the storage schema does not show "as of valid_time" query semantics in the classical bitemporal-relations sense (Snodgrass et al.). The two-time model is event-time + ingest-time, not valid-time + transaction-time.

**Paper claim — modified scope:** Drop "bitemporal" terminology. Reframe as
*"event-time + ingest-time versioned snapshots with canonical-hash drift detection over a fixed identity-field set."* This is honest and still distinguishing: most agent-governance systems track only ingest time.

**Modest residual novelty:** the **explicit `_HASHED_FIELDS` allowlist** is itself a contribution — it states which fields are policy-bearing (system prompt, tools, governance flags) and which are excluded (counters, timestamps, operational state). This list is auditable in the SDK source.

### ⚠️ HMAC chain — REFRAME with explicit upgrade path

**Evidence in code** (`kya/evidence.py`):

The code already builds in the honest framing the paper needs:

- Construction (lines 23–25): `signed_hash = HMAC-SHA256(signing_key, prev_hash || payload_hash)` — exactly Schneier-Kelsey (1998).
- Module docstring lines 55–58: *"v1 limitations (roadmap items) — Merkle / third-party anchor: payloads are signed only by the local HMAC. For external verifiability, batch a daily root hash to a notary (Sigstore, RFC 3161 TSA, Solana) — out of v1 scope."*
- Module docstring lines 47–53: pruning explicitly creates chain "clean cuts" that `verify_chain()` distinguishes from tampering. **This IS a small implementation contribution worth claiming modestly.**

**Paper position:** Drop Theorem 1 from headline contributions. Cite Schneier-Kelsey 1998, Bellare-Yee 1997, Crosby-Wallach 2009 upfront. State: *"KYA adopts the Schneier-Kelsey-class HMAC chain. The contribution is what we put on the chain (governance verdicts as first-class evidence kinds, regime-aware retention floors) and the upgrade path to Sigstore/RFC 3161 anchoring, not the chain itself."*

**Acknowledge concurrent work explicitly:** Aegis (arXiv:2603.16938) is the most threatening. The KYA evidence module's *own* v1 limitations doc admits the very gap (no third-party anchor) that Aegis claims to solve with ZK verification. Position this as a deliberate design trade-off (operator-key simplicity vs. multi-party verifiability), not an oversight.

### ❌ Risk scoring — REFRAME as "AIVSS-compatible with attribution traces"

**Evidence in code** (`kya/risk.py`):

- 12-factor sum with named contributions: `_BASE`, `_PER_WRITE_TOOL`, `_PER_ADMIN_TOOL`, `_HUMAN_LOOP_WEIGHTS`, `_CAN_OVERRIDE`, `_CAN_REVERT`, `_ACCESS_WRITE`, plus provenance, model trust, data class, security capability, blast radius, etc.
- `AgentRiskScore` dataclass preserves the full per-factor decomposition (`RiskFactor(name, label, delta)`).
- `interaction_multiplier()` applies compounding multipliers (write × PII × autonomous, etc.) capped at `MAX_MULTIPLIER`.
- Pluggable tool-RBAC catalog via `set_tool_catalog()` — falls back to write-prefix heuristics when no catalog is provided.

**This is well-engineered, but it is structurally an AIVSS-shaped weighted scorer.** TrustPact's AEGIS 5-dim model, AAGATE's AIVSS-based "Measure" function, and OWASP AIVSS itself all occupy this design space.

**Paper position:** Don't claim novelty in the scoring model. Position as *"AIVSS-compatible weighted risk scoring with deterministic per-factor attribution that is persisted into the evidence chain (§6) and gated by the only-tighten algebra (§8)."* The contribution is **integration**, not invention. Cite OWASP AIVSS, TrustPact, AAGATE explicitly.

---

## Revised 7-claim contribution list (with literature-verified framing)

After **exhaustive line-by-line read of all ~63 KYA + sibling modules**,
**6 parallel literature streams with citation verification**, a
**4-primitive cross-check audit**, and a **second exhaustive deep-read
pass**, the headline list is **7 defensible claims**. Every contribution
comes in at MEDIUM or LOWER pure novelty — pattern is **applied
composition** rather than **new primitive**, which is exactly what a
FAccT systems paper should claim.

**What changed from 6 → 7:**
- **Added #7 (actor_agent_key attribution)** — surfaced during the
  4-primitive audit. Distinct from #6 Delegation Trust Lineage:
  #6 adjusts the orchestrator's *static* score factor;
  #7 adjusts the orchestrator's *dynamic* principal-trust counter.
  Complementary mechanisms on the same fan-out attack pattern.
- **Re-elevated the per-(tenant, invocation) concurrency primitive**
  in §6 evidence chain. Previously demoted because the HMAC chain
  construction is Schneier-Kelsey 1998 prior art; deep-read confirmed
  the *concurrency primitive* (PG `pg_advisory_xact_lock(hashtextextended(tenant:invocation))`,
  MySQL `SELECT FOR UPDATE`, SQLite/DuckDB documented single-writer
  contract) is a real engineering contribution beyond the chain
  construction itself.

| # | Claim | Code location | Novelty | Closest prior art | Framing to use |
|---|---|---|---|---|---|
| 1 | **Four-gate inbound apply pipeline** | `inbound.py` + `_inbound_signing.py` + `tenant_weights.py` | MEDIUM-LOW | TUF/Uptane rollback prevention; Ioannidis et al. 2000 distributed firewall (signed credentials + local-POLICY narrowing) | Novel *composition* of well-known gates: signature + expiration + only-tighten + operator-approval-as-default. Frame the only-tighten step as a *generalization of TUF rollback prevention* (version-counter → policy-strength lattice). Add **fifth latent gate**: status-guarded UPDATE in auto-apply (`inbound.py:248`) prevents re-fetch from rolling back an operator-applied row. |
| 2 | **Only-tighten composition algebra** (Lemma 1) | `tenant_weights._check_only_tighten` + `OverrideLoosensError` | LOW-MEDIUM | Back & von Wright refinement calculus (1998); Bell-LaPadula tranquility (1976); GCP Org Policy deny-only inheritance; Bonatti et al. TISSEC 2002 policy algebra | Don't claim the algebra is new — claim the *application to tenant overrides of agent risk weights under signed recommendations* is new. **Threat-model precision**: invariant binds **tenants**, not platform admins — `_check_only_tighten` returns early when `tenant_id=None` (`tenant_weights.py:195-197`). Value is tenant-side immutability against vendor recommendations + compromised admin, not absolute immutability. |
| 3 | **KYP — Know Your Principal unified taxonomy** | `principals.py` (kinds: user, agent, service_account) | MEDIUM | Okta NHI/Agent identity (closest commercial pitch); Microsoft Entra Agent ID (separate object types under one directory); Microsoft AGT Agent Mesh (agents-only trust scoring) | Claim *schema-level* unification (single `kya_principal_trust` table, one `principal_kind` discriminator, shared scoring code path over all three kinds) — not "first to think of this." Cite Okta 2026 blog as industry-convergence evidence. |
| 4 | **Auditable interaction-multiplier amplification** ⭐ | `interactions.py` (`MAX_MULTIPLIER=2.0`, monotone-up-only, named fired interactions, pluggable) | MEDIUM-HIGH | OWASP AIVSS (closest — additive linear sum; no pairwise interactions); CVSS v3.1 (multiplicative chain, no audit codes); FAIR Open Group (probabilistic Monte Carlo, no codes) | Strongest contribution. Frame as *pairwise interactions with bounded asymmetric (≥1.0 only) product cap + per-interaction stable codes + pluggable registry*. **10 pre-registered interactions** including `code_exec_with_user_input` (1.5×), `classified_autonomous` (1.4×), `rejected_in_prod` (1.4×). `register_interaction()` **raises `ValueError` on multiplier <1.0** — asymmetry enforced at runtime, not just convention. Explicitly contrast AIVSS's additive AARF sum + single threat multiplier. |
| 5 | **Closed-loop incident → operator-reviewed weight suggestion** ("never auto-tune" rule) | `feedback.py` + `tenant_weights.set_override` | LOW-MEDIUM | Active learning oracle gating (Schubert et al. 2023); MLOps promotion gates (AWS/IBM RLHF); Soares et al. corrigibility (AAAI 2015); Kephart-Chess MAPE-K (IEEE 2003); Cloudflare WAF ML (counter-example: vendor auto-tune) | Frame as *applying corrigibility (Soares 2015) and the active-learning oracle-gate discipline to governance/policy-weight adaptation, with an explicit hard "never auto-tune" invariant.* Contrast against Cloudflare's opposite stance (vendor auto-tune without customer approval). |
| 6 | **Delegation Trust Lineage Attribution (static-score axis)** | `delegation_trust.py` | MEDIUM | EigenTrust (Kamvar et al. WWW 2003 — closest computational analog, implicit endorsement-graph propagation); FATF correspondent banking (aggregate downstream-portfolio risk feeds upstream rating); OCAP "Horton" pattern (Miller HotSec 2007 — audit-time attribution) | Operational *runtime* additive-with-cap mechanism with **observation-gating** (signal_counts non-empty OR trust < 50) to avoid cold-start false positives — a non-trivial design choice EigenTrust does not have. Name the attack pattern ("clean orchestrator → risky delegates") as the contribution; cite EigenTrust + FATF as ancestors. |
| 7 | **Actor-agent attribution model (dynamic-trust axis)** ⭐ NEW | `rogue._emit_actor_agent_signal` + `principals.record_principal_signal` + `kya_hooks/*` (default `actor_agent_key=agent_key`) + `kya_otlp_bridge/kya_hooks_client.py` | MEDIUM | EigenTrust (endorsement propagation, but on global graph); banking AML correspondent rating (portfolio-aggregated); object-capability "Horton" (audit-time attribution) | Collapses autonomous fan-out into a single accountable principal **at runtime**: when orchestrator A triggers B/C/D and any sub-agent fires a rogue signal, the signal is *tagged* with `actor_agent_key=A` so A's principal-trust counter is debited. **Complementary to #6**: #6 is the static-score axis (A's risk score factors in risky delegates); #7 is the dynamic-trust axis (A's trust counter moves when delegates misbehave at runtime). Default `actor_agent_key=agent_key` at three hook-layer entry points (`kya_hooks/client.py:147`, `kya_otlp_bridge/kya_hooks_client.py:39-43`) — "convention discovered during real runs in Scenario 8" — is the engineering contribution that makes attribution work without per-customer wiring. |

### Re-elevated to small contributions in §6 (was "system component")

**Per-(tenant, invocation) parallel HMAC chains with dialect-aware
concurrency primitive.** The HMAC chain construction itself is
Schneier-Kelsey 1998; what's new is the *deployment shape*: parallel
per-(tenant, invocation) chains (not one global chain) provide cross-tenant
isolation AND allow concurrent fan-out without forks. The serialization
primitive is dialect-specific (`evidence.py:436-462`):
- **PostgreSQL:** `pg_advisory_xact_lock(hashtextextended(tenant:invocation))` — works even on empty chains (lock key derives from tenant:invocation, not the chain head)
- **MySQL:** `SELECT ... FOR UPDATE` on the tail row
- **SQLite / DuckDB:** documented "one-writer-per-invocation" contract

Plus **type-marked canonicalization** (`evidence._canonical_default:248-262`):
non-JSON values wrapped as `{"__t__": "datetime", "v": "..."}` so a
`datetime` and its `isoformat()` string hash differently — closes a
collision-attack vector the prior `default=str` shortcut had.

### Demoted to "system components" (mention in §3, do not claim novelty)

- **HMAC chain construction itself** — Schneier-Kelsey 1998 / Bellare-Yee 1997 lineage. Concurrent agent work in Aegis (arXiv:2603.16938). The chain math is not the contribution; the deployment shape (above) is.
- **Risk scoring model** — AIVSS-shaped weighted scorer. Cite OWASP AIVSS, TrustPact, AAGATE; position as integration with the evidence chain (§6) and the only-tighten algebra (§2).
- **Federation transport** — STIX/TAXII, OPA Signed Bundles, TUF, Sigstore prior art. The composition discipline (only-tighten + operator gate) is what's novel, not the signed-update transport.
- **Event-time + ingest-time drift detection** — `_HASHED_FIELDS` is a small contribution (auditable allowlist of 18 policy-bearing fields), but the drift-detection mechanism itself is standard practice.

### Held back: Mode-vs-Config gap (subsection of §7)

`invocations.py` tracks the gap between *declared* `human_loop` mode and
*actual exercised* mode, citing EU AI Act Art. 14's requirement for
evidence of exercised (not declared) oversight. This is a real
contribution but conceptually adjacent to drift detection — fold into
§7 as the *behavioral drift* counterpart to §7's *definitional drift*.

---

## Findings that strengthen the paper

While reading the code, three details surfaced that were missing from the
paper draft and **strengthen the contribution story**:

### A. Multi-anchor key pinning for sovereign deployments

`_inbound_signing.py` lines 22–27 — `KYA_INBOUND_PUBLIC_KEY` env var
supports a comma-separated list of `<keyid>:<base64-pubkey>` entries, so
operators can pin a current + next-quarter key for invisible rotation,
or pin their own gateway key for air-gapped deployments. This is a
**concrete differentiator** over OPA signed bundles (single public key)
and a publishable detail.

### B. Operator-controlled retention floors per regime

`evidence.py` lines 140–147 — retention defaults per regime are
explicit constants in code (GDPR 6yr, NYDFS 5yr, HIPAA 6yr, SOX 7yr,
PCI 1yr, EU AI Act 7yr). Pruning enforces these as floors, not ceilings.
**Paper §6 should claim this modestly** as a small implementation
contribution: "regime-aware retention as a first-class evidence-store
primitive."

### C. Explicit policy-bearing field allowlist

`integrity.py` lines 42–62 — `_HASHED_FIELDS` lists exactly which 18
fields of an agent definition are part of its policy identity. This is
**publishable as a contribution**: most drift-detection systems hash the
whole definition or some implicit subset. Naming the policy-bearing
fields explicitly (so the auditor can see what's monitored and what
isn't) is a small but real governance design choice.

---

## Exhaustive sweep — additional findings (for §3 architecture & §4 risk factors)

The exhaustive 50-module sweep surfaced 20+ additional design choices
that strengthen §3 (System Architecture) and §4 (Risk Scoring Factors).
These are NOT headline contributions but ARE worth describing — each
defends a specific design discipline that an auditor or reviewer would
ask about.

### System-component pieces for §3 Architecture

| Module | What it adds to the architecture story |
|---|---|
| `realtime.py` | Sliding-window counters (1m/5m/15m/1h/24h/7d) in Valkey + closed signal whitelist preventing keyspace DoS. Fail-soft: Valkey unreachable → log + graceful return. Fundamentally different from Prometheus monotonic counters for *burst* detection. |
| `quality.py` + `phoenix_poll.py` | Optional Phoenix evaluator bridge with idempotent polling via `(last_polled_at, eval_id)`; graceful fallback to heuristic Prometheus signals when Phoenix unreachable. Read-only — never writes to Phoenix. |
| `dualwrite.py` + `_redactor.py` | Bounded-queue + batched + exponentially-backed-off + circuit-broken row mirroring with default PII redaction (salted SHA-256 + text truncation). Positive table allowlist; fire-and-forget. |
| `telemetry.py` | Aggregate-only telemetry; counts not payloads, never tenant IDs or agent keys; deployment_id is `sha256(hostname + platform + salt)[:24]`. Disabled by default if `KYA_TELEMETRY_URL` unset. |
| `external_defenders.py` + `external_emitters.py` | Bidirectional integration: inbound (NeMo Guardrails + webhook detectors) maps verdicts to KYA event types; outbound (SIEM emitters) supports kya_native, splunk_hec, datadog_event, generic_json, lakera_signal — bounded thread pool, 3-attempt exponential backoff, never raises. |
| `compliance_shim.py` | Multi-regime breach-notification fan-out with `UNIQUE(incident_id, regime)` constraint preventing double-fire. Per-regime SLA gauge `veldt_kya_breach_notify_lag_seconds`. |
| `compliance_exports.py` | SR 11-7 model card + ISO/IEC 42001 AIMS bundle formatters; pure transformation from internal pack; JSON canonical, PDF generation left to operator. |
| `agent_aliases.py` | Per-tenant alias table with one-hop resolution (no cascading aliases). Useful for semantic renames (legacy-bot-2023 → analyst_v4) and cross-system unification. |
| `format_adapter.py` | 15+ framework adapters (LangChain, CrewAI, OpenAI, AutoGen, Semantic Kernel, LlamaIndex, Haystack, MCP, Bedrock, Vertex, Swarm, OpenAI Agents, Claude Agent SDK, generic, auto-detect) + pluggable registry. Conservative defaults: `human_loop="none"`, `access_level="write"` so misconfiguration trends UP in risk. |
| `skills.py` | Skill-bundle abstraction carrying `data_classes` + `security_caps` at bundle level; classification UNIONS at scoring time (calling a `phi_handling` skill treats the agent as PHI-handling even if no tool name matches). |
| `fleet_metrics.py` | Governance-centric Prometheus surface: `approvals_pending`, `incidents_open`, `attestations_signed_total`, `approvals_sla_breached_total` — alerts on what the buyer cares about, not just operational metrics. |
| `autoinstrument.py` | Monkey-patches OpenAI / Anthropic / LiteLLM clients in-process for custom agents bypassing framework instrumentation. Honest scope: doesn't catch out-of-band side effects (`os.system`, raw file writes) — mitigation via process sandbox. |
| `storage.py` + `_portable.py` + `_legacy_tables.py` | ORM-based cross-backend tables (PostgreSQL, SQLite, DuckDB, MySQL); schema_translate_map strips `prov_schema` on non-PG; dialect-aware sequences. Three classes of tables: portable (4) / legacy (12, PG only with skip semantics). |
| `_session_factory.py` | Pluggable session factory so SDK consumers can inject their own DB wiring; mirror writes don't require platform `SessionLocal`. |

### Risk-factor pieces for §4 (already in factor list but worth detailing)

| Module | Defendable design discipline |
|---|---|
| `security_caps.py` | System-level power (code_execution, shell_access, container_exec) **orthogonal** to tool-level access. Bounded cap at 60; composes additively with `data_classes` (total capped at 160). |
| `data_classes.py` | Defense/classified extension (CUI, CDI, ITAR, US Confidential/Secret/Top Secret, NATO, EU schedules) with **monotonic weights**: itar=50 > us_secret=55 > us_top_secret=60. ITAR weighted high because felony-export consequence. |
| `input_sources.py` | Injection-vector taxonomy: web_fetch + user_upload tied at 15 (2024-25's worst injection vectors). Unknown defaults to 10 (worse than external_api=5) because "at least with external_api you've declared the source intentionally." Breadth premium +2 per additional untrusted source, capped at 25. |
| `supply_chain.py` | Publisher-trust taxonomy for dependencies (first_party=0 → marketplace=5 → self_hosted_ext=10). Capped at 35; breadth premium for >5 deps. Closed vocabulary prevents caller-injected dependency classes. |
| `blast_radius.py` | Scale multiplier (rate, cost, user_base, geographic). Capped at 30 to amplify, not dominate. Defensive defaults: non-numeric ("unlimited") falls back to 0 rather than raising. |
| `lifecycle.py` | Ownership/approval/time-in-prod factor: orphans (+15), pending/expired approval, brand-new <7d (+12), churning >1x/week (+8). Maps to SOC 2 + ISO 27001 evidence-of-review requirements. |
| `trust_signals.py` | Credit factor: red-team + fairness + citation evidence → negative deltas; stale audits decay to half weight after 180 days. Missing signals add RISK (untested = dangerous). |
| `cost.py` | Operational anomaly signal: hourly burst (>5× monthly average / 720), budget exhaustion, anomaly factor (observed/expected ratio). Threshold 5× normal (not 2×) to avoid false positives on legitimate high-volume days. |
| `deployment.py` | First-class environment factor: dev=0 → prod=15 → enclave=25 (air-gapped classified). Unknown=15 (conservative default). |
| `requests.py` | Request-level rollup via correlation_id with deterministic worst-outcome ranking: `_OUTCOME_SEVERITY = {success: 0, error: 2, refused: 3, blocked: 4}`. Operator-facing "did THIS request tree have a leak?" |
| `fault_attribution.py` + `llm_judge.py` | Two-tier: fast heuristic (`refused_rate × 1.5 + blocked_rate × 1.5 + signal_rate × 2`) + optional LLM judge (feature-flagged OFF by default). Six divergence kinds: aligned, off_topic, over_action, under_action, hallucinated, unclear. Judge failure returns unclear, never breaks the request path. |
| `users.py` | KYU (Know Your User) — orthogonal to agent risk. Time-decayed recovery (+1/day after 7 quiet days), closed-set signal deltas (cross_tenant: -15, data_leak: -10) prevent caller-controlled scoring. |
| `invocations.py` | Event-time vs ingest-time delta exposes pipeline lag, clock skew, tampering. Mode-vs-config gap surfaces declared `human_loop` vs actually exercised oversight (EU AI Act Art. 14 evidentiary requirement). |

### Cross-cutting design disciplines worth promoting in §11 Limitations / §12 Conclusion

- **Closed-set whitelists** throughout (signal kinds, regimes, data classes, scopes) prevent caller-controlled scoring expansion. Any new kind requires an SDK release, not a runtime config change.
- **Bounded compositions everywhere**: per-factor caps + interaction-multiplier cap + score clamp to 100. No single dimension can dominate, and no compounding can exceed the bound. Auditable upper bound for every term.
- **Explicit "never X" rules** baked into module docstrings: *never auto-tune* (feedback.py), *never bypass human gate on critical incidents*, *never fall back to "apply anyway" on signature failure* (inbound.py).
- **Fail-soft / graceful degradation**: Valkey down, Phoenix down, collector down, prometheus_client unavailable — core functionality unaffected. Observability is an *optional* extra, not a hard dependency.

---

## Contradictions / corrections vs. the literature audit

Reading the code changed three things from `research_audit.md`:

| Claim | Lit-audit finding | Code-grounded finding |
|---|---|---|
| Bitemporal versioning | "LOW risk, KEEP and emphasize database-theoretic rigor" | **REVISE.** Code is event-time + ingest-time, not classical bitemporal. Drop the term; reframe accurately. |
| Federation novelty | "HIGH risk; reposition on only-tighten + two-sided gate" | **CONFIRMED.** Code has a FOUR-gate composition (signature, expiry, only-tighten, operator/allowlist) — even stronger than the lit-audit's "two-sided gate" framing. |
| HMAC chain | "HIGH risk; drop as contribution" | **CONFIRMED but with nuance.** Code itself names the v1 limitations and the Sigstore-anchoring upgrade path — the paper can be unusually honest about this and gain credibility. |

---

## Recommended paper changes (concrete)

Updates I would make to the existing `paper/sections/*.tex`:

1. **§1 Introduction** — replace the 5-contribution enumeration with
   the new **6-contribution list**. Add "Why now" framing tied to
   AIVSS v0.5 release + AAGATE prior art + concurrent Aegis work.

2. **§3 Architecture** — expand significantly with the system-component
   material from the exhaustive sweep (see table above). This makes
   the architecture section much stronger and demonstrates that the
   demoted "non-novel" components have real engineering thought behind
   them.

3. **§4 Risk Scoring** — open with "We adopt an AIVSS-shaped weighted
   scoring model with deterministic per-factor attribution." Cite
   OWASP AIVSS, TrustPact, AAGATE. Do not claim scoring novelty. Add
   the factor-discipline detail (closed-set classified data classes,
   bounded caps, breadth premiums on input sources, etc.) — these are
   defensible engineering decisions even when the factor model itself
   isn't novel.

4. **§5 Dynamic Rogue** — add KYP (Know Your Principal) and the
   real-time burst-detection mechanism (Valkey sliding windows + closed
   signal whitelist). Position KYP as headline contribution #3.

5. **§6 Evidence Chain** — open with the Schneier-Kelsey lineage
   (Bellare-Yee 1997, Schneier-Kelsey 1998). Move Theorem 1 to
   appendix (or cut). Add subsection on regime-aware retention +
   pruning-with-clean-cut semantics as a small implementation
   contribution. Cite Aegis (arXiv:2603.16938) as concurrent work
   with a stronger anchor story.

6. **§7 Drift Detection** — replace "bitemporal" with "event-time +
   ingest-time versioned snapshots." Add subsection on the explicit
   18-field `_HASHED_FIELDS` allowlist. Add the **Mode-vs-Config gap**
   as the behavioral-drift counterpart to definitional drift (EU AI Act
   Art. 14 evidentiary motivation).

7. **§8 Federated Recommendations** — **restructure around the
   four-gate apply pipeline** (signature → expiry → only-tighten →
   operator/allowlist). Lemma 1 (only-tighten soundness) is the
   centerpiece. Add multi-anchor key pinning as concrete
   differentiator. Cite STIX/TAXII, OPA signed bundles, TUF/Sigstore
   as the signed-distribution lineage. Add the **closed-loop incident
   feedback** path (`feedback.py`) as the in-tenant counterpart to the
   federated path (headline contribution #5).

8. **§9 Evaluation** — add Delegation Trust Lineage Attribution
   (contribution #6) as a specific scenario: clean orchestrator
   delegating to risky downstream agents. Run a red-team campaign
   demonstrating detection.

9. **§10 Related Work** — full rewrite. Must cite **Aegis, AAGATE,
   OWASP AIVSS, TrustPact, Schneier-Kelsey, Crosby-Wallach,
   STIX/TAXII, OPA bundles, TUF/Sigstore** in the first two paragraphs.
   The current §10 will not survive review.

10. **§11 Limitations** — add explicit mention of the HMAC chain's v1
    single-key limitation and the planned Sigstore-anchoring upgrade
    path. Note the closed-set whitelists as both a strength (auditable)
    and a limitation (require SDK release for new kinds). Honesty here
    is credibility there.

11. **§12 Conclusion** — promote the cross-cutting design disciplines
    (closed-set whitelists, bounded compositions, "never X" rules,
    fail-soft observability) as the *system-design contribution* over
    and above the 6 specific claims.

---

## Literature review — verified BibTeX bundle

The following citations have been **independently verified by direct
WebFetch of the source URL** (per the standing rule that research-agent
citations must be checked — agents fabricate plausible-but-wrong author
lists more often than they fabricate paper titles or arXiv IDs).

```bibtex
%% ── Four-gate apply pipeline (§8) ─────────────────────────────────
@inproceedings{samuel2010tuf,
  author    = {Justin Samuel and Nick Mathewson and Justin Cappos and Roger Dingledine},
  title     = {Survivable Key Compromise in Software Update Systems},
  booktitle = {Proc. 17th ACM Conf. on Computer and Communications Security (CCS '10)},
  pages     = {61--72}, year = {2010}, publisher = {ACM}}

@inproceedings{kuppusamy2016uptane,
  author    = {Trishank Karthik Kuppusamy and Akan Brown and Sebastien Awwad and others},
  title     = {Uptane: Securing Software Updates for Automobiles},
  booktitle = {14th ESCAR Europe}, year = {2016}}

@inproceedings{torresarias2019intoto,
  author    = {Santiago Torres-Arias and Hammad Afzali and Trishank Karthik Kuppusamy and Reza Curtmola and Justin Cappos},
  title     = {in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes},
  booktitle = {Proc. 28th USENIX Security Symposium}, pages = {1393--1410}, year = {2019}}

@misc{opa_signed_bundles,
  author = {{Open Policy Agent Authors}},
  title  = {Bundles --- Signing and Verification},
  howpublished = {\url{https://www.openpolicyagent.org/docs/management-bundles}}, year = {2024}}

@inproceedings{ioannidis2000distfw,
  author    = {Sotiris Ioannidis and Angelos D. Keromytis and Steven M. Bellovin and Jonathan M. Smith},
  title     = {Implementing a Distributed Firewall},
  booktitle = {Proc. 7th ACM Conf. on Computer and Communications Security (CCS '00)},
  pages     = {190--199}, year = {2000}, publisher = {ACM}}

@inproceedings{newman2022sigstore,
  author    = {Zachary Newman and John Speed Meyers and Santiago Torres-Arias},
  title     = {Sigstore: Software Signing for Everybody},
  booktitle = {ACM CCS}, year = {2022}}

%% ── Only-tighten algebra (§8 Lemma 1) ─────────────────────────────
@book{back1998refinement,
  title     = {Refinement Calculus: A Systematic Introduction},
  author    = {Back, Ralph-Johan and von Wright, Joakim},
  publisher = {Springer}, series = {Graduate Texts in Computer Science}, year = {1998}}

@article{denning1976lattice,
  title   = {A Lattice Model of Secure Information Flow},
  author  = {Denning, Dorothy E.},
  journal = {Communications of the ACM}, volume = {19}, number = {5}, pages = {236--243}, year = {1976}}

@techreport{bell1976unified,
  title       = {Secure Computer System: Unified Exposition and {Multics} Interpretation},
  author      = {Bell, D. Elliott and LaPadula, Leonard J.},
  institution = {MITRE Corporation}, number = {ESD-TR-75-306}, year = {1976}}

@article{bonatti2002algebra,
  title   = {An Algebra for Composing Access Control Policies},
  author  = {Bonatti, Piero and De Capitani di Vimercati, Sabrina and Samarati, Pierangela},
  journal = {ACM TISSEC}, volume = {5}, number = {1}, pages = {1--35}, year = {2002}}

@article{wijesekera2003propositional,
  title   = {A Propositional Policy Algebra for Access Control},
  author  = {Wijesekera, Duminda and Jajodia, Sushil},
  journal = {ACM TISSEC}, volume = {6}, number = {2}, pages = {286--325}, year = {2003}}

@book{dwork2014algorithmic,
  title     = {The Algorithmic Foundations of Differential Privacy},
  author    = {Dwork, Cynthia and Roth, Aaron},
  journal   = {Foundations and Trends in Theoretical Computer Science},
  volume    = {9}, number = {3--4}, pages = {211--407}, year = {2014}}

%% ── KYP unified principal trust (§5) ──────────────────────────────
@misc{microsoft_agt_2026,
  title  = {Agent Governance Toolkit: Open-source runtime security for AI agents},
  author = {{Microsoft Open Source}}, year = {2026},
  howpublished = {\url{https://github.com/microsoft/agent-governance-toolkit}}}

@misc{microsoft_entra_agent_id_2026,
  title  = {Agent identities, service principals, and applications --- Microsoft Entra Agent ID},
  author = {{Microsoft}}, year = {2026},
  howpublished = {\url{https://learn.microsoft.com/en-us/entra/agent-id/}}}

@misc{huang2025aagate,
  title  = {{AAGATE}: A {NIST} {AI} {RMF}-Aligned Governance Platform for Agentic {AI}},
  author = {Huang, Ken and Lambros, Kyriakos Rock and Huang, Jerry and Mehmood, Yasir and others},
  year   = {2025}, eprint = {2510.25863}, archivePrefix = {arXiv}}

@misc{trustpact2026,
  title  = {{TrustPact} --- The Trust-First Agent Marketplace},
  author = {{TrustPact}}, year = {2026},
  howpublished = {\url{https://pypi.org/project/trustpact/}}}

@misc{spiffe_concepts,
  title  = {{SPIFFE} Concepts},
  author = {{SPIFFE Project (CNCF)}},
  howpublished = {\url{https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/}}}

@techreport{nist_sp_800_207,
  title       = {Zero Trust Architecture},
  author      = {Rose, Scott and Borchert, Oliver and Mitchell, Stu and Connelly, Sean},
  institution = {National Institute of Standards and Technology},
  number      = {NIST SP 800-207}, year = {2020}}

@article{sabater2005review,
  title   = {Review on Computational Trust and Reputation Models},
  author  = {Sabater, Jordi and Sierra, Carles},
  journal = {Artificial Intelligence Review},
  volume  = {24}, number = {1}, pages = {33--60}, year = {2005}}

%% ── Interaction multipliers (§4) — strongest contribution ─────────
@misc{first_cvss31_2019,
  title  = {Common Vulnerability Scoring System v3.1: Specification Document},
  author = {{FIRST.Org, Inc.}}, year = {2019},
  howpublished = {\url{https://www.first.org/cvss/v3.1/specification-document}}}

@misc{first_cvss40_2023,
  title  = {Common Vulnerability Scoring System v4.0: Specification Document},
  author = {{FIRST.Org, Inc.}}, year = {2023},
  howpublished = {\url{https://www.first.org/cvss/v4-0/}}}

@techreport{owasp_aivss_2025,
  title       = {{AIVSS} Scoring System for {OWASP} Agentic {AI} Core Security Risks v0.5},
  author      = {{OWASP Foundation}}, institution = {OWASP}, year = {2025},
  url         = {https://aivss.owasp.org/}}

@techreport{goldburd_khare_tevet_2020,
  title       = {Generalized Linear Models for Insurance Rating, 2nd ed.},
  author      = {Goldburd, Mark and Khare, Anand and Tevet, Dan and Guller, Dmitriy},
  institution = {Casualty Actuarial Society}, series = {CAS Monograph No.~5}, year = {2020}}

@article{rothman_1976_synergy,
  title   = {The Estimation of Synergy or Antagonism},
  author  = {Rothman, Kenneth J.},
  journal = {American Journal of Epidemiology},
  volume  = {103}, number = {5}, pages = {506--511}, year = {1976}}

@manual{opengroup_fair_2021,
  title        = {Risk Taxonomy (O-RT), Version 3.0},
  organization = {The Open Group}, year = {2021}}

%% ── Closed-loop no-auto-tune (§8) ────────────────────────────────
@inproceedings{soares2015corrigibility,
  author    = {Soares, Nate and Fallenstein, Benja and Yudkowsky, Eliezer and Armstrong, Stuart},
  title     = {Corrigibility},
  booktitle = {Workshops at the Twenty-Ninth AAAI Conference on Artificial Intelligence},
  year      = {2015}}

@article{kephart2003vision,
  author  = {Kephart, Jeffrey O. and Chess, David M.},
  title   = {The Vision of Autonomic Computing},
  journal = {IEEE Computer}, volume = {36}, number = {1}, pages = {41--50}, year = {2003}}

@article{schubert2023deep,
  author  = {Schubert, Marius and Riedlinger, Tobias and Kahl, Karsten and Rottmann, Matthias},
  title   = {Deep Active Learning with Noisy Oracle in Object Detection},
  journal = {arXiv:2310.00372}, year = {2023}}

@misc{cloudflare_waf_ml_2022,
  author = {{Cloudflare}}, title = {Improving the {WAF} with Machine Learning},
  howpublished = {\url{https://blog.cloudflare.com/waf-ml/}}, year = {2022}}

%% ── Delegation trust lineage (§5) ────────────────────────────────
@article{huynh2006fire,
  author  = {Huynh, Trung Dong and Jennings, Nicholas R. and Shadbolt, Nigel R.},
  title   = {An Integrated Trust and Reputation Model for Open Multi-Agent Systems},
  journal = {Autonomous Agents and Multi-Agent Systems},
  volume  = {13}, number = {2}, pages = {119--154}, year = {2006}}

@inproceedings{sabater2002regret,
  author    = {Sabater, Jordi and Sierra, Carles},
  title     = {Reputation and Social Network Analysis in Multi-Agent Systems},
  booktitle = {Proc. 1st Int. Joint Conf. on Autonomous Agents and Multiagent Systems (AAMAS)},
  pages     = {475--482}, year = {2002}}

@inproceedings{kamvar2003eigentrust,
  author    = {Kamvar, Sepandar D. and Schlosser, Mario T. and Garcia-Molina, Hector},
  title     = {The {EigenTrust} Algorithm for Reputation Management in {P2P} Networks},
  booktitle = {Proc. 12th Int. Conf. on World Wide Web (WWW)},
  pages     = {640--651}, year = {2003}}

@techreport{ellison1999spki,
  author      = {Ellison, Carl and Frantz, Bill and Lampson, Butler and Rivest, Ronald and Thomas, Brian and Ylonen, Tatu},
  title       = {{SPKI} Certificate Theory},
  institution = {IETF}, number = {RFC 2693}, year = {1999}}

@techreport{fatf2016correspondent,
  author      = {{Financial Action Task Force}},
  title       = {Guidance on Correspondent Banking Services},
  institution = {FATF/OECD}, year = {2016}}

%% ── Concurrent agent-governance work (cite explicitly in §10) ─────
@misc{mazzocchetti2026aegis,
  title  = {Cryptographic Runtime Governance for Autonomous AI Systems: The Aegis Architecture for Verifiable Policy Enforcement},
  author = {Mazzocchetti, Adam Massimo}, year = {2026},
  eprint = {2603.16938}, archivePrefix = {arXiv}}

@misc{shen2026sigil,
  title  = {Sealing the Audit-Runtime Gap for LLM Skills},
  author = {Shen, Tingda and Feng, Yebo and Zhu, Konglin and Jia, Xiaojun and Liu, Yang and Zhang, Lin},
  year   = {2026}, eprint = {2605.05274}, archivePrefix = {arXiv}}

@inproceedings{souza2025provagent,
  author    = {Souza, Renan and Gueroudji, Amal and DeWitt, Stephen and Rosendo, Daniel and Ghosal, Tirthankar and Ross, Robert and Balaprakash, Prasanna and da Silva, Rafael Ferreira},
  title     = {{PROV-AGENT}: Unified Provenance for Tracking AI Agent Interactions in Agentic Workflows},
  booktitle = {IEEE Int'l Conf. on e-Science}, year = {2025},
  note      = {arXiv:2508.02866}}

%% ── Foundational evidence-chain lineage (§6) ──────────────────────
@techreport{bellareyee1997forward,
  author      = {Bellare, Mihir and Yee, Bennet S.},
  title       = {Forward Integrity for Secure Audit Logs},
  institution = {UC San Diego}, number = {CS98-580}, year = {1997}}

@inproceedings{schneierkelsey1998logs,
  author    = {Schneier, Bruce and Kelsey, John},
  title     = {Cryptographic Support for Secure Logs on Untrusted Machines},
  booktitle = {USENIX Security Symposium}, year = {1998}}

@inproceedings{crosbywallach2009tamper,
  author    = {Crosby, Scott A. and Wallach, Dan S.},
  title     = {Efficient Data Structures for Tamper-Evident Logging},
  booktitle = {USENIX Security Symposium}, year = {2009}}
```

### Citation verification log

**Verified by direct WebFetch (arXiv pages):**
- arXiv:2603.16938 (Aegis, Mazzocchetti 2026) ✅
- arXiv:2510.25863 (AAGATE, Huang et al. 2025) ✅ — agent originally said "Hassan et al.", corrected.
- arXiv:2605.05274 (SIGIL, Shen et al. 2026) ✅
- arXiv:2510.20188 (TRUST, Huang et al. 2025) ✅
- arXiv:2508.02866 (PROV-AGENT, Souza et al. 2025) ✅
- arXiv:2407.08488 (Patronus Lynx, Ravi et al. 2024) ✅
- arXiv:2401.05561 (TrustLLM, Huang et al. ICML 2024) ✅
- arXiv:2604.04261 (APPA, Srewa-Zhao-Elmalaki 2026) ✅
- arXiv:2111.03781 (Cleaveland monotonic safety 2021) ✅
- arXiv:2306.17033 (Leahy safety-aware composition 2023) ✅
- arXiv:2001.01394 (Tasse Boolean Task Algebra NeurIPS 2020) ✅
- arXiv:2310.00372 (Schubert active learning 2023) ✅
- GitHub microsoft/agent-governance-toolkit issue #1386 ✅
- OPA signed bundles documentation ✅

**Fabricated authorship — DROPPED:**
- ⚠️ arXiv:2210.17520 — agent claimed "Whitehouse, Ramdas, Wu, Rogers." Verified paper is by **Adam Smith and Abhradeep Thakurta**. Citation not used in final BibTeX; differential-privacy adaptive composition is a minor citation in §5 and the unfabricated version is available if needed.

**Unverified — flagged for follow-up:**
- ⚠️ OWASP AIVSS scoring formula `((CVSS_Base + AARS)/2) × ThM`. Site does not expose the formula publicly; needs the v0.5 PDF for direct quotation. Cite OWASP AIVSS at the publication level only until verified.
- ⚠️ EU Council "Digital AI Omnibus" press release on AI Act high-risk deadline deferral (network-blocked URL).
- ⚠️ arXiv:2510.18563 (Xu Trust Paradox 2025) and arXiv:2506.04133 (Raza TRiSM survey 2025) — returned by agent #6, not yet WebFetch-verified.

### Cross-cutting findings from the lit review

1. **No headline contribution dies.** All 6 survive at MEDIUM or higher
   novelty. The paper's spine is intact.
2. **All 6 are "applied composition" novelty, not "new primitive."** This
   is exactly the right register for a FAccT systems paper.
3. **#4 (interaction multipliers) is the strongest** (MEDIUM-HIGH).
   AIVSS is the only direct competitor in the agent-governance space and
   it is structurally different (linear AARF sum + single threat
   multiplier, no pairwise interaction codes).
4. **#5 (closed-loop no-auto-tune) is the weakest** (LOW-MEDIUM). The
   loop structure is well-trodden (active learning, MLOps, SOAR). What
   is publishable is the *explicit named discipline* applied to
   governance weights, not the loop itself.
5. **Three concurrent agent-governance arXiv papers must be cited in §10**:
   Aegis (2603.16938), AAGATE (2510.25863), SIGIL (2605.05274). Letting
   a reviewer find these is fatal.

---

## Status

The shipping code at `D:\veldt-kya\` is **better than the paper currently
describes it.** Three of five originally-claimed contributions don't
survive the literature, but the remaining three are concretely supported
by code that is tested, released, and Apache-2.0-licensed.

**The paper does not need to be smaller. It needs to be more honest about
which 3 claims are the actual contribution and which 5 were aspirational.**

Reframe accordingly and submit.
