# KYA — Novel Primitives

**Status:** technical contributions catalogue
**Date:** 2026-05-21
**Audience:** engineers onboarding, paper reviewers, IP counsel, design partners

Four primitives in the KYA codebase are genuinely novel — not in the sense of
"never been thought before" but in the sense of "haven't been combined and
shipped this way." The rest of the codebase is solid composition of
well-known patterns (HMAC chains, PKI pinning, retry-with-backoff, etc.) —
no claim of novelty there.

This doc exists for three reasons:
1. **Defensive prior art** for the forthcoming paper — by publishing,
   we preempt anyone patenting these primitives against us.
2. **Onboarding material** — new engineers can locate the load-bearing
   ideas fast.
3. **Differentiation positioning** vs eval-only tools (`deepeval`,
   `lm-eval`) and broad-scope governance toolkits (Microsoft Agent
   Governance Toolkit) — those don't have these specific primitives.

---

## 1. The `actor_agent_key` attribution model

**Where it lives:**
- `kya/rogue.py:_emit_actor_agent_signal()` — the mirror helper
- Routed from `record_oos_tool_attempt()`, `record_cross_tenant_attempt()`,
  `record_data_leak()`, `record_policy_violation()` (all in `rogue.py`)
- Persisted via `kya/principals.py:record_principal_signal()`
- Read back via `kya/rogue.py:get_rogue_signals()` (the DB-primary path)

**What it does.** When agent A triggers a fan-out (calls or delegates to
agents B, C, D) and any of B/C/D misbehave — wrong tool, cross-tenant
attempt, data leak — the rogue signal attributes back to **A** (the
trigger / orchestrator-of-record), not just to B/C/D. Each `record_*`
call accepts an `actor_agent_key` parameter; when supplied, the
signal is mirrored to the actor's principal-trust row in addition to
the immediate offender's metrics.

```python
record_oos_tool_attempt(
    agent_key="OpenClawBrowserAgent",     # the agent that misbehaved
    tool="export_dom_to_clipboard",
    tenant_id=tid,
    actor_agent_key="OpenClawCalendarAgent",  # who started the chain
)
# → Calendar's principal-trust row gets credited with one oos_tool signal
```

**Why it's novel.** Multi-agent governance literature (Microsoft Agent
Governance Toolkit, the Mosaic paper, NIST AI RMF) treats agents as
independent accountable units. SOC tools log each event separately. None
collapse a fan-out into the trigger principal automatically. The
`actor_agent_key` field generalises across:

- CrewAI orchestrator → workers
- AutoGen conversational chains
- OpenAI Agents SDK handoffs
- OpenCLAW autonomous triggers
- Anthropic Claude Agent SDK subagents

…all through a single field rather than per-framework adapters.

**What it enables.** One accountable principal for an entire autonomous
chain. A SOC analyst sees ONE risky entity, not three scattered events
that need correlation. Trust scores accumulate against the agent that
controls behaviour — exactly the entity the governance team can
reconfigure / revoke.

---

## 2. Per-(tenant, invocation) tamper-evident chain

**Where it lives:**
- `kya/evidence.py:record_evidence()` — chain extension
- `kya/evidence.py:verify_chain()` — chain validation
- `kya/evidence.py` lines around the `prev_hash` SELECT — uses
  `pg_advisory_xact_lock` on PostgreSQL keyed on `(tenant_id, invocation_id)`
  and `SELECT FOR UPDATE` on MySQL for the tail row
- Schema: `kya_evidence` table with composite scoping by `(tenant_id, invocation_id)`

**What it does.** Each evidence row carries `prev_hash` (the previous
row's `signed_hash` in this exact `(tenant, invocation)` chain) and
its own `signed_hash = HMAC(key, prev_hash || payload_hash)`. The
chain is therefore append-only and tamper-evident: any modification to
a past row breaks every signature downstream. Verification walks the
chain from genesis to tip recomputing each signature.

Concurrency: PG advisory locks keyed on (tenant, invocation) serialise
chain extensions. MySQL uses `FOR UPDATE` on the tail row. SQLite/DuckDB
rely on default serial isolation. The 5-phase concurrency load test
(20 workers × 50 ops on a single chain) passes with `verify_chain →
valid=True checked=1000` — proof the serialisation works.

**Why it's novel.** HMAC chains in isolation are standard (Merkle trees,
blockchain). What's unusual is the combination:

| Aspect | Standard practice | KYA |
|---|---|---|
| Chain scoping | Per-system or per-stream | Per-(tenant, invocation) — every individual agent execution gets its own chain |
| Concurrency primitive | Single-writer assumed | Cross-dialect locks (advisory on PG, FOR UPDATE on MySQL) |
| Verification | Linear walk | Walk + cross-check against payload hashes |
| Tenant isolation | Application-level | Schema-enforced |

**What it enables.** A regulator can demand "show me everything agent X
did during incident 4271, and prove no row was tampered with after the
fact." The chain verifies in O(n) and surfaces the exact byte position
of any mutation. EU AI Act Article 12 + Article 19 evidentiary
requirements map directly to this.

---

## 3. The only-tighten weight invariant

**Where it lives:**
- `kya/tenant_weights.py:set_override()` — the single enforcement point
- Called from:
  - `kya/feedback.py:approve_suggestion()` (in-tenant feedback loop)
  - `kya/inbound.py:approve_recommendation()` (cross-tenant signed
    recommendations)
  - `kya/inbound.py:_auto_apply_if_allowed()` (customer-configured
    auto-apply allowlist)

**What it does.** A tenant weight override can only **raise** the
effective risk weight relative to the platform default — never lower
it. The constraint is checked inside `set_override()` and raises
`OverrideLoosensError` on violation. Every code path that mutates a
weight routes through this function; no escape hatch.

```python
set_override(scope="class_weights", key="pii",
             value=lower_than_platform_default)
# → raises OverrideLoosensError; the row is NOT updated
```

**Why it's novel.** Governance frameworks (Snyk policies, AWS Config
Rules, OPA Rego) allow arbitrary policy mutation by sufficiently-
privileged admins. They assume admins are trusted. KYA's invariant
**takes that assumption away**: even a compromised admin, a malicious
inside attacker, or a leaked signing key cannot loosen tenant risk
weights below the platform default. The system is *trust-monotonic* —
once a weight is tightened, it only goes higher (or stays).

Combine this with cryptographic attestation at every weight change
(`kya_weight_changes` table) and you get a **provable monotone
ratchet**: an auditor can reconstruct the entire history of weight
adjustments, verify each was attested, and prove no past tightening
was undone.

**What it enables.** Survives compromise. Survives social engineering.
Survives a "we'll just lower this temporarily" Slack request. Maps
cleanly to the immutability/integrity controls that SOC 2 CC6 / EU AI
Act Article 15 / ISO 42001 demand.

---

## 4. In-tenant feedback loop with attestation closure

**Where it lives:**
- Trigger: `decisions/governance/incidents.py:resolve_incident()` (in
  the `veldt-decisions` private repo — vd-app's resolution endpoint)
- Suggestion generator: `kya/feedback.py:propose_from_incident()`
- Approval + apply: `kya/feedback.py:approve_suggestion()` →
  `kya/tenant_weights.py:set_override()`
- Audit trail tables: `governance_incidents` → `kya_weight_suggestions`
  → `kya_weight_changes` → `kya_weight_overrides`

**What it does.** A complete closed-loop control system:

```
critical incident
      ↓ resolve_incident(status="resolved")
propose_from_incident() — generates 1-N weight-tightening suggestions
      ↓ persisted to kya_weight_suggestions (status="pending")
operator reviews via admin UI / API
      ↓ approve_suggestion(suggestion_id, ...)
set_override() — applies the new weight (only-tighten gate)
      ↓
effective risk weight is now tightened for this tenant
```

Every transition writes to a separate audit table; every transition
has attestation; the apply step is gated by the only-tighten invariant
(Primitive 3); the proposal logic is incident-type-aware (different
patterns for `pii_detection`, `content_safety`, `cross_tenant`).

**Why it's novel.** Most governance systems stop at "alert the
operator." Some (PolicyPak, OPA) let you write static policies. None
build the **automatic learning loop** where:

- The system itself proposes the tightening from observed incidents
- The operator's role is reduced to approve/reject (one click)
- The terminal state is mathematically constrained (only-tighten)
- Every transition is attested for an auditor

This is **closed-loop trust engineering**: incidents tighten the
governance posture without manual policy authoring, while preserving
human-in-the-loop control and mathematical guarantees against abuse.

**What it enables.** "We learn from our incidents — by design, with
proof." A regulator can demand evidence that the tenant's risk
posture has actually responded to the past 12 months of incidents.
KYA can produce that evidence as a queryable trail with attestation
at every step.

---

## What is NOT novel (so readers don't confuse standard composition)

To preempt the "is X novel?" objection — the following are well-known
patterns that KYA composes well but didn't invent:

- HMAC chains in isolation (Merkle trees, hash chains, blockchain)
- TUF (The Update Framework) style signed metadata distribution
- PKI key pinning (RFC 7469 HPKP, certificate pinning)
- Dual-write / change-data-capture mirroring patterns
- Open-core monetization (HashiCorp Vault, Sentry, Confluent)
- Additive risk scoring with attributable factors (FICO, every credit
  model since 1980)
- PEP 562 lazy module imports
- Pluggable session factory / dependency injection
- `SELECT FOR UPDATE` for read-modify-write
- Retry-with-exponential-backoff
- Bounded queue + circuit breaker for fire-and-forget delivery
- Per-tenant schema isolation
- Ed25519 signature verification

The 4 primitives above are novel **because of the specific combination
and constraints**, not the underlying cryptographic / database / Python
primitives.

---

## IP strategy implications

Software patents are hard post-*Alice v. CLS Bank* (2014). Pure SDK
plays usually skip patents and rely on:

1. **Speed + distribution** (first-mover, brand)
2. **Network-effect moat** (the proprietary collector / aggregate
   telemetry — see `OPEN_CORE_STRATEGY.md`)
3. **Defensive paper publication** (this doc + a peer-reviewed paper
   become *prior art* that prevents competitors from patenting against
   you)

**The cheap optionality move:** before the public GitHub push, file a
US provisional patent for ~$65 USPTO fee naming Primitives 1-4 as
claims. A provisional is a placeholder filing — it locks the priority
date but doesn't commit you to a full filing. You have 12 months to
decide whether to convert to a non-provisional ($10k-$30k) or let the
provisional lapse. Useful insurance even if you ultimately skip
patents.

**Don't bother with international patents.** Most jurisdictions (EU,
China, Japan, India, Korea) have absolute novelty rules — any public
disclosure (arXiv, GitHub, blog) destroys patentability everywhere
except the US.

**Recommended path:** publish the paper (Primitive 1-4 as defensive
prior art), file one US provisional naming the combination as the
claim, skip everything else. Total cost ~$130 in filing fees.
Maximum optionality for the next 12 months at almost zero cost.

---

## Related docs

- [`OPEN_CORE_STRATEGY.md`](OPEN_CORE_STRATEGY.md) — what's OSS vs proprietary
- [`PAPER_REPOSITIONING_AUDIT.md`](PAPER_REPOSITIONING_AUDIT.md) — paper claim audit
- [`PYPI_RELEASE_CHECKLIST.md`](PYPI_RELEASE_CHECKLIST.md) — pre-publish gate
- [`VERIFICATION_REPORT.md`](VERIFICATION_REPORT.md) — what's actually tested
