# KYA — Novel Primitives

**Status:** technical contributions catalogue (Round-2 lit-review verified, 2026-05-21)
**Audience:** engineers onboarding, paper reviewers, IP counsel, design partners

Seven primitives in the KYA codebase are independently surveyed in a
two-round literature review (arXiv + Google Scholar + OOPSLA / S&P /
FSE recent venues). The result of the review:

| # | Primitive | Novelty (R1) | Novelty (R2) | Direction |
|---|---|---|---|---|
| 1 | Four-gate apply | medium-low | **medium** | ⬆ |
| 2 | Only-tighten algebra | low-medium | **low** (Cedar precedent) | ⬇ |
| 3 | **KYP — unified principal** taxonomy | medium | **medium-high** | ⬆ |
| 4 | Interaction multipliers ⭐ | medium-high | **high** | ⬆ |
| 5 | Closed-loop no-auto-tune | low-medium | **medium** | ⬆ |
| 6 | Delegation trust lineage | medium | **medium-high** | ⬆ |
| 7 | `actor_agent_key` attribution (new) | — | **medium-high** | new |

Round-2 found more prior art for some primitives (notably Cedar OOPSLA 2024
for #2) and confirmed others. **Six of seven contributions strengthened; one
weakened but survives via reframing.** None were gutted.

This doc exists for three reasons:
1. **Defensive prior art** for the forthcoming paper — by publishing,
   we preempt anyone patenting these primitives against us.
2. **Onboarding material** — new engineers can locate the load-bearing
   ideas fast.
3. **Differentiation positioning** vs eval-only tools (`deepeval`,
   `lm-eval`) and broad-scope governance toolkits (Microsoft Agent
   Governance Toolkit) — those don't have these specific primitives.

Note on naming: **"KYA" is the product / SDK brand**, unchanged. **"KYP"
(Know Your Principal)** is the *paper's name for contribution #3* (the
unified user + agent + service-account principal taxonomy). Chaffer 2025
SSRN coined "Know Your Agent" first for an agent-only Web3 framework, so
the paper uses KYP for the broader unification, citing Chaffer and
extending the analogy.

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

## 3. KYP — Know Your Principal (unified user + agent + service taxonomy)

**Where it lives:**
- `kya/principals.py:81` — `PRINCIPAL_KINDS = ("user", "agent", "service_account")`
- `kya/principals.py:213` — `_PrincipalRow` declarative model: **one table** for all three kinds, composite PK on `(tenant_id, principal_kind, principal_id)`
- `kya/principals.py:record_principal_signal()`, `record_principal_clean()`, `get_principal_trust()`, `list_principals()` — same API operates on any kind
- Table: `kya_principal_trust` with `principal_kind` field discriminating user / agent / service_account

**What it does.** A single trust-scoring schema and API spans three
principal kinds. A user, an agent, and a service account in the same
tenant are scored on identical signal counters and trust math. When
an agent acts on a user's behalf and that action misbehaves, the
signal can be attributed to *either* the agent (immediate offender)
*or* the user (driving principal) *or* both — via the same primitive.

**Why it's novel.** Most "agent governance" tools (Microsoft AGT,
LangSmith, Arize Phoenix) treat agents as a separate object class from
users. Identity tools (Okta, Azure AD) treat humans and service
accounts but not agents. The IAM/IdP literature has no unified
principal taxonomy that includes autonomous AI agents alongside
humans and service accounts.

Chaffer 2025 (SSRN) coined "Know Your Agent" for a Web3 agent-only
framework — but constrained to agents alone. The KYP unification
extends the KYC analogy to **all principals that can drive agent
actions** — humans, agents, and service accounts in one schema.

**What it enables.** A single audit log query answers "who is the
risky principal in this tenant?" regardless of whether the answer is
a user, an autonomous agent, or a service account. Enterprise buyers
who already trust KYC processes for humans get a natural extension to
agents and service accounts — same operational mental model.

---

## 4. Interaction multipliers (multiplicative risk composition) ⭐

**Where it lives:**
- `kya/interactions.py` — `INTERACTIONS` rule table, `interaction_multiplier()`
- `kya/risk.py` — `score_agent()` applies `MAX_MULTIPLIER` cap of 1.5×
- `kya/interactions.py:detect_interactions()` — surfaces which pairwise
  factor combinations trigger amplification

**What it does.** Risk score isn't just `base + sum(factors)`. When
certain factor pairs co-occur, the score is *multiplied* by a
configured factor (e.g., 1.15× for `unowned_high_risk`, 1.2× for
`unowned_autonomous`). The total composite cannot exceed
`base + sum × MAX_MULTIPLIER` (currently 1.5×), so the boost is
bounded — but the *direction* of asymmetry is intentional.

**Why it's novel.** This is the **strongest single claim** in the
paper per Round-2 lit review. Closest priors:

- **AIVSS** (AI Vulnerability Scoring System) — uses additive AARS
  (Adjusted Aggregate Risk Score). Linear composition only.
- **AURA** (arXiv:2510.15739, 2025) — closest competitor for
  agentic-risk scoring; still additive.
- **CVSS / EPSS / NVD scoring** — all additive.

KYA's multiplicative composition with directional asymmetry (only
amplifies; never reduces) means risk grows *super-additively* when
red-flag factors co-occur, which is closer to how humans actually
intuit compound risk. Standard methodologies under-score the truly
dangerous combinations.

**What it enables.** "Two yellow flags = one red flag" — the math
catches dangerous combinations that additive scoring misses (e.g.,
unowned + autonomous + write-access becomes >100 = critical, not
just summed to "high").

---

## 5. Only-tighten weight invariant — three-channel hierarchy extension

**Where it lives:**
- `kya/tenant_weights.py:set_override()` — the single enforcement point
- Called from three independent authority channels:
  - `kya/feedback.py:approve_suggestion()` (in-tenant feedback loop)
  - `kya/inbound.py:approve_recommendation()` (cross-tenant signed
    recommendations)
  - `kya/inbound.py:_auto_apply_if_allowed()` (customer-configured
    auto-apply allowlist)

**What it does.** A tenant weight override can only **raise** the
effective risk weight relative to the platform default — never lower
it. The constraint is checked inside `set_override()` and raises
`OverrideLoosensError` on violation. The invariant holds across all
three authority channels: in-tenant operator approvals, cross-tenant
Veldt-signed recommendations, and customer-configured auto-apply.

```python
set_override(scope="class_weights", key="pii",
             value=lower_than_platform_default)
# → raises OverrideLoosensError; the row is NOT updated
```

**Why it's "low" individual novelty but useful in combination.**
Round-2 lit review found **Cedar (Cutler et al., OOPSLA 2024,
arXiv:2403.04651)** ships a Lean-mechanized formal proof that *forbid
dominates permit under composition* at the single-policy-set level.
That's structurally similar to "only-tighten" — same one-way property
at the policy-language layer.

The KYA contribution that survives review: **extending Cedar-style
forbid-dominance to a multi-authority hierarchy** (platform-default →
tenant override → signed external recommendation), with the
same one-way invariant holding across all three channels — not just
within one policy set. Paper framing: *"three-channel extension of
Cedar's forbid-dominance to multi-tenant authority hierarchy with
signed external recommendations."*

Closest baselines (to cite, not claim novelty over):
- Cedar (Cutler et al., OOPSLA 2024) — single-policy forbid-dominance ✓
- Istio AuthorizationPolicy — deny-default precedence
- GCP Deny Policies — deny dominates allow
- Linux capabilities `drop-only`, SELinux strict mode

**What it enables.** Survives compromise. Survives social engineering.
Survives a "we'll just lower this temporarily" Slack request — across
all three authority paths simultaneously. Maps cleanly to the
immutability/integrity controls that SOC 2 CC6 / EU AI Act Article 15
/ ISO 42001 demand.

---

## 6. Delegation trust lineage (child-debits-parent, not parent-caps-child)

**Where it lives:**
- `kya/delegation.py` — `delegation_chain()`, `max_delegation_depth()`,
  `delegation_weight()`
- `kya/delegation_trust.py` — `delegation_trust_weight()`
- Cross-references in `kya/principals.py` — `actor_human_id` field
- Audit chain attribute `_collaboration_chain` on agent contexts

**What it does.** When a parent agent delegates to a child agent and
the child misbehaves, the **trust deficit propagates UP the chain**
to the parent — not the inverse direction (parent imposing constraints
downward). Each delegation step recorded as a lineage edge that
contributes to retrospective accountability.

**Why it's novel.** This is the direction-flip claim — and the lit
review confirms it's defensible:

- **Microsoft Agent Governance Toolkit** (April 2026) — does
  **parent-caps-child**: the parent's policy ceiling constrains what
  delegated children may do. Constraints flow downward.
- **Liang et al. 2025** (arXiv:2512.04129, "Don't Trust Your
  Upstream") — names the *attack pattern* (upstream agents compromise
  downstream) but no countermeasure direction.
- **AgenTracer** (arXiv:2509.03312) — failure attribution flows
  *downward* (root-cause to leaf agent).

KYA's contribution: trust deficit flows **child → parent**. If
delegate B misbehaves under principal A's direction, A's trust takes
the hit too. This generalizes "the manager owns the work" to
autonomous agent hierarchies.

**What it enables.** SOC analysts see the actual responsible
principal, not just the immediate offender. Aligns governance with
real organizational accountability (you're responsible for what your
delegates do).

---

## 7. `actor_agent_key` runtime attribution (new contribution)

**Where it lives:**
- `kya/rogue.py:_emit_actor_agent_signal()` — the mirror helper
- Routed from `record_oos_tool_attempt()`, `record_cross_tenant_attempt()`,
  `record_data_leak()`, `record_policy_violation()` (all in `rogue.py`)
- Persisted via `kya/principals.py:record_principal_signal()`
- Read back via `kya/rogue.py:get_rogue_signals()`

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
independent accountable units. SOC tools log each event separately.
Round-2 lit review found:

- **Gabison & Xian 2025** (arXiv:2504.03255) — *names* the
  principal-agent liability gap but provides no implementation.
- **AgenTracer** (arXiv:2509.03312) — opposite direction (downward
  trace of failures).
- **Wu et al. 2025** (arXiv:2510.19420) — node-level evaluation of
  multi-agent systems; doesn't unify attribution to a trigger.

The `actor_agent_key` field generalises across:

- CrewAI orchestrator → workers
- AutoGen conversational chains
- OpenAI Agents SDK handoffs
- OpenCLAW autonomous triggers
- Anthropic Claude Agent SDK subagents

…all through a single field rather than per-framework adapters.

**Paper-venue strategy (per Round-2 review):** workshop venue
(SafeAI / REALM / SaTML) safer than top-tier first — the contribution
is genuinely new but reviewers could argue "obvious extension of
provenance." Workshop venue establishes priority; top-tier follows
after empirical evidence.

**What it enables.** One accountable principal for an entire autonomous
chain. A SOC analyst sees ONE risky entity, not three scattered events
that need correlation. Trust scores accumulate against the agent that
controls behaviour — exactly the entity the governance team can
reconfigure / revoke.

---

## In-tenant feedback loop with attestation closure (composition of #1+#5)

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

## Round-2 lit review — required citations (must-add)

Verified prior art that the paper must engage with directly:

- **Cedar** (Cutler et al., OOPSLA 2024, arXiv:2403.04651) — single-policy forbid-dominance; baseline for primitive #5
- **Microsoft Agent Governance Toolkit** (April 2026) — parent-caps-child; explicit contrast for #6
- **AURA** (arXiv:2510.15739, 2025) — closest agentic risk competitor; additive, not multiplicative (for #4)
- **AIVSS** — Adjusted Aggregate Risk Score, confirmed additive (for #4 contrast)
- **AgenTracer** (arXiv:2509.03312) — failure attribution opposite direction (for #6, #7)
- **Gabison & Xian 2025** (arXiv:2504.03255) — names principal-agent liability gap (for #7 motivation)
- **Liang et al. 2025** (arXiv:2512.04129) "Don't Trust Your Upstream" — names attack pattern (for #6)
- **Wu et al. 2025** (arXiv:2510.19420) — multi-agent system node evaluation
- **Chaffer 2025** (SSRN) — "Know Your Agent" for Web3; KYP rebrand precedent for #3
- **Janani 2025** (arXiv:2503.18255) — human-machine identity blur (for #3)
- **FDA PCCP guidance 2024** — change-envelope analog for closed-loop framing
- **Nayebi 2025** (arXiv:2507.20964) — corrigibility formal framework
- **Hudson 2025** (arXiv:2510.15395) — corrigibility transformation
- **Tan et al. 2026** (arXiv:2603.28988) — attestation gates
- **Burke et al. 2026** (arXiv:2511.13641) — Rebound IEEE S&P
- **Sanwouo et al. 2025** (FSE 2025) — AWARE MAPE-K successor

## Key reframings per Round-2 findings

| Where | Was | Now |
|---|---|---|
| §1 / §8 of paper | "Novel only-tighten algebra" | "Three-channel extension of Cedar's forbid-dominance to multi-tenant authority hierarchy" |
| §1 / §5 of paper | "KYA — Know Your Agent" | "KYP — Know Your Principal" (citing Chaffer 2025) |
| §5 closed-loop | "Never auto-tune as design discipline" | "First SaaS-tenant analog of FDA PCCP-style change-envelope for AI governance weights" |
| §6 delegation | "Lineage attribution" | Explicit direction-flip contrast with Microsoft AGT (parent-caps-child vs child-debits-parent) |
| §8 actor_agent_key | "Runtime attribution" | Workshop-venue framing (SafeAI/REALM/SaTML first) — preempts "obvious extension of provenance" objection |

## Related docs

- [`OPEN_CORE_STRATEGY.md`](OPEN_CORE_STRATEGY.md) — what's OSS vs proprietary
- [`PAPER_REPOSITIONING_AUDIT.md`](PAPER_REPOSITIONING_AUDIT.md) — Round-2 lit review verdicts
- [`PYPI_RELEASE_CHECKLIST.md`](PYPI_RELEASE_CHECKLIST.md) — pre-publish gate
- [`VERIFICATION_REPORT.md`](VERIFICATION_REPORT.md) — what's actually tested
