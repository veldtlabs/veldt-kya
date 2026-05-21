# KYA Collector — scope, phasing, and recommendation

**Status:** decision doc · not yet committed to a build
**Date:** 2026-05-20
**Owner:** Veldt Labs founders

## Context

The KYA SDK ships with both an outbound (telemetry + dual-write) path
and an inbound (signed recommendations) path. Both are wired, tested,
and committed (`5bb9574` → `c5f6cf8`). The SDK is complete and
ship-ready today.

What is NOT built is the **Veldt-side collector service** that the
inbound path pulls from. This doc captures what the collector
actually is, what it would take to build, and the recommendation on
whether to build it now or later.

---

## What "build the collector" actually means

The SDK side is done. The collector is a separate Veldt-operated
service that:

1. Receives outbound telemetry + dual-write rows from customer SDKs
2. Stores them with per-customer isolation and time-series indexing
3. Analyzes patterns across customer fleets to find recommendation
   candidates
4. Routes candidates through a Veldt-internal analyst review queue
   (we don't want to auto-sign auto-generated weight changes either)
5. Signs approved recommendations using KMS/Vault
6. Serves them at `GET /v1/recommendations` for SDKs to pull

It is a *new service*, not a feature of vd-app. It holds the signing
key. It's the most security-sensitive piece in the whole product.

---

## Honest phasing

### Phase A — Minimal demo collector
- **What it is:** one Python service, SQLite, manual recommendations,
  real Ed25519 signing, full `GET /v1/recommendations` endpoint
- **Time:** ~3-4 hours focused
- **Unlocks:** demo the full loop end-to-end on one machine; record a
  60-sec "watch the SDK get smarter live" video. Use as a
  sales/demo asset. NOT production-ready.

### Phase B — Production collector
- **What it is:** API keys + auth, TimescaleDB, real KMS, Veldt-side
  analyst review UI, deployment infra, observability
- **Time:** 1-2 weeks
- **Unlocks:** real customer onboarding; first paid pilot

### Phase C — Automated learning
- **What it is:** anomaly detection, pattern mining, A/B testing of
  recommendations, ML-driven candidates
- **Time:** months
- **Unlocks:** the actual moat — KYA gets smarter without a human
  analyst in the loop

### Phase D — Ops at scale
- **What it is:** multi-region, DR, SOC2, FedRAMP
- **Time:** months
- **Unlocks:** enterprise + federal deals

---

## What's shippable today without the collector

The SDK is a complete, documented, opt-in product. Customers can
install it and immediately use:

- The in-tenant feedback loop (critical incident → suggestion →
  operator approve → effective weight tightened)
- Aggregate telemetry counters (anonymous, no payloads)
- Dual-write capability (opt-in row mirroring with PII hashing)
- The inbound recommendations mechanism — they can pin a key from
  your gateway when you stand one up later

You can sell + onboard the SDK now and turn on the collector later.
SDK installations contribute to your telemetry corpus the moment the
collector goes live, so shipping the SDK now is itself a step toward
making the collector useful.

---

## Recommendation: don't build the collector yet

Three reasons:

### 1. The signing key is the crown jewel

Building the collector means deciding now how you operate that key —
KMS vs Vault, escrow procedures, rotation cadence, who has access,
audit logging. Better to make those decisions deliberately than rush
them into code under build pressure.

### 2. Demand isn't yet validated

A customer needs to want the cross-tenant feedback enough to pay for
it. The right next step might be to talk to 5 prospects and find out
if *"Veldt's analysis bumps your pii weight from 20 to 25 with
cross-fleet evidence"* is the wedge they actually want, or if they'd
rather have:

- Better dashboards (KYA score distribution across an agent fleet)
- More framework adapters (LiteLLM, DSPy, AutoGen)
- Deeper red-team integration
- Something else entirely

### 3. The SDK can be shipped and adopted while you decide

Every SDK install today is one more contributor to tomorrow's
collector dataset. The SDK adoption work and the collector build are
NOT sequential — they're parallel, and the SDK side compounds value
the longer you wait on the collector.

---

## Options on the table

| # | Option | Time | Recommendation |
|---|---|---|---|
| 1 | **Build Phase A demo collector** | 3-4 hrs | Good for a sales/demo asset; not the right use of time if pre-revenue |
| 2 | **Stop coding; validate demand first** | 1 session of outreach | The honest move pre-revenue. Talk to 5 prospects, take notes, return |
| 3 | **Pivot to a different gap** | varies | KYA dashboards, more adapters, founder memo, a16z speedrun deadline — pick a thing that closes a customer faster |
| 4 | **Plan the production collector (no code)** | 1-2 hrs | Architecture doc for Phase B. Sets up future work without committing build time today |

---

## Decision pending

To be filled in when chosen. The choice between these isn't a
technical question — it's a sequencing question about what moves
KYA toward revenue fastest given current constraints.
