# KYA Open-Core Strategy

**Status:** locked
**Date:** 2026-05-21
**Owners:** Veldt Labs Inc. founders

## Decision

KYA is shipped as **open-core**:

- The **SDK** (and all SDK-shaped code that customers run on their own infra) ships **Apache-2.0** on PyPI as `veldt-kya`.
- The **monetization layer** (collector, dashboards, curated content, enterprise features) stays **proprietary** in the private `veldt-decisions` monorepo.

The moat is **network effects in the collector** — cross-customer telemetry, aggregate analysis, signed recommendations. The SDK is the protocol + reference implementation that drives adoption + paper credibility. Closing the SDK kills the flywheel; closing the collector preserves the business.

This is the same model as HashiCorp Vault/Consul, Sentry, Grafana, Confluent (Kafka), Databricks (Spark).

---

## What goes open-source

Repo: `veldtlabs/veldt-kya` (lives at `D:\veldt-kya\` locally)
License: Apache-2.0

| Component | What it is |
|---|---|
| `kya/` | Core SDK: scoring, versioning, evidence chain, principal trust, telemetry counters, dual-write outbound, inbound recommendations *fetcher*, in-tenant feedback loop, format adapters for 5 frameworks, compliance helpers, autoinstrument, red-team integration glue. ~49 modules, ~15.5k LOC. |
| `kya_hooks/` | Framework adapters: `claude_agent.py`, `langchain.py`, `openai_agents.py`, `scanner.py`, `client.py`. |
| `kya_otlp_bridge/` | OTel → KYA signal mapping sidecar (Dockerized). |
| `kya_redteam/` framework | PyRIT/Garak harness, scoring logic, runners. **Framework code only — not the curated attack corpus.** |
| `scripts/generate_kya_signing_key.py` | Ed25519 keypair helper for self-hosters. |
| All SDK tests, examples, docs | The 34 pytests, OpenCLAW e2e, concurrency load test, smoke, `sdk/docs/*.md`. |

---

## What stays proprietary

Repo: `veldtlabs/veldt-decisions` (private monorepo, lives at `D:\veldt-decisions\`)
License: All rights reserved

| Component | Why it's the moat |
|---|---|
| **Veldt collector** (Phase B build, not yet built) | Receives outbound telemetry + dual-write from all customer SDKs, aggregates, runs cross-customer pattern analysis, signs recommendations with the Veldt root key. Network effects compound here. |
| **Hosted dashboards / SaaS UI** | Multi-tenant fleet view, alerting, integrations. The subscription product. |
| **Production signing private keys** | In KMS/Vault. Customer SDKs verify against pinned public keys; private side never leaves Veldt infrastructure. |
| **Curated red-team attack corpus** | Real-world prompts mined from customer engagements. Sold as "Red-Team Pro Pack" — framework is open, corpus is paid. |
| **Compliance pre-configured bundles** | FedRAMP / SOC2 / EU AI Act / HIPAA ready-to-ship audit report templates and evidence packs. Generators are open; bundles are paid. |
| `app/decisions/` Decision Intelligence Platform | The broader Veldt product (not KYA). Decision graph engine, governance, attestation, rule engine. |
| `app/routes/` platform HTTP API | Internal admin + customer-facing endpoints. |
| Enterprise integrations | SSO providers, Salesforce/Slack/ServiceNow connectors, custom RBAC tiers. |
| Customer data, internal admin tools, infra config | Obviously. |

---

## Revenue streams (proprietary)

1. **Hosted collector + dashboards** — subscription. The main revenue driver. Like Sentry's hosted offering vs the open-source SDK.
2. **Red-Team Pro Pack** — one-time + update fees for the curated attack corpus.
3. **Compliance bundles** — per-regime add-ons (FedRAMP, SOC2, EU AI Act, HIPAA, GDPR…).
4. **Enterprise plan** — SSO, custom RBAC tiers, dedicated integrations, SLA, dedicated support, on-prem deployment guidance.

---

## Decision rules for future code

When adding new functionality, ask:

| Question | If yes |
|---|---|
| Is it a primitive that customers run on their own infrastructure? | **OSS** |
| Is it a framework adapter or integration glue? | **OSS** |
| Is it data we collected from customers (corpus, baselines, models trained on customer signals)? | **Proprietary** |
| Does it run on Veldt's hosted infrastructure (collector, dashboards, scoring services)? | **Proprietary** |
| Does it use a signing key that lives in Veldt's KMS? | The SDK side that verifies = OSS; the Veldt side that signs = proprietary |
| Is it a compliance pack, audit template, or pre-configured bundle tailored to a specific regulation? | **Proprietary** (the generator that produces it can be OSS) |
| Is it a novel algorithm with patent-track potential? | Case-by-case. Generally OSS once a defensive paper is published. |

---

## Where signing keys live

- **Public key**: embedded in the OSS SDK (`_inbound_signing.DEFAULT_PINNED_KEYS`) — shipped to every PyPI install.
- **Private key**: KMS / Vault inside Veldt infrastructure. Used by the proprietary collector to sign outbound recommendations. Never appears in any open-source artifact.
- **Customer-side override**: `KYA_INBOUND_PUBLIC_KEY` env var lets enterprise customers pin their own gateway key for air-gapped / sovereign deployments.

---

## Related decisions

- [PYPI_RELEASE_CHECKLIST.md](PYPI_RELEASE_CHECKLIST.md) — the 10-item readiness gate before publishing v0.1
- [kya_collector_roadmap.md](kya_collector_roadmap.md) — the proprietary collector's phased build plan
- [veldt_kya_founder_memo.md](veldt_kya_founder_memo.md) — broader product positioning
