# KYP v0.1 — Evidence Record

This section defines the JSON shape of a single evidence record. An
evidence record is the smallest unit of attributable, verifiable
content produced by a KYP-conformant system.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**,
**SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**,
and **OPTIONAL** in this document are to be interpreted as described
in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Wire format

An evidence record is a JSON object. The canonical schema is at
[`schemas/evidence-record.schema.json`](./schemas/evidence-record.schema.json).

```json
{
  "tenant_id":            "00000000-0000-0000-0000-000000000001",
  "invocation_id":        42,
  "correlation_id":       null,
  "parent_invocation_id": null,
  "span_id":              null,
  "evidence_kind":        "prompt",
  "role":                 "user",
  "payload":              {"content": "summarize this document"},
  "payload_hash":         "<sha256 hex>",
  "payload_size_bytes":   45,
  "prev_hash":            null,
  "signed_hash":          "<hmac-sha256 hex>",
  "signing_key_id":       "env-v1",
  "occurred_at":          "2026-06-05T05:00:00+00:00",
  "ingested_at":          "2026-06-05T05:00:01+00:00",
  "source":               null,
  "data_classes":         null,
  "redacted":             false,
  "redaction_reason":     null,
  "retention_until":      null
}
```

## Field semantics

### Identity + scoping (REQUIRED)

The following fields MUST be present and non-null on every record
that goes on the wire:

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | string | UUID-like tenant identifier. Records from different tenants MUST NOT be interleaved in a single chain. |
| `invocation_id` | integer (uint64) | The chain partition key. All records with the same `(tenant_id, invocation_id)` form one chain. |
| `evidence_kind` | string enum | See [Evidence kinds](#evidence-kinds). |
| `payload` | object | The actual content. MUST be a JSON object (not an array, scalar, or null). Implementations MUST NOT mutate the payload between canonicalization and storage. |
| `payload_hash` | string (64 hex chars) | SHA-256 of the canonicalized payload. See [`04-canonicalization.md`](./04-canonicalization.md). |
| `signed_hash` | string (64 hex chars) | HMAC-SHA256 over `prev_hash \|\| "\|" \|\| payload_hash`. See [`05-signing.md`](./05-signing.md). |
| `signing_key_id` | string (≤ 40 chars) | Identifier of the key that produced `signed_hash`. Verifiers use this to look up the correct key when key rotation is in use. |
| `occurred_at` | string (RFC 3339 timestamp) | Event time — when the thing being recorded happened. MUST be timezone-aware. |

### Set by the recorder (PRESENT but not caller-supplied)

| Field | Type | Notes |
|---|---|---|
| `ingested_at` | string (RFC 3339 timestamp) | When the record was committed. Set by the recording implementation, not the caller. Conformant implementations MUST stamp this on write but the field is NOT required in the JSON schema for inputs to a recorder. |

### Chain linking (CONDITIONAL)

| Field | Type | Notes |
|---|---|---|
| `prev_hash` | string (64 hex chars) \| null | `signed_hash` of the previous record in the same `(tenant_id, invocation_id)` chain. MUST be `null` (or absent) for the first record. MUST NOT be `null` for non-first records. |

### Lineage + correlation (OPTIONAL)

| Field | Type | Notes |
|---|---|---|
| `correlation_id` | string \| null | Cross-invocation grouping (e.g., conversation, request id). |
| `parent_invocation_id` | integer \| null | The invocation that delegated to this one. Forms the cross-invocation delegation tree. |
| `span_id` | string (≤ 32 chars) \| null | OpenTelemetry span id, if telemetry is correlated. |
| `role` | string \| null | Conversational role: `user`, `agent`, `system`, `tool`, `human_reviewer`. |
| `source` | string \| null | Origin tool / framework, e.g., `langchain`, `crewai`, `falco`, `mavlink`. |

### Compliance + retention (OPTIONAL)

| Field | Type | Notes |
|---|---|---|
| `data_classes` | array of strings \| null | Sensitivity tags driving regime mapping (e.g., `pii`, `phi`, `pci`). |
| `redacted` | boolean | `true` iff payload was redacted before recording. Default `false`. |
| `redaction_reason` | string \| null | Free-text reason when `redacted=true`. |
| `retention_until` | string (RFC 3339) \| null | Earliest time at which the record MAY be pruned. |
| `payload_size_bytes` | integer \| null | Length of the canonical-payload byte string. SHOULD be set by recorders. |

## Evidence kinds

The `evidence_kind` field MUST be one of the values below. v0.1
implementations MAY accept additional values, but MUST default
unknown values to `system_message` to preserve chain integrity.

### Conversational
- `prompt` — what the agent received
- `response` — what the agent produced
- `tool_call` — tool invocation (name + arguments)
- `tool_result` — tool output
- `delegation_message` — agent-to-agent message
- `hil_decision` — human-in-the-loop approval / rejection
- `system_message` — framework / system context
- `judge_verdict` — multi-judge orchestrator per-judge verdict

### Runtime security (runtime evidence bridge)
- `runtime_falco`
- `runtime_tetragon`
- `runtime_tracee`
- `runtime_sysdig`
- `runtime_osquery`
- `runtime_auditd`
- `runtime_k8s_audit`
- `runtime_ebpf`

### Autonomy
- `autonomy_mavlink`

Future kinds MUST be additive — existing values MUST NOT be renamed
or repurposed in a minor version.

## Constraints

- `payload_hash` MUST equal `SHA-256(canonicalize(payload))`.
  Implementations MUST recompute and validate on read where chain
  integrity is being asserted.
- `signed_hash` MUST equal `HMAC-SHA256(key, prev_hash_str || "|" || payload_hash)`
  where `prev_hash_str` is `""` (empty string) for the first record
  in a chain and the literal `prev_hash` string for all subsequent
  records. The pipe character `|` is a literal ASCII 0x7C separator.
- `occurred_at` SHOULD be sourced from a monotonic, timezone-aware
  clock at the recording site. Implementations MUST NOT use ingestion
  time as event time.

## Non-normative payload conventions

The `payload` is free-form, but the following conventions are
RECOMMENDED for the bundled `evidence_kind` values:

| Kind | Recommended shape |
|---|---|
| `prompt`, `response`, `system_message`, `delegation_message` | `{"content": "<string>"}` |
| `tool_call` | `{"tool_name": "<string>", "args": {...}}` |
| `tool_result` | `{"tool_name": "<string>", "result": <any>}` |
| `hil_decision` | `{"decision": "approve"\|"reject", "reviewer_id": "<string>", "reason": "<string>"}` |
| `judge_verdict` | `{"judge_name": "<string>", "verdict": "BREACH"\|"OK"\|"UNCLEAR"\|"ERROR", "dimension": "<string>", "raw_score": <number or null>, "threshold": <number or null>}` |

Conformant implementations MAY use richer payloads. The
`payload_hash` makes any shape auditable as long as canonicalization
is applied per [`04-canonicalization.md`](./04-canonicalization.md).
