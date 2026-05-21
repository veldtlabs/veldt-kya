# Dual-write & telemetry

KYA has two independent paths that can forward data out of your
process. Both are designed for a *security-sensitive* deployment: nothing
sensitive leaves your network without your explicit decision, and even
when you opt in, the local DB write is the source of truth and always
succeeds first.

| Path | Default | What flows | Where to enable |
|---|---|---|---|
| **Aggregate telemetry** | On (counts only), but **does not transmit** unless a URL is configured | Per-event counts in 15-minute windows. No payloads, no tenant IDs, no agent keys, no PII. | `kya.enable_telemetry(url=...)` or env `KYA_TELEMETRY_URL` |
| **Dual-write** | Off | Full row payloads for an explicit allowlist of tables. PII fields are hashed by default. | `kya.enable_dual_write(...)` |

Both can be disabled at runtime: `kya.disable_telemetry()` /
`kya.disable_dual_write()`.

---

## Aggregate telemetry

Aggregate telemetry is the *anonymous* path. It exists so the platform
can build cross-customer risk baselines ("99th percentile rogue-score
for agents tagged `production`") without ever learning anything about
your individual rows.

What gets transmitted on each 15-minute flush:

```json
{
  "v": 1,
  "kind": "kya_aggregate_telemetry",
  "kya_version": "0.1.0",
  "deployment_id": "sha256:abc1234...",
  "window_start": "2026-05-20T12:00:00Z",
  "window_end":   "2026-05-20T12:15:00Z",
  "counts": {
    "snapshot_agent":            {"total": 142},
    "record_invocation":         {"total": 580, "by_kind": {"success": 540, "failure": 40}},
    "record_evidence":           {"total": 234, "by_kind": {"tool_call": 110, "agent_response": 124}},
    "record_principal_signal":   {"total": 8,   "by_kind": {"oos_tool": 6, "clean_invocation": 2}},
    "rogue_event":               {"total": 12,  "by_kind": {"oos_tool": 8, "policy_violation": 4}}
  }
}
```

There is no row content, no agent identity, no tenant identity, and no
PII anywhere in this payload. The `deployment_id` is a salted hash of
`(hostname, platform, KYA_DEPLOYMENT_SALT)`. Pin `KYA_DEPLOYMENT_ID` if
you want a stable string of your own choosing.

### Enable

```python
import kya
kya.enable_telemetry(url="https://telemetry.kya.veldtlabs.ai/v1/aggregate")
# or:
# KYA_TELEMETRY_URL=https://telemetry... in env, telemetry auto-starts on import
```

### Disable

```python
kya.disable_telemetry()
# or:
# KYA_TELEMETRY=off in env (checked at import time)
```

### What the counter store looks like

```python
kya.telemetry_status()
# {
#   "disabled": False,
#   "transmitting": True,
#   "url": "https://...",
#   "flush_interval_s": 900.0,
#   "in_flight": {"window_start": "...", "totals": {...}, "by_kind": {...}}
# }
```

---

## Dual-write

Dual-write is the *full-row* path. Off by default. After you call
`kya.enable_dual_write()`, every recorder writes locally first as it
always has, and then asynchronously posts the same row to your
configured collector for the tables in your allowlist.

### Failure-mode contract

* The local DB write **always** happens synchronously and successfully
  before the dual-write hook fires.
* Collector POST is asynchronous. If the collector is unreachable, the
  recorder still returns success and your application is unaffected.
* On 5xx or 429 the worker retries with exponential backoff (max 5
  attempts, ~30 s ceiling). On 4xx other than 429 the batch is dropped
  with a warning — your payload is wrong, retrying won't help.
* After N consecutive failed batches (default 5) the circuit breaker
  opens for 5 minutes. New events are dropped with
  `veldt_kya_dualwrite_dropped{reason="breaker_open"}` and the worker
  recovers cleanly when traffic resumes.
* Queue is bounded (default 10 000 rows). When full, new emits drop
  with `veldt_kya_dualwrite_dropped{reason="queue_full"}`.

### Enable

```python
import kya
import os

kya.enable_dual_write(
    collector_url="https://collect.kya.veldtlabs.ai/v1/rows",
    api_key=os.environ["VELDT_KYA_API_KEY"],
    allowlist=["agent_versions", "kya_invocations", "kya_principal_trust", "rogue_signal"],
    # redact=True (default) — hash PII fields and truncate large text
    # redact=False — send raw rows
    # Or pass redactor=DualWriteRedactor(pii_fields=("email", "user_id"))
)
```

### Allowlist

Only these table names are accepted (typos raise
`DualWriteAllowlistError` at enable time):

```python
kya.DUAL_WRITE_ALLOWED_TABLES
# {
#   "agent_versions",
#   "kya_invocations",
#   "kya_evidence",
#   "kya_principal_trust",
#   "kya_user_trust",
#   "kya_agent_aliases",
#   "kya_weight_overrides",
#   "kya_weight_changes",
#   "kya_weight_suggestions",
#   "kya_breach_notifications",
#   "rogue_signal",     # synthetic — covers all rogue.record_* funnels
# }
```

### Redaction (default ON)

The bundled `Redactor`:

* sha256-hashes (with salt) any field whose name matches the PII list
  (`email`, `phone`, `ssn`, `address`, `ip_address`, `user_id`,
  `principal_id`, `actor_id`, `actor_email`, `actor_name`,
  `subject_email`, `subject_name`, `patient_id`, `customer_id`,
  `session_token`, `api_key`, `bearer`, `authorization`)
* truncates strings over 200 chars with a marker
* drops `bytes`/`bytearray` values (replaced with a length-only stub)
* recurses into nested dicts / lists up to depth 6

The salt is read once at import from `KYA_DUALWRITE_SALT`. If unset, a
random per-process salt is used — hashes will not be comparable across
restarts. Pin the salt yourself if you want stable cross-day cohort
counts.

### Disable

```python
kya.disable_dual_write()  # safe to call multiple times
```

### Introspection

```python
kya.dual_write_status()
# {
#   "enabled": True,
#   "collector_url": "https://...",
#   "allowlist": ["agent_versions", "kya_invocations"],
#   "queue_depth": 17,
#   "queue_max": 10000,
#   "breaker_open": False,
#   "consecutive_failures": 0,
#   "sent_batches": 142,
#   "failed_batches": 1
# }
```

### Observability counters

If `prometheus_client` is installed, the following are exported:

| Metric | Labels | Description |
|---|---|---|
| `veldt_kya_dualwrite_emitted` | `table` | Rows handed to the sink |
| `veldt_kya_dualwrite_dropped` | `reason` | `not_allowlisted` / `breaker_open` / `queue_full` / `redact_error` |
| `veldt_kya_dualwrite_sent` | `outcome` | `ok` / `bad_request` / `failed` |
| `veldt_kya_dualwrite_queue_depth` | — | Current queue length |

---

## Threat model — what dual-write does not do

* **No magical re-encryption**. The dual-write payload travels in
  plain JSON over the TLS-protected POST you configured. If your
  collector URL is `https://`, payloads are encrypted in transit; if
  `http://`, they are not. The SDK does NOT downgrade TLS.
* **No retry on 4xx**. We assume malformed payloads (4xx) are a bug we
  need to fix in code, not a transient condition.
* **No payload retention**. If the collector is permanently down, the
  bounded queue overflows and we drop. We do not persist a local
  fallback queue (a corrupted local spool is a worse failure than a
  dropped event).
* **No tenant fan-out**. The SDK ships every allow-listed row regardless
  of tenant. If you want per-tenant filtering, set
  `enable_dual_write(allowlist=...)` separately on isolated KYA
  installs, or build a router in front of your collector.
* **Telemetry vs. dual-write are independent**. Disabling one does not
  affect the other.

---

## Choosing what to enable

| You are | Recommendation |
|---|---|
| Self-hosting KYA SDK and want platform-side learning to benefit you over time | Enable aggregate telemetry. Leave dual-write off unless you want richer signal in exchange for sending row payloads. |
| Self-hosting KYA SDK with **strict data residency** (GDPR, FedRAMP, EU AI Act sensitive deployments) | Leave both off. KYA is 100% local. |
| Using Veldt's hosted KYA (SaaS tier) | Dual-write is implicit — your rows are already on Veldt infra by design. No SDK setup needed. |
