# Inbound recommendations — the cross-tenant feedback loop

KYA gets smarter over time. The aggregate telemetry path (see
`dualwrite.md`) ships anonymous counters *out*. The inbound path
documented here brings signed recommendations *in*: Veldt's analysis
across customer fleets produces weight-tightening proposals, signs them
with a key held outside the customer-facing infra, and your SDK pulls
them on a schedule.

Nothing leaves your local DB by enabling this. It is pull-only and
operator-gated by default. Off by default.

---

## Trust anchor

The SDK does NOT trust the collector URL alone. Every payload is
signed with **Ed25519**, and the SDK verifies against pinned public keys.
A compromised CDN, a fraudulent CA-issued cert, or a misconfigured
collector URL cannot make your SDK apply a recommendation, because the
signing key is held separately from any of those failure points.

### Pin a key

Set the env var BEFORE the first `import kya`:

```bash
KYA_INBOUND_PUBLIC_KEY="veldt-kya-2026-q2:<base64-32B-pubkey>"
```

Multiple keys (for rotation) — separate with commas:

```bash
KYA_INBOUND_PUBLIC_KEY="veldt-kya-2026-q2:KEYA,veldt-kya-2026-q3:KEYB"
```

`KEYA` / `KEYB` are base64-encoded raw 32-byte Ed25519 public keys.
The envelope's `signing_key_id` selects which key to verify against;
any envelope whose `signing_key_id` is NOT in the trust map is
rejected outright.

The SDK also ships with a `DEFAULT_PINNED_KEYS` constant in
`_inbound_signing.py`. Env keys *merge over* defaults, so customers
who want to swap to a self-managed gateway just set the env var.

### v0.1 default behavior: no implicit trust

`DEFAULT_PINNED_KEYS` ships empty in v0.1 by design — the SDK never
implicitly trusts a vendor-published key without you opting in. The
inbound enforcement path (`enable_inbound()` and `fetch_now()`)
hard-refuses with `RuntimeError` when neither
`KYA_INBOUND_PUBLIC_KEY` nor `DEFAULT_PINNED_KEYS` has at least one
entry. This is a deliberate choice over silently no-op'ing — see the
"why" note in `_inbound_signing.py` and the v0.1 release notes.

When Veldt's production collector signing key is live, the published
key will land in `DEFAULT_PINNED_KEYS` in a subsequent SDK release;
customers who want to opt in by then will already be pinned via
`DEFAULT_PINNED_KEYS`. Customers who prefer to remain on a
self-managed key can keep their env override (env wins over defaults).

### Key rotation

Veldt's signing key lives in KMS / Vault (separate from anything
customer-facing). Rotation procedure:

1. Generate the new keypair in KMS. Get its `signing_key_id` and base64
   public bytes.
2. Veldt publishes both old AND new keys in `DEFAULT_PINNED_KEYS` of
   the next SDK release.
3. Veldt signs new envelopes with both keys for the overlap window
   (typically one full poll cycle + a buffer).
4. After the overlap, drops the old key from publishing AND from the
   next SDK release.

Customers on the overlap-period SDK accept both. Customers stuck on
the pre-rotation SDK see verification fail once the old key is dropped
— this is intentional and observable via the counter
`veldt_kya_inbound_rejected{reason="signature_invalid"}`.

---

## Wire protocol

```
GET https://collect.kya.veldtlabs.ai/v1/recommendations?since=<iso8601>
Accept: application/json
User-Agent: veldt-kya-inbound/<sdk-version>
```

`since` is optional; the collector may use it to return a delta.

### Response envelope

```json
{
  "v": 1,
  "kind": "kya_inbound_recommendations",
  "signing_key_id": "veldt-kya-2026-q2",
  "issued_at":  "2026-05-20T12:00:00Z",
  "expires_at": "2026-06-20T12:00:00Z",
  "deployment_id": null,
  "recommendations": [
    {
      "id": "rec_abc123",
      "scope": "class_weights",
      "key":   "pii",
      "current_value_at_issue": 20,
      "recommended_value":      25,
      "rationale": "Observed 3.2x elevated PII incident rate across 47 deployments over the past 7d window vs baseline.",
      "evidence_summary": {
        "deployments_observed": 47,
        "window": "7d",
        "incident_count_baseline": 12,
        "incident_count_current":  38
      }
    }
  ],
  "signature": "ed25519:<base64>"
}
```

### Canonicalization for signing

The `signature` field is computed over **everything else in the
envelope**:

```python
canonical = json.dumps(
    {k: v for k, v in envelope.items() if k != "signature"},
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode("utf-8")
signature = ed25519_sign(private_key, canonical)
envelope["signature"] = "ed25519:" + base64(signature)
```

Receivers reconstruct `canonical` the same way and call `verify`. If
the envelope was rewritten in flight (CDN, MITM, proxy), the
reconstructed canonical won't match what was signed and verification
fails.

### Empty / unmodified responses

`HTTP 204 No Content` or `Content-Length: 0` → SDK treats as "no new
recommendations." Polling continues.

---

## Enable on your SDK

```python
import kya
from db.database import SessionLocal

kya.enable_inbound(
    SessionLocal,
    collector_url="https://collect.kya.veldtlabs.ai/v1/recommendations",
    interval_s=86400,                  # daily poll, clamped to >= 60s
    request_timeout_s=15,
    auto_apply_allowlist=None,         # default: all recommendations land as pending
)
```

A daemon thread now pulls from the collector on the configured cadence.
Every fetch:

1. GET → response body parsed
2. Signature verified against pinned key
3. Each recommendation validated for known scope + non-expired
4. Verified rows inserted into `kya_inbound_recommendations` with
   `status='pending'` (idempotent on `external_id` UNIQUE)
5. Rows matching `auto_apply_allowlist` are applied immediately via
   `set_override()` and marked `status='auto_applied'`

### Stop polling

```python
kya.disable_inbound()
```

### Inspect state

```python
kya.inbound_status()
# {
#   "enabled": True,
#   "collector_url": "https://...",
#   "interval_s": 86400.0,
#   "auto_apply_allowlist": [...],
#   "trust_anchors": ["veldt-kya-2026-q2"],
#   "last_fetch": {"ok": True, "persisted": 1, "rejected": 0, ...}
# }
```

---

## Operator review

The pending queue is identical in shape to in-tenant suggestions, so
the same UI / API surfaces both. Programmatic access:

```python
pending = kya.list_recommendations(db, status="pending")
# [{"id": 12, "scope": "class_weights", "key": "pii",
#   "current_value_at_issue": 20, "recommended_value": 25,
#   "rationale": "...", "evidence_summary": {...},
#   "issued_at": ..., "fetched_at": ..., "status": "pending"}]

kya.approve_recommendation(db, rec_id=12, approved_by=user_id, notes="...")
# Calls set_override under the hood; effective weight changes after this returns.
# Status flips: pending -> approved -> applied.

kya.reject_recommendation(db, rec_id=12, rejected_by=user_id, notes="...")
# Status flips: pending -> rejected. No weight change.
```

**Crucial**: `approve_recommendation` routes the apply step through
`tenant_weights.set_override`, which **still enforces only-tighten**.
If a recommendation tries to lower the platform default, the
`set_override` call raises `OverrideLoosensError` and the row is
left in `status='approved'` (decided but not applied) so the operator
sees the failure.

---

## Auto-apply mode

If you trust Veldt enough to let some recommendation classes apply
without an operator click, pass an allowlist of `(scope, key)` tuples:

```python
kya.enable_inbound(
    SessionLocal,
    collector_url="...",
    auto_apply_allowlist=[
        ("class_weights", "pii"),
        ("class_weights", "phi"),
        ("class_weights", "confidential"),
    ],
)
```

Recommendations matching ANY pair in the allowlist auto-apply on the
fetch worker thread. Everything else still goes to the pending queue.

The allowlist is *positive* — anything not in it never auto-applies.

---

## Threat model

| Threat | Defense |
|---|---|
| Network MITM | TLS + signature verification |
| Compromised CA issues fake `collect.kya.veldtlabs.ai` cert | Signature verification — attacker doesn't have the signing key |
| DNS hijack | Same as above |
| BGP hijack | Same as above |
| Compromised CDN rewrites response body | Body re-canonicalized in SDK; mutation breaks signature |
| Customer admin paste-bins a malicious collector URL | Same as CDN compromise — attacker can return only what they sign with a key the SDK trusts; without that key, rejected |
| Replayed old envelope | `expires_at` is signed; rows past expiry rejected at persist |
| Replayed envelope across deployments | `external_id` is UNIQUE per row — re-fetches are idempotent ON CONFLICT |
| Insider at Veldt with TLS cert but NOT signing key | Recommendation issuance requires both the TLS cert AND the signing key |
| Insider with the signing key | Bleeds — key rotation + KMS/Vault audit is the mitigation; this is by design (no system is safe from a fully-trusted insider) |
| Auto-apply approves loosening | `set_override` raises `OverrideLoosensError`; the only-tighten rule still gates the final effective value |
| Unknown scope or malformed payload | Validated before persist; rejected with `unknown_scope:` / `missing_key` reason in counter |

---

## Observability

If `prometheus_client` is installed:

| Metric | Labels | Meaning |
|---|---|---|
| `veldt_kya_inbound_fetched` | `outcome` | One increment per fetch attempt: `ok` / `empty` / `signature_invalid` / `network_error` / `not_json` / `http_4xx` / `http_5xx` |
| `veldt_kya_inbound_rejected` | `reason` | Per-recommendation rejection: `signature_invalid` / `expired_at_fetch` / `unknown_scope` / `missing_key` / `not_dict` / `db_error` |
| `veldt_kya_inbound_applied` | `mode` | `auto` (allowlist) or `operator` (approve_recommendation) |
| `veldt_kya_inbound_last_fetch_unixtime` | — | Gauge; last successful fetch time. Use for staleness alerts |

---

## When NOT to enable this

- Air-gapped deployments with no egress to a collector — leave it off, or stand up your own gateway and pin its key via `KYA_INBOUND_PUBLIC_KEY`.
- Regulated deployments where any inbound config change requires an
  approval committee — keep `auto_apply_allowlist=None` so every change
  hits your ticketing system before applying.
- Deployments establishing their first telemetry baseline — start
  with the in-tenant feedback loop. Cross-tenant recommendations are
  aggregated from the same telemetry shape and become useful once
  your own agents are actively producing recordable events.
