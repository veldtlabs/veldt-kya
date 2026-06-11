# Phase 5h Issuance Approval — Operator Runbook

Operational guidance for the per-credential VC issuance approval
workflow. Pairs with `docs/requirements/phase5h_issuance_approval.md`.

## Dashboard / metric interpretation

### Counting issued VCs

Filter on **`evidence_kind = 'issuer_vc_issued'`**. Every mint writes
this row regardless of path:

- Pure `mode=auto` deployments
- Auto-approve fast path in `mode=queue`
- Dual-admin approve flow in `mode=queue` / `mode=require_dual`

DO NOT filter on `vc_request_approved` or `vc_request_auto_approved`
to count issuance — those are workflow tags layered on top of the
canonical `issuer_vc_issued` row and you'll undercount auto-approved
or pure-auto mints.

### Counting revoked VCs (5h-N-2)

Filter on **`evidence_kind = 'issuer_vc_revoked'`**. Do NOT count
raw calls to `StatusListManager.revoke()` — Phase 5h's race-
recovery path (5h-01) calls `revoke()` internally to free a
status-list bit when `resolve_minted` loses the race against the
sweeper. That call frees the bit but does NOT emit
`issuer_vc_revoked` evidence (the VC was never durably bound to
begin with). Counting raw revoke calls will inflate your "revoked"
metric without a matching `issuer_vc_issued`.

### Correlating audit to pending rows (5h-N-3)

- `vc_request_queued` carries `request_uuid` (joinable)
- `vc_request_approved` carries `request_uuid` + `approver_principal_id`
  + `requested_by_principal_id` (joinable)
- `vc_request_denied` carries `request_uuid` (joinable)
- **`vc_request_auto_approved` carries `request_uuid: null`** — auto-
  approved VCs bypass the queue, so no pending row exists. Dashboards
  joining `evidence.payload.request_uuid` to
  `kya_pending_credentials.request_uuid` should treat null as the
  explicit "auto-approve" signal, not as missing data.

## Configuration footguns

### `admin_dids` allowlist (5h-N-1)

Validate every entry in `admin_dids` is a well-formed DID URI before
deploying. A malformed entry like `"did:web"` (too few segments)
passes the issuer-API's allowlist check but lands in audit rows as
raw garbage. The handler logs at WARNING when it normalizes a
malformed iss; treat any such log line as a misconfiguration to fix.

Acceptable shapes:
- `did:web:<host>` or `did:web:<host>:<path-segment>:...`
- `did:key:z<base58>`
- `did:jwk:<base64url>`

### `auto_approve_patterns`

The matcher is segment-aware — `*` matches exactly one segment,
never multiple. Patterns are validated at config-load:

```python
ApprovalConfig(
    auto_approve_patterns=["did:web:fleet-a:*"],   # OK
)
# Rejects at construction:
ApprovalConfig(
    auto_approve_patterns=["did:web:*.example"],   # mid-pattern
    auto_approve_patterns=[42],                    # non-string
)
ApprovalConfig(                                    # mode footgun
    mode="require_dual",
    auto_approve_patterns=["did:web:fleet-a:*"],
)
```

Hostname case is folded for did:web only; did:key / did:jwk are
byte-exact. An operator pasting `did:web:Fleet-A:*` as a pattern
will match `did:web:fleet-a:drone-1234` (and vice-versa) — the
matcher normalizes both sides before comparison.

### `mode` switching

Flipping `approval.mode` back to `auto` while `pending` rows exist
leaves those rows untouched. They will NOT auto-mint. Drain the
queue (approve / deny / let expire) or enable the sweeper before
switching modes. Startup logs WARN with the pending count.

## Sweeper deployment

- Sweeper is **opt-in** (`approval.sweep_enabled: true`).
- Replica-safe: every issuer-API replica can run the sweeper; the
  atomic status-guarded UPDATE makes duplicate sweeps no-ops.
- Without the sweeper, rows stuck in `approving` (crash between
  KMS sign and commit-2) sit in that state until manually resolved.
- The LIST endpoint hides expired rows by default even without the
  sweeper — pass `?include_expired=true` for forensics.

## Recovery procedures

### Row stuck in `approving`

A crash between `claim_for_approval` (commit 1) and `resolve_minted`
(commit 2) leaves the row in `approving`. The KMS sign may have
succeeded — check the KMS audit log for the request's vc_id.

Recovery options:
- Enable the sweeper → automatic flip to `expired` after
  `expires_at + sweep_grace_seconds`
- Manual: investigate the KMS log, then either let the sweeper run
  or manually `UPDATE kya_pending_credentials SET status='expired'
  WHERE request_uuid='...' AND status='approving'`
- DO NOT re-issue with the same parameters — the original sign-
  attempt may have produced a valid VC out there that the
  re-issuance would shadow

### Row stuck in `pending` past TTL

Auto-handled — the LIST endpoint hides these by default; the
sweeper flips them to `expired` when enabled.

## Migration: pre-5h → 5h

| You were running | After 5h upgrade |
|---|---|
| Default issuer-API (no `approval` block) | `mode=auto`, behavior unchanged |
| HMAC admin tokens only, want `mode=queue`/`require_dual` | Generate at least one DID-signed admin token (recipe in requirements doc); HMAC tokens are refused on `/approve` and `/deny` in non-auto modes |
| Existing `kya_invocations` rows | New rows write **normalized** `principal_id` (case-folded did:web hostname); pre-5h rows kept raw `iss`. Dashboards joining across the boundary may need a `LOWER()` on the host portion |
