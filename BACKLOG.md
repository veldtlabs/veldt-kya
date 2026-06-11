# KYA Backlog

Items deferred from active development. No commitment timeline — pull
into a phase when a customer asks or a regulator names the item.

## Sigstore / Rekor transparency log

**Trigger to revisit:** customer ask or NIST AI RMF / EU follow-on
guidance names transparency-log anchoring.

**Scope:**
- `sigstore-python` integration + Rekor REST anchoring
- New columns `rekor_log_index` on `kya_evidence` + `kya_signed_manifests`
- Helper `kya/transparency.py` — `anchor_to_rekor()`, `verify_inclusion()`
- Async/queue (network call); backoff + retry
- Opt-in flag (most customers won't want public anchoring of internal evidence)
- Tests with Rekor mocked

**Effort:** ~400 LoC, 3–4 days, real new build.

**Why deferred:** HMAC chain + Ed25519 export already satisfies EU AI
Act Art 12/19, SOC 2 CC6, ISO 42001. Auditors accept this today.
Public-log anchoring is also a *sales objection* for some buyers
(compliance/legal don't love their evidence being publicly indexed)
— must be opt-in if/when built.

## KMS-backed signer — additional backends

**Already shipped:** AWS KMS (ES256 + RS256, JWK extraction, DER→JOSE
conversion — `kya_pro/issuer/_signer.py:126`). AWS production
deployments work today.

**Backlog:**

| Item | Effort |
|---|---|
| GCP Cloud KMS backend | ~80 LoC, 0.5d |
| Azure Key Vault backend | ~80 LoC, 0.5d |
| HashiCorp Vault Transit backend | ~80 LoC, 0.5d |
| Key rotation hook + DID-doc update flow | ~50 LoC, 1d |
| E2E test against real KMS (LocalStack mock) | 1d |
| Ed25519 over KMS | Blocked — no provider supports it as of 2026-06 |

**Trigger to revisit:** customer's cloud choice forces the backend
(e.g., GCP-only buyer can't deploy AWS KMS).

**Total if all three backends + rotation:** ~290 LoC, ~3 days.

## Native Slack / Email / PagerDuty notifiers

**Trigger to revisit:** repeated customer asks for batteries-included
delivery rather than wiring a webhook.

**Scope:**
- New formatters in `kya/external_emitters.py`:
  - `slack_block_kit` — Slack incoming-webhook envelope
  - `pagerduty_events_v2` — PD Events API v2
  - `email_smtp` — minimal SMTP delivery with templating
- Tests + docs

**Effort:** ~150 LoC, 1 day.

**Why deferred:** existing webhooks + Valkey pub/sub already deliver
to any of these via generic webhook URLs. Native formatters are
convenience, not capability.

## Approver-side abuse detection (Phase 5h follow-on)

**Trigger to revisit:** Phase 5h customer reports rogue-approver
mass-deny pattern, or proactive hardening request.

**Scope:**
- Second sliding-window counter keyed on
  `(tenant_id, approver_principal_id)` over `WINDOWS["1m"]`
- New event kind `vc_approval_excessive_denial` (or reuse existing
  `vc_approval_denied` with different `principal_id`)
- Threshold + trust debit on the approver's row
- Whitelist propagation (`_HARDENING_EVENT_KINDS` + `realtime` +
  `SIGNAL_DELTAS` — 5g lesson)

**Effort:** ~60 LoC + tests, 0.5 day.

**Why deferred:** Phase 5h protects against compromised *requester*;
compromised *approver* is the symmetric concern but not yet a real
customer ask. Deferred to keep 5h scope tight.

## Multi-step approval (>2 admins)

**Trigger to revisit:** regulated buyer with M-of-N approval policy.

**Scope:** Phase 5h's queue-state machine generalized to
`pending → approving → minted` with an M-of-N approval threshold.
Approvers signal via separate endpoint; mint only when threshold met.

**Effort:** ~200 LoC + tests, 1.5 days. Builds on 5h.

## Cryptographic threshold signing

**Trigger to revisit:** state-actor-threat buyer (defense, intelligence,
high-value crypto custody).

**Scope:** Issuer signing key split via Shamir secret sharing or
threshold ECDSA so M-of-N admins must combine partial signatures to
mint. Eliminates the single-key compromise vector.

**Effort:** unknown — probably 800+ LoC, 1–2 weeks, real crypto review.

**Why deferred:** customer base doesn't require it today; current
admin-token + dual-admin (5h) is policy-level separation of duties,
which auditors accept. Document explicitly so this isn't oversold.
