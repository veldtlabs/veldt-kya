# Phase 5h — Per-credential VC issuance approval

## Why this exists

KYA's inbound pipeline (`kya/inbound.py`) has four-gate
operator-approval-as-default for cross-org policy recommendations:
signed envelope → expiry check → only-tighten validation → operator
approval. Phase 5h gives the **outbound** issuance path the same
discipline: when the pro issuer-API receives a request to mint a VC,
it can be queued for a second admin's approval instead of being
minted inline.

This closes a real audit gap (any admin with a bearer token can mint
any VC; no per-credential record of "who approved this") that
regulated buyers (pharma, finance, EU AI Act Annex III) will flag.

## Reuse, don't rebuild

| 5h need | Existing primitive | How |
|---|---|---|
| State machine + race protection | `kya/inbound.py:_decide` | Copy the `WHERE status='pending'` UPDATE pattern |
| Approve / deny semantics | `kya/inbound.py:approve_recommendation` + `reject_recommendation` | Mirror — outbound version mints VC instead of `set_override` |
| Auto-apply allowlist | `kya/inbound.py:_auto_apply_if_allowed` | Outbound analog for `auto_approve_patterns` |
| Cross-dialect DDL + upsert | `kya/_dialect_helpers.portable_upsert` | New table; same dialect helpers |
| Admin auth | `kya_pro/issuer_api/_auth.py` `_require_admin` | Already wired; both `requested_by` and `approver` flow through it |
| Audit + evidence | `kya.record_evidence` + `VALID_EVIDENCE_KINDS` | Add `vc_request_queued / _approved / _denied` |
| Trust signal | `kya._security_events.emit_security_event` | Add `vc_approval_denied` to `_HARDENING_EVENT_KINDS` + realtime + SIGNAL_DELTAS (5g pattern) |
| Delegation lineage | `kya.principal_edges.add_principal_edge` | `requester_admin → approver_admin` edge with `edge_kind="vc_approval_chain"` |
| Cursor pagination | Existing trust-registry pagination helper in `kya_pro/issuer_api` | Reuse |
| Three-mode liability isolation | `kya_gateway/config.py:EnforcementConfig` (Phase 5g) | Issuer-API gets `approval.mode: auto / queue / require_dual` — same off/flag/block pattern |

## What's actually new

* `kya_pending_credentials` table (one new schema)
* State machine: `pending → approving → minted | denied | expired`
  (round-3 NEW-5 — `approving` is the in-flight state; `approved`
  was a pre-round-2 misnomer)
* Deny-cannot-be-resubmitted invariant
* Four endpoints: queue, approve, deny, list-pending
* `auto_approve_patterns` DID-glob matcher
* `require_dual_admin` constraint (approver ≠ requester)

Estimated ~150 LoC across two repos.

## Schema

Cross-dialect via SQLAlchemy declarative model (not raw SQL):

```python
# kya_pro/issuer_api/_pending.py

from sqlalchemy import (
    BigInteger, Column, Sequence, String, Text, TIMESTAMP,
    Index, CheckConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

_PendingCredentialsSeq = Sequence("kya_pending_credentials_id_seq")
_JsonType = JSON().with_variant(JSONB(), "postgresql")   # 5h-DOC-10

class _PendingCredentialRow(Base):
    __tablename__ = "kya_pending_credentials"
    id = Column(BigInteger, _PendingCredentialsSeq, primary_key=True,
                server_default=_PendingCredentialsSeq.next_value())
    tenant_id = Column(String(36), nullable=False)
    request_uuid = Column(String(36), nullable=False, unique=True)
    requested_by_principal_id = Column(Text, nullable=False)   # 5h-DOC-03
    subject_did = Column(Text, nullable=False)
    claims = Column(_JsonType, nullable=False)                 # 5h-DOC-10
    vc_types = Column(_JsonType, nullable=False)
    audience = Column(String(512), nullable=True)
    expiration_seconds = Column(BigInteger, nullable=True)
    status = Column(String(16), nullable=False, default="pending")
    # State enum: pending | approving | minted | denied | expired
    # (`approving` is the in-flight state; see 5h-DOC-01)
    approver_principal_id = Column(Text, nullable=True)        # 5h-DOC-03
    denial_reason = Column(Text, nullable=True)
    minted_vc = Column(Text, nullable=True)
    minted_vc_id = Column(String(64), nullable=True, unique=True)
    minted_at = Column(TIMESTAMP, nullable=True)
    revoked_at = Column(TIMESTAMP, nullable=True)              # 5h-DOC-11
    revoked_by_principal_id = Column(Text, nullable=True)      # 5h-DOC-11
    requested_at = Column(TIMESTAMP, nullable=False,
                          server_default=func.now())
    decided_at = Column(TIMESTAMP, nullable=True)
    expires_at = Column(TIMESTAMP, nullable=False)
    __table_args__ = (
        Index("ix_pending_creds_tenant_status",
              "tenant_id", "status", "requested_at"),
        # 5h-DOC-10 — never accept zero/negative TTL.
        CheckConstraint("expiration_seconds IS NULL OR "
                        "expiration_seconds > 0",
                        name="ck_pending_creds_positive_exp"),
    )
```

**`expires_at` derivation rule (round-2 N-7):** at queue-time,
`expires_at = requested_at + (expiration_seconds OR
approval.request_ttl_seconds)`. The column is non-null because
`approval.request_ttl_seconds` has a non-null default in
`ApprovalConfig`. `expiration_seconds` on the request is the
**VC's** lifetime (passed to `key_manager.sign`), not the
**request's** queue lifetime — different concepts; the column
name was preserved for back-compat with the existing issuance
shape.

**`minted_vc_id` uniqueness (round-2 N-8; round-3 NEW-4):** add
`unique=True` (nulls allowed). All four target engines apply
the SQL standard rule "NULL is not equal to NULL" in UNIQUE
constraints — multiple NULLs coexist on PG, MySQL (InnoDB),
SQLite, and DuckDB without violation. The constraint only fires
on a duplicate non-null `minted_vc_id`. This guarantees the
revocation write-back hits exactly one row, never multiple.

Cross-dialect notes — same `Sequence("...")` pattern as
`kya_principal_edges` for DuckDB BIGSERIAL portability.

## Endpoints

All under `kya_pro/issuer_api/_app.py`. All require `_require_admin`.

### `POST /v1/issuer/credentials`  *(modified — existing endpoint)*

Behavior gated by `IssuerAPIConfig.approval`:

| mode | Behavior |
|---|---|
| `auto` (default — back-compat) | Mints inline, same as today |
| `queue` | Writes `pending` row, returns `{request_uuid, status: "pending"}` HTTP 202. Auto-approve allowlist may still mint inline. |
| `require_dual` | Same as `queue` but `auto_approve_patterns` are ignored |

### `POST /v1/issuer/credentials/{request_uuid}/approve`  *(new)*

**State machine (5h-DOC-01):**
```
pending  ── approve (commit 1) ──>  approving  ── mint+commit 2 ──>  minted
                                       │
                                       └── crash / sign fail
                                           sweeper finds row in `approving`
                                           past TTL+grace → flips to `expired`
                                           (re-issue is a fresh request_uuid)
```

* Caller's **normalized admin principal_id** extracted from token
  via `_admin_principal_id(_require_admin(...))` (5h-DOC-03):
  * DID-signed tokens normalized **per DID method** (round-2 N-3):
    * `did:web:<host>:<path>` → hostname case-folded per RFC 3986
      §3.2.2 (hosts are case-insensitive); path components left
      byte-exact
    * `did:key:z6Mk...` → byte-exact (multibase encoding is
      case-sensitive; `z6Mk` ≠ `z6mk`)
    * `did:jwk:...` → byte-exact (base64url encoding is
      case-sensitive)
    * Other DID methods → byte-exact by default; a method that
      wants normalization adds its rule to `_NORMALIZE_RULES` in
      `_auth.py`. Document the closed set; refuse silent equality
      on unknown methods.
  * HMAC tokens → **REFUSED on /approve and /deny** when
    `mode != auto`. Pre-shared HMAC secrets can't carry
    separation-of-duties identity. Operators wanting dual-admin
    MUST use DID-signed tokens.
* `require_dual_admin: true` → caller's normalized principal_id MUST
  ≠ `requested_by_principal_id`
* **Commit 1 (intent):** atomic `UPDATE ... WHERE status='pending'
  SET status='approving', approver_principal_id=..., decided_at=...`
  — race-safe, exactly one approver wins (mirrors `_decide`)
* **Mint:** `key_manager.sign(...)`
* **Commit 2 (resolve):** `UPDATE ... WHERE status='approving' SET
  status='minted', minted_vc=..., minted_at=...`
* Write `record_evidence(evidence_kind='vc_request_approved')` after
  commit 2
* Write `principal_edges` row (requester → approver,
  `edge_kind="vc_approval_chain"`, both kinds = `"admin"`) —
  see 5h-DOC-05 for principal registration

**Crash recovery (5h-DOC-01):** background sweeper (or per-call
opportunistic sweep) flips `approving` rows past `expires_at +
sweep_grace_seconds` → `expired`. The operator can then re-queue
under a new `request_uuid`. The original sign-attempt may have
succeeded at the KMS layer but the row was lost — operators are
documented to verify via KMS audit log; we never silently re-attempt
mint with the same parameters because that would risk double-issue
under the same `(subject, requested_at)`.

**409 response discrimination (round-2 N-1; round-3 NEW-1):** when
an approve call finds the row not in `pending`, the 409 body MUST
tell the caller what state was found, so caller-side retries after
network drops can act. **The minted VC itself is NEVER returned in
a 409 body** — it's a bearer credential, and any admin who can call
`/approve/{uuid}` on an already-minted row would otherwise get a
free copy. Operators retrieve a re-issued copy only via the original
success-response delivery channel (or a separate, audited
"retrieve by vc_id" path that is out of scope for 5h).

```json
// row already minted (your last response was lost) — NO vc field
{"status": "minted", "vc_id": "...", "minted_at": "..."}

// row stuck in-flight (server crashed between sign and resolve)
{"status": "approving", "retry_after_s": 3600,
 "note": "sweeper will expire this row at expires_at+grace"}

// row already denied — Round-4 F2: include denial_reason
{"status": "denied", "decided_at": "...", "denial_reason": "..."}

// row already expired
{"status": "expired", "decided_at": "..."}
```

Callers MUST inspect `status` before retrying; a blind retry on 409
without inspection is documented as a bug.

### `POST /v1/issuer/credentials/{request_uuid}/deny`  *(new)*

* Same admin normalization + DID-only refusal of HMAC tokens
* Atomic state transition `pending → denied` (single commit; no
  in-flight state needed since no crypto step follows)
* Records `vc_request_denied` evidence with `denial_reason`
* **Burst detection (5h-DOC-09):** counter keyed by
  `(tenant_id, requested_by_principal_id)`, window =
  `realtime.WINDOWS["1m"]` (60s sliding via Valkey), threshold = 5.
  When threshold exceeded, emit `emit_security_event(
  "vc_approval_denied", tenant_id=..., principal_kind="admin",
  principal_id=requested_by_principal_id)` so the requester's admin
  principal-trust row is debited.
* **Out of scope for 5h (round-2 N-6):** approver-side abuse (a
  rogue approver mass-denying legitimate requests as a DoS) is NOT
  detected by the requester-keyed counter. Tracking approver
  behavior requires a second counter keyed on the approver's
  principal_id and a different threshold; deferred to a follow-on
  phase. The current scheme protects against a compromised
  *requester*, not a compromised *approver*.

### `GET /v1/issuer/credentials/pending`  *(new)*

* Cursor pagination (reuse existing trust-registry cursor helper)
* Filter by `requester_principal_id=`, `subject_did=`, `older_than=`
* **Default filter:** `WHERE status='pending' AND expires_at > now()`
  — actively hides TTL-expired rows even if no sweeper ran yet
  (5h-DOC-06)
* `include_expired=true` opt-in returns `expired` rows for forensics

## Config additions

```python
@dataclass(frozen=True)
class ApprovalConfig:
    mode: str = "auto"   # auto | queue | require_dual
    request_ttl_seconds: int = 86400   # 24h to approve before expires
    auto_approve_patterns: list[str] = field(default_factory=list)
    require_dual_admin: bool = True   # only fires in require_dual mode
    # Round-4 F4 — sweeper knobs.
    sweep_enabled: bool = False
    sweep_grace_seconds: int = 3600   # 1h grace past expires_at
```

Validation in `IssuerAPIConfig.__post_init__`:
* `mode` ∈ `{auto, queue, require_dual}`
* `auto_approve_patterns` must be DID URIs with optional `*` suffix
  (e.g., `did:web:fleet-a:*`)

## Auto-approve allowlist (DID-segment matcher, 5h-DOC-02)

**NOT `fnmatch`.** `fnmatch`'s `*` crosses `:` boundaries (verified:
`fnmatchcase("did:web:fleet-a:evil:drone", "did:web:fleet-a:*")` is
True). Phase 5h ships a **DID-aware segment matcher** that treats
`:` as a path separator — `*` matches one segment, NEVER multiple.

Semantics:
* `did:web:fleet-a:*` matches `did:web:fleet-a:drone-1234`
* `did:web:fleet-a:*` does **NOT** match `did:web:fleet-a-evil:drone`
  (different second-segment)
* `did:web:fleet-a:*` does **NOT** match `did:web:fleet-a:evil:drone`
  (`*` matches one segment, not multiple)
* Exact match if no `*`
* Mid-pattern wildcards (`did:web:*.example`) are rejected at
  config-load time

**Path case-sensitivity examples (round-3 NEW-2)** — the case-fold
rule applies ONLY to the `did:web` hostname segment. Path segments
are byte-exact:

* `did:web:Org.Example:users:alice` ≡ `did:web:org.example:users:alice`
  (hostname differs only in case → equivalent)
* `did:web:org.example:USERS:alice` ≢ `did:web:org.example:users:alice`
  (hostname identical; path case differs → DISTINCT)
* `did:web:Org.Example:USERS:alice` ≡ `did:web:org.example:USERS:alice`
  (hostname differs only in case; path identical → equivalent)

Validation regex at `ApprovalConfig.__post_init__` (round-2 N-2):

```python
# Per DID Core §3.1 + RFC 3986 — per-segment grammar is
# idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
# where pct-encoded = "%" HEXDIG HEXDIG. We validate that `%` is
# ALWAYS followed by two hex digits, rejecting `did:web:fleet%XY`.
_SEGMENT_RE = r"(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+"
_PATTERN_RE = re.compile(
    rf"^did:[a-z0-9]+(:{_SEGMENT_RE})+(:\*)?$",
)
```
The pattern MUST start with `did:`, contain at least one literal
segment, every literal segment MUST be RFC-3986-valid (including
proper percent-encoding), and `*` (if present) MUST be the final
segment only.

Implementation:
```python
def _did_segment_match(did: str, pattern: str) -> bool:
    if not pattern.endswith(":*"):
        return did == pattern
    prefix = pattern[:-1]   # strip trailing "*", keep trailing ":"
    if not did.startswith(prefix):
        return False
    tail = did[len(prefix):]
    return tail and ":" not in tail   # exactly one segment
```

When `mode=queue` and the subject_did matches a pattern, the request
**auto-mints inline** and records the new evidence kind
`vc_request_auto_approved` (5h-DOC-04) — NOT `vc_request_queued`,
which would misrepresent the audit chain. When `mode=require_dual`,
patterns are IGNORED (operator demands explicit dual approval for all).

## Audit + evidence flow

```
POST /v1/issuer/credentials  (mode=queue, no auto-approve match)
  → kya_pending_credentials INSERT (status=pending)
  → record_evidence(kind='vc_request_queued', payload={...})

POST /v1/issuer/credentials/{uuid}/approve
  → UPDATE ... WHERE status='pending'   (race-safe)
  → key_manager.sign(...) → minted VC
  → UPDATE status='minted', minted_vc=..., minted_at=now
  → record_evidence(kind='vc_request_approved', payload={...})
  → record_evidence(kind='issuer_vc_issued', payload={vc_id, ...})
  → add_principal_edge(requester, approver, edge_kind='vc_approval_chain')

POST /v1/issuer/credentials/{uuid}/deny
  → UPDATE ... WHERE status='pending'
  → record_evidence(kind='vc_request_denied', payload={reason})
  → if recent denial-burst from same requester:
       emit_security_event('vc_approval_denied', ...)
```

All evidence rows are HMAC-chained per `(tenant_id, invocation_id)` —
the audit chain proves the request → approval → mint sequence is
unbroken.

## New evidence kinds

Append to `kya/evidence.py:VALID_EVIDENCE_KINDS`:

```python
"vc_request_queued",          # mode=queue, request entered the queue
"vc_request_approved",        # explicit dual-admin approval
"vc_request_auto_approved",   # 5h-DOC-04 — auto-approve pattern matched
"vc_request_denied",          # explicit denial
```

## New security event kind

Append to `kya/_security_events.py:_HARDENING_EVENT_KINDS` AND
`kya/realtime.py:ALLOWED_SIGNAL_KINDS` AND `kya/users.py:SIGNAL_DELTAS`
(Phase 5g lesson):

```python
"vc_approval_denied": -3,   # softer than rbac_refusal; denial is a
                            # legitimate operator decision, but
                            # repeated denials from one requester are
                            # signal of attempted misuse.
```

## New edge kind + new principal kind (5h-DOC-05)

`kya/principal_edges.py` already accepts arbitrary `edge_kind` strings
matched by `_EDGE_KIND_REGEX`; no schema change. Document
`vc_approval_chain` in the constants module.

**Admin principal kind:** `kya/principals.py:PRINCIPAL_KINDS` does
not currently include `"admin"`. Phase 5h extends it:

```python
PRINCIPAL_KINDS = ("user", "agent", "service_account", "admin")
```

And `bind_did_principal` is called once for each admin DID at
process start (or lazily on first request) so the
`requester_admin → approver_admin` edge points at real principal
rows (not orphan IDs — the 5g-B-03 lesson). The trust score on the
admin's row is debited by `vc_approval_denied` events (5h-DOC-09).

## Concurrency invariants (5h-DOC-08)

* **Sole race protection: atomic `UPDATE ... WHERE status='pending'`.**
  This is genuinely race-safe across all four backends (PG / MySQL /
  SQLite / DuckDB) — no advisory lock needed. The two-commit
  in-flight `approving` state (5h-DOC-01) handles the
  crash-between-sign-and-resolve case. We DROP the previously-proposed
  PG advisory lock entirely; it added complexity without correctness
  benefit.
* `add_principal_edge` already idempotent + retry-safe (5g reuse).
* The sweeper that flips `approving → expired` past `expires_at +
  sweep_grace_seconds` runs in the same `_InboundWorker`-shaped
  daemon (see 5h-DOC-06) — operators choose to enable it via
  `approval.sweep.enabled: true`.
* **Multi-replica sweeper safety (round-2 N-4; round-3 NEW-3):** the
  sweeper uses the SAME status-guarded atomic UPDATE pattern.
  **Time arithmetic is computed in Python, not SQL**, mirroring
  `kya/inbound.py:169` — there is no portable cross-dialect
  expression for `expires_at + grace_seconds` (PG needs
  `INTERVAL '60 seconds'`, MySQL needs `DATE_ADD(...)`, SQLite needs
  `datetime(..., '+60 seconds')`, DuckDB needs `INTERVAL 60 SECOND`).
  The portable shape:

  ```python
  # Round-4 F3 — single now_utc binds threshold AND decided_at so
  # the row reflects one consistent instant.
  now_utc = datetime.now(timezone.utc)
  threshold = now_utc - timedelta(
      seconds=approval.sweep_grace_seconds,
  )
  db.execute(
      update(_PendingCredentialRow)
      .where(_PendingCredentialRow.status == "approving")
      .where(_PendingCredentialRow.expires_at < threshold)
      .values(status="expired", decided_at=now_utc)
  )
  ```

  Running the sweeper on N replicas is safe — each replica's update
  is idempotent; only the first wins, others affect zero rows. No
  leader election needed.

## Liability isolation

Mirrors Phase 5g modes — operator chooses where liability sits:

| Library mode (`rbac.py`) | Gateway mode (`5g`) | Issuer mode (`5h`) |
|---|---|---|
| off | audit_only | auto |
| flag | advise | queue |
| block | enforce | require_dual |

Operators in `auto` accept the legacy "any admin token mints" risk.
Operators in `require_dual` opt INTO KYA's "two admins, one VC"
discipline.

## Acceptance tests (~30)

State machine (5h-DOC-01):
1. Queue → approve → minted (happy path)
2. Queue → approve → in-flight crash (sign fails) → row in
   `approving` state; subsequent approve returns 409; sweeper past
   TTL+grace flips to `expired`
3. Queue → deny → denied
4. Queue → TTL expires → row marked `expired`; approve returns 410
5. Denied row: re-queueing same `(requester, subject)` allowed →
   NEW `request_uuid`

DID-aware matcher (5h-DOC-02):
6. `did:web:fleet-a:*` matches `did:web:fleet-a:drone-1234` ✓
7. `did:web:fleet-a:*` does NOT match `did:web:fleet-a-evil:drone`
8. `did:web:fleet-a:*` does NOT match `did:web:fleet-a:evil:drone`
9. Mid-pattern wildcard `did:web:*.example` rejected at config-load

Admin identity normalization (5h-DOC-03):
10. HMAC token on `/approve` in `mode=require_dual` → 401
11. HMAC token on `/v1/issuer/credentials` in `mode=auto` still works
12. Same DID-signed admin can't approve own request (403)
13. `did:web:Org.Example` requester + `did:web:org.example` approver
    → REJECTED as self-approval (case-fold equivalent)
14. Two distinct DIDs → approver succeeds

Auto-approve evidence (5h-DOC-04):
15. Auto-approve match → records `vc_request_auto_approved`
    (NOT `vc_request_queued`)
16. `mode=require_dual` ignores patterns

Principal lineage (5h-DOC-05):
17. After approve, both requester + approver registered as
    `principal_kind="admin"` rows
18. `principal_edges` row exists with `edge_kind='vc_approval_chain'`
19. `vc_approval_denied` event debits the requester admin's
    trust score

Sweeper + LIST defaults (5h-DOC-06):
20. `GET /pending` hides TTL-expired rows without sweeper run
21. Sweeper (when enabled) flips `pending → expired` and
    `approving → expired` past TTL+grace

Concurrency:
22. Two parallel approves → one mints, other gets 409
23. Approve raced with deny → first transition wins

Audit:
24. Approve flow writes 3 evidence rows (queued + approved +
    issuer_vc_issued)
25. `verify_chain()` valid across the sequence
26. Revocation via `/v1/issuer/revoke` writes back
    `revoked_at` / `revoked_by_principal_id` on the pending row

Security events (5h-DOC-09):
27. 5 denials in 60s from same requester triggers
    `emit_security_event('vc_approval_denied', principal_kind="admin",
    principal_id=requested_by_principal_id)`
28. `vc_approval_denied` registered in all three whitelists

Mode switching (5h-DOC-12):
29. Flip `queue → auto` mid-run; pending rows untouched; startup
    WARN names the count

Cross-dialect:
30. SQLite + DuckDB + (env-gated) PG + MySQL all pass.

## CHANGELOG note (additive)

```
### Added
- Pro issuer-API: per-credential approval workflow.
  - `approval.mode: queue` queues VC requests for a second admin's
    approval; `require_dual` mandates the approver be a different
    admin than the requester.
  - `auto_approve_patterns` allowlist for fast-path DID globs
    (segment-aware; `*` never crosses `:`).
  - Full audit chain: `vc_request_queued / _approved /
    _auto_approved / _denied` evidence kinds + `vc_approval_chain`
    delegation edge.
  - Default `mode: auto` preserves pre-5h behavior — no breaking
    change for existing deployments.

### Migration
- Operators currently using HMAC admin tokens who want to flip
  `approval.mode` from `auto` to `queue` or `require_dual` must
  first migrate at least one admin to a **DID-signed token**.
  HMAC tokens are refused on `/approve` and `/deny` in non-auto
  modes (round-2 N-5).

  **Migration recipe (round-3 NEW-6; round-4 F1):**
  1. Generate an Ed25519 keypair offline:
     ```python
     from cryptography.hazmat.primitives.asymmetric.ed25519 import (
         Ed25519PrivateKey,
     )
     priv = Ed25519PrivateKey.generate()
     raw_pub = priv.public_key().public_bytes(
         encoding=serialization.Encoding.Raw,
         format=serialization.PublicFormat.Raw,
     )
     ```
     Encode as `did:key`: `did:key:z<multibase(0xed01 || raw_pub)>` —
     the published `did:key` resolver in `kya/did_methods/key.py`
     verifies this format.
  2. Add the DID to `IssuerAPIConfig.admin_dids`:
     `admin_dids: ["did:key:z6Mk...AdminBob..."]`. Restart the
     issuer-API.
  3. Mint a JWT offline signed by the private half with pyjwt.
     **All seven of `iss / aud / iat / nbf / exp / jti` MUST be
     present** — `verify_did_admin_token` requires them
     (`kya_pro/issuer_api/_auth.py:264`).
     ```python
     now = int(time.time())
     jwt.encode({
         "iss": "did:key:z6Mk...",
         "aud": cfg.did_admin_audience,
         "iat": now,
         "nbf": now,                # F1 — REQUIRED
         "exp": now + 300,
         "jti": uuid4().hex,
     }, private_jwk, algorithm="EdDSA",
        headers={"kid": "did:key:z6Mk...#z6Mk..."})
     ```
  4. Bearer the JWT to `/approve` or `/deny`.
     `verify_did_admin_token` accepts it.

  Once at least one admin is on DID-signed tokens, you can safely
  flip `approval.mode: queue` and the system has at least one
  separation-of-duties principal available.
```

## Revocation hook (5h-DOC-11)

The minted VC's eventual revocation via `/v1/issuer/revoke` writes
back to the pending-creds row when `minted_vc_id` matches:
```
UPDATE kya_pending_credentials
   SET revoked_at = now(), revoked_by_principal_id = :caller
 WHERE minted_vc_id = :vc_id
```
Auditors querying "which approved VCs were later revoked, and by
whom?" get a direct answer without joining through the status-list
table.

## Mode switching footgun (5h-DOC-12)

Switching `approval.mode` back to `auto` while `pending` rows exist
is documented as operator footgun: existing pending rows STAY in
their current state and DO NOT auto-mint. Operators must drain
(approve/deny/expire) the backlog manually or enable the sweeper.
The startup-time WARNING log lists the count of pending rows when
the configured mode is `auto`.

## Out of scope

* Web UI for pending-credentials review (operators can curl or
  build their own)
* Email/Slack notification on new pending requests — `kya/external_
  emitters.py` does NOT auto-fire on new evidence kinds (5h-DOC-07);
  it has a closed `event_type` vocabulary. Operators wanting Slack/
  email must either (a) poll `GET /v1/issuer/credentials/pending`,
  or (b) write a small bridge that listens on `kya.realtime`'s
  pub/sub `kya:alerts:{tenant_id}` channel and forwards.
* Multi-step approval (>2 admins) — single approver after requester
  is sufficient for v1
* Cryptographic separation of duties (e.g., threshold signatures) —
  documented as future work; current scheme is policy-level dual
  admin, not crypto-level
