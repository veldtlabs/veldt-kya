# Phase 5g — Enforcement modes + DID-to-KYA integration

## Why this exists

Two design corrections caught during deep codebase audit:

**A. Liability isolation broken at the gateway boundary.** KYA's library
exposes `KYA_RBAC_ENFORCEMENT = off | flag | block` (`kya/rbac.py:27`)
so the customer's framework decides the HTTP outcome — KYA scores +
records + signs but never returns HTTP responses. The Phase 4 gateway
hardcodes 401/403 enforcement, transferring liability to KYA whenever
the gateway is deployed. Phase 5g exposes the same three-mode toggle
at the gateway boundary.

**B. DID was built as a parallel system.** Nine integration points
where the new identity layer should plug into KYA's existing trust /
audit / delegation / attack-chain primitives (and currently doesn't).

## Scope

* In: gateway `enforcement.mode`, 9 integration points, RED+GREEN
  tests, double review.
* Out: regulator pack content for VC-specific rules (Phase 5h), pro
  policy compiler that consumes VC scope claims (Phase 6+).

## Part A — Gateway enforcement modes

### Three modes, mirrors `kya/rbac.py`

| Library | Gateway | Behavior |
|---|---|---|
| `off` | `audit_only` (default) | Always forwards to backend. Records verdict + evidence. Response carries `X-KYA-Verdict: deny\|allow\|require_human` header so backend can choose. Customer enforces. |
| `flag` | `advise` | Forwards. Records. Response body includes verdict + reason_codes + signature so MCP clients can pre-check. Customer still enforces. |
| `block` | `enforce` | Current behavior. KYA returns 401/403 on deny. **Operator opted into KYA-side enforcement liability.** |

### Config

```yaml
gateway:
  enforcement:
    mode: "audit_only"   # or "advise" | "enforce"
```

### Where the mode applies

* Identity binding failures (missing/invalid PoP, bad DPoP, wrong JWT)
* Revocation block (status list bit set)
* Policy pipeline deny / require_human verdicts

### What stays unchanged

* Evidence chain recording — every mode records signed evidence.
* Trust signal emission — every mode debits trust on denied calls.
* Header attachment — `X-KYA-Verdict`, `X-KYA-Reason-Codes`,
  `X-KYA-Evidence-Hash` always set.

## Part B — Nine integration points

| # | Where today | Where it should be | Why |
|---|---|---|---|
| 1 | `kya_gateway/server.py` `_ME_RATE_WINDOWS` dict | `kya.rate_limit.maybe_rate_limit(tenant, "principals_me")` | Existing Valkey-backed primitive; per-tenant + per-primitive granularity; multi-replica safe. |
| 2 | `kya_pro/issuer_api/_auth.py` `JtiCache` in-process LRU | Same JtiCache wired to `kya._valkey.get_valkey()` + `SET NX EX` (in progress) | Multi-replica replay rejection without parallel mechanism. |
| 3 | `kya_gateway/identity.py` `_maybe_check_revocation` raises silently | Also `emit_security_event("revocation_blocked", ...)` | Feeds existing trust system + attack chains. |
| 4 | `kya_gateway/_dpop.py` DPoP errors | Emit `dpop_replay`, `dpop_forge_attempt`, `dpop_expired` events | Feeds attack-chain correlation. |
| 5 | `kya/external_id.py:bind_did_principal` ignores VC issuer-DID lineage | When VC `iss` is a KYA-known principal, write a `kya_principal_edges` row | Delegation graph stays whole. |
| 6 | `kya/external_id.py:bind_did_principal` doesn't check VC scope vs parent | Run VC claim's `role` / `scopes` through `delegation_policy.enforce` | Sub-agent ceiling enforced |
| 7 | `kya_pro/trust_registry/_registry.py:flag_rotation` | Also `emit_security_event("issuer_rotation_pending", ...)` so principals bound to that issuer's VCs see degraded trust | Trust score signal |
| 8 | `kya_pro/issuer_api/_app.py:_audit` uses `tenant_id="kya-pro-issuer"` (string) | Normalize to UUID derived from issuer_did so multi-tenant tables behave | Schema compliance |
| 9 | `kya/evidence.py:VALID_EVIDENCE_KINDS` | Add `issuer_vc_issued`, `issuer_vc_revoked`, `trust_registry_change`, `revocation_blocked`, `dpop_replay`, `dpop_forge_attempt`, `dpop_expired`, `issuer_rotation_pending` | Stops silent fallback to `system_message`. |

## Acceptance tests

(Tests must surface real bugs; bug→fix→re-test.)

### Mode tests

1. `audit_only` default: deny verdict → HTTP 200 + `X-KYA-Verdict: deny`
   header + backend reached + evidence row written.
2. `advise`: deny verdict → HTTP 200 + body contains
   `{"kya_verdict":"deny","reason_codes":[...],"signature":"..."}`.
3. `enforce`: deny verdict → HTTP 403 (regression of existing behavior).
4. Mode applies to identity invalid (DPoP bad, VC revoked) not just
   policy deny.
5. In `audit_only`, evidence row is still HMAC-chained.

### Integration tests

6. `/v1/principals/me` rate limit fires when
   `KYA_RATE_LIMIT_RPS_<TENANT>_PRINCIPALS_ME=0.5` is set.
7. Revocation block emits `security_event("revocation_blocked")` →
   trust score on principal decreases.
8. DPoP forgery (wrong key) emits `security_event("dpop_forge_attempt")`.
9. VC issued by a known parent DID → `kya_principal_edges` row created
   with parent_principal_id, child_principal_id.
10. VC scope `role=admin` for a child of a `role=user` parent →
    `delegation_policy.enforce` raises / records violation.
11. `flag_rotation` → `security_event("issuer_rotation_pending")` for
    every principal currently bound to that issuer's VCs.
12. Issuer-API `tenant_id` is a valid UUID after normalization.
13. `record_evidence(kind="issuer_vc_issued", ...)` lands with the
    requested kind, not falls back to `system_message`.

## Migration / backwards compat

5g default mode `audit_only` **changes existing gateway behavior**
for operators upgrading. The CHANGELOG must call out:

> Phase 5g changes the gateway's default behavior from `enforce` to
> `audit_only`. Existing deployments that relied on the gateway
> returning 401/403 must set `gateway.enforcement.mode: enforce`
> explicitly. The change aligns the gateway with KYA's library
> philosophy: KYA recommends + records + signs; the customer enforces.

## Threat model deltas

* `audit_only` makes the gateway permissive — wrong verdicts produce
  records but no blocks. **This is correct under KYA's design** —
  customer's enforcement layer (their MCP client, their backend, their
  middleware) is the security boundary.
* `enforce` mode unchanged from Phase 4–6.
* Mode mismatch (operator wants enforce, ships audit_only) is an
  operational footgun — startup logs the active mode at WARNING level
  so it's visible.

## CLI

```bash
kya-gateway --config gateway.yaml \
  --enforcement-mode audit_only  # override config for testing
```
