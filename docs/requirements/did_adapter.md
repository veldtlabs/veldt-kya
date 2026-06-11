# DID Adapter — Requirements

**Status:** draft
**Phase:** 3d
**Owner:** veldt-kya
**Last updated:** 2026-06-10

---

## 1. Why this exists

KYA already binds principals to identity providers (Okta, Auth0, Keycloak, Google, Entra, Cognito, SPIFFE) via `kya/external_id.py`. Every one of those bindings depends on a centralized IdP — a vendor that has to be online, that the auditor has to trust, and that may rotate keys silently.

W3C **Decentralized Identifiers (DID)** + **Verifiable Credentials (VC)** are the emerging standard for non-human identity:

- Workday's June 2026 "Agent Trust and Inspection" job posting names DIDs as a required identity standard.
- Cloud Security Alliance's NHI/Agentic AI Governance whitepaper points at decentralized cryptographic identity as the next-gen NHI substrate.
- The 2026 Verizon DBIR calls identity "the control plane for agentic AI" and explicitly names DID-style approaches as the direction of travel.
- Microsoft Entra Verified ID and mDL (mobile drivers licenses) ship on DID infrastructure already.

KYA's DID adapter gives the existing principal-binding family a new flavor: an identity that's verifiable without phoning home to a vendor, that survives key rotation under a stable identifier, and that can carry signed authority claims via Verifiable Credentials.

## 2. Goals (MVP)

1. Resolve three DID methods that cover ≥90% of real-world use:
   - **`did:key`** — fully offline, public key encoded into the identifier
   - **`did:web`** — DNS-based, fetches DID document from a well-known URL
   - **`did:jwk`** — single JWK encoded into the identifier
2. Verify **W3C Verifiable Credentials in JWT-VC format** (the most-deployed VC shape).
3. Extend `kya/external_id.py` so a DID URI can bind a principal alongside the existing IdP-bound flow.
4. Capture the resolved DID document hash on the evidence chain so old audit records remain verifiable after the agent rotates keys.
5. Off-by-default — only activates when `KYA_DID_RESOLVERS` is set.

## 3. Non-goals (this phase)

- `did:plc` (Bluesky), `did:ion`, `did:ethr`, blockchain-backed methods. Add later if customers ask.
- JSON-LD Verifiable Credentials (the more academic VC shape). JWT-VC covers the practical ground.
- A full VC issuance toolchain (KYA is a verifier, not a wallet).
- DIF Presentation Exchange queries.
- DID URL dereferencing beyond the document itself.

## 4. Out-of-scope, must coexist gracefully

- Existing OIDC / Keycloak / SPIFFE bindings keep working unchanged.
- A principal MAY be bound by both a DID and an OIDC subject — KYA records the binding tier and picks the strongest available.

## 5. Threat model

| Threat | Mitigation |
|---|---|
| Malicious DID resolver impersonates a real one | Trusted-method allowlist (`KYA_DID_RESOLVERS=key,web,jwk`); no method runs unless explicitly enabled. |
| MITM on `did:web` HTTPS fetch | TLS required; HTTP rejected; pinned issuer allowlist via `KYA_DID_TRUSTED_ISSUERS`. |
| Issuer key rotates after evidence is signed | DID document hash captured into evidence at signing time so the verification context is reproducible offline. |
| Bogus `did:key` multibase prefix | Strict spec-compliant parser; unknown multicodec prefixes fail closed. |
| VC with no expiry / replay | Required `exp` claim; replay protection via existing `kya/replay_protection.py`. |
| `did:web` returns oversized document | Hard cap on document size (configurable, default 256 KB). |

## 6. Public API (Python)

```python
from kya.did import resolve_did, verify_vc, register_did_method
from kya.external_id import bind_did_principal

# 1. Resolve a DID to a DID document
doc = resolve_did("did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8")
print(doc.verification_methods[0].public_key_jwk)

# 2. Verify a JWT-VC
verified = verify_vc(jwt_vc_string, trusted_issuers=["did:web:bank.example"])
print(verified.claims["sub"], verified.claims["role"])

# 3. Bind a DID-rooted principal into KYA
with default_session() as db:
    bind_did_principal(
        db,
        tenant_id="tenant-alpha",
        did="did:web:bank.example:user-42",
        vc=jwt_vc_string,
        principal_kind="agent",
        principal_id="planner_agent",
    )

# 4. Register a custom DID method
register_did_method("plc", my_plc_resolver_callable)
```

## 7. Configuration (environment)

| Variable | Purpose | Default |
|---|---|---|
| `KYA_DID_RESOLVERS` | Comma-separated list of enabled methods | unset → DID resolution disabled |
| `KYA_DID_TRUSTED_ISSUERS` | Comma-separated allowlist of issuer DIDs for VC verification | unset → no allowlist (verifier checks signature + expiry only) |
| `KYA_DID_WEB_MAX_DOC_BYTES` | Max `did:web` document size | 262144 (256 KB) |
| `KYA_DID_WEB_TIMEOUT_S` | HTTP timeout for `did:web` fetches | 5.0 |
| `KYA_DID_REQUEST_USER_AGENT` | UA header for `did:web` fetches | `kya-did-resolver/0.x` |

## 8. Module shape

```
kya/
  did.py                # facade + resolver registry + verify_vc()
  did_document.py       # DIDDocument, VerificationMethod, Service dataclasses
  did_methods/
    __init__.py
    key.py              # did:key resolver
    web.py              # did:web resolver
    jwk.py              # did:jwk resolver
  vc.py                 # JWT-VC verifier
  external_id.py        # bind_did_principal() added
```

Single facade (`kya.did`) keeps the rest of the codebase simple. Internal modules are private (`did_methods/`).

## 9. Acceptance tests

| # | Scenario | Expected |
|---|---|---|
| 1 | `resolve_did("did:key:z6Mk…")` for a known Ed25519 multibase | Returns DIDDocument with the right public key, no network call |
| 2 | `resolve_did("did:web:example.com:user")` returns the served document | HTTPS GET to `https://example.com/user/did.json` |
| 3 | `resolve_did("did:web:example.com")` returns the root document | HTTPS GET to `https://example.com/.well-known/did.json` |
| 4 | `resolve_did("did:jwk:eyJ…")` returns the embedded key | No network call |
| 5 | `verify_vc(valid_jwt_vc, trusted_issuers=[…])` returns verified claims | Pass |
| 6 | `verify_vc(expired_jwt_vc, …)` raises `VCExpired` | Pass |
| 7 | `verify_vc(jwt_vc_signed_by_wrong_key, …)` raises `VCSignatureInvalid` | Pass |
| 8 | `bind_did_principal(db, …)` records the binding + evidence | Reading back the principal shows the DID as the external_id |
| 9 | Disabled method (`KYA_DID_RESOLVERS=key`) refuses `did:web:…` | Raises `DIDMethodNotEnabled` |
| 10 | `did:web` doc > `KYA_DID_WEB_MAX_DOC_BYTES` | Raises `DIDDocumentTooLarge` |

## 10. Dependencies

- **Existing KYA stack:** SQLAlchemy 2.x, evidence chain, external_id, principals.
- **New optional deps** (declared as `extras_require['did']` in pyproject.toml):
  - `cryptography` ≥ 41 — for Ed25519, X25519, secp256k1 verification.
  - `pyjwt` ≥ 2.8 — for JWT-VC parsing and signature verification.
  - `requests` ≥ 2.31 — already in core KYA, used here for `did:web` HTTP.
  - `python-multibase` ≥ 1 — for `did:key` multibase decoding.

`pip install veldt-kya[did]` opts in.

## 11. Backwards compatibility

- `bind_did_principal()` is a new function; existing `bind_external_principal()` keeps the same signature.
- No DB schema change. Reuses `kya_external_ids` table with `provider="did"` and `external_id=<the DID URI>`.
- `KYA_DID_RESOLVERS` defaulting to unset means existing deployments don't accidentally activate DID resolution.

## 12. Open questions

- Should we capture the *full* DID document or just its SHA-256 onto the evidence chain? *MVP answer: SHA-256 only, document held in memory at verification time and discarded.*
- Should we support DID-bound *delegation* (one DID grants authority to another via a VC)? *Out of scope for 3d; revisit in 3e.*
- `did:web` redirects — follow or refuse? *Refuse for MVP; CSRF / SSRF surface is too wide. Customers who need redirects can override the resolver.*

## 13. Future work (Phase 3e+)

- `did:plc` resolver (Bluesky / AT Protocol).
- JSON-LD VC verifier alongside JWT-VC.
- DID Communication 2.0 envelope for agent-to-agent signed messaging.
- VC presentation requests.
- Hardware-attested DIDs (TPM-bound `did:web` with attestation header).
