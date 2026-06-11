# KYA + W3C DID — 5-minute Quickstart

KYA's DID adapter binds principals (humans, agents, service accounts) to
**W3C Decentralized Identifiers** instead of (or alongside) traditional
IdP subjects. This guide gets you from `pip install` to a verified DID
binding in under five minutes.

---

## 1. Install

```bash
pip install veldt-kya[did]
```

That installs the optional DID extras (`cryptography`, `pyjwt`). Core KYA
already has the rest of the dependencies.

## 2. Enable the resolvers you want

DID resolution is off by default. Opt in with an env var:

```bash
# Enable the three MVP methods
export KYA_DID_RESOLVERS=key,web,jwk

# Optional — only accept VCs from these issuer DIDs
export KYA_DID_TRUSTED_ISSUERS=did:web:bank.example,did:web:health.example
```

The three methods cover the practical ground:

| Method | What it is | When to use |
|---|---|---|
| `did:key` | Public key encoded into the URI. Offline. | Air-gapped agents, ephemeral workloads, tests. |
| `did:web` | DID document served from a well-known HTTPS path. | DNS-controlled identity (e.g., `did:web:bank.example`). |
| `did:jwk` | Single JWK encoded as base64url. Offline. | Lightweight binding when you already have a JWK. |

## 3. Resolve a DID

```python
from kya.did import resolve_did

doc = resolve_did("did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8")
print(doc.id)
print(doc.verification_methods[0].public_key_jwk)
# {'kty': 'OKP', 'crv': 'Ed25519', 'x': '...'}
```

`doc.doc_hash` is a SHA-256 of the canonical DID document JSON. Capture it
in audit records so the verification context stays reproducible after the
agent rotates keys.

## 4. Verify a Verifiable Credential

```python
from kya.vc import verify_vc

# jwt_vc is a JWT-VC string you received from the agent or its IdP
verified = verify_vc(jwt_vc, trusted={"did:web:bank.example"})
print(verified.issuer_did)         # 'did:web:bank.example'
print(verified.subject_did)        # 'did:web:bank.example:user42'
print(verified.claims["vc"])       # the W3C VC payload
```

Errors are typed so callers can branch cleanly:

- `VCExpired` — `exp` claim is in the past
- `VCNotYetValid` — `nbf` claim is in the future
- `VCSignatureInvalid` — JWT signature failed against the issuer's DID key
- `VCIssuerNotTrusted` — issuer isn't in your trusted set
- `VCMalformed` — JWT is structurally broken

## 5. Bind a principal to a DID

```python
from kya import default_session, snapshot_agent, record_principal_signal
from kya.external_id import bind_did_principal

with default_session() as db:
    # The principal row needs to exist first (this creates it if missing
    # via the standard snapshot + signal flow).
    snapshot_agent(db, tenant_id="tenant-alpha",
                   agent_key="planner",
                   definition={"agent_key": "planner", "tools": ["read"]})
    record_principal_signal(db, tenant_id="tenant-alpha",
                            principal_kind="agent",
                            principal_id="planner",
                            signal_kind="clean_invocation")
    db.commit()

    # Now bind the DID
    ok = bind_did_principal(
        db,
        tenant_id="tenant-alpha",
        principal_kind="agent",
        principal_id="planner",
        did="did:web:bank.example:planner",
        vc=jwt_vc,  # optional — verifies + stamps claims onto attributes
    )
    print(f"bound: {ok}")
```

The DID becomes the canonical `idp_subject` for the principal with
`idp_kind="did"`. All existing KYA flows that key off `external_id`
(audit export, delegation, RBAC, regulator pack) work without
modification.

## 6. Read the binding back

```python
from kya.external_id import lookup_principal_by_idp

with default_session() as db:
    found = lookup_principal_by_idp(
        db,
        tenant_id="tenant-alpha",
        idp_kind="did",
        idp_subject="did:web:bank.example:planner",
    )
    print(found)
    # {
    #     "principal_id": "planner",
    #     "principal_kind": "agent",
    #     "trust_score": 51,
    #     "idp_subject": "did:web:bank.example:planner",
    #     "idp_issuer": "did:web:bank.example",
    #     "idp_kind": "did",
    #     ...
    # }
```

## 7. Register a custom DID method

Need to support a method KYA doesn't ship (say, `did:plc` for Bluesky)?
Register a resolver at runtime:

```python
from kya.did import register_did_method
from kya.did_document import DIDDocument, VerificationMethod

def my_plc_resolver(suffix: str) -> DIDDocument:
    # ... your method-specific logic ...
    return DIDDocument(id=f"did:plc:{suffix}", verification_methods=[...])

register_did_method("plc", my_plc_resolver)
```

Then add `plc` to your `KYA_DID_RESOLVERS` env var and you can resolve
`did:plc:...` URIs through the same `resolve_did()` facade.

## Acceptance checklist

After running through this guide you should be able to:

- [x] `pip install veldt-kya[did]` succeeds
- [x] `KYA_DID_RESOLVERS=key,web,jwk python examples/live_e2e_did_principal.py`
      prints a successful bind
- [x] The bound principal shows up in `lookup_principal_by_idp(..., idp_kind="did")`
- [x] An expired VC raises `VCExpired` and the bind doesn't proceed
- [x] An untrusted issuer raises `VCIssuerNotTrusted` and the bind doesn't proceed

## See also

- `docs/requirements/did_adapter.md` — full requirements doc
- `examples/live_e2e_did_principal.py` — runnable end-to-end
- `tests/test_did_key.py`, `test_did_web.py`, `test_did_jwk.py`, `test_vc.py`
