# KYA Gateway — 10-minute Quickstart

KYA Gateway is an MCP-compatible reverse proxy that runs your existing KYA
policy stack (identity, RBAC, rate limit, budget, evidence chain) at the
gateway boundary. Drop it in front of any MCP server and every tool call
gets scored, signed, and recorded — before it reaches your tools.

This guide takes you from `pip install` to a gated MCP call in under
10 minutes.

---

## 1. Install

```bash
pip install "veldt-kya[gateway,did]"
```

Optional extras:

- `gateway` — pulls in FastAPI, uvicorn, httpx, PyYAML, sse-starlette
- `did`     — pulls in cryptography, pyjwt (needed if you want DID-bound principals)

## 2. Configure

Save this as `gateway.yaml`:

```yaml
gateway:
  bind: "0.0.0.0:8080"
  tenant_id: "tenant-alpha"

identity:
  methods: ["did", "bearer_jwt"]
  did:
    resolvers: ["key", "web", "jwk"]
    # PoP audience MUST be set — otherwise a proof minted for another
    # gateway can be replayed here. Use this gateway's external URL.
    pop_audience: "https://gateway.example.com/mcp"
  jwt:
    jwks_url: "https://idp.example/.well-known/jwks.json"
    trusted_issuers: []   # leave empty to downgrade self-elevation claims

backends:
  - name: "default"
    url: "http://localhost:9001"   # your MCP backend

policy:
  min_trust: 50
  rate_limit:
    requests_per_minute: 600
  payload_caps:
    max_bytes: 65536
  rbac:
    default: "deny"
    rules:
      - principal_kind: "agent"
        actions: ["mcp.default.read_*", "mcp.default.list_*"]
        verdict: "allow"
      - principal_kind: "agent"
        actions: ["mcp.default.write_*", "mcp.default.delete_*"]
        verdict: "require_human"

audit:
  evidence_signing_key_env: "KYA_EVIDENCE_SIGNING_KEY"
  hmac_chain: true
```

## 3. Validate

```bash
kya-gateway --validate-config gateway.yaml
# OK: parsed 1 backend(s), identity methods=['did', 'bearer_jwt']
```

`--validate-config` exits 1 on bad YAML, so you can wire it into CI as a
guard before deployment.

## 4. Run

```bash
export KYA_DB_URL=sqlite:///./kya.db
export KYA_EVIDENCE_SIGNING_KEY=$(openssl rand -base64 32)
export KYA_DID_RESOLVERS=key,web,jwk

kya-gateway --config gateway.yaml --port 8080
```

Or as a Python import:

```python
from kya_gateway import Gateway, GatewayConfig

cfg = GatewayConfig.from_yaml("gateway.yaml")
Gateway(cfg).run(host="0.0.0.0", port=8080)
```

## 5. Test it

```bash
# Liveness
curl http://localhost:8080/healthz

# Readiness (verifies KYA DB connectivity)
curl http://localhost:8080/readyz

# Send an MCP initialize request
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

# Or with DID identity instead.
# The X-KYA-DID-Proof header must be a JWT signed by a key in the DID
# document's `authentication` set, with iss=<the DID>, aud=<the gateway
# URL configured in pop_audience>, and a short exp (max 10 minutes).
# Without it the gateway rejects the request — anyone-can-claim-any-DID
# is not a posture KYA accepts by default.
curl -X POST http://localhost:8080/mcp \
  -H "X-KYA-DID: did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8" \
  -H "X-KYA-DID-Proof: eyJhbGciOi...your.pop.jwt" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

## 6. Point an agent at it

In a Claude Desktop config, replace the backend MCP server URL with
`http://localhost:8080/mcp`. The agent's `tools/call` requests now flow
through the gateway. Verdicts (`allow`, `deny`, `require_human`) are
recorded on the KYA evidence chain for every call.

## 7. Audit the recorded calls

```python
from kya import default_session, verify_chain, list_evidence

with default_session() as db:
    rows = list_evidence(
        db,
        tenant_id="tenant-alpha",
        evidence_kind="gateway_verdict",
    )
    for r in rows:
        print(r["payload"]["verdict"], r["payload"]["action"])

    ok = verify_chain(db, tenant_id="tenant-alpha", invocation_id=rows[-1]["invocation_id"])
    print("chain integrity:", ok)
```

## 8. Add a `require_human` workflow

When `verdict="require_human"` lands in your audit log, your platform
gets a JSON-RPC error with `data.verdict="require_human"` and the
`reason_codes`. Your platform's job is to display the pending decision
to an approver and re-submit the call once approved (with a header
indicating human approval, e.g., `X-KYA-Human-Approved-By: alice@bank.com`).

The Gateway records the approval action as a separate evidence row so
the audit trail shows both "agent requested" and "human approved" tied
to the same invocation_id.

## Acceptance checklist

- [x] `kya-gateway --validate-config gateway.yaml` exits 0
- [x] `curl http://localhost:8080/healthz` returns `{"status":"ok"}`
- [x] `curl http://localhost:8080/readyz` returns `{"ready":true}` once KYA DB is up
- [x] Bearer JWT, DID, and SPIFFE identity headers all bind to a principal
- [x] An RBAC deny rule returns JSON-RPC error code -32001
- [x] Allowed calls reach the backend and stream the response back
- [x] Every call (allow, deny, require_human) produces a signed evidence row

## See also

- `docs/requirements/kya_gateway.md` — full requirements doc
- `examples/gateway/basic.yaml` — runnable config
- `examples/gateway/docker-compose.yml` — Postgres + backend + gateway in one shot
- `docs/did_quickstart.md` — DID-bound principals
