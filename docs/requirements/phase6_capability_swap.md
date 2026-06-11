# Phase 6 — Friction → Capability Swap

## Why this exists

KYA's positioning ("capability-removal at runtime") was credible except for two endpoints that still used pure friction:

1. **`GET /v1/principals/me`** — rate-limited to 60/min/IP. Friction: an attacker with a stolen credential can confirm token validity at line rate from any IP.
2. **`POST /mcp` body** — capped at 32 MB. Friction: an attacker can send a 31.9 MB malformed JSON to consume parsing CPU.

Per the Sisinty test (*"Does this make the attack impossible, or just tedious?"*), both are tedious-not-impossible. Phase 6 converts them to capability-removal.

## Scope

* **In**: DPoP-style proof on `/v1/principals/me`, strict MCP envelope schema on `/mcp`
* **Out**: jti replay LRU (Phase 5e backlog), per-tenant body limits, multi-region DPoP nonces

## Threat model

| Threat | Friction-shaped today | Capability-shaped after Phase 6 |
|---|---|---|
| Stolen access token, attacker confirms validity | Rate limit → attacker still confirms in <1s | Requires DPoP key → token alone is dead |
| Stolen access token, replay later | Token valid until expiry | DPoP iat-bound; replay window is ±30s |
| Body-shaped DoS (huge malformed JSON) | 32 MB cap → 31.9 MB still parsed | Envelope schema → ~10 KB envelope ceiling |
| Param-shape attack (deeply nested object that exhausts JSON parser) | Not bounded | Depth-bounded schema |
| Method-name probing | Free | Allowed-method set |

## DPoP for /v1/principals/me

### Header shape

```
GET /v1/principals/me HTTP/1.1
Authorization: Bearer <jwt>            # (or X-KYA-DID + X-KYA-DID-Proof flow)
DPoP: <dpop-jwt>
```

The DPoP JWT is signed by a private key whose public counterpart is in
the resolved DID document's `authentication` set. Same key the
`X-KYA-DID-Proof` flow uses.

### DPoP JWT claims

```json
{
  "iss":  "did:web:agent.acme.com",
  "htm":  "GET",
  "htu":  "https://gateway.acme.com/v1/principals/me",
  "iat":  1717000000,
  "jti":  "8c4d2b9a..."
}
```

### Verification flow

1. Read `DPoP` header.
2. Parse JWS header — extract `kid`.
3. Look up `kid` in the bound principal's DID doc `authentication` set.
4. Single-algorithm verify via `_algorithms_for_jwk` (no family acceptance).
5. Assert `htm` matches HTTP method.
6. Assert `htu` matches the request URL (scheme + host + path; no query
   sensitivity — operators may strip / canonicalize via config).
7. Assert `iat` within ±30s leeway.
8. (Optional, Phase 5e) Track `jti` in LRU cache; reject if seen.

### What capability is removed

* **Replay-grinding the endpoint**: requires the DID's private key, which lives in the agent's keystore. The endpoint can no longer be queried at line-rate just from a stolen bearer.
* **Cross-call replay**: htm/htu binding means a DPoP for `GET /me` cannot be reused for any other method/path.

### Backward compatibility

Phase 6 makes DPoP **required** when the request reaches `/me` via DID identity (the only path that has a key to mint with). Bearer-JWT-only deployments retain the rate-limit fallback because OAuth IdPs don't usually mint DPoP-shaped keys per agent. Documented as a deployment choice — operators in DID-only mode get capability-removal, OAuth-mixed deployments retain friction for the legacy path.

A request without `DPoP` (or with bad DPoP) on a DID-mode deployment returns:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="invalid_dpop_proof", error_description="missing or invalid DPoP header"
```

## Strict envelope schema for /mcp

### Allowed top-level keys

```
{jsonrpc, id, method, params}
```

Anything else → reject with `-32600 Invalid Request`.

### Type constraints

```
jsonrpc: literal "2.0"
id:      int | str | null
method:  str matching ^[a-z][a-zA-Z0-9_/.\-]{0,63}$
params:  object | null  (NOT array — MCP uses named params only)
```

### MCP method allowlist

```
initialize | tools/list | tools/call | resources/list |
prompts/list | notifications/cancelled | notifications/progress |
ping
```

Unknown methods → `-32601 Method not found`. (Was: pass-through.)

### tools/call params shape

```
params.name:       str matching ^[a-zA-Z_][a-zA-Z0-9_.\-]{0,127}$
params.arguments:  object (recursive bound: max depth 8, max keys 64
                   per level, max string length 16384, max array
                   length 1024)
```

### Body size ceiling (defense in depth)

Stays at 32 MB as a process-protection guardrail — but the schema-bounded envelope means a well-shaped request can never approach it.

### What capability is removed

* **Send arbitrarily shaped JSON to the gateway**: the parser refuses anything that isn't a JSON-RPC envelope of the exact shape.
* **Send well-shaped but huge envelopes** (deeply nested attacker-controlled `params.arguments`): bound by depth + per-level key count + string length.
* **Probe for new methods**: only the MCP-defined set is honored; everything else returns `-32601`.

## Acceptance tests

Tests must surface real bugs.

1. **DPoP missing → 401 with WWW-Authenticate hint**
2. **DPoP signed by key NOT in DID's authentication set → 401**
3. **DPoP with `htm: POST` for a GET request → 401**
4. **DPoP with `htu` pointing at a different gateway → 401**
5. **DPoP with `iat` 60 seconds in the future → 401**
6. **DPoP with valid signature + htm/htu/iat → 200 echo**
7. **Body with `{"jsonrpc": "2.0", "id": 1, "method": "x", "params": {}, "extra": "boo"}` → -32600**
8. **Body with `params: [...]` (array form) → -32600**
9. **Body with `method: "evil_method"` not in allowlist → -32601**
10. **`params.arguments` with nesting depth 10 → -32600**
11. **`params.arguments` with a 100 KB string → -32600**

## Config

```yaml
identity:
  did:
    require_dpop_on_me: true              # default true in DID-mode
    dpop_audience: "https://gateway.acme.com"
    dpop_leeway_seconds: 30
policy:
  envelope:
    max_arguments_depth: 8
    max_arguments_keys_per_level: 64
    max_string_length: 16384
    max_array_length: 1024
```

## CLI smoke after implementation

```bash
# Without DPoP — expect 401
curl -i http://localhost:8080/v1/principals/me
# With DPoP — expect 200
curl -i http://localhost:8080/v1/principals/me -H "DPoP: $(mint-dpop GET /v1/principals/me)"
```
