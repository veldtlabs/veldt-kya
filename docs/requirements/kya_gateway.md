# KYA Gateway — Requirements

**Status:** draft
**Phase:** 4 (sits alongside Phase 3d DID)
**Owner:** veldt-kya
**Last updated:** 2026-06-10

---

## 1. Why this exists

KYA already ships every governance primitive a runtime gate needs:

- Identity (`kya/principals.py` + `kya/external_id.py` + `kya/did.py`)
- Authority (`require_action`, `min_trust`, `delegation_policy`)
- Policy (`rbac`, `payload_caps`, `replay_protection`, `rate_limit`)
- Economics (`tenant_budget`)
- Evidence (`record_evidence`, `verify_chain`, HMAC + Ed25519)
- Verdict scoring (`scorer_orchestrator`, multi-judge consensus)

What's missing is a **deployable, MCP-protocol-aware reverse proxy** that wraps those primitives so customers can drop a single container in front of their MCP servers and get the full KYA decision pipeline at runtime.

KYA Gateway is **assembly, not invention.** It packages existing KYA primitives behind an MCP-compatible HTTP surface plus a CLI launcher.

## 2. Goals (MVP)

1. **MCP-compatible reverse proxy** — speaks JSON-RPC 2.0 over HTTP / Server-Sent Events to MCP-aware agents (Claude Desktop, Cursor, custom LangGraph MCP clients).
2. **Forwards authorized calls** to a configured backend MCP server.
3. **Runs the KYA policy pipeline** on every `tools/call` before forwarding.
4. **Records a tamper-evident audit record** for every decision (allow + deny + escalate).
5. **Identity binding** via DID (Phase 3d), JWT bearer, or SPIFFE — pluggable.
6. **Single binary deploy** — Docker image, Helm chart, or `kya-gateway --config gateway.yaml`.
7. **Hot-reloadable config** — `SIGHUP` re-reads the YAML config without restarting connections.
8. **Observability** — Prometheus metrics + OpenTelemetry spans + structured logs.

## 3. Non-goals (this phase)

- MCP over stdio transport (will come once the HTTP transport is stable; stdio adds process management complexity that doesn't pay until customers ask).
- A web UI for managing gateway rules (the UI is a separate product — this is the data plane).
- Building new policy primitives — Gateway only orchestrates what `kya/` already ships.
- LLM-side reasoning (the Gateway sits between the agent and its tools; reasoning happens in the agent).

## 4. Design principles

| Principle | What it means |
|---|---|
| **Assembly over invention** | Reuse `require_action`, `record_evidence`, `verify_chain`, `tenant_budget`, etc. directly. Zero policy logic in `kya_gateway/`. |
| **Framework-agnostic** | Works with any MCP client; doesn't depend on LangChain, OpenAI Agents, or any specific framework. |
| **Self-contained** | One Python wheel + one Docker image. No external services required beyond the KYA DB. |
| **Fail-closed** | If the policy pipeline can't evaluate a call (DB unreachable, evidence chain locked), the gateway denies. |
| **Decision = artifact** | Every verdict produces a signed audit record. The platform that calls the Gateway decides whether to enforce; the Gateway records what it would have done either way. |
| **Streamable** | The forwarder must preserve MCP streaming responses (SSE) so the agent's UX is unchanged. |
| **Operable** | Health + readiness + metrics endpoints, structured JSON logs, exit codes that supervisord understands. |

## 5. Threat model

| Threat | Mitigation |
|---|---|
| Agent forges a tool call with someone else's principal | Identity verified at the gateway boundary (DID/JWT/SPIFFE). Forged or unsigned principals fail closed. |
| Agent floods the gateway to bypass policy | `rate_limit` + `payload_caps` + `tenant_budget` checked before forwarding. |
| Backend MCP server compromised | Gateway never trusts backend responses; evidence is recorded for both call and response. |
| Replay of a prior valid call to drain budget | `replay_protection` checks the trace ID. |
| Gateway operator alters evidence after the fact | HMAC chain + Ed25519 signed exports — same primitives KYA already ships. |
| Misconfigured forwarder leaks tokens to the wrong upstream | Per-route allowlists; upstream URLs are pinned at config-load time, not at request time. |
| SSRF via gateway to internal services | Outbound URL allowlist + DNS rebind protection. |
| Slowloris / connection exhaustion | Connection-level timeouts + max concurrent connections per principal. |

## 6. Architecture

```
┌──────────────────┐    HTTP/SSE     ┌─────────────────────────────────┐    HTTP/SSE    ┌──────────────────┐
│  MCP Client      │  JSON-RPC 2.0   │           KYA GATEWAY           │   forward      │ Backend MCP      │
│  (Claude Desktop,│ ────────────────▶                                 │ ──────────────▶│ Server           │
│  Cursor, agent)  │                 │  ┌──────────────────────────┐   │                │ (filesystem,     │
└──────────────────┘                 │  │ 1. Identity binding      │   │                │  postgres, etc.) │
                                     │  │    (DID / JWT / SPIFFE)  │   │                └──────────────────┘
                                     │  │ 2. Policy pipeline       │
                                     │  │    require_action +      │
                                     │  │    RBAC + rate +         │
                                     │  │    payload_caps +        │
                                     │  │    tenant_budget +       │
                                     │  │    replay_protection     │
                                     │  │ 3. record_evidence       │
                                     │  │    (HMAC + Ed25519)      │
                                     │  │ 4. Forward OR deny       │
                                     │  └──────────────────────────┘
                                     │             │
                                     │             ▼
                                     │     ┌───────────────┐
                                     │     │ KYA Storage   │ (SQLAlchemy — PG/MySQL/SQLite/DuckDB)
                                     │     │ (evidence,    │
                                     │     │  principals,  │
                                     │     │  audit log)   │
                                     │     └───────────────┘
                                     └─────────────────────────────────┘
```

## 7. Module shape

```
kya_gateway/
  __init__.py            # public API: Gateway, run(), version()
  __main__.py            # python -m kya_gateway
  server.py              # FastAPI app + lifecycle
  mcp_protocol.py        # JSON-RPC 2.0 framing + MCP method routing
  policy_pipeline.py     # The KYA decision stack (wraps existing primitives)
  forwarder.py           # Backend MCP server proxy (HTTP + SSE streaming)
  evidence.py            # Convenience wrappers around kya.record_evidence
  identity.py            # Identity adapter (DID/JWT/SPIFFE) — delegates to kya.did, kya.auth, kya.spiffe
  config.py              # YAML schema, loader, validator
  cli.py                 # Argparse CLI (kya-gateway entry point)
  metrics.py             # Prometheus + OTel hooks (optional extras)
  errors.py              # Typed errors (PolicyDenied, ForwarderFailed, etc.)
```

## 8. Public API

### Python (programmatic)

```python
from kya_gateway import Gateway, GatewayConfig

cfg = GatewayConfig.from_yaml("gateway.yaml")
gw = Gateway(cfg)
gw.run(host="0.0.0.0", port=8080)
```

### CLI (operational)

```bash
kya-gateway --config gateway.yaml --port 8080
kya-gateway --version
kya-gateway --validate-config gateway.yaml   # exit 0/1
```

### Docker

```bash
docker run --rm -p 8080:8080 \
    -v $(pwd)/gateway.yaml:/etc/kya/gateway.yaml \
    -e KYA_DB_URL=postgresql://... \
    -e KYA_EVIDENCE_SIGNING_KEY=... \
    veldtlabs/kya-gateway:0.x
```

### Config schema (excerpt)

```yaml
# gateway.yaml
gateway:
  bind: "0.0.0.0:8080"
  tenant_id: "tenant-alpha"

identity:
  methods: ["did", "jwt"]            # order = preference
  jwt:
    jwks_url: "https://idp.example/.well-known/jwks.json"
  did:
    resolvers: ["key", "web", "jwk"]
    trusted_issuers:
      - "did:web:bank.example"

backends:
  - name: "filesystem"
    url: "http://filesystem-mcp:9001"
    timeout_s: 30
  - name: "postgres"
    url: "http://postgres-mcp:9002"
    timeout_s: 60

policy:
  min_trust: 70
  rate_limit:
    requests_per_minute: 600
  payload_caps:
    max_bytes: 65536
  tenant_budget:
    daily_usd: 50
  rbac:
    default: "deny"
    rules:
      - principal_kind: "agent"
        actions: ["filesystem.read", "postgres.read"]
        verdict: "allow"
      - principal_kind: "agent"
        actions: ["filesystem.write", "postgres.write"]
        verdict: "require_human"

audit:
  evidence_signing_key_env: "KYA_EVIDENCE_SIGNING_KEY"
  hmac_chain: true
  ed25519_export_on_shutdown: true
```

## 9. HTTP surface

| Path | Method | Purpose |
|---|---|---|
| `/mcp` | POST | JSON-RPC 2.0 endpoint — main MCP traffic |
| `/mcp/sse` | GET | Server-Sent Events stream for tool responses |
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe (checks DB + at least one backend) |
| `/metrics` | GET | Prometheus metrics (extra) |
| `/v1/principals/me` | GET | Returns the bound principal for the current bearer/DID |
| `/v1/audit/{evidence_id}` | GET | Returns a signed audit record (auth-gated) |

## 10. Acceptance tests

| # | Scenario | Expected |
|---|---|---|
| 1 | MCP `initialize` request | Returns server capabilities |
| 2 | MCP `tools/list` request | Returns the union of backend tools, scoped by RBAC |
| 3 | MCP `tools/call` with passing policy | Forwards to backend, returns response, records evidence |
| 4 | MCP `tools/call` with failing `min_trust` | Returns JSON-RPC error, records denial evidence |
| 5 | MCP `tools/call` exceeding `tenant_budget` | Returns budget-exceeded error, records denial |
| 6 | Replay of a prior signed request | Returns replay-detected error |
| 7 | Unbound principal (no DID/JWT/SPIFFE) | Returns 401, no evidence recorded (auth precedes audit) |
| 8 | DB unreachable | Returns 503, gateway is unhealthy |
| 9 | Backend MCP server unreachable | Returns JSON-RPC error, evidence records the forwarder failure |
| 10 | Config validation fails | CLI exits with code 1 and a helpful error |
| 11 | SIGHUP after config edit | Reloads config without dropping in-flight connections |
| 12 | Streaming SSE response from backend | Forwards through unchanged |

## 11. Dependencies

- **Core KYA stack** — SQLAlchemy 2.x, evidence chain, principals, RBAC, tenant_budget, etc.
- **Phase 3d DID adapter** (optional, only if `identity.methods` includes `did`).
- **New deps** (`extras_require['gateway']`):
  - `fastapi` ≥ 0.110
  - `uvicorn[standard]` ≥ 0.27
  - `httpx` ≥ 0.27 (for forwarder)
  - `pyyaml` ≥ 6.0 (for config)
  - `sse-starlette` ≥ 2.0 (for backend SSE streaming)

`pip install veldt-kya[gateway]` opts in.

## 12. Backwards compatibility

- New top-level package; no existing module shape changes.
- Gateway uses the same `kya_evidence` table as the rest of KYA — running it alongside an existing KYA deployment is non-destructive.
- Pre-existing principals work without DID — the JWT/SPIFFE bindings already in `kya/external_id.py` are first-class identity methods.

## 13. Open questions

- Should the gateway support **stdio MCP** transport for use with Claude Desktop directly? *MVP: no. Add when there's a customer using it.*
- Should the gateway carry tenant-scoped **per-tool feature flags** so different agents see different tool surfaces? *Out of scope for MVP; RBAC at action level is enough.*
- How does the gateway behave when **the customer's platform decides not to enforce** the verdict? *MVP: gateway always records the verdict honestly; if the platform forwards anyway, that's the customer's audit trail to defend.*

## 14. Future work (Phase 4.x)

- stdio MCP transport.
- A2A (Anthropic Agent-to-Agent) protocol adapter alongside MCP.
- LangChain / CrewAI passthrough mode (not just MCP).
- Tenant-scoped feature flags.
- Built-in admin UI (a separate product).
- Multi-region active-active deployment with shared evidence chain.

## 15. Release shape

- Wheel published on PyPI: `pip install veldt-kya[gateway]`
- Docker image: `veldtlabs/kya-gateway:0.x` (multi-arch — amd64, arm64)
- Helm chart in `helm/kya-gateway/` (ships in `veldt-kya-pro`)
- `examples/gateway/` with a basic.yaml, with-did.yaml, and docker-compose.yml
