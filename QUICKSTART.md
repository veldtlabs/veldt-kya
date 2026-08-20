# Veldt KYA — 60-second quickstart

Govern every tool call your AI agent makes. Two wiring options for Claude Code below.

Requires Docker, `bash`, `curl`, `jq`. Windows: WSL or Git Bash.

---

## Option A — PreToolUse hook (recommended)

Every Bash / Read / Write / Edit / MCP call is routed through the gateway.

```bash
# 1. Start the gateway
docker compose up -d kya-gateway

# 2. Set your identity + point the hook at the gateway
export KYA_HOOK_DID="did:key:z6Mkr..."          # your subject DID
export KYA_GATEWAY_URL="http://localhost:18080" # optional (default shown)

# 3. Verify it works
bash scripts/test-policy-gate.sh
```

Add the hook to `~/.claude/settings.json` and restart Claude Code:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": ".*",
      "hooks": [{
        "type": "command",
        "command": "env KYA_HOOK_DID=did:key:z6Mkr... KYA_GATEWAY_URL=http://localhost:18080 bash /absolute/path/to/policy-gate.sh",
        "timeout": 10
      }]
    }]
  }
}
```

**Windows users:** Claude Code may spawn hooks via a shell that lacks POSIX `env` on PATH, so the `env VAR=x ...` prefix can silently fail to launch. Create a personal wrapper script that exports env vars inside bash and points at `policy-gate.sh`:

```bash
# ~/kya-hook.sh (outside the repo)
#!/usr/bin/env bash
export KYA_HOOK_DID="did:key:your-did-here"
export KYA_GATEWAY_URL="http://localhost:18080"
exec bash /absolute/path/to/veldt-kya/scripts/policy-gate.sh
```

Then point settings.json at your wrapper:

```json
{ "type": "command", "command": "bash /absolute/path/to/kya-hook.sh", "timeout": 10 }
```

Keep the wrapper OUTSIDE the repo — it contains your identity DID.

**Fail-CLOSED by default:** gateway unreachable → tool call denied. Set `KYA_HOOK_FAIL_OPEN=1` in the wrapper to opt into allow-on-failure (logs to stderr; use only for dev).

**Debug tee (opt-in):** set `KYA_HOOK_STDIN_DUMP=/absolute/path/to/hook.log` in the wrapper to append every hook stdin + forwarded body to that file — useful when troubleshooting delegation-context flow. Point it at a trusted path only (the file contains full tool inputs, which may include secrets from Bash commands or Read file contents).

---

## Option B — MCP server (MCP tools only)

Governs only tools exposed as MCP; native Bash/Read/Write are NOT gated.

```bash
claude mcp add --transport http kya-gateway http://localhost:18080/mcp \
  -H "X-KYA-DID: did:key:z6Mkr..."
```

---

## Trade-offs

| | Hook (A) | MCP (B) |
|---|---|---|
| Coverage | every tool call | MCP tools only |
| Fail-closed | yes | client-dependent |
| Setup | 1 script + 5-line JSON | 1 CLI command |

Run both together: hook enforces at the tool-call boundary, MCP governs at the tool-provider boundary.
