# veldt-kya

**Verifiable records for AI agent actions.**

When an AI agent takes an action, KYA records it in a cryptographically
verifiable chain. If anyone modifies the record later, KYA detects it and
pinpoints exactly where the chain was broken.

Think of it as **Git for agent actions**: every action is committed,
hash-chained, and independently verifiable by anyone with the key.

```
Agent acts
      ↓
KYA records
      ↓
Record verified
      ↓
Record tampered
      ↓
KYA detects exactly where it changed
```

```bash
pip install veldt-kya
```

## The 30-second demo

**Step 1.** An AI agent issues a $50 refund.

```python
import json
from kya import (
    default_session, record_invocation, record_evidence, verify_chain,
)
from sqlalchemy import text

with default_session() as db:
    inv = record_invocation(
        db, tenant_id="acme", agent_key="support_bot",
        principal_kind="agent", principal_id="support_bot",
    )
    record_evidence(
        db, tenant_id="acme", invocation_id=inv,
        evidence_kind="tool_call",
        payload={"tool": "refund", "customer": "alice", "amount_usd": 50},
    )
    db.commit()
```

**Step 2.** Verify the audit chain — clean.

```python
    print(verify_chain(db, tenant_id="acme", invocation_id=inv))
    # → {'valid': True, 'broken_at': None, 'checked': 1, 'reason': None}
```

**Step 3.** Someone tampers — changes the refund from $50 to $5000 directly in the database.

```python
    tampered = json.dumps({"tool": "refund", "customer": "alice", "amount_usd": 5000})
    db.execute(
        text("UPDATE kya_evidence SET payload = :p WHERE invocation_id = :i"),
        {"i": inv, "p": tampered},
    )
    db.commit()
```

**Step 4.** Verify again — KYA pinpoints the modified row.

```python
    print(verify_chain(db, tenant_id="acme", invocation_id=inv))
    # → {'valid': False, 'broken_at': 1, 'checked': 1,
    #    'reason': 'payload_hash mismatch — payload was modified'}
```

All four steps run inside the same `with default_session() as db:` block from Step 1.

That's the whole pitch. The rest of this README is what to do next.

## What you get out of the box

- **Cryptographically chained evidence** — every action HMAC-linked to the previous one
- **Independent verification** — any party with the key can re-verify the whole chain
- **Pinpoint tamper detection** — exact row identified when the chain breaks
- **Portable storage** — SQLite, PostgreSQL, MySQL, or DuckDB; same code, any database
- **Persistent by default** — survives process restart, container restart, host failure
- **Framework-agnostic** — works with LangChain, CrewAI, LangGraph, OpenAI Agents, Claude SDK, and MCP

## Setup

`pip install veldt-kya` is enough to run the demo above. KYA falls back to
`sqlite:///~/.kya/kya.db` when nothing is configured.

For production, point KYA at your real database and signing key:

```bash
export KYA_DB_URL=postgresql://user:pass@host/db
export KYA_EVIDENCE_KEY_PROVIDER=aws-kms://arn:aws:kms:...
```

Vault, sealed secrets, and HSM-backed keys are supported via the same env var.

## Beyond the demo

The 30-second demo shows evidence — the core primitive. The open-source
package also includes:

- **Agent identity** anchored on W3C DIDs
- **Delegation chains** with attribution that carries upstream
- **Runtime policy enforcement** at the gateway
- **Per-agent revocation** via W3C StatusList 2021

Each one has the same shape as the demo above: a small, composable API you
can adopt one piece at a time.

## What KYA isn't

KYA isn't an observability tool. Datadog, OpenTelemetry, and your traces
explain *what happened operationally* — latency, cost, exceptions, execution
paths.

KYA explains something different: *was the action authorized, who was it
attributable to, and can the record be trusted weeks or months later?*

## Links

- [Full documentation](https://docs.veldtlabs.ai) — every primitive, with examples
- [arXiv paper](https://arxiv.org/abs/2605.25376) — formal model of the seven
  systems primitives behind KYA
- [veldt-kya-pro](https://veldtlabs.ai/pro) — commercial overlay with signed
  verdicts, regulator pack, and controls mapped to major healthcare,
  government, and AI governance frameworks

## License

Apache License 2.0 — © 2026 Veldt Labs Inc. See [LICENSE](LICENSE).
