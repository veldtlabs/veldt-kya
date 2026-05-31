# veldt-kya

**KYA (Know Your Agents)** is open-source trust, governance, and
evidentiary assurance infrastructure for autonomous systems.

It helps organizations answer:

- Who — or what — acted?
- What authority did they possess?
- What data and resources could they access?
- How did authority propagate across humans, AI agents, and services?
- Did the actions conform to policy?
- Can the decision be verified afterward?

The challenge is not simply telemetry. It is identity, authority,
evidentiary provenance, and enforceable behavioral contracts across
autonomous systems.

**KYA builds on KYP (Know Your Principal)**, a unified trust model
spanning human users, AI agents, service accounts, and machine
identities. Together they provide trust scoring, delegated-authority
attribution, policy enforcement, evidentiary provenance, drift
detection, data-sensitivity controls, and compliance-grade evidence
chains.

Applicable to LLM agents, multi-agent systems, autonomous workflows,
agentic RAG, AutoML pipelines, RPA bots, service accounts, and
machine identities.

```bash
pip install veldt-kya
```

KYA does not replace observability. Observability helps explain what
happened operationally — latency, cost, traces, and execution paths.
KYA helps determine whether actions were *authorized*,
*policy-conforming*, *attributable*, and *verifiable*.

> Framework paper (preprint): [KYA: A Framework-Agnostic Trust Layer
> for Autonomous Systems with Verifiable Provenance and Hierarchical
> Policy Composition](https://arxiv.org/abs/2605.25376).

---

## In 60 seconds — the full KYA story

One agent. One invocation. Every primitive at once: score it,
register it, observe what it touched, update its trust, prove the
chain wasn't tampered with, and emit an audit-ready compliance
summary.

```python
from kya import (
    score_agent, default_session,
    snapshot_agent, record_invocation, record_evidence,
    record_principal_signal, get_principal_trust,
    verify_chain, compliance_summary,
    require_action, AccessDeniedError,
)

# 1) Pre-deployment: assess the agent against its declared capabilities
billing_agent = {
    "agent_key": "billing_agent",
    "model": "openai/gpt-4o-mini",
    "tools": ["read_customer", "issue_credit"],
    "human_loop": "in_the_loop",
    "access_level": "write",
    "can_override": False,
    "data_classes": ["pii"],
    "compliance_scope": ["nydfs_500", "gdpr"],
}
risk = score_agent(billing_agent)

# 2) At runtime: record what happened
gate = "ALLOWED"
with default_session() as db:
    snapshot_agent(db, tenant_id="bank-1",
                   agent_key="billing_agent",
                   definition=billing_agent)

    inv = record_invocation(
        db, tenant_id="bank-1",
        agent_key="billing_agent",
        principal_kind="agent", principal_id="billing_agent",
        mode="observed", outcome="success",
    )

    record_evidence(db, tenant_id="bank-1", invocation_id=inv,
                    evidence_kind="tool_call",
                    payload={
                        "tool": "read_customer",
                        "query": "SELECT ssn, balance FROM customers WHERE id=:cid",
                        "data_class": "pii",
                    })

    record_principal_signal(
        db, tenant_id="bank-1",
        principal_kind="agent", principal_id="billing_agent",
        signal_kind="clean_invocation",
        actor_human_id="user_42",
    )
    db.commit()

    # 3) Governance gate: try a privileged action; min_trust=70 fires
    #    because the agent's trust score has not yet crossed the bar.
    try:
        require_action(db, tenant_id="bank-1",
                       principal_kind="agent",
                       principal_id="billing_agent",
                       action="kya.budget.write",
                       min_trust=70)
    except AccessDeniedError:
        gate = "BLOCKED"

    # 4) Audit time: prove nothing was tampered + read live trust
    chain = verify_chain(db, tenant_id="bank-1", invocation_id=inv)
    trust = get_principal_trust(
        db, tenant_id="bank-1",
        principal_kind="agent", principal_id="billing_agent",
    )

# 5) Compliance: what controls apply, what's the retention?
summary = compliance_summary(billing_agent, risk.score)

print(f"Principal:        agent:{trust.principal_id}")
print(f"Risk score:       {risk.score} ({risk.bucket})")
print(f"Data touched:     {billing_agent['data_classes']}")
print(f"Trust score:      {trust.trust_score} ({trust.bucket})")
print(f"Evidence chain:   {'valid' if chain['valid'] else 'broken'}  "
      f"(checked {chain['checked']} rows)")
print(f"Gate (min=70):    {gate}")
print(f"Signal ledger:    {trust.signal_counts}")
print(f"Compliance:       {summary['scope']}")
print(f"Retention req:    {summary['retention_days']} days")
```

```text
Principal:        agent:billing_agent
Risk score:       100 (critical)
Data touched:     ['pii']
Trust score:      49 (neutral)
Evidence chain:   valid  (checked 1 rows)
Gate (min=70):    BLOCKED
Signal ledger:    {'clean_invocation': 1, 'rbac_refusal': 1}
Compliance:       ['nydfs_500', 'gdpr']
Retention req:    2190 days
```

One snippet, every primitive: **identity (KYP), authority (risk
score + min-trust gate), governance (BLOCKED action records its own
audit signal), evidence (HMAC-chained), provenance (verify_chain),
and compliance (regime-aware retention + controls).**

The rest of this README breaks each primitive out so you can see
exactly how it works.

---

## 1. KYP — Know Your Principal

One trust ledger across humans, agents, and service accounts.
Signals from any source — runtime judges, RBAC refusals, kernel
alerts, manual ops decisions — feed the same principal's trust
score.

```python
from kya import (
    default_session, snapshot_agent,
    record_principal_signal, get_principal_trust,
)

with default_session() as db:
    snapshot_agent(db, tenant_id="bank-1",
                   agent_key="loan_writer",
                   definition={"agent_key": "loan_writer",
                               "tools": ["write_loan"]})

    # Signals can come from anywhere: runtime judges, RBAC gates,
    # kernel-level alerts, manual ops decisions. They all converge
    # on one principal ledger.
    for sig in ["clean_invocation", "received_attack", "data_leak"]:
        new = record_principal_signal(
            db, tenant_id="bank-1",
            principal_kind="agent", principal_id="loan_writer",
            signal_kind=sig,
        )
        print(f"  after {sig:<22} -> trust={new}")
    db.commit()

    trust = get_principal_trust(
        db, tenant_id="bank-1",
        principal_kind="agent", principal_id="loan_writer",
    )

print(f"final  trust={trust.trust_score} ({trust.bucket})")
print(f"       ledger={trust.signal_counts}")
```

```text
  after clean_invocation       -> trust=51
  after received_attack        -> trust=50
  after data_leak              -> trust=40
final  trust=40 (neutral)
       ledger={'clean_invocation': 1, 'received_attack': 1, 'data_leak': 1}
```

The ledger preserves every signal that ever fired on this
principal — not just the current score. Compliance teams reading
the audit later can see the full behavioral history.

Built-in signal kinds (with default trust deltas): `clean_invocation`
(+1), `received_attack` (-1), `governance_block` / `rate_limit_exceeded`
/ `rbac_refusal` (-2), `oos_tool` (-3), `payload_too_large` (-4),
`hallucination_detected` / `injection_attempt` (-5), `policy_violation`
(-7), `replay_detected` (-8), `data_leak` (-10), `cross_tenant` (-15).

---

## 2. Delegated authority

When a sub-agent misbehaves, the orchestrator is still accountable.
KYA's trust signals carry attribution so a parent agent's score
reflects the behavior of the delegates it dispatched.

```python
from kya import (
    default_session, snapshot_agent,
    record_principal_signal, get_principal_trust,
)

with default_session() as db:
    snapshot_agent(db, tenant_id="bank-1",
                   agent_key="loan_orchestrator",
                   definition={"agent_key": "loan_orchestrator",
                               "tools": ["delegate"]})

    # The delegate leaks data, attribution carried in attributes
    record_principal_signal(
        db, tenant_id="bank-1",
        principal_kind="agent", principal_id="loan_writer",
        signal_kind="data_leak",
        attributes={"delegated_by": "loan_orchestrator"},
    )

    # The orchestrator takes a smaller hit for failing to gate
    record_principal_signal(
        db, tenant_id="bank-1",
        principal_kind="agent", principal_id="loan_orchestrator",
        signal_kind="governance_block",
        attributes={"delegate": "loan_writer",
                    "reason": "delegate_misbehavior"},
    )
    db.commit()

    child = get_principal_trust(db, tenant_id="bank-1",
                                principal_kind="agent",
                                principal_id="loan_writer")
    parent = get_principal_trust(db, tenant_id="bank-1",
                                 principal_kind="agent",
                                 principal_id="loan_orchestrator")

print(f"child   (loan_writer):       trust={child.trust_score} "
      f"({child.bucket})  signals={child.signal_counts}")
print(f"parent  (loan_orchestrator): trust={parent.trust_score} "
      f"({parent.bucket})  signals={parent.signal_counts}")
print(f"  attribution carried:       {child.attributes}")
```

```text
child   (loan_writer):       trust=30 (risky)  signals={'data_leak': 2}
parent  (loan_orchestrator): trust=48 (neutral)  signals={'governance_block': 1}
  attribution carried:       {'delegated_by': 'loan_orchestrator'}
```

The orchestrator's trust drops too — by less, because the leak was a
delegate's action, but enough that repeated delegate misbehavior
will eventually push the orchestrator's trust into the policy-gate
threshold.

---

## 3. Verifiable provenance — evidence chains

Every `record_evidence` call HMAC-chains the new row to the prior
one. A single tampered payload anywhere in the chain shows up as a
hash mismatch — including the exact row that broke.

```python
from sqlalchemy import text
from kya import (
    default_session, record_invocation, record_evidence, verify_chain,
)

with default_session() as db:
    inv = record_invocation(
        db, tenant_id="bank-1",
        agent_key="loan_writer",
        principal_kind="agent", principal_id="loan_writer",
        mode="observed", outcome="success",
    )
    for kind, payload in [
        ("prompt",    {"text": "Approve loan #4521"}),
        ("tool_call", {"tool": "read_credit", "applicant": "id_84"}),
        ("response",  {"text": "Approved at $25,000 APR 8.2%"}),
    ]:
        record_evidence(db, tenant_id="bank-1", invocation_id=inv,
                        evidence_kind=kind, payload=payload)
    db.commit()
    ok = verify_chain(db, tenant_id="bank-1", invocation_id=inv)

    # Attacker rewrites the approved amount post-hoc
    db.execute(text(
        "UPDATE kya_evidence "
        "SET payload = json('{\"text\":\"Approved at $250,000\"}') "
        "WHERE invocation_id = :i AND evidence_kind = 'response'"
    ), {"i": inv})
    db.commit()
    bad = verify_chain(db, tenant_id="bank-1", invocation_id=inv)

print(f"intact:   valid={ok['valid']}  checked={ok['checked']}")
print(f"tampered: valid={bad['valid']}  "
      f"broken_at={bad['broken_at']}  reason={bad['reason']}")
```

```text
intact:   valid=True  checked=3
tampered: valid=False  broken_at=4  reason=payload_hash mismatch — payload was modified
```

Mount a real signing key in production via `KYA_EVIDENCE_KEY_PROVIDER`
(KMS, Vault, or sealed-secret). The chain survives process restart
and remains independently verifiable by anyone holding the key.

---

## 4. Compliance regimes

Convert a scored agent into the regime-specific obligations an
auditor will ask about: required controls, retention, breach-
notification windows, and the regulator's citation chain.

```python
from kya import compliance_summary, REGIME_BREACH_NOTIFY

agent_def = {
    "agent_key": "billing_agent",
    "compliance_scope": ["nydfs_500"],
    "data_classes": ["pii"],
}
summary = compliance_summary(agent_def, risk_score=100)

print(f"scope:           {summary['scope']}")
print(f"retention_days:  {summary['retention_days']}")
print(f"first control:   {summary['required_controls'][0]['id']}  "
      f"({summary['required_controls'][0]['source']})")
print(f"NYDFS notify:    {REGIME_BREACH_NOTIFY['nydfs_500']}")
```

```text
scope:           ['nydfs_500']
retention_days:  1825
first control:   nydfs_500_02  (23 NYCRR §500.02)
NYDFS notify:    {'window_hours': 72, 'format': 'nydfs_breach', 'authority': 'NYDFS Superintendent (23 NYCRR §500.17)'}
```

Built-in regimes: GDPR, EU AI Act, HIPAA, SOX, PCI, CCPA, GLBA,
FERPA, ISO 27001, SOC 2, NYDFS 500, DORA, SR 11-7, ISO 42001,
EO 14110, AI Bill of Rights — plus federal/defense (ITAR, EAR,
CMMC, FedRAMP, DFARS, NIST 800-171, NIST 800-53, FIPS 140-2/3) and
international equivalents (IRAP, CCCS, C5, ENS, IL5/IL6).

---

## 5. Works with the frameworks you already use

`normalize_agent_def(framework, raw_def)` adapts foreign agent shapes
into the canonical schema. Wrap the same conceptual agent in
LangChain, CrewAI, OpenAI Assistants, Claude Agent SDK — KYA
produces the same canonical view + the same risk score.

```python
from kya import normalize_agent_def, score_agent

# Same billing-triage agent, three framework shells:

oa = normalize_agent_def("openai", {
    "id": "billing_triage", "model": "gpt-4o-mini",
    "instructions": "Triage billing tickets",
    "tools": [
        {"type": "function", "function": {"name": "read_billing"}},
        {"type": "function", "function": {"name": "issue_credit"}},
    ],
})

from crewai import Agent
from crewai.tools import tool as crewai_tool

@crewai_tool("read_billing")
def read_billing(customer_id: str) -> str:
    """Read billing records."""
    return ""

@crewai_tool("issue_credit")
def issue_credit(customer_id: str, amount: float) -> str:
    """Issue billing credit."""
    return ""

crew = normalize_agent_def("crewai", Agent(
    role="Billing Triage", goal="Triage billing tickets",
    backstory="Senior billing analyst",
    tools=[read_billing, issue_credit],
    allow_delegation=False, verbose=False,
))

gen = normalize_agent_def("generic", {
    "agent_key": "billing_triage",
    "model": "openai/gpt-4o-mini",
    "tools": ["read_billing", "issue_credit"],
    "access_level": "write",
    "data_classes": ["customer_financial"],
    "compliance_scope": ["nydfs_500", "pci"],
})

for name, canon in [("OpenAI", oa), ("CrewAI", crew), ("Generic", gen)]:
    r = score_agent(canon)
    print(f"  {name:<8}  score={r.score} ({r.bucket})  "
          f"tools={canon.get('tools')}")
```

```text
  OpenAI    score=100 (critical)  tools=['read_billing', 'issue_credit']
  CrewAI    score=100 (critical)  tools=['read_billing', 'issue_credit']
  Generic   score=100 (critical)  tools=['read_billing', 'issue_credit']
```

Same authority. Same trust posture. Same governance outcome. Built-
in adapters cover **23 frameworks** including LangChain, CrewAI,
OpenAI Agents, Claude Agent SDK, AutoGen, Semantic Kernel,
LlamaIndex, Haystack, MCP, Bedrock, Vertex, Pydantic AI, Letta,
Smol, Strands, Google ADK, and more.

For proprietary frameworks, register your own adapter:

```python
from dataclasses import dataclass
from kya import register_adapter, normalize_agent_def, score_agent

@dataclass
class AcmeAgent:
    id: str
    allowed_actions: list
    model: str = "gpt-4o-mini"

def acme_adapter(raw):
    return {
        "agent_key": raw.id,
        "model": raw.model,
        "tools": raw.allowed_actions,
        "human_loop": "in_the_loop",
        "access_level": "write",
        "data_classes": ["operational"],
        "compliance_scope": [],
    }

register_adapter("acme", acme_adapter)
r = score_agent(normalize_agent_def("acme", AcmeAgent(
    id="ticket_router",
    allowed_actions=["read_ticket", "assign_owner"],
)))
print(f"acme.ticket_router  score={r.score} ({r.bucket})")
```

```text
acme.ticket_router  score=97 (critical)
```

---

## 6. Runtime security correlation

Kernel-level evidence (Falco, auditd, eBPF probes) lands on the
same principal as the agent's tool-call evidence — so a "terminal
shell in container" alert flows into the agent's trust ledger and
attack-chain correlation.

```python
from sqlalchemy import text
from kya import (
    default_session, record_invocation, record_evidence,
    record_principal_signal, get_principal_trust,
)

with default_session() as db:
    # One invocation -- the agent's normal work
    inv = record_invocation(
        db, tenant_id="bank-1",
        agent_key="research_agent",
        principal_kind="agent", principal_id="research_agent",
        mode="observed", outcome="success",
        correlation_id="incident_2026_0531",
    )

    # Application-layer evidence: the tool call the agent made
    record_evidence(db, tenant_id="bank-1", invocation_id=inv,
                    evidence_kind="tool_call",
                    payload={"tool": "fetch_url",
                             "url": "https://internal-corpus.example.com/doc-42"})

    # Kernel-layer evidence: Falco fires on the agent's container.
    # ``runtime_falco`` is one of KYA's canonical evidence_kinds
    # for runtime-security sources (runtime_auditd, runtime_tetragon,
    # runtime_tracee, runtime_osquery, runtime_sysdig, runtime_k8s_audit,
    # runtime_ebpf).
    record_evidence(db, tenant_id="bank-1", invocation_id=inv,
                    evidence_kind="runtime_falco",
                    payload={"rule": "Terminal shell in container",
                             "priority": "critical",
                             "container_id": "ab12c4",
                             "mitre_attack": ["T1059"]})

    # Route the kernel signal into the principal's trust ledger
    record_principal_signal(
        db, tenant_id="bank-1",
        principal_kind="agent", principal_id="research_agent",
        signal_kind="policy_violation",
        attributes={"source": "falco", "mitre": "T1059"},
    )
    db.commit()

    # Show the correlation: both layers, one principal, one invocation
    rows = db.execute(text(
        "SELECT evidence_kind, "
        "       coalesce(json_extract(payload,'$.tool'),'-') as tool, "
        "       coalesce(json_extract(payload,'$.rule'),'-') as rule "
        "FROM kya_evidence WHERE invocation_id = :i ORDER BY id"
    ), {"i": inv}).fetchall()
    trust = get_principal_trust(db, tenant_id="bank-1",
                                principal_kind="agent",
                                principal_id="research_agent")

print(f"invocation_id={inv}  correlation_id=incident_2026_0531")
print(f"principal=agent:research_agent  "
      f"trust={trust.trust_score} ({trust.bucket})")
print()
print(f"  {'evidence_kind':<16}  {'tool':<12}  rule")
print(f"  {'-'*16}  {'-'*12}  {'-'*30}")
for r in rows:
    print(f"  {r[0]:<16}  {r[1]:<12}  {r[2]}")
```

```text
invocation_id=1  correlation_id=incident_2026_0531
principal=agent:research_agent  trust=43 (neutral)

  evidence_kind     tool          rule
  ----------------  ------------  ------------------------------
  tool_call         fetch_url     -
  runtime_falco     -             Terminal shell in container
```

Both layers — the agent's `tool_call` and the kernel's `runtime_falco` — land on the **same invocation_id, the same principal, and the same correlation_id**. The kernel-level signal also flows into the principal's trust ledger, so attack-chain rules can correlate the two timelines without a separate join.

Premium runtime parsers for Falco, auditd, Kubernetes audit log,
Tetragon, osquery, Tracee, Sysdig OSS, and custom eBPF probes — plus
a K8s annotation resolver for principal binding — ship in the
commercial `veldt-kya-pro` overlay.

---

## 7. Drift detection

A one-line edit to `system_prompt` or `tools` flips the canonical
hash. Detect when the agent in production has mutated since its
registration.

```python
from kya import canonical_hash, detect_drift

declared = {"agent_key": "billing_agent",
            "tools": ["read_customer"],
            "model": "gpt-4o-mini"}
declared_hash = canonical_hash(declared)

# Someone adds a high-power tool without re-registering
current = {"agent_key": "billing_agent",
           "tools": ["read_customer", "shell_exec"],
           "model": "gpt-4o-mini"}

print(f"same def:      drift={detect_drift(declared_hash, declared)}")
print(f"+ shell_exec:  drift={detect_drift(declared_hash, current)}")
```

```text
same def:      drift=False
+ shell_exec:  drift=True
```

---

## Persistence — zero-config to start, production-grade to scale

`score_agent()`, `normalize_agent_def()`, `canonical_hash()`, and
`compliance_summary()` are pure functions. Anything that records
evidence, principal trust, agent versions, or invocations needs a
database.

`kya.default_session()` falls back to `sqlite:///~/.kya/kya.db` when
`KYA_DB_URL` is unset. For production, set
`KYA_DB_URL=postgresql://...` (or MySQL / DuckDB). All KYA tables
are portable across **PostgreSQL, MySQL, SQLite, and DuckDB**.

---

## Runtime: multi-judge orchestration + trust

`score_agent()` is pre-deployment. At runtime, `check_consensus()`
runs N third-party judges in parallel and routes the verdict into
the principal's trust ledger:

```python
from kya.scorer_orchestrator import (
    check_consensus, register_available_adapters, signals_from_consensus,
)

register_available_adapters()   # auto-wires opt-in judges if installed

r = check_consensus(
    input_text="Summarize this report.",
    response="The report says Q3 revenue was up 12%.",
    context="Q3 revenue rose 12%.",
)
print(f"consensus={r.consensus}  judges_voted={sum(1 for j in r.judges if j.verdict)}")
```

```text
consensus=OK  judges_voted=8
```

Default panel splits into three tiers:

**Bundled** (no setup, ships with `pip install veldt-kya`):
`openai_judge` (uses your existing `OPENAI_API_KEY` if set),
`refusal_heuristic` (substring detection, no API call), `kya_pyrit`
(output data-leak scanning), `kya_attack_patterns` (encoded
payloads, exfil paths, indirect injection, PII smuggling, role
hijack, authority claims, external redirects).

**Optional extras** (one install command, no external service):
`kya_presidio` (PII detector) via `pip install veldt-kya[presidio]`.
`arize_phoenix` (hallucination methodology) via
`pip install veldt-kya[recommended]`.

**BYOC bridges** (Bring Your Own Cloud — wraps an existing account):
`fiddler_safety` and `fiddler_faithfulness` adapt your Fiddler
Guardrails account into the panel; both require `FIDDLER_API_KEY`.
When not configured, those judges no-op and the rest of the panel
keeps voting.

Customers plug in their own judges via `register_judge(name, fn)`.

Signal routing is dimension-correct: `input_safety` →
`received_attack` (-1), `safety` → `policy_violation` (-7),
`faithfulness` → `hallucination_detected` (-5). Identity bindings
ship via `kya.auth`: JWT introspection, SPIFFE workload identity,
and OIDC (Keycloak / Okta / Auth0). See `examples/live_e2e_jwt_auth.py`,
`live_e2e_spiffe.py`, and `live_e2e_keycloak_real_idp.py`.

---

## Optional features (extras)

```
pip install "veldt-kya[recommended]"   # multi-judge starter pack
                                       # (Presidio PII + litellm for
                                       # arize_phoenix + openai_judge)

pip install "veldt-kya[presidio]"      # Presidio PII detector only
pip install "veldt-kya[judge]"         # litellm (Phoenix + LLM judges)
pip install "veldt-kya[all_judges]"    # presidio + litellm + langkit

pip install "veldt-kya[metrics]"       # Prometheus counters
pip install "veldt-kya[tracing]"       # OpenTelemetry span events
pip install "veldt-kya[webhooks]"      # Outbound emit (Splunk /
                                       # Datadog / regulator formats)
pip install "veldt-kya[attack_chains]" # YAML rule DSL for multi-step
                                       # attack-chain detection
pip install "veldt-kya[all]"           # everything
```

Core (`pip install veldt-kya`) is stdlib + SQLAlchemy + requests
only. The multi-judge orchestrator auto-registers judges from the
core install; opt-in extras add Presidio + Phoenix without changing
your code.

---

## Roadmap

This is the standalone packaging of the KYA infrastructure already
running in production inside Veldt Decisions. Items still on the
roadmap:

- Lakehouse adapter (Databricks Genie / Snowflake Cortex)
- Hosted KYA dashboard for self-managed deployments
- SQL-aware data-policy judge (customers bring this today via
  `register_judge()`; bundled adapter in a future release)
- Third-party-attestable notarization for the evidence chain
  (Sigstore / RFC 3161) layered on top of the existing HMAC chain
- Full DAG-wide topology validation for delegated agent graphs.
  v1 enforces pairwise parent-child ceilings (the Liang-2025
  topology-attack defense)

---

## License

Apache License 2.0 — © 2026 Veldt Labs Inc. See [LICENSE](LICENSE).
