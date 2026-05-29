# veldt-kya

**KYA (Know Your Agents)** is open-source trust, governance, and evidentiary
assurance infrastructure for autonomous systems.

It helps organizations answer:

- Who — or what — acted?
- What authority did they possess?
- What data and resources could they access?
- How did authority propagate across humans, AI agents, and services?
- Did the actions conform to policy?
- Can the decision be verified afterward?

The challenge is not simply telemetry. It is identity, authority, evidentiary
provenance, and enforceable behavioral contracts across autonomous systems.

**KYA builds on KYP (Know Your Principal)**, a unified trust model spanning
human users, AI agents, service accounts, and machine identities. Together they
provide trust scoring, delegated-authority attribution, policy enforcement,
evidentiary provenance, drift detection, data-sensitivity controls, and
compliance-grade evidence chains.

Applicable to LLM agents, multi-agent systems, autonomous workflows, agentic
RAG, AutoML pipelines, RPA bots, service accounts, and machine identities.

```bash
pip install veldt-kya
```

KYA does not replace observability. Observability helps explain what happened
operationally — latency, cost, traces, and execution paths. KYA helps determine
whether actions were *authorized*, *policy-conforming*, *attributable*, and
*verifiable*.

> Framework paper (preprint): [KYA: A Framework-Agnostic Trust Layer for
> Autonomous Systems with Verifiable Provenance and Hierarchical Policy
> Composition](https://arxiv.org/abs/2605.25376) — Quadri (2026).

## Quick start

```python
from kya import score_agent, normalize_agent_def

# Score a Veldt-native agent definition
risk = score_agent({
    "agent_key": "my_agent",
    "model": "openai/gpt-4o-mini",
    "tools": ["search_docs", "execute_sql"],
    "human_loop": "in_the_loop",
    "access_level": "write",
    "can_override": True,
    "data_classes": ["pii"],
    "compliance_scope": ["gdpr", "nydfs_500"],
})
print(risk.score, risk.bucket)          # 100 critical
for f in risk.factors:
    print(f.name, f.delta)              # attributable per-factor breakdown
```

## Persistence — zero-config evaluation

`score_agent()` is a pure function with no I/O. Anything that records
evidence, principal trust, agent versions, or invocations needs a
database. `kya.default_session()` gives you that with no setup —
it falls back to `sqlite:///~/.kya/kya.db` if `KYA_DB_URL` is unset:

```python
from kya import default_session, snapshot_agent, record_invocation, record_evidence

with default_session() as db:
    snapshot_agent(db, tenant_id="t1", agent_key="loan_triage",
                   definition={"agent_key": "loan_triage", "tools": ["check_credit"]})
    inv = record_invocation(db, tenant_id="t1", agent_key="loan_triage",
                            principal_kind="agent", principal_id="loan_triage",
                            mode="observed", outcome="success")
    record_evidence(db, tenant_id="t1", invocation_id=inv,
                    evidence_kind="prompt", payload={"text": "..."})
    db.commit()
```

For production, set `KYA_DB_URL=postgresql://...` (or MySQL / DuckDB).
All 17 KYA-owned tables are portable across **PostgreSQL, MySQL,
SQLite, and DuckDB** — verified by `tests/verify_all_backends_with_data.py`
(17 tables × 4 backends × non-empty row counts = 68/68 cells green).

## Bring your own framework

KYA's `normalize_agent_def(framework, raw_def)` adapts foreign agent
shapes into the canonical schema. **23 built-in adapters** across the
major agent frameworks (LangChain, CrewAI, OpenAI Agents, Claude Agent
SDK, AutoGen, Semantic Kernel, LlamaIndex, Haystack, MCP, Bedrock,
Vertex, Pydantic AI, Letta, Smol, Strands, Google ADK, and more):

```python
from kya import normalize_agent_def, score_agent

# LangChain
from langchain.agents import AgentExecutor
ex = AgentExecutor.from_agent_and_tools(agent, tools=[my_sql_tool, my_email_tool])
risk = score_agent(normalize_agent_def("langchain", ex))

# CrewAI
from crewai import Agent
agent = Agent(role="Analyst", goal="...", tools=[...])
risk = score_agent(normalize_agent_def("crewai", agent))

# OpenAI Assistants
risk = score_agent(normalize_agent_def("openai", openai_assistant_dict))

# Generic dict (everything else)
risk = score_agent(normalize_agent_def("generic", your_dict))
```

Register your own adapter for proprietary frameworks:

```python
from kya import register_adapter

def my_adapter(raw):
    return {"agent_key": raw.id, "tools": raw.allowed_actions, ...}

register_adapter("acme", my_adapter)
score_agent(normalize_agent_def("acme", proprietary_agent))
```

## Runtime: multi-judge orchestration + trust

`score_agent()` is pre-deployment. At runtime, `check_consensus()`
runs N third-party judges in parallel and routes the verdict into
per-principal trust:

```python
from kya.scorer_orchestrator import (
    check_consensus, register_available_adapters, signals_from_consensus,
)
from kya import record_principal_signal, require_action, AccessDeniedError

register_available_adapters()   # auto-wires opt-in judges if installed

r = check_consensus(input_text=user_msg, response=agent_response,
                    context=rag_context)
# r.consensus -> BREACH/OK/SPLIT/UNCLEAR
# r.per_dimension -> input_safety / safety / faithfulness
# r.judges -> per-judge verdict + score + latency

# Trust decay routed by dimension:
for signal_kind, dim in signals_from_consensus(r):
    record_principal_signal(db, tenant_id="t1", principal_kind="agent",
                            principal_id="my_agent", signal_kind=signal_kind)

# Gate privileged actions on trust:
try:
    require_action(db, tenant_id="t1", principal_kind="agent",
                   principal_id="my_agent", action="kya.budget.write",
                   min_trust=45)
except AccessDeniedError:
    ...   # agent's trust fell below 45 -- auto-block, no operator needed
```

The orchestrator's default panel splits into three honest tiers
so you can tell what works out of the box vs what needs setup:

**Bundled (no setup, works after `pip install veldt-kya`):**
`openai_judge` (uses your existing `OPENAI_API_KEY` if set),
`refusal_heuristic` (substring detection, no API call),
`kya_pyrit` (output data-leak scanning), `kya_attack_patterns`
(7 categories: encoded payloads, exfil paths, indirect injection,
PII smuggling, role hijack, authority claims, external redirects).

**Optional extras (one install command, no external service):**
`kya_presidio` (PII detector, tunable: entities / threshold /
min-findings) via `pip install veldt-kya[presidio]`. `arize_phoenix`
(hallucination-methodology judge via litellm) via
`pip install veldt-kya[recommended]`.

**BYOC bridges (Bring Your Own Cloud — wraps an existing paid
account):** `fiddler_safety` and `fiddler_faithfulness` adapt your
Fiddler Guardrails account into the panel; both require
`FIDDLER_API_KEY` in env. If you don't have an account these
judges no-op, the rest of the panel keeps voting, and the
orchestrator's consensus stays defensible. The same bucket is
where future commercial-guardrail bridges land — KYA orchestrates
above the service rather than replacing it.

Customers plug in their own judges (SQL-aware policy engines,
internal red-team scorers, etc.) via `register_judge(name, fn)`.

Signal routing is dimension-correct: `input_safety` → `received_attack`
(-1, agent was attacked but may have refused), `safety` →
`policy_violation` (-7), `faithfulness` → `hallucination_detected`
(-5). Identity bindings ship today via `kya.auth`: JWT introspection,
SPIFFE workload identity, and OIDC (Keycloak / Okta / Auth0). See
`examples/live_e2e_jwt_auth.py`, `live_e2e_spiffe.py`, and
`live_e2e_keycloak_real_idp.py`.

## Drift detection

```python
from kya import canonical_hash, detect_drift

# At registration time, store the hash:
declared = canonical_hash(agent_def)

# Later, anywhere — did anyone tamper with the definition?
if detect_drift(declared, current_agent_def):
    alert("agent identity has mutated since registration")
```

A one-line edit to `system_prompt` flips the SHA. Observability tools
don't watch your config — KYA does.

## Compliance regimes

```python
from kya import compliance_summary, REGIME_BREACH_NOTIFY

summary = compliance_summary(agent_def, risk.score)
# {"scope": ["gdpr", "nydfs_500"],
#  "eu_ai_act_tier": "high",
#  "required_controls": [...],
#  "retention_days": 2190}

# What's the regulator's SLA + format if this agent has a breach?
print(REGIME_BREACH_NOTIFY["nydfs_500"])
# {"window_hours": 72, "format": "nydfs_breach",
#  "authority": "NYDFS Superintendent (23 NYCRR §500.17)"}
```

Built-in regimes: GDPR, EU AI Act, HIPAA, SOX, PCI, CCPA, GLBA, FERPA,
ISO 27001, SOC 2, NYDFS 500, DORA, SR 11-7, ISO 42001, EO 14110,
AI Bill of Rights — plus federal/defense (ITAR, EAR, CMMC, FedRAMP,
DFARS, NIST 800-171, NIST 800-53, FIPS 140-2/3) and international
equivalents (IRAP, CCCS, C5, ENS, IL5/IL6).

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
only. The multi-judge orchestrator auto-registers 6 judges from
the core install; opt-in extras add Presidio + Phoenix without
changing your code.

## Roadmap

This is the standalone packaging of the KYA infrastructure already
running in production inside Veldt Decisions. Items still on the
roadmap:

- Lakehouse adapter (Databricks Genie / Snowflake Cortex)
- Hosted KYA dashboard for self-managed deployments
- SQL-aware data-policy judge (customers bring this today via
  `register_judge()`; bundled adapter in a future release)
- Third-party-attestable notarization for the evidence chain
  (Sigstore / RFC 3161). v1 uses single-key HMAC chains — see
  §11 of the paper for the limitation.
- Full DAG-wide topology validation for delegated agent graphs.
  v1 enforces pairwise parent-child ceilings (the Liang-2025
  topology-attack defense).

## License

Apache License 2.0 — © 2026 Veldt Labs Inc. See [LICENSE](LICENSE).
