# veldt-kya

**Know Your Agents** — risk scoring, drift detection, rogue-behavior
observation, and compliance-grade evidence for any autonomous system.

```
pip install veldt-kya
```

## What it does

KYA is the trust + governance layer for autonomous systems. It scores any
agent (LLM, AutoML pipeline, lakehouse auto-SQL, RPA bot, schema-evolution
job) against a published risk model, detects drift in the agent's
definition, observes rogue behavior at runtime, and emits regulator-grade
evidence — model cards (SR 11-7), AIMS bundles (ISO 42001), breach
notifications (NYDFS, DORA, GDPR, HIPAA).

Observability tools tell you when an agent is *slow*. KYA tells you when
an agent is *wrong, drifting, leaking, or quietly going rogue.*

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
shapes into the canonical schema. Five built-in adapters:

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
pip install "veldt-kya[metrics]"    # Prometheus counters
pip install "veldt-kya[tracing]"    # OpenTelemetry span events
pip install "veldt-kya[webhooks]"   # Outbound emit (Splunk / Datadog / Lakera / regulator-grade formats)
pip install "veldt-kya[judge]"      # LiteLLM-backed semantic alignment judge
pip install "veldt-kya[all]"        # everything above
```

The core scoring + adapter API is stdlib + SQLAlchemy only.

## Roadmap

This is the standalone SDK packaging of the KYA module already running
in production inside Veldt Decisions. Surfaces still being polished:

- Lakehouse adapter (Databricks Genie / Snowflake Cortex)
- Native pytest harness for `[storage]` extra
- Hosted KYA dashboard for SDK consumers

## License

Apache License 2.0 — © 2026 Veldt Labs Inc. See [LICENSE](LICENSE).
