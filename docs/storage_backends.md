# Storage backends for veldt-kya

KYA's pure-function APIs (`score_agent`, `normalize_agent_def`,
`bucket_for`, `is_write_tool`, `is_admin_tool`, `compliance_summary`,
`detect_drift`, etc.) need NO storage. Import the package and call them.

The stateful APIs — versioning, principal trust, invocation tracking,
rogue-signal history — need a SQLAlchemy `Session`. KYA does NOT
dictate where that Session points: any Postgres, MySQL, SQLite, or
even an in-memory SQLite for dev works.

## Pure-function (zero storage)

```python
from kya import score_agent, normalize_agent_def, bucket_for

risk = score_agent(normalize_agent_def("langchain", my_agent))
print(risk.score, bucket_for(risk.score))
```

## In-memory SQLite for dev

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from kya import snapshot_agent, list_versions, ensure_user_trust_table

engine = create_engine("sqlite:///:memory:")
ensure_user_trust_table(engine)        # creates the trust schema
Session = sessionmaker(bind=engine)

with Session() as db:
    snapshot_agent(db, tenant_id="dev", agent_key="my_agent",
                   definition={"tools": ["search"]})
    print(list_versions(db, "dev", "my_agent"))
```

## Postgres in production

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine("postgresql://kya@localhost/kya")
# Run the migration helpers once (idempotent):
from kya import (
    ensure_weight_tables,           # tenant-scoped weight overrides
    ensure_user_trust_table,        # KYU per-user trust
    ensure_suggestions_table,       # incident feedback loop
    ensure_principal_table,         # principal trust (humans + agents)
    ensure_invocations_table,       # invocation correlation
)
for fn in (
    ensure_weight_tables,
    ensure_user_trust_table,
    ensure_suggestions_table,
    ensure_principal_table,
    ensure_invocations_table,
):
    fn(engine)

Session = sessionmaker(bind=engine)
# ... use as normal
```

## Bring-your-own-storage (no SQLAlchemy)

If you don't want SQLAlchemy at all, KYA's pure-function APIs still
work — you just lose versioning history + trust scores. You can
back them with your own KV store by wrapping the SQLAlchemy session
interface (only `db.execute(text(...))`, `db.commit()`, `db.rollback()`,
and result-fetch primitives are used).

See `app/agents/kya/versioning.py` for the small surface area you'd
need to mock.

## Metrics + tracing

Optional dependencies. KYA's `record_*` helpers no-op when these
aren't installed.

```bash
pip install veldt-kya[metrics]   # adds prometheus_client
pip install veldt-kya[tracing]   # adds opentelemetry-sdk
pip install veldt-kya[all]       # everything
```

When `prometheus_client` is available, every `record_oos_tool_attempt`
etc. bumps a Counter. Scrape your Prometheus as normal.

When `opentelemetry-sdk` is available, the same calls emit OTel span
events with `veldt.rogue=true` tag — pipe to Phoenix, Tempo, or
whatever else listens on OTLP.

## Rogue-signal HTTP endpoint (zero state)

If you want rogue signals tracked across processes (e.g. you have
N stateless agent runners), wrap the helpers in your own HTTP
endpoint. KYA does NOT ship that endpoint — you control the
authentication, the rate limit, the persistence model. The Veldt
platform exposes `POST /api/v1/admin/agents/events/rogue` as one such
endpoint (in `app/routes/admin_agents.py`).
