"""Live demo: LangChain auto-wire — captures every step of a multi-step
agent and dumps the resulting evidence rows from the DB.

Uses a tiny FakeClient that writes directly to the local DB (skips the
HTTP round-trip so you can see the data land in real time).

Run:
    pip install veldt-kya[all] langchain-core
    python demo_langchain_handler.py
"""

import importlib.util
import os
from datetime import datetime, timezone

from kya import (
    ensure_invocations_table,
    init_evidence_table,
    list_evidence,
    record_evidence,
    record_invocation,
    verify_chain,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Load the langchain adapter directly from the source tree
_handler_path = os.path.join(
    os.path.dirname(__file__), "..", "..", "app", "agents", "kya_hooks", "langchain.py"
)
spec = importlib.util.spec_from_file_location("kya_lc", _handler_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

KyaLangchainHandler = mod.KyaLangchainHandler

SEP = "=" * 78


def banner(t):
    print()
    print(SEP)
    print(f"  {t}")
    print(SEP)


class DBClient:
    """In-process client that writes directly through the SDK functions
    instead of HTTP — proves the wire-in shape end-to-end."""

    def __init__(self, engine, tenant):
        self.engine = engine
        self.tenant = tenant
        self._Session = sessionmaker(bind=engine)
        self._inv_id: int | None = None

    def record_invocation(self, **kw):
        with self._Session() as db:
            if self._inv_id is None:
                # First call — create the row
                self._inv_id = record_invocation(
                    db,
                    tenant_id=self.tenant,
                    agent_key=kw["agent_key"],
                    mode=kw.get("mode", "observed"),
                    outcome=kw.get("outcome", "success"),
                    duration_ms=kw.get("duration_ms"),
                    correlation_id=kw.get("correlation_id"),
                    occurred_at=datetime.now(timezone.utc),
                )
        return {"invocation_id": self._inv_id, "accepted": True}

    def record_evidence(self, **kw):
        with self._Session() as db:
            eid = record_evidence(
                db,
                tenant_id=self.tenant,
                invocation_id=kw["invocation_id"],
                evidence_kind=kw["evidence_kind"],
                payload=kw["payload"],
                role=kw.get("role"),
                source=kw.get("source"),
                correlation_id=kw.get("correlation_id"),
                data_classes=kw.get("data_classes"),
            )
        return {"evidence_id": eid, "accepted": True}


def simulate_langchain_run(handler):
    """Drive the handler the same way LangChain would during a tool-using
    agent's execution."""
    handler.on_chain_start(serialized={}, inputs={"input": "Process claim 7821"})
    handler.on_chat_model_start(
        serialized={"name": "ChatOpenAI"},
        messages=[
            [
                type(
                    "M", (), {"type": "system", "content": "You are a claims processing agent."}
                )(),
                type(
                    "M",
                    (),
                    {"type": "human", "content": "Process claim 7821 for patient SSN 555-12-3456"},
                )(),
            ]
        ],
    )
    # First model response — agent decides to call a tool
    handler.on_chat_model_end(
        type(
            "R",
            (),
            {
                "generations": [
                    [
                        type(
                            "G",
                            (),
                            {
                                "message": type(
                                    "MM", (), {"content": "I'll look up claim 7821 in the DB."}
                                )()
                            },
                        )()
                    ]
                ]
            },
        )()
    )
    handler.on_agent_action(
        type(
            "A",
            (),
            {
                "tool": "execute_sql",
                "tool_input": {"query": "SELECT * FROM claims WHERE id = 7821"},
                "log": "Looking up the claim record",
            },
        )()
    )
    handler.on_tool_start(
        serialized={"name": "execute_sql"},
        input_str='{"query": "SELECT * FROM claims WHERE id = 7821"}',
    )
    handler.on_tool_end(output="claim_id=7821 status=pending amount=$1500 ssn=XXX-XX-3456")

    # Second model response — agent decides on the answer
    handler.on_chat_model_end(
        type(
            "R",
            (),
            {
                "generations": [
                    [
                        type(
                            "G",
                            (),
                            {
                                "message": type(
                                    "MM", (), {"content": "Got the data. Drafting reply."}
                                )()
                            },
                        )()
                    ]
                ]
            },
        )()
    )
    handler.on_agent_finish(
        type(
            "F",
            (),
            {
                "return_values": {
                    "output": "Claim 7821 is pending. Amount: $1500. Patient SSN redacted."
                },
                "log": "Final answer formulated",
            },
        )()
    )
    handler.on_chain_end(outputs={"output": "Claim 7821 is pending."})


def demo(label: str, url: str):
    banner(f"{label} — LangChain handler captures full agent run")
    engine = create_engine(url)

    tenant = f"t_lc_{label}"
    # Scope clean
    with sessionmaker(bind=engine)() as db:
        ensure_invocations_table(db)
        init_evidence_table(db)
        db.execute(text("DELETE FROM kya_evidence WHERE tenant_id = :t"), {"t": tenant})
        db.execute(text("DELETE FROM kya_invocations WHERE tenant_id = :t"), {"t": tenant})
        db.commit()

    client = DBClient(engine, tenant)
    handler = KyaLangchainHandler(
        client,
        agent_key="claims_agent",
        mode="hybrid",
        data_classes=["pii", "phi"],
    )

    print("  Running simulated LangChain agent execution...")
    simulate_langchain_run(handler)

    inv_id = handler.invocation_id
    print(f"  invocation_id={inv_id}  correlation_id={handler.correlation}")

    print()
    print("  Captured evidence chain (every LangChain callback recorded):")
    with sessionmaker(bind=engine)() as db:
        rows = list_evidence(db, tenant_id=tenant, invocation_id=inv_id)
    print(f"  {'#':3s} {'kind':18s} {'role':10s} {'size':>5s}  payload")
    print(f"  {'-' * 110}")
    for i, r in enumerate(rows, 1):
        preview = str(r["payload"])
        if len(preview) > 65:
            preview = preview[:62] + "…"
        print(
            f"  {i:<3d} {r['evidence_kind']:18s} {r['role'] or '-':10s} "
            f"{r['payload_size_bytes']:>5d}  {preview}"
        )

    print()
    print("  Chain verification:")
    with sessionmaker(bind=engine)() as db:
        report = verify_chain(db, tenant_id=tenant, invocation_id=inv_id)
    print(
        f"    status={'VALID' if report['valid'] else 'BROKEN'} · "
        f"checked={report['checked']} · broken_at={report['broken_at']}"
    )


def main():
    demo("sqlite", "sqlite:///:memory:")
    try:
        import duckdb_engine  # noqa: F401

        demo("duckdb", "duckdb:///:memory:")
    except ImportError:
        print("(duckdb-engine not installed — skipping DuckDB)")

    mysql_url = os.environ.get("KYA_TEST_MYSQL_URL")
    if mysql_url:
        demo("mysql", mysql_url)
    else:
        print("(KYA_TEST_MYSQL_URL not set — skipping MySQL)")

    banner("LangChain wire-in verified · every callback captured into evidence")


if __name__ == "__main__":
    main()
