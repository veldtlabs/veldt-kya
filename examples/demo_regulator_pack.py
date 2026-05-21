"""Dump the actual JSON content of the regulator pack so you can see
what a regulator/auditor would receive when they hit the endpoint.

This runs the same code paths as the HTTP endpoint, just bypassing the
FastAPI auth chain.
"""

import json
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
from kya.invocations import list_invocations
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def build_pack(url: str, tenant: str, agent_key: str) -> dict:
    """Replicate _build_regulator_pack's kya_evidence section (Item 7),
    which is the portable backend-agnostic part. The 6 PG-only sections
    return empty on non-PG with section_errors populated."""
    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    with Session() as db:
        ensure_invocations_table(db)
        init_evidence_table(db)

        # Seed a realistic multi-step agent run
        inv = record_invocation(
            db,
            tenant_id=tenant,
            agent_key=agent_key,
            mode="hybrid",
            outcome="success",
        )
        record_evidence(
            db,
            tenant_id=tenant,
            invocation_id=inv,
            evidence_kind="prompt",
            payload={"content": "Process claim 7821 — patient SSN 555-12-3456"},
            role="user",
            data_classes=["pii", "phi"],
            source="hooks",
        )
        record_evidence(
            db,
            tenant_id=tenant,
            invocation_id=inv,
            evidence_kind="tool_call",
            payload={
                "tool_name": "execute_sql",
                "args": {"query": "SELECT * FROM claims WHERE id = 7821"},
            },
            role="assistant",
            source="hooks",
        )
        record_evidence(
            db,
            tenant_id=tenant,
            invocation_id=inv,
            evidence_kind="tool_result",
            payload={"output": "claim_id=7821 status=pending amount=$1500"},
            role="tool",
            source="hooks",
        )
        record_evidence(
            db,
            tenant_id=tenant,
            invocation_id=inv,
            evidence_kind="response",
            payload={"content": "Claim 7821 is pending review."},
            role="assistant",
            source="hooks",
        )

    # Build the pack's evidence section (the new Item 7)
    with Session() as db:
        invs = list_invocations(db, tenant_id=tenant, agent_key=agent_key)
        evidence_rows: list = []
        chain_results: list = []
        for i in invs:
            ev = list_evidence(db, tenant_id=tenant, invocation_id=i["id"])
            evidence_rows.extend(ev)
            rep = verify_chain(db, tenant_id=tenant, invocation_id=i["id"])
            chain_results.append({
                "invocation_id": i["id"],
                "valid": rep["valid"],
                "checked": rep["checked"],
                "broken_at": rep["broken_at"],
                "reason": rep["reason"],
            })

    return {
        "agent_key": agent_key,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "meta": {
            "name": agent_key,
            "source": "veldt",
            "version_count": 0,
            "created_at": None,
        },
        "classification": {
            "score": 35,
            "bucket": "medium",
            "factors": [
                {"name": "base", "delta": 5, "label": "Base score"},
                {"name": "write_tools", "delta": 4, "label": "1 write tool"},
                {"name": "data_classes", "delta": 25, "label": "pii+phi handled"},
            ],
        },
        "controls": {
            "tools": ["execute_sql", "send_alert"],
            "human_loop": "hybrid",
            "access_level": "write",
            "can_override": False,
        },
        "monitoring": {
            "rogue": {"oos_tool": 0, "data_leak": 0, "cross_tenant": 0},
            "realtime_windows": {"1m": 0, "5m": 0, "15m": 0, "1h": 0, "24h": 1},
            "anomalies": [],
            "effective_risk": 35,
        },
        "response": {
            "incidents_count": 0,
            "incidents": [],
            "audit_count": 0,
            "audit_log": [],
            "judge_count": 0,
            "judge_history": [],
        },
        "attestation": {
            "count": 0,
            "chain_valid": True,
            "attestations": [],
        },
        "evidence": {
            "count": len(evidence_rows),
            "chain_verification_enabled": True,
            "chain_results": chain_results,
            "all_chains_valid": all(r["valid"] for r in chain_results),
            "rows": evidence_rows,
        },
        "section_errors": {
            "incidents": "no such table: governance_incidents (PG-only on this backend)",
            "audit_log": "no such table: governance_audit_log (PG-only on this backend)",
            "judge_history": "no such table: kya_judge_history (PG-only on this backend)",
            "attestations": "no such table: decision_attestations (PG-only on this backend)",
        },
    }


if __name__ == "__main__":
    url = "sqlite:///:memory:"
    pack = build_pack(url, tenant="00000000-0000-0000-0000-demo000000001", agent_key="claims_agent")
    print(json.dumps(pack, indent=2, default=str))
