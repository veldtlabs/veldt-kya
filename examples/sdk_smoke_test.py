"""End-to-end SDK smoke test: install veldt-kya in a clean env, exercise
the major code paths, and dump raw SQL row counts per table to show what
auto-creates vs auto-populates.

Run from a fresh `pip install veldt-kya` venv (the test container does
this; see the shell pipeline in the harness).
"""

import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from kya import (
    autoinstrument,
    deinstrument,
    init_evidence_table,
    init_storage,
    list_evidence,
    record_evidence,
    record_invocation,
    record_principal_clean,
    record_principal_signal,
    score_agent,
    snapshot_agent,
    verify_chain,
)


def main(url: str):
    engine = create_engine(url)
    Session = sessionmaker(bind=engine)
    # IMPORTANT: tenant_id columns are VARCHAR(36) — must fit a UUID.
    tenant = "00000000-0000-0000-0000-000000000001"

    print("=" * 78)
    print(f"  SDK SMOKE TEST  ·  backend: {engine.dialect.name}")
    print("=" * 78)

    # ── 1. Pure-function check ──
    print()
    print("1. score_agent() — pure function, no DB:")
    r = score_agent({
        "agent_key": "smoke_agent",
        "model": "gpt-4o-mini",
        "tools": ["execute_sql", "send_email"],
        "human_loop": "hybrid",
        "access_level": "write",
        "can_override": True,
        "data_classes": ["pii"],
    })
    print(f"     risk = {r.score}  bucket = {r.bucket}")
    print(f"     security_caps = {r.security_caps}")

    # ── 2. init_storage → bulk create of all KYA tables ──
    print()
    print("2. init_storage(db) — bulk-create all KYA tables:")
    with Session() as db:
        report = init_storage(db)
    print(f"     dialect    : {report['dialect']}")
    print(f"     succeeded  : {report['succeeded']}")
    if report["skipped"]:
        print(f"     skipped    : {len(report['skipped'])} (see report['skipped'])")

    # ── 3. snapshot_agent — populates agent_versions ──
    print()
    print("3. snapshot_agent — populates agent_versions:")
    with Session() as db:
        v1 = snapshot_agent(db, tenant, "smoke_agent",
                            {"tools": ["search"]}, note="v1")
        v2 = snapshot_agent(db, tenant, "smoke_agent",
                            {"tools": ["search", "execute_sql"]}, note="v2")
    print(f"     versioned twice → v{v1}, v{v2}")

    # ── 4. record_invocation — populates kya_invocations + kya_principal_trust ──
    print()
    print("4. record_invocation — populates kya_invocations:")
    with Session() as db:
        inv = record_invocation(
            db, tenant_id=tenant, agent_key="smoke_agent",
            mode="hybrid", outcome="success",
        )
    print(f"     invocation_id = {inv}")

    # ── 5. record_evidence — populates kya_evidence with HMAC chain ──
    print()
    print("5. record_evidence — chain of 4 rows + verify:")
    with Session() as db:
        for kind, payload, role in [
            ("prompt",       {"content": "Process claim 7821 (SSN 555-12-3456)"}, "user"),
            ("tool_call",    {"tool_name": "execute_sql",
                              "args": {"query": "SELECT * FROM claims WHERE id=7821"}}, "assistant"),
            ("tool_result",  {"output": "claim_id=7821 status=pending"}, "tool"),
            ("response",     {"content": "Claim 7821 pending."}, "assistant"),
        ]:
            record_evidence(
                db, tenant_id=tenant, invocation_id=inv,
                evidence_kind=kind, payload=payload, role=role,
                data_classes=["pii"], source="smoke_test",
            )
    with Session() as db:
        chain = verify_chain(db, tenant_id=tenant, invocation_id=inv)
    print(f"     4 evidence rows · verify_chain → valid={chain['valid']} checked={chain['checked']}")

    # ── 6. record_principal_signal/clean — populates kya_principal_trust ──
    print()
    print("6. principal trust mechanics:")
    with Session() as db:
        s1 = record_principal_signal(
            db, tenant_id=tenant, principal_kind="agent",
            principal_id="smoke_agent", signal_kind="oos_tool",
        )
        s2 = record_principal_clean(
            db, tenant_id=tenant, principal_kind="agent",
            principal_id="smoke_agent",
        )
    print(f"     after oos_tool → trust={s1}; after clean → trust={s2}")

    # ── 7. autoinstrument — would patch OpenAI/Anthropic clients in prod ──
    print()
    print("7. autoinstrument helpers exist + clean up properly:")
    from kya import patched_sdks
    result = autoinstrument(
        db_factory=Session, tenant_id=tenant, agent_key="smoke_auto",
        data_classes=["pii"], sdks=[],  # empty list → no SDKs to patch in this env
    )
    print(f"     autoinstrument returned: {result}")
    print(f"     patched_sdks() = {patched_sdks()}")
    deinstrument()

    # ── 8. RAW SQL ROW COUNTS PER TABLE ──
    print()
    print("=" * 78)
    print("  TABLE STATE — every KYA table on this backend after smoke test")
    print("=" * 78)
    insp = inspect(engine)
    schema = "prov_schema" if engine.dialect.name == "postgresql" else None
    tables = insp.get_table_names(schema=schema)

    expected_tables = [
        "agent_versions", "kya_invocations", "kya_principal_trust", "kya_evidence",
        "governance_policies", "ai_model_registry", "governance_audit_log",
        "governance_incidents", "compliance_regulation_map",
        "decision_attestations", "decision_attestation_keypairs",
        "kya_judge_history", "kya_agent_aliases", "kya_user_trust",
        "kya_weight_overrides", "kya_weight_changes", "kya_weight_suggestions",
        "kya_breach_notifications", "kya_redteam_campaigns",
        "kya_redteam_findings", "kya_redteam_tenant_policy",
        "kya_redteam_runs", "kya_redteam_targets", "kya_redteam_target_secrets",
        "kya_inbound_recommendations",
    ]

    populated_via_smoke = {
        "agent_versions": "snapshot_agent",
        "kya_invocations": "record_invocation",
        "kya_principal_trust": "record_principal_signal/clean",
        "kya_evidence": "record_evidence",
    }

    with engine.connect() as conn:
        ns = f"{schema}." if schema else ""
        print(f"  {'table':32s} {'created':>8s} {'rows':>5s}  populated by")
        print(f"  {'-' * 78}")
        present = 0
        populated = 0
        for t in expected_tables:
            if t in tables:
                present += 1
                count = int(conn.execute(text(f"SELECT COUNT(*) FROM {ns}{t}")).scalar() or 0)
                if count > 0:
                    populated += 1
                src = populated_via_smoke.get(t, "(domain-specific event)")
                print(f"  {t:32s} {'YES':>8s} {count:>5d}  {src}")
            else:
                print(f"  {t:32s} {'NO':>8s} {'-':>5s}")

    print()
    total = len(expected_tables)
    print(f"  {present}/{total} tables CREATED · {populated}/{total} tables POPULATED by smoke flow")
    print()
    print("  The unpopulated tables fill when their respective code path")
    print("  runs (governance check fires → audit_log/incidents; redteam campaign")
    print("  runs → kya_redteam_*; admin POSTs → governance_policies; etc).")
    print("=" * 78)


if __name__ == "__main__":
    backends: list[tuple[str, str]] = [("sqlite", "sqlite:///:memory:")]
    try:
        import duckdb_engine  # noqa
        backends.append(("duckdb", "duckdb:///:memory:"))
    except ImportError:
        pass
    if os.environ.get("KYA_TEST_MYSQL_URL"):
        backends.append(("mysql", os.environ["KYA_TEST_MYSQL_URL"]))
    if os.environ.get("KYA_TEST_PG_URL"):
        backends.append(("pg", os.environ["KYA_TEST_PG_URL"]))

    for _, url in backends:
        main(url)
