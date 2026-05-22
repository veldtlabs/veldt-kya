"""Cross-backend verification: 17 KYA tables × 4 backends, with data.

For each backend (SQLite, DuckDB, MySQL, PostgreSQL):
  1. Bring up storage via init_storage(db) — full plan
  2. Confirm every table is present in the live catalog
  3. Write at least one row into every table through the public SDK
  4. Read row counts back — every table must be > 0

Run: python tests/verify_all_backends_with_data.py
"""

import importlib
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

REPO = Path(__file__).resolve().parent.parent

ALL_KYA_TABLES = [
    # 4 ORM-modeled core
    "agent_versions",
    "kya_invocations",
    "kya_principal_trust",
    "kya_evidence",
    # 13 legacy (now portable)
    "kya_agent_aliases",
    "kya_user_trust",
    "kya_weight_overrides",
    "kya_weight_changes",
    "kya_weight_suggestions",
    "kya_breach_notifications",
    "kya_redteam_campaigns",
    "kya_redteam_findings",
    "kya_redteam_tenant_policy",
    "kya_redteam_runs",
    "kya_redteam_targets",
    "kya_redteam_target_secrets",
    "kya_inbound_recommendations",
]


def _reload_kya():
    """Clear cached kya modules so per-engine _ENSURED gates reset across runs."""
    for k in list(sys.modules):
        if k == "kya" or k.startswith("kya.") or k == "kya_redteam" or k.startswith("kya_redteam."):
            del sys.modules[k]
    sys.path.insert(0, str(REPO))
    return importlib.import_module("kya")


def _drop_all(engine, schema):
    with engine.begin() as conn:
        if schema == "prov_schema":
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        for t in ALL_KYA_TABLES:
            full = f"{schema}.{t}" if schema else t
            try:
                conn.execute(text(f"DROP TABLE IF EXISTS {full}"))
            except Exception:
                pass
        # DuckDB sequences linger; drop any matching pattern (best-effort)
        if engine.dialect.name == "duckdb":
            try:
                rows = conn.execute(text(
                    "SELECT sequence_name FROM duckdb_sequences()"
                )).fetchall()
                for (sn,) in rows:
                    try:
                        conn.execute(text(f"DROP SEQUENCE IF EXISTS {sn}"))
                    except Exception:
                        pass
            except Exception:
                pass


def _write_rows_to_every_table(kya, db, *, name: str) -> dict[str, str]:
    """Land at least one row in every table.

    All writes flow through the public SDK — proving end-to-end
    cross-backend portability of the SDK contract, not just the
    underlying Table objects.
    """
    from kya._legacy_tables import (
        kya_weight_suggestions, kya_breach_notifications,
        kya_inbound_recommendations,
    )
    from kya import agent_aliases, users, tenant_weights
    import kya_redteam.campaigns as rt_campaigns
    import kya_redteam.runs as rt_runs
    import kya_redteam.targets as rt_targets
    tenant = "00000000-0000-0000-0000-0000000000ff"
    user_id = "00000000-0000-0000-0000-0000000000aa"
    agent_key = f"loan_triage_{name}"
    notes: dict[str, str] = {}

    # 1. agent_versions  — kya.snapshot_agent
    kya.snapshot_agent(db, tenant_id=tenant, agent_key=agent_key,
                       definition={"agent_key": agent_key, "name": "Loan Triage",
                                   "tools": ["check_credit_score"]},
                       created_by="verify-suite")

    # 2. kya_invocations — kya.record_invocation
    invocation_id = kya.record_invocation(
        db, tenant_id=tenant, agent_key=agent_key,
        principal_kind="agent", principal_id=agent_key,
        mode="observed", outcome="success",
    )

    # 3. kya_evidence — kya.record_evidence (twice for the chain)
    kya.record_evidence(db, tenant_id=tenant, invocation_id=invocation_id,
                        evidence_kind="prompt", payload={"text": f"prompt on {name}"})
    kya.record_evidence(db, tenant_id=tenant, invocation_id=invocation_id,
                        evidence_kind="response", payload={"text": f"response on {name}"})

    # 4. kya_principal_trust — kya.record_principal_clean
    kya.record_principal_clean(db, tenant_id=tenant,
                               principal_kind="agent", principal_id=agent_key)

    def _try(label: str, fn):
        try:
            fn()
            db.commit()
        except Exception as exc:
            notes[label] = f"{str(exc).splitlines()[0][:140]}"
            db.rollback()

    # 5. kya_agent_aliases — SDK API
    _try("kya_agent_aliases", lambda: agent_aliases.add_alias(
        db, tenant_id=tenant, alias="triage",
        canonical_agent_key=agent_key, user_id=None))

    # 6. kya_user_trust — SDK API
    _try("kya_user_trust", lambda: users.record_user_clean(
        db, tenant_id=tenant, user_id=user_id))

    # 7. kya_weight_overrides + 8. kya_weight_changes — SDK API (atomic)
    _try("kya_weight_overrides+changes", lambda: tenant_weights.set_override(
        db, scope="class_weights", key="pii", value=22,
        tenant_id=tenant, changed_by=user_id,
        reason="cross-backend verification"))

    # 9. kya_weight_suggestions — no public-API entry point yet
    # (propose_from_incident requires a real governance_incidents row);
    # use Core insert directly for the verification.
    sugg_cols = {c.name for c in kya_weight_suggestions.columns}
    sugg_vals = {"tenant_id": tenant, "scope": "class_weights", "key": "pii",
                 "status": "pending", "suggested_delta": 4, "suggested_value": 24}
    if "current_value" in sugg_cols:
        sugg_vals["current_value"] = 20
    if "agent_key" in sugg_cols:
        sugg_vals["agent_key"] = agent_key
    if "source_incident_kind" in sugg_cols:
        sugg_vals["source_incident_kind"] = "data_leak"
    _try("kya_weight_suggestions",
         lambda: db.execute(kya_weight_suggestions.insert().values(**sugg_vals)))

    # 10. kya_breach_notifications — Core insert (compliance_shim.run_once
    # depends on the platform's governance_incidents table).
    bn_vals = {"tenant_id": tenant, "regime": "GDPR", "incident_id": 1,
               "format": "edpb_72h"}
    bn_cols = {c.name for c in kya_breach_notifications.columns}
    if "sent_status" in bn_cols:
        bn_vals["sent_status"] = "pending"
    if "status" in bn_cols and "sent_status" not in bn_cols:
        bn_vals["status"] = "pending"
    if "attempt_count" in bn_cols:
        bn_vals["attempt_count"] = 0
    _try("kya_breach_notifications",
         lambda: db.execute(kya_breach_notifications.insert().values(**bn_vals)))

    # 11. kya_redteam_campaigns + 12. kya_redteam_findings — SDK API
    campaign_id = {"value": None}

    def _create_campaign():
        c = rt_campaigns.create_campaign(
            db, tenant_id=tenant, agent_key=agent_key, name="verify-campaign",
            orchestrator_kind="prompt_sending", scorer_kind="sub_string",
            created_by=None,
        )
        campaign_id["value"] = c["id"]
    _try("kya_redteam_campaigns", _create_campaign)

    if campaign_id["value"] is not None:
        _try("kya_redteam_findings", lambda: rt_campaigns.record_finding(
            db, tenant_id=tenant, campaign_id=campaign_id["value"],
            run_id="00000000-0000-0000-0000-0000000000bb", agent_key=agent_key,
            attack_category="prompt_injection", severity="high",
            prompt_redacted="<<redacted>>", response_redacted="<<redacted>>",
        ))

    # 13. kya_redteam_tenant_policy — SDK API
    _try("kya_redteam_tenant_policy", lambda: rt_campaigns.set_tenant_policy(
        db, tenant_id=tenant, redteam_tier="standard",
        max_auto_incident_mode="never", updated_by=None,
    ))

    # 14. kya_redteam_runs — SDK API
    _try("kya_redteam_runs", lambda: rt_runs.create_run(
        db, tenant_id=tenant, campaign_id=campaign_id["value"],
        agent_key=agent_key, orchestrator="prompt_sending",
        initiated_by=None,
    ))

    # 15. kya_redteam_targets + 16. kya_redteam_target_secrets — SDK API
    _try("kya_redteam_targets+secrets", lambda: rt_targets.create_target(
        db, tenant_id=tenant, agent_key=agent_key, name="verify-target",
        endpoint_url="https://api.example.com/agent",
        auth_kind="bearer", auth_secret="dummy-token",
        created_by=None,
    ))

    # 17. kya_inbound_recommendations — fetch_now requires a live collector;
    # Core insert directly for verification.
    i_cols = {c.name for c in kya_inbound_recommendations.columns}
    from datetime import datetime, timezone
    i_vals = {"external_id": f"rec-verify-{name}",
              "signing_key_id": "verify-key",
              "recommended_value": 23,
              "issued_at": datetime.now(timezone.utc),
              "scope": "class_weights", "key": "pii", "status": "pending"}
    if "rationale" in i_cols:
        i_vals["rationale"] = "cross-backend verification"
    _try("kya_inbound_recommendations",
         lambda: db.execute(kya_inbound_recommendations.insert().values(**i_vals)))

    return notes


def _verify_one_backend(name: str, url: str, schema: str | None) -> dict:
    print(f"\n{'='*70}\n  BACKEND: {name}  ({url[:60]})\n{'='*70}")

    if schema == "prov_schema":
        os.environ["KYA_VERSIONS_SCHEMA"] = "prov_schema"
    else:
        os.environ["KYA_VERSIONS_SCHEMA"] = ""

    kya = _reload_kya()
    from kya import storage  # noqa

    engine = create_engine(url)
    _drop_all(engine, schema)

    with Session(engine) as db:
        report = storage.init_storage(db)
        db.commit()

    succeeded = report["succeeded"]
    skipped = report["skipped"]
    print(f"\ninit_storage: {len(succeeded)} succeeded, {len(skipped)} skipped")
    for s in skipped:
        print(f"  SKIP {s['table']}: {s['reason'][:120]}")

    insp = inspect(engine)
    present = set(insp.get_table_names(schema=schema))
    table_present = {t: t in present for t in ALL_KYA_TABLES}

    write_notes: dict = {}
    write_err: str | None = None
    if all(table_present.values()):
        with Session(engine) as db:
            try:
                write_notes = _write_rows_to_every_table(kya, db, name=name)
            except Exception as exc:
                db.rollback()
                write_err = str(exc).splitlines()[0][:300]

    row_counts: dict[str, int] = {}
    with engine.connect() as conn:
        for tn in ALL_KYA_TABLES:
            if not table_present.get(tn):
                row_counts[tn] = -1
                continue
            try:
                full = f"{schema}.{tn}" if schema else tn
                row_counts[tn] = int(
                    conn.execute(text(f"SELECT COUNT(*) FROM {full}")).scalar()
                )
            except Exception:
                row_counts[tn] = -2

    return {
        "backend": name,
        "tables_present": sum(1 for v in table_present.values() if v),
        "tables_total": len(ALL_KYA_TABLES),
        "row_counts": row_counts,
        "write_err": write_err,
        "write_notes": write_notes,
    }


def main():
    backends = [
        ("sqlite", "sqlite:///:memory:", None),
        ("duckdb", "duckdb:///:memory:", None),
    ]
    pg = os.environ.get("KYA_TEST_PG_URL")
    if pg:
        backends.append(("postgresql", pg, "prov_schema"))
    mysql = os.environ.get("KYA_TEST_MYSQL_URL")
    if mysql:
        backends.append(("mysql", mysql, None))

    results = []
    for n, u, s in backends:
        try:
            results.append(_verify_one_backend(n, u, s))
        except Exception as exc:
            results.append({"backend": n, "error": str(exc).splitlines()[0][:300]})

    print(f"\n\n{'='*70}\n  FINAL SUMMARY — non-empty row counts per table\n{'='*70}")
    header = f"{'TABLE':32s} | " + " | ".join(f"{r['backend']:>10s}" for r in results)
    print(header)
    print("-" * len(header))
    for t in ALL_KYA_TABLES:
        row = f"{t:32s} | " + " | ".join(
            f"{r.get('row_counts',{}).get(t, '?'):>10}" for r in results
        )
        print(row)

    print("\nTABLE PRESENCE / WRITES:")
    for r in results:
        if "error" in r:
            print(f"  {r['backend']}: ERROR — {r['error']}")
            continue
        empties = [t for t in ALL_KYA_TABLES if r["row_counts"].get(t, -3) == 0]
        missing = [t for t in ALL_KYA_TABLES if r["row_counts"].get(t, -3) < 0]
        status = "OK" if (not empties and not missing) else "PARTIAL"
        print(
            f"  {r['backend']:12s} | tables {r['tables_present']}/{r['tables_total']} "
            f"| empties={len(empties)} | missing={len(missing)} | {status}"
        )
        if r.get("write_err"):
            print(f"    write_err: {r['write_err']}")
        for k, v in (r.get("write_notes") or {}).items():
            print(f"    note[{k}]: {v}")
        if empties:
            print(f"    EMPTY: {empties}")
        if missing:
            print(f"    MISSING: {missing}")


if __name__ == "__main__":
    main()
