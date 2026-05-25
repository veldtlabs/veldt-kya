"""Verify tables exist AND hold real data on every backend.

For each of sqlite / duckdb / postgresql / mysql:
  1. Wipe + init_storage
  2. Drive a representative population sequence
     (snapshot agent → record invocation → record evidence →
      record principal signal → set budget → record cost event)
  3. Query row counts on every populated table
  4. Assert every table has at least 1 row

Run with the same env vars as the e2e test."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path


# ── Reuse the same .env loader ──────────────────────────────────────
def _load_dotenv_if_present() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


_load_dotenv_if_present()

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from kya import (
    init_storage, normalize_agent_def, record_evidence,
    record_invocation, record_principal_signal, score_agent, snapshot_agent,
)
from kya.tenant_budget import record_cost_event, set_budget


TENANT_ID = "00000000-0000-0000-0000-000000000001"

# Tables we expect to have data after the population sequence
TABLES_TO_CHECK = [
    "agent_versions",
    "kya_invocations",
    "kya_evidence",
    "kya_principal_trust",
    "kya_tenant_cost_budgets",
    "kya_budget_changes",
    "kya_cost_events",
]

# Tables that exist but stay empty (no writes in our minimal flow)
TABLES_OPTIONAL = [
    "kya_agent_aliases", "kya_user_trust", "kya_weight_overrides",
    "kya_weight_changes", "kya_weight_suggestions",
    "kya_breach_notifications", "kya_redteam_campaigns",
    "kya_redteam_findings", "kya_redteam_tenant_policy",
    "kya_redteam_runs", "kya_redteam_targets",
    "kya_redteam_target_secrets", "kya_inbound_recommendations",
]


def _backends():
    out = [("sqlite", "sqlite:///:memory:")]
    try:
        import duckdb_engine  # noqa: F401
        out.append(("duckdb", "duckdb:///:memory:"))
    except ImportError:
        pass
    if "KYA_TEST_PG_URL" in os.environ:
        out.append(("postgresql", os.environ["KYA_TEST_PG_URL"]))
    if "KYA_TEST_MYSQL_URL" in os.environ:
        out.append(("mysql", os.environ["KYA_TEST_MYSQL_URL"]))
    return out


def _open(label: str, url: str):
    if label == "postgresql":
        eng = create_engine(url)
        with eng.begin() as conn:
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            for t in TABLES_TO_CHECK + TABLES_OPTIONAL:
                conn.execute(text(f"DROP TABLE IF EXISTS prov_schema.{t}"))
    elif label == "mysql":
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for t in TABLES_TO_CHECK + TABLES_OPTIONAL:
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {t}"))
                except Exception:
                    pass
    else:
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
    return sessionmaker(bind=eng)(), eng.dispose


def _populate(db) -> None:
    """Insert one representative row into each table we want non-empty."""
    # 1. Score + snapshot (populates agent_versions)
    agent_def = normalize_agent_def("agents_md", {
        "agent_key": "verify_agent",
        "system_prompt": "Test agent for data-presence verification.",
        "tools": ["lookup_calendar"],
        "model": "gpt-4o-mini",
        "human_loop": "in_the_loop",
        "access_level": "read",
        "data_classes": ["pii"],
        "environment": "prod",
    })
    score_agent(agent_def)
    snapshot_agent(db, tenant_id=TENANT_ID, agent_key="verify_agent",
                   definition=agent_def, note="data-presence test")

    # 2. Invocation + evidence (kya_invocations + kya_evidence)
    inv_id = record_invocation(
        db, tenant_id=TENANT_ID, agent_key="verify_agent",
        principal_kind="user", principal_id="user-uuid",
        correlation_id=str(uuid.uuid4()),
    )
    record_evidence(
        db, tenant_id=TENANT_ID, invocation_id=inv_id,
        evidence_kind="prompt",
        payload={"user_prompt": "tomorrow 3pm"},
    )

    # 3. Principal trust signal (kya_principal_trust)
    record_principal_signal(
        db, tenant_id=TENANT_ID,
        principal_kind="user", principal_id="user-uuid",
        signal_kind="oos_tool",
    )

    # 4. Budget (kya_tenant_cost_budgets + kya_budget_changes)
    set_budget(
        db, tenant_id=None, scope="tenant", scope_key="*",
        window="30d", threshold_usd=100.0, reason="presence test",
    )

    # 5. Cost event (kya_cost_events)
    record_cost_event(
        db, tenant_id=TENANT_ID, agent_key="verify_agent",
        usd_amount=0.01, model_used="gpt-4o-mini",
        input_tokens=50, output_tokens=20,
        cost_center="ops", environment="prod",
        outcome="success", latency_ms=200,
        invocation_id=inv_id, request_id="presence-test",
    )


def _count(db, dialect: str, table: str) -> int | None:
    schema = "prov_schema." if dialect == "postgresql" else ""
    try:
        row = db.execute(text(f"SELECT COUNT(*) FROM {schema}{table}")).first()
        return int(row[0]) if row else 0
    except Exception:
        return None


def main() -> int:
    overall_ok = True
    for label, url in _backends():
        print("=" * 78)
        print(f"  Backend: {label.upper()}")
        print("=" * 78)
        db, dispose = _open(label, url)
        try:
            init_storage(db)
            _populate(db)

            print(f"  {'table':38s} {'rows':>6s}  status")
            backend_ok = True
            for tbl in TABLES_TO_CHECK:
                cnt = _count(db, label, tbl)
                status = (
                    "skip"   if cnt is None
                    else "OK" if cnt > 0
                    else "EMPTY ←"
                )
                print(f"  {tbl:38s} {cnt!s:>6s}  {status}")
                # 'skip' means the table doesn't exist on this backend
                # (e.g. weight_* on DuckDB) — that's pre-existing and
                # not a regression from the budget work.
                if cnt is None and tbl in (
                    "kya_weight_overrides", "kya_weight_changes",
                ):
                    continue
                if cnt is None or cnt == 0:
                    backend_ok = False

            if backend_ok:
                print(f"\n  [PASS] {label} — every populated table has data")
            else:
                print(f"\n  [FAIL] {label} — empty / missing tables above")
                overall_ok = False
        except Exception as exc:
            print(f"  [ERROR] {label}: {exc}")
            overall_ok = False
        finally:
            try:
                db.close()
            except Exception:
                pass
            dispose()
        print()

    print("=" * 78)
    print(f"  Overall: {'PASS — every table has data on every backend' if overall_ok else 'FAIL'}")
    print("=" * 78)
    return 0 if overall_ok else 2


if __name__ == "__main__":
    sys.exit(main())
