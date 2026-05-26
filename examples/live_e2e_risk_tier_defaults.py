"""Live e2e for Phase 3a — risk-tier defaults at first-sight.

What this validates against REAL databases (sqlite/duckdb/postgresql/
mysql) using ONLY public API (no synthetic table inserts):

  Scenario A — CRITICAL agent's auto-override gets applied
      Snapshot a definition that should score critical →
      verify a flag-mode override exists scoped to that agent.
      Verify the override's changed_by = our supplied operator UUID.

  Scenario B — LOW-risk agent gets NO auto-override
      Snapshot a low-risk definition → no override row.

  Scenario C — Drift (v2 of same agent) does NOT re-apply
      v2 of a critical agent → still exactly one override.

  Scenario D — Tenant scoping isolation
      Same agent_key in tenant A vs tenant B → only A has an
      override; B falls through to global env.

  Scenario E — Operator-set override is preserved
      Operator manually sets a block override BEFORE first-sight →
      auto-default does NOT overwrite it.

  Scenario F — End-to-end with delegation enforcement
      Critical-but-read-only orchestrator → auto-flag override →
      delegates to admin sub-agent (escalation) → violation row
      lands in 'flag' mode, NOT the env default 'observe'.

  Scenario G — Env-var disable
      KYA_RISK_TIER_AUTO_DEFAULTS=0 → no auto-override even for
      critical agents.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _load_dotenv():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


_load_dotenv()

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    DelegationPolicyError,
    init_storage,
    list_delegation_overrides,
    record_invocation,
    resolve_effective_mode,
    set_delegation_override,
    snapshot_agent,
    snapshot_on_first_sight,
)


TENANT_A = "00000000-0000-0000-0000-0000000000a1"
TENANT_B = "00000000-0000-0000-0000-0000000000a2"
OPERATOR = "11111111-2222-3333-4444-555555555555"


def _hdr(t):
    print(); print("=" * 78); print(f"  {t}"); print("=" * 78)


def _check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          f"{(' - ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(2)


_CRITICAL_DEF = {
    "agent_key": "PLACEHOLDER",
    "system_prompt": "Execute admin-level operations autonomously.",
    "tools": ["execute_sql", "delete_user", "modify_permissions",
              "send_email", "deploy_code", "manage_secrets"],
    "human_loop": "out_of_loop",
    "access_level": "admin",
    "data_classes": ["pii", "phi", "financial", "secret"],
    "environment": "prod",
    "model_trust": "open_source",
    "can_override": True,
    "can_revert": True,
}

_LOW_DEF = {
    "agent_key": "PLACEHOLDER",
    "system_prompt": "Look up the time of day.",
    "tools": ["get_time"],
    "human_loop": "in_the_loop",
    "access_level": "read",
    "data_classes": [],
    "environment": "dev",
    "model_trust": "frontier",
}


def open_backend(label):
    if label == "sqlite":
        eng = create_engine("sqlite:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None})
    elif label == "duckdb":
        eng = create_engine("duckdb:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None})
    elif label == "postgresql":
        url = os.environ.get("KYA_TEST_PG_URL")
        if not url: return None, None
        eng = create_engine(url)
        with eng.begin() as conn:
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            for tbl in ("kya_delegation_policy_overrides",
                        "kya_delegation_violations", "kya_invocations",
                        "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_delegation_policy_overrides",
                        "kya_delegation_violations", "kya_invocations",
                        "agent_versions"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception:
                    pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


def run_scenarios(db, label):
    os.environ.pop("KYA_RISK_TIER_AUTO_DEFAULTS", None)
    os.environ["KYA_DELEGATION_POLICY"] = "observe"

    # ── A. critical agent gets flag auto-override ─────────────
    snapshot_on_first_sight(
        db, tenant_id=TENANT_A, agent_key=f"Crit_{label}",
        definition={**_CRITICAL_DEF, "agent_key": f"Crit_{label}"},
        created_by=OPERATOR,
        note="A: critical risk first sight")
    overrides = list_delegation_overrides(
        db, tenant_id=TENANT_A,
        parent_agent_key=f"Crit_{label}")
    _check(f"{label}/A: 1 override row for critical agent",
           len(overrides) == 1, f"got {len(overrides)}")
    _check(f"{label}/A: mode is 'flag'",
           overrides[0]["mode"] == "flag")
    _check(f"{label}/A: changed_by = operator UUID",
           overrides[0]["changed_by"] == OPERATOR,
           f"got '{overrides[0]['changed_by']}'")
    _check(f"{label}/A: reason mentions risk_bucket=critical",
           "risk_bucket=critical" in (overrides[0]["reason"] or ""))

    # ── B. low-risk agent — no override ────────────────────────
    snapshot_on_first_sight(
        db, tenant_id=TENANT_A, agent_key=f"Low_{label}",
        definition={**_LOW_DEF, "agent_key": f"Low_{label}"},
        created_by=OPERATOR, note="B: low risk")
    overrides_low = list_delegation_overrides(
        db, tenant_id=TENANT_A,
        parent_agent_key=f"Low_{label}")
    _check(f"{label}/B: 0 override rows for low-risk agent",
           len(overrides_low) == 0, f"got {len(overrides_low)}")

    # ── C. drift does NOT re-apply ─────────────────────────────
    drifted_def = {**_CRITICAL_DEF,
                    "agent_key": f"Crit_{label}",
                    "tools": _CRITICAL_DEF["tools"] + ["new_tool"]}
    snapshot_on_first_sight(
        db, tenant_id=TENANT_A, agent_key=f"Crit_{label}",
        definition=drifted_def, created_by=OPERATOR,
        note="C: drift v2")
    overrides_after_drift = list_delegation_overrides(
        db, tenant_id=TENANT_A,
        parent_agent_key=f"Crit_{label}")
    _check(f"{label}/C: still exactly 1 override after drift",
           len(overrides_after_drift) == 1,
           f"got {len(overrides_after_drift)}")

    # ── D. tenant scoping isolation ────────────────────────────
    overrides_other_tenant = list_delegation_overrides(
        db, tenant_id=TENANT_B,
        parent_agent_key=f"Crit_{label}")
    _check(f"{label}/D: tenant B has no override for same agent_key",
           len(overrides_other_tenant) == 0,
           f"got {len(overrides_other_tenant)}")

    # ── E. operator pre-set override is preserved ──────────────
    set_delegation_override(
        db, tenant_id=TENANT_A, mode="block",
        parent_agent_key=f"OpFirst_{label}",
        reason="E: operator set this BEFORE first-sight",
        changed_by=OPERATOR)
    snapshot_on_first_sight(
        db, tenant_id=TENANT_A, agent_key=f"OpFirst_{label}",
        definition={**_CRITICAL_DEF, "agent_key": f"OpFirst_{label}"},
        created_by=OPERATOR, note="E: should NOT overwrite")
    op_overrides = list_delegation_overrides(
        db, tenant_id=TENANT_A,
        parent_agent_key=f"OpFirst_{label}")
    _check(f"{label}/E: operator override preserved (still 1 row)",
           len(op_overrides) == 1)
    _check(f"{label}/E: operator's BLOCK mode preserved",
           op_overrides[0]["mode"] == "block",
           f"got {op_overrides[0]['mode']}")

    # ── F. end-to-end delegation with auto-flag ────────────────
    critical_read_def = {
        "agent_key": f"CritReadOrch_{label}",
        "system_prompt": "Autonomous critical agent.",
        "tools": ["get_user", "lookup_emr", "fetch_financial",
                  "read_secret", "scan_pii", "audit_log",
                  "tail_logs", "query_db"],
        "human_loop": "out_of_loop",
        "access_level": "read",
        "data_classes": ["pii", "phi", "financial", "secret"],
        "environment": "prod",
        "model_trust": "open_source",
    }
    snapshot_on_first_sight(
        db, tenant_id=TENANT_A,
        agent_key=f"CritReadOrch_{label}",
        definition=critical_read_def,
        created_by=OPERATOR,
        note="F: critical read-only orch")
    snapshot_agent(db, tenant_id=TENANT_A,
                   agent_key=f"AdminSub_{label}",
                   definition={"agent_key": f"AdminSub_{label}",
                                "access_level": "admin"},
                   note="F: admin sub")

    # Verify the resolver picks up the auto-flag override
    mode, source = resolve_effective_mode(
        db, tenant_id=TENANT_A,
        parent_agent_key=f"CritReadOrch_{label}",
        sub_agent_key=f"AdminSub_{label}",
        violation_kind="access_escalation")
    _check(f"{label}/F: resolver returns flag from auto-override",
           mode == "flag", f"got {mode} from {source}")

    record_invocation(
        db, tenant_id=TENANT_A,
        agent_key=f"AdminSub_{label}",
        principal_kind="agent",
        principal_id=f"CritReadOrch_{label}")
    schema_prefix = "prov_schema." if label == "postgresql" else ""
    rows = db.execute(text(
        f"SELECT mode_active FROM {schema_prefix}"
        f"kya_delegation_violations "
        f"WHERE sub_agent_key = :s"
    ), {"s": f"AdminSub_{label}"}).fetchall()
    _check(f"{label}/F: violation persisted",
           len(rows) >= 1, f"got {len(rows)}")
    modes = {r[0] for r in rows}
    _check(f"{label}/F: violation row in flag mode (NOT observe)",
           "flag" in modes, f"got modes {modes}")

    # ── G. env disable ─────────────────────────────────────────
    os.environ["KYA_RISK_TIER_AUTO_DEFAULTS"] = "0"
    snapshot_on_first_sight(
        db, tenant_id=TENANT_A, agent_key=f"DisabledCrit_{label}",
        definition={**_CRITICAL_DEF,
                     "agent_key": f"DisabledCrit_{label}"},
        created_by=OPERATOR, note="G: env disabled")
    disabled_overrides = list_delegation_overrides(
        db, tenant_id=TENANT_A,
        parent_agent_key=f"DisabledCrit_{label}")
    _check(f"{label}/G: env=0 disables auto-default",
           len(disabled_overrides) == 0,
           f"got {len(disabled_overrides)}")
    os.environ.pop("KYA_RISK_TIER_AUTO_DEFAULTS", None)


def main():
    backends = ["sqlite"]
    try:
        import duckdb_engine  # noqa: F401
        backends.append("duckdb")
    except ImportError:
        pass
    if os.environ.get("KYA_TEST_PG_URL"):
        backends.append("postgresql")
    if os.environ.get("KYA_TEST_MYSQL_URL"):
        backends.append("mysql")

    results = {}
    for label in backends:
        _hdr(f"BACKEND  ·  {label.upper()}")
        db, dispose = open_backend(label)
        if db is None:
            print("  skipped: env not set"); continue
        try:
            init_storage(db)
            run_scenarios(db, label)
            results[label] = "PASS"
        except SystemExit:
            results[label] = "FAIL"
        except Exception as exc:
            import traceback
            traceback.print_exc()
            results[label] = f"ERROR: {exc}"
        finally:
            try: db.close()
            except Exception: pass
            try: dispose()
            except Exception: pass

    _hdr("CROSS-BACKEND SUMMARY")
    for label, status in results.items():
        print(f"  {label:15s} {status}")
    all_pass = all(s == "PASS" for s in results.values())
    if all_pass:
        _hdr("RISK-TIER DEFAULTS E2E - ALL BACKENDS PASSED")
        return 0
    _hdr("RISK-TIER DEFAULTS E2E - FAILURES ABOVE")
    return 2


if __name__ == "__main__":
    sys.exit(main())
