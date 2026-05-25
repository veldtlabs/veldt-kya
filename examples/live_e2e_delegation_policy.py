"""Cross-backend e2e for delegation-policy enforcement.

Validates on sqlite / duckdb / postgresql / mysql:

  Scenario A — clean delegation (sub stricter than parent):
      Expect: 0 violations, no rows in kya_delegation_violations.

  Scenario B — access_level escalation in OBSERVE mode:
      sub.access_level=admin under parent.access_level=read.
      Expect: 1 row in kya_delegation_violations with
      violation_kind='access_escalation', mode_active='observe',
      blocked=False. record_invocation returns normally.

  Scenario C — data_class widening + human_loop relaxation
                under FLAG mode:
      Expect: 2 violations rows, mode_active='flag', blocked=False.

  Scenario D — access_level escalation in BLOCK mode:
      Expect: DelegationPolicyError raised. The kya_invocations row
      for the blocked sub still exists with outcome='blocked'.
      The kya_delegation_violations row has blocked=True.

  Scenario E — caller's principal is a USER (not an agent):
      No parent agent → no check should run even in block mode.
      Expect: invocation succeeds, no violation rows.

Each backend is wiped before its run for deterministic IDs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


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

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    DelegationPolicyError,
    init_storage,
    record_invocation,
    snapshot_agent,
)


TENANT = "00000000-0000-0000-0000-000000000aaa"


def _hdr(t): print(); print("=" * 78); print(f"  {t}"); print("=" * 78)
def _check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          f"{(' - ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(2)


def open_backend(label: str):
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
            for tbl in ("kya_delegation_violations", "kya_invocations",
                        "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_delegation_violations", "kya_invocations",
                        "agent_versions"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception:
                    pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


def _violation_rows(db, label, sub_agent_key):
    schema = "prov_schema." if label == "postgresql" else ""
    return db.execute(text(
        f"SELECT violation_kind, mode_active, blocked, parent_agent_key "
        f"FROM {schema}kya_delegation_violations "
        f"WHERE sub_agent_key = :s "
        f"ORDER BY id"
    ), {"s": sub_agent_key}).fetchall()


def _invocation_outcome(db, label, sub_agent_key, principal_id):
    schema = "prov_schema." if label == "postgresql" else ""
    rows = db.execute(text(
        f"SELECT outcome FROM {schema}kya_invocations "
        f"WHERE agent_key = :a AND principal_id = :p "
        f"ORDER BY id DESC LIMIT 1"
    ), {"a": sub_agent_key, "p": principal_id}).fetchall()
    return rows[0][0] if rows else None


def run_scenarios(db, label: str) -> dict:
    # Set up the four agents we'll use across scenarios.
    parent_strict = {
        "agent_key": f"P_strict_{label}",
        "access_level": "read",
        "data_classes": ["pii"],
        "human_loop": "in_the_loop",
        "tools": [],
    }
    sub_clean = {
        "agent_key": f"S_clean_{label}",
        "access_level": "read",
        "data_classes": ["pii"],
        "human_loop": "in_the_loop",
        "tools": [],
    }
    sub_escalating = {
        "agent_key": f"S_esc_{label}",
        "access_level": "admin",  # escalates from parent.read
        "data_classes": ["pii"],
        "human_loop": "in_the_loop",
        "tools": [],
    }
    sub_widening = {
        "agent_key": f"S_wide_{label}",
        "access_level": "read",
        "data_classes": ["pii", "phi"],  # adds phi
        "human_loop": "autonomous",      # weakens oversight
        "tools": [],
    }
    sub_user_principal = {
        "agent_key": f"S_userp_{label}",
        "access_level": "admin",
        "data_classes": [],
        "human_loop": "in_the_loop",
        "tools": [],
    }

    for d in (parent_strict, sub_clean, sub_escalating,
              sub_widening, sub_user_principal):
        snapshot_agent(db, tenant_id=TENANT, agent_key=d["agent_key"],
                       definition=d, note=f"deleg-policy e2e {label}")

    # ── A. clean delegation ──────────────────────────────────────
    os.environ["KYA_DELEGATION_POLICY"] = "block"  # most aggressive — clean run must still pass
    record_invocation(
        db, tenant_id=TENANT, agent_key=sub_clean["agent_key"],
        principal_kind="agent", principal_id=parent_strict["agent_key"],
        mode="observed", outcome="success",
    )
    rows = _violation_rows(db, label, sub_clean["agent_key"])
    _check(f"{label}/A: clean delegation produces no violations",
           len(rows) == 0, f"got {len(rows)} rows")

    # ── B. access escalation in observe mode ─────────────────────
    os.environ["KYA_DELEGATION_POLICY"] = "observe"
    record_invocation(
        db, tenant_id=TENANT, agent_key=sub_escalating["agent_key"],
        principal_kind="agent", principal_id=parent_strict["agent_key"],
        mode="observed", outcome="success",
    )
    rows = _violation_rows(db, label, sub_escalating["agent_key"])
    _check(f"{label}/B: access_escalation detected (1 row)",
           len(rows) == 1, f"got {len(rows)}")
    _check(f"{label}/B: violation_kind=access_escalation",
           rows[0][0] == "access_escalation")
    _check(f"{label}/B: mode_active=observe", rows[0][1] == "observe")
    _check(f"{label}/B: blocked=False", rows[0][2] in (0, False))

    # ── C. widening + relaxation in flag mode (2 violations) ─────
    os.environ["KYA_DELEGATION_POLICY"] = "flag"
    record_invocation(
        db, tenant_id=TENANT, agent_key=sub_widening["agent_key"],
        principal_kind="agent", principal_id=parent_strict["agent_key"],
        mode="observed", outcome="success",
    )
    rows = _violation_rows(db, label, sub_widening["agent_key"])
    _check(f"{label}/C: 2 violations (data_widening + human_loop_relax)",
           len(rows) == 2, f"got {len(rows)}")
    kinds = {r[0] for r in rows}
    _check(f"{label}/C: includes data_class_widening",
           "data_class_widening" in kinds)
    _check(f"{label}/C: includes human_loop_relax",
           "human_loop_relax" in kinds)
    _check(f"{label}/C: mode_active=flag",
           all(r[1] == "flag" for r in rows))

    # ── D. block mode raises ─────────────────────────────────────
    os.environ["KYA_DELEGATION_POLICY"] = "block"
    raised = False
    try:
        record_invocation(
            db, tenant_id=TENANT,
            agent_key=sub_escalating["agent_key"],
            principal_kind="agent",
            principal_id=parent_strict["agent_key"],
            mode="observed", outcome="success",
        )
    except DelegationPolicyError as exc:
        raised = True
        _check(f"{label}/D: exception names parent + sub",
               exc.parent_agent_key == parent_strict["agent_key"]
               and exc.sub_agent_key == sub_escalating["agent_key"])
    _check(f"{label}/D: block mode raises DelegationPolicyError", raised)

    outcome = _invocation_outcome(
        db, label, sub_escalating["agent_key"],
        parent_strict["agent_key"])
    _check(f"{label}/D: invocation row marked outcome=blocked",
           outcome == "blocked", f"got '{outcome}'")

    # Filter to the BLOCK-mode row for the escalating sub (mode_active=block)
    rows = [r for r in _violation_rows(db, label,
                                          sub_escalating["agent_key"])
            if r[1] == "block"]
    _check(f"{label}/D: blocked violation row persisted",
           len(rows) == 1 and rows[0][2] in (1, True))

    # ── E. user principal — check should NOT fire ────────────────
    record_invocation(
        db, tenant_id=TENANT,
        agent_key=sub_user_principal["agent_key"],
        principal_kind="user", principal_id="alice@example.com",
        mode="observed", outcome="success",
    )
    rows = _violation_rows(db, label,
                            sub_user_principal["agent_key"])
    _check(f"{label}/E: user-principal invocation produces no violations",
           len(rows) == 0, f"got {len(rows)}")

    # Reset env
    os.environ.pop("KYA_DELEGATION_POLICY", None)

    return {"status": "PASS"}


def main() -> int:
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

    results: dict[str, str] = {}
    for label in backends:
        _hdr(f"BACKEND  ·  {label.upper()}")
        db, dispose = open_backend(label)
        if db is None:
            print(f"  skipped: env not set"); continue
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
        _hdr("DELEGATION POLICY E2E - ALL BACKENDS PASSED")
        return 0
    else:
        _hdr("DELEGATION POLICY E2E - FAILURES ABOVE")
        return 2


if __name__ == "__main__":
    sys.exit(main())
