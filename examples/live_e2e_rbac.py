"""Phase 5b — live e2e for RBAC across all 4 backends.

Exercises ACTUAL feature behavior:
  - Off-by-default: configure_rbac("off") → require_action never
    checks the DB
  - Grant CRUD: grant + revoke roundtrip with audit fields
  - Time-bounded grants: expires_at honored
  - Wildcard: kya.* grants everything
  - Block-mode denial: AccessDeniedError raised + security event
    persists to kya_principal_trust signal_counts
  - Flag-mode allow-with-log: returns True, log emitted, signal
    still persists (operator can see what WOULD have been denied)
  - Cross-tenant isolation: grants in tenant A don't leak to
    tenant B even for same principal_id

Runs against real DBs (sqlite/duckdb/postgresql/mysql).
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
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
    AccessDeniedError,
    configure_rbac,
    get_principal_trust,
    grant_action,
    has_action,
    init_storage,
    list_grants,
    record_principal_signal,
    require_action,
    revoke_action,
)


TENANT_A = "11111111-2222-3333-4444-eeeeeeeeeeee"
TENANT_B = "11111111-2222-3333-4444-ffffffffffff"
OPERATOR = "00000000-0000-0000-0000-000000000001"


def _hdr(t):
    print(); print("=" * 78); print(f"  {t}"); print("=" * 78)


def _check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          f"{(' - ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(2)


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
            for tbl in ("kya_role_grants", "kya_principal_trust",
                        "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_role_grants", "kya_principal_trust",
                        "agent_versions"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception: pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


def run_scenarios(db, label):
    # Always start with off mode so prior tests' env doesn't leak
    os.environ.pop("KYA_RBAC_ENFORCEMENT", None)

    # ── A. off-by-default contract ─────────────────────────────
    assert require_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="ghost",
        action="kya.budget.write") is True
    _check(f"{label}/A: off-by-default allows without grant", True)

    # ── B. grant CRUD ───────────────────────────────────────────
    gid = grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.write",
        granted_by=OPERATOR,
        reason="Alice runs budget team")
    _check(f"{label}/B: grant_action returns positive id",
           isinstance(gid, int) and gid > 0)
    # Idempotent re-grant
    gid2 = grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.write",
        granted_by=OPERATOR)
    _check(f"{label}/B: re-grant returns same id (idempotent)",
           gid == gid2)
    # has_action
    _check(f"{label}/B: has_action sees the grant",
           has_action(db, tenant_id=TENANT_A,
                       principal_kind="user", principal_id="alice",
                       action="kya.budget.write") is True)

    # ── C. block-mode denial + security event ──────────────────
    # Note: task #42 (record_principal_signal on DuckDB) is now
    # fixed -- the previous DuckDB skip here has been removed.
    configure_rbac("block")
    record_principal_signal(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="evil",
        signal_kind="clean_invocation")
    raised = False
    try:
        require_action(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id="evil",
            action="kya.budget.write")
    except AccessDeniedError as exc:
        raised = True
        _check(f"{label}/C: AccessDeniedError names principal + action",
               exc.principal_id == "evil"
               and exc.action == "kya.budget.write")
    _check(f"{label}/C: block mode raises AccessDeniedError", raised)
    trust = get_principal_trust(db, TENANT_A, "user", "evil")
    counts = trust.signal_counts or {}
    _check(f"{label}/C: rbac_refusal signal persisted",
           counts.get("rbac_refusal", 0) >= 1,
           f"counts={dict(counts)}")
    _check(f"{label}/C: trust_score debited",
           trust.trust_score < 50,
           f"trust_score={trust.trust_score}")
    # Granted principal still passes
    assert require_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice",
        action="kya.budget.write") is True
    _check(f"{label}/C: granted principal still allowed", True)

    # ── D. flag mode — log + allow ─────────────────────────────
    configure_rbac("flag")
    record_principal_signal(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="eve",
        signal_kind="clean_invocation")
    allowed = require_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="eve",
        action="kya.evidence.export")
    _check(f"{label}/D: flag mode allows (no raise)",
           allowed is True)
    trust_eve = get_principal_trust(db, TENANT_A, "user", "eve")
    _check(f"{label}/D: flag mode still emits rbac_refusal signal",
           (trust_eve.signal_counts or {}).get("rbac_refusal", 0) >= 1)

    # ── E. wildcard grant ──────────────────────────────────────
    configure_rbac("block")
    grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="admin",
        action="kya.*",
        granted_by=OPERATOR)
    # Admin can do ANY KYA action
    for act in ("kya.budget.write", "kya.budget.read",
                "kya.evidence.export", "kya.delegation.override.set",
                "kya.signal.record"):
        require_action(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id="admin",
            action=act)
    _check(f"{label}/E: wildcard grants every KYA action", True)

    # ── F. expired grant doesn't count ─────────────────────────
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="expired_user",
        action="kya.budget.read",
        granted_by=OPERATOR,
        expires_at=past)
    _check(f"{label}/F: has_action FALSE for expired grant",
           has_action(db, tenant_id=TENANT_A,
                       principal_kind="user",
                       principal_id="expired_user",
                       action="kya.budget.read") is False)

    # ── G. revoke roundtrip ────────────────────────────────────
    grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="charlie",
        action="kya.cost.read")
    _check(f"{label}/G: revoke returns True when row exists",
           revoke_action(db, tenant_id=TENANT_A,
                          principal_kind="user", principal_id="charlie",
                          action="kya.cost.read") is True)
    _check(f"{label}/G: revoke returns False on second call",
           revoke_action(db, tenant_id=TENANT_A,
                          principal_kind="user", principal_id="charlie",
                          action="kya.cost.read") is False)
    _check(f"{label}/G: revoked principal no longer has action",
           has_action(db, tenant_id=TENANT_A,
                       principal_kind="user", principal_id="charlie",
                       action="kya.cost.read") is False)

    # ── H. cross-tenant isolation ──────────────────────────────
    grant_action(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="shared_id",
        action="kya.budget.write",
        granted_by=OPERATOR)
    # Same principal_id in tenant B has NOT been granted
    _check(f"{label}/H: tenant A sees the grant",
           has_action(db, tenant_id=TENANT_A,
                       principal_kind="user", principal_id="shared_id",
                       action="kya.budget.write") is True)
    _check(f"{label}/H: tenant B does NOT inherit it",
           has_action(db, tenant_id=TENANT_B,
                       principal_kind="user", principal_id="shared_id",
                       action="kya.budget.write") is False)

    # Reset env so subsequent test runs start clean
    os.environ.pop("KYA_RBAC_ENFORCEMENT", None)


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
        _hdr("RBAC E2E — ALL BACKENDS PASSED")
        return 0
    _hdr("RBAC E2E — FAILURES ABOVE")
    return 2


if __name__ == "__main__":
    sys.exit(main())
