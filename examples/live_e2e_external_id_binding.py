"""Live e2e for Phase 4b — external_id binding across all backends.

Drives the bind/lookup APIs against a real database with realistic
IdP-claim shapes (Okta sub, Auth0 sub, Keycloak sub, SPIFFE
trust-domain ID). Verifies that:

  A. bind + lookup roundtrip
  B. Re-bind same subject is idempotent
  C. Re-bind different subject overwrites (rotation case)
  D. Cross-tenant isolation: same idp_subject in 2 tenants → 2 rows
  E. list_principals_by_idp_kind filter
  F. Operator can populate from "any source" (caller-supplied claims)
  G. fail-soft when principal row doesn't exist

Runs cross-backend on sqlite/duckdb/postgresql/mysql.

NOTE: record_user_signal has a pre-existing DuckDB incompatibility
(task #42); the user-binding scenarios are skipped on DuckDB only.
"""

from __future__ import annotations

import os
import sys
import uuid
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
    bind_principal_to_idp,
    bind_user_to_idp,
    init_storage,
    InvalidIdpKindError,
    list_principals_by_idp_kind,
    lookup_principal_by_idp,
    lookup_user_by_idp,
    record_principal_signal,
    record_user_signal,
)


TENANT_A = "00000000-0000-0000-0000-0000000004b1"
TENANT_B = "00000000-0000-0000-0000-0000000004b2"


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
            for tbl in ("kya_principal_trust", "kya_user_trust"):
                conn.execute(text(f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_principal_trust", "kya_user_trust"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception:
                    pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


def run_scenarios(db, label):
    is_duckdb = (db.get_bind().dialect.name == "duckdb")

    # ── A. bind + lookup roundtrip (principal) ────────────────────
    record_principal_signal(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"alice_internal_{label}",
        signal_kind="oos_tool")
    ok = bind_principal_to_idp(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"alice_internal_{label}",
        idp_subject=f"00uXY_alice_{label}",  # Okta-style sub
        idp_issuer="https://acme.okta.com",
        idp_kind="okta",
    )
    _check(f"{label}/A: bind returns True", ok is True)
    found = lookup_principal_by_idp(
        db, tenant_id=TENANT_A,
        idp_subject=f"00uXY_alice_{label}")
    _check(f"{label}/A: lookup finds bound principal",
           found is not None)
    _check(f"{label}/A: roundtrip principal_id matches",
           found["principal_id"] == f"alice_internal_{label}")
    _check(f"{label}/A: idp_issuer roundtrips",
           found["idp_issuer"] == "https://acme.okta.com")
    _check(f"{label}/A: idp_kind roundtrips",
           found["idp_kind"] == "okta")
    # federated_id was auto-derived (idp_kind|idp_issuer|idp_subject)
    expected_fed = (f"okta|https://acme.okta.com|"
                     f"00uXY_alice_{label}")
    _check(f"{label}/A: federated_id auto-derived",
           found["federated_id"] == expected_fed,
           f"got '{found['federated_id']}'")

    # ── B. Re-bind same subject is idempotent ─────────────────────
    ok2 = bind_principal_to_idp(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"alice_internal_{label}",
        idp_subject=f"00uXY_alice_{label}",
        idp_kind="okta",
        idp_issuer="https://acme.okta.com")
    _check(f"{label}/B: re-bind same subject returns True", ok2)
    found2 = lookup_principal_by_idp(
        db, tenant_id=TENANT_A,
        idp_subject=f"00uXY_alice_{label}")
    _check(f"{label}/B: still findable after re-bind", found2 is not None)

    # ── C. Re-bind to DIFFERENT subject (rotation) ────────────────
    record_principal_signal(
        db, tenant_id=TENANT_A,
        principal_kind="agent",
        principal_id=f"rotating_agent_{label}",
        signal_kind="oos_tool")
    bind_principal_to_idp(
        db, tenant_id=TENANT_A,
        principal_kind="agent",
        principal_id=f"rotating_agent_{label}",
        idp_subject="spiffe://acme/orig", idp_kind="spiffe")
    bind_principal_to_idp(
        db, tenant_id=TENANT_A,
        principal_kind="agent",
        principal_id=f"rotating_agent_{label}",
        idp_subject="spiffe://acme/rotated", idp_kind="spiffe")
    old = lookup_principal_by_idp(
        db, tenant_id=TENANT_A, idp_subject="spiffe://acme/orig")
    new = lookup_principal_by_idp(
        db, tenant_id=TENANT_A, idp_subject="spiffe://acme/rotated")
    _check(f"{label}/C: old subject no longer found", old is None)
    _check(f"{label}/C: new subject found",
           new is not None and new["principal_id"] == f"rotating_agent_{label}")

    # ── D. Cross-tenant isolation ─────────────────────────────────
    shared_sub = "00uShared|abc123"
    record_principal_signal(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice_in_A",
        signal_kind="oos_tool")
    record_principal_signal(
        db, tenant_id=TENANT_B,
        principal_kind="user", principal_id="alice_in_B",
        signal_kind="oos_tool")
    bind_principal_to_idp(
        db, tenant_id=TENANT_A,
        principal_kind="user", principal_id="alice_in_A",
        idp_subject=shared_sub, idp_kind="okta")
    bind_principal_to_idp(
        db, tenant_id=TENANT_B,
        principal_kind="user", principal_id="alice_in_B",
        idp_subject=shared_sub, idp_kind="okta")
    fa = lookup_principal_by_idp(
        db, tenant_id=TENANT_A, idp_subject=shared_sub)
    fb = lookup_principal_by_idp(
        db, tenant_id=TENANT_B, idp_subject=shared_sub)
    _check(f"{label}/D: tenant A sees its own principal",
           fa is not None and fa["principal_id"] == "alice_in_A")
    _check(f"{label}/D: tenant B sees its own principal",
           fb is not None and fb["principal_id"] == "alice_in_B")
    _check(f"{label}/D: no cross-tenant leak",
           fa["principal_id"] != fb["principal_id"])

    # ── E. list_principals_by_idp_kind ────────────────────────────
    # Create 3 agents bound to different IdPs in tenant A
    for pid, kind in (("svc_okta", "okta"), ("svc_okta_2", "okta"),
                      ("svc_auth0", "auth0")):
        record_principal_signal(
            db, tenant_id=TENANT_A,
            principal_kind="service_account",
            principal_id=f"{pid}_{label}",
            signal_kind="oos_tool")
        bind_principal_to_idp(
            db, tenant_id=TENANT_A,
            principal_kind="service_account",
            principal_id=f"{pid}_{label}",
            idp_subject=f"sub_{pid}_{label}", idp_kind=kind)
    okta_only = list_principals_by_idp_kind(
        db, tenant_id=TENANT_A, idp_kind="okta")
    okta_pids = {p["principal_id"] for p in okta_only
                  if p["principal_id"].startswith("svc_okta")}
    _check(f"{label}/E: list by idp_kind=okta finds both okta SAs",
           okta_pids == {f"svc_okta_{label}", f"svc_okta_2_{label}"},
           f"got {okta_pids}")

    # ── F. Caller-supplied claims (Phase 4a-independent path) ─────
    # Simulate FastAPI middleware that decoded a JWT upstream
    fake_jwt_claims = {
        "sub": "auth0|65abc...def",
        "iss": "https://acme.us.auth0.com/",
        "email": "bob@acme.com",
    }
    record_principal_signal(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"bob_kya_{label}",
        signal_kind="data_leak")
    bind_principal_to_idp(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"bob_kya_{label}",
        idp_subject=fake_jwt_claims["sub"],
        idp_issuer=fake_jwt_claims["iss"],
        idp_kind="auth0")
    found_bob = lookup_principal_by_idp(
        db, tenant_id=TENANT_A,
        idp_subject="auth0|65abc...def")
    _check(f"{label}/F: caller-supplied claims path works",
           found_bob is not None
           and found_bob["principal_id"] == f"bob_kya_{label}"
           and found_bob["idp_kind"] == "auth0")

    # ── G. fail-soft when principal row doesn't exist ─────────────
    ghost_ok = bind_principal_to_idp(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"never_signaled_{label}",
        idp_subject="ghost|sub")
    _check(f"{label}/G: bind on missing principal returns False",
           ghost_ok is False)

    # ── User binding (skipped on DuckDB due to pre-existing bug) ──
    if not is_duckdb:
        user_uuid = str(uuid.uuid4())
        record_user_signal(
            db, tenant_id=TENANT_A, user_id=user_uuid,
            signal_kind="oos_tool")
        user_bind_ok = bind_user_to_idp(
            db, tenant_id=TENANT_A, user_id=user_uuid,
            idp_subject=f"entra|tenant1|{user_uuid}",
            idp_issuer="https://login.microsoftonline.com/...",
            idp_kind="microsoft")
        _check(f"{label}/USER: bind_user roundtrip", user_bind_ok)
        u_found = lookup_user_by_idp(
            db, tenant_id=TENANT_A,
            idp_subject=f"entra|tenant1|{user_uuid}")
        _check(f"{label}/USER: lookup_user finds bound user",
               u_found is not None and u_found["user_id"] == user_uuid)
    else:
        print(f"  [SKIP] {label}/USER: record_user_signal pre-existing "
              f"DuckDB issue (task #42)")

    # ── Validation surface ────────────────────────────────────────
    raised = False
    try:
        bind_principal_to_idp(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id="x",
            idp_subject="some_sub", idp_kind="frobozz")
    except InvalidIdpKindError:
        raised = True
    _check(f"{label}/VAL: unknown idp_kind raises", raised)


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
        _hdr("EXTERNAL_ID BINDING E2E - ALL BACKENDS PASSED")
        return 0
    _hdr("EXTERNAL_ID BINDING E2E - FAILURES ABOVE")
    return 2


if __name__ == "__main__":
    sys.exit(main())
