"""Phase 4c -- live e2e for SPIFFE/OIDC workload identity.

Drives the SPIFFE module against real databases on all 4 backends
(sqlite / duckdb / postgresql / mysql). Exercises ACTUAL feature
behavior (not synthetic fixtures):

  A. parse_spiffe_id contract on realistic SPIFFE IDs
  B. Trust-domain allowlist enforcement via env var
  C. bind happy path: SPIFFE ID -> service_account principal
  D. lookup roundtrip
  E. Re-bind same SPIFFE ID is idempotent
  F. Cross-tenant isolation: same SPIFFE ID in two tenants -> two rows
  G. verify_jwt_svid with mocked Phase 4a (we don't run a real SPIRE
     server in the live e2e; the JWT verification path is unit-tested
     elsewhere -- here we verify SPIFFE-specific decoration only)
  H. bind_principal_from_svid one-call (mocked verify)

NOTE: record_principal_signal has the same DuckDB constraint as
other phases (task #42); SPIFFE binding works fine on DuckDB but
trust_score updates skip there. The bind itself is testable.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch


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
    SpiffeIdFormatError,
    bind_principal_from_svid,
    bind_spiffe_id_to_principal,
    init_storage,
    is_allowed_trust_domain,
    is_valid_spiffe_id,
    lookup_principal_by_spiffe_id,
    parse_spiffe_id,
    record_principal_signal,
    verify_jwt_svid,
)


TENANT_A = "11111111-2222-3333-4444-aaaaaaaa4cab"
TENANT_B = "11111111-2222-3333-4444-aaaaaaaa4cba"


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
            for tbl in ("kya_principal_trust", "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl} CASCADE"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_principal_trust", "agent_versions"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception: pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


def run_scenarios(db, label):
    # Reset SPIFFE env (some scenarios set it; clean between backends)
    os.environ.pop("KYA_SPIFFE_TRUST_DOMAINS", None)

    is_duckdb = (db.get_bind().dialect.name == "duckdb")

    # ── A. parse_spiffe_id contract (no DB needed) ─────────────
    td, path = parse_spiffe_id("spiffe://example.org/ns/prod/sa/svc")
    _check(f"{label}/A: parse trust_domain", td == "example.org")
    _check(f"{label}/A: parse path",
           path == "/ns/prod/sa/svc")
    _check(f"{label}/A: trust-domain-only id",
           parse_spiffe_id("spiffe://example.org") == ("example.org", ""))
    raised = False
    try:
        parse_spiffe_id("spiffe://EXAMPLE.ORG/path")  # uppercase
    except SpiffeIdFormatError: raised = True
    _check(f"{label}/A: rejects uppercase td", raised)
    _check(f"{label}/A: is_valid_spiffe_id positive",
           is_valid_spiffe_id("spiffe://example.org/sa/svc"))
    _check(f"{label}/A: is_valid_spiffe_id negative",
           not is_valid_spiffe_id("urn:not:spiffe"))

    # ── B. Trust-domain allowlist via env ──────────────────────
    os.environ["KYA_SPIFFE_TRUST_DOMAINS"] = "prod.example.org,corp.example.com"
    _check(f"{label}/B: env allowlist hit",
           is_allowed_trust_domain("prod.example.org"))
    _check(f"{label}/B: env allowlist miss",
           not is_allowed_trust_domain("attacker.evil"))
    _check(f"{label}/B: kwarg overrides env",
           is_allowed_trust_domain(
               "custom.td", allowed=["custom.td"]))
    os.environ.pop("KYA_SPIFFE_TRUST_DOMAINS", None)

    # ── C. bind happy path ────────────────────────────────────
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="service_account",
        principal_id="inference-svc",
        signal_kind="clean_invocation")
    spiffe_id_a = "spiffe://prod.example.org/ns/ml/sa/inference"
    ok = bind_spiffe_id_to_principal(
        db, tenant_id=TENANT_A,
        principal_kind="service_account",
        principal_id="inference-svc",
        spiffe_id=spiffe_id_a)
    _check(f"{label}/C: bind happy path", ok)

    # ── D. lookup roundtrip ───────────────────────────────────
    found = lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT_A, spiffe_id=spiffe_id_a)
    _check(f"{label}/D: lookup finds principal",
           found is not None
           and found["principal_id"] == "inference-svc"
           and found["principal_kind"] == "service_account",
           f"got={found}")
    _check(f"{label}/D: idp_kind stored as 'spiffe'",
           found and found.get("idp_kind") == "spiffe")
    _check(f"{label}/D: idp_issuer derived correctly",
           found and found.get("idp_issuer") == "spiffe://prod.example.org")

    # ── E. Re-bind idempotent ─────────────────────────────────
    ok2 = bind_spiffe_id_to_principal(
        db, tenant_id=TENANT_A,
        principal_kind="service_account",
        principal_id="inference-svc",
        spiffe_id=spiffe_id_a)
    _check(f"{label}/E: re-bind same SPIFFE ID returns True", ok2)
    # Verify still finds it
    _check(f"{label}/E: lookup still works after re-bind",
           lookup_principal_by_spiffe_id(
               db, tenant_id=TENANT_A,
               spiffe_id=spiffe_id_a) is not None)

    # ── F. Cross-tenant isolation ─────────────────────────────
    record_principal_signal(
        db, tenant_id=TENANT_B, principal_kind="service_account",
        principal_id="inference-svc",  # same principal name
        signal_kind="clean_invocation")
    ok3 = bind_spiffe_id_to_principal(
        db, tenant_id=TENANT_B,
        principal_kind="service_account",
        principal_id="inference-svc",
        spiffe_id=spiffe_id_a)  # same SPIFFE ID, different tenant
    _check(f"{label}/F: cross-tenant bind succeeds", ok3)
    # Tenant A still finds its own binding
    a_found = lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT_A, spiffe_id=spiffe_id_a)
    b_found = lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT_B, spiffe_id=spiffe_id_a)
    _check(f"{label}/F: tenant A lookup intact", a_found is not None)
    _check(f"{label}/F: tenant B lookup intact", b_found is not None)
    _check(f"{label}/F: cross-tenant rows are distinct",
           a_found and b_found
           and a_found.get("tenant_id") != b_found.get("tenant_id"))

    # ── G. Trust-domain allowlist blocks bind ─────────────────
    os.environ["KYA_SPIFFE_TRUST_DOMAINS"] = "prod.example.org"
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="service_account",
        principal_id="malicious-svc",
        signal_kind="clean_invocation")
    blocked = bind_spiffe_id_to_principal(
        db, tenant_id=TENANT_A,
        principal_kind="service_account",
        principal_id="malicious-svc",
        spiffe_id="spiffe://attacker.evil/sa/payload")
    _check(f"{label}/G: blocked trust domain refuses bind",
           blocked is False)
    # No binding created
    _check(f"{label}/G: no row from blocked attempt",
           lookup_principal_by_spiffe_id(
               db, tenant_id=TENANT_A,
               spiffe_id="spiffe://attacker.evil/sa/payload") is None)
    os.environ.pop("KYA_SPIFFE_TRUST_DOMAINS", None)

    # ── H. verify_jwt_svid (mocked Phase 4a) ──────────────────
    # Real SVID verification requires a SPIRE Server; mock the
    # underlying Phase 4a verify_jwt to simulate "JWT validated
    # against trust-domain JWKS" and confirm SPIFFE-specific
    # decoration is correct.
    os.environ["KYA_SPIFFE_JWKS_URL"] = "https://spire/jwks"
    fake_claims = {
        "sub": "spiffe://prod.example.org/ns/payments/sa/billing",
        "iss": "spiffe://prod.example.org",
        "aud": "kya",
        "exp": 9999999999,
    }
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        result = verify_jwt_svid("real.jwt.svid")
    _check(f"{label}/H: verify returns dict on valid SVID",
           result is not None)
    _check(f"{label}/H: extracts spiffe_id",
           result and result["spiffe_id"]
           == "spiffe://prod.example.org/ns/payments/sa/billing")
    _check(f"{label}/H: extracts trust_domain",
           result and result["trust_domain"] == "prod.example.org")
    _check(f"{label}/H: extracts path",
           result and result["path"] == "/ns/payments/sa/billing")
    _check(f"{label}/H: derives canonical idp_issuer",
           result and result["idp_issuer"] == "spiffe://prod.example.org")

    # ── I. bind_principal_from_svid one-call ──────────────────
    record_principal_signal(
        db, tenant_id=TENANT_A, principal_kind="service_account",
        principal_id="billing-svc",
        signal_kind="clean_invocation")
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        ok = bind_principal_from_svid(
            db, tenant_id=TENANT_A,
            principal_kind="service_account",
            principal_id="billing-svc",
            svid="real.jwt.svid")
    _check(f"{label}/I: one-call verify+bind succeeds", ok)
    _check(f"{label}/I: lookup finds bound principal",
           lookup_principal_by_spiffe_id(
               db, tenant_id=TENANT_A,
               spiffe_id="spiffe://prod.example.org/ns/payments/sa/billing")
           is not None)

    # ── J. verify_jwt_svid fails closed when verify_jwt fails ──
    # Simulates: bad signature / expired token / wrong audience
    with patch("kya.auth.verify_jwt", return_value=None):
        result = verify_jwt_svid("bad.jwt.svid")
    _check(f"{label}/J: verify returns None on Phase 4a fail",
           result is None)
    # Also test bind_principal_from_svid path
    with patch("kya.auth.verify_jwt", return_value=None):
        ok = bind_principal_from_svid(
            db, tenant_id=TENANT_A,
            principal_kind="service_account",
            principal_id="billing-svc",
            svid="bad.jwt.svid")
    _check(f"{label}/J: bind_from_svid returns False when verify fails",
           ok is False)
    os.environ.pop("KYA_SPIFFE_JWKS_URL", None)


def main():
    backends = ["sqlite", "duckdb"]
    if os.environ.get("KYA_TEST_PG_URL"):
        backends.append("postgresql")
    if os.environ.get("KYA_TEST_MYSQL_URL"):
        backends.append("mysql")

    skipped = []
    for label in backends:
        _hdr(f"Phase 4c live e2e: {label}")
        result = open_backend(label)
        if result == (None, None):
            print(f"  [SKIP] no URL for {label}"); skipped.append(label)
            continue
        db, dispose = result
        try:
            init_storage(db)
            run_scenarios(db, label)
        finally:
            db.close(); dispose()

    _hdr("Phase 4c live e2e: SUMMARY")
    print(f"  backends exercised: "
          f"{[b for b in backends if b not in skipped]}")
    if skipped:
        print(f"  skipped: {skipped} "
              f"(set KYA_TEST_PG_URL / KYA_TEST_MYSQL_URL)")
    print("  result: ALL ASSERTIONS PASS")


if __name__ == "__main__":
    main()
