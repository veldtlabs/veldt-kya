"""Phase 4a live e2e — JWT introspection across all 4 backends.

What this validates against REAL databases (sqlite/duckdb/postgresql/
mysql) using a REAL JWT signed by a real RSA keypair, served via an
in-process JWKS HTTP server (no external IdP required):

  A. End-to-end: verify_jwt → claims → bind_principal_to_idp →
     lookup_principal_by_idp roundtrips correctly
  B. Token rejected at the JWT layer never reaches the DB
  C. Token verifies but no principal row exists → fail-soft
  D. Multi-IdP-kind detection (Okta, Auth0, Microsoft, SPIFFE)
     all classify correctly and persist correctly
  E. JWKS cache hit on rapid repeated calls
  F. Cross-tenant isolation: same idp_subject in 2 tenants → 2 rows

NOTE: record_user_signal pre-existing DuckDB issue (task #42) does
NOT apply here because Phase 4a binds PRINCIPALS, not USERS.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import sys
import threading
import time
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

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("Phase 4a e2e requires PyJWT + cryptography. Install with:")
    print("  pip install PyJWT cryptography")
    sys.exit(0)

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    bind_principal_from_token,
    claims_to_kya_principal,
    init_storage,
    lookup_principal_by_idp,
    record_principal_signal,
    reset_jwks_cache,
    verify_jwt,
)


TENANT_A = "11111111-2222-3333-4444-aaaaaaaaaaaa"
TENANT_B = "11111111-2222-3333-4444-bbbbbbbbbbbb"


def _hdr(t):
    print(); print("=" * 78); print(f"  {t}"); print("=" * 78)


def _check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          f"{(' - ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(2)


# ── Build an in-process IdP (RSA key + JWKS server) ───────────────


def setup_idp():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    import base64
    def _b64u(n: int) -> str:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    jwks = {"keys": [{
        "kty": "RSA",
        "use": "sig",
        "kid": "e2e-key-1",
        "alg": "RS256",
        "n": _b64u(public_numbers.n),
        "e": _b64u(public_numbers.e),
    }]}
    jwks_body = json.dumps(jwks).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/.well-known/jwks.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(jwks_body)))
                self.end_headers()
                self.wfile.write(jwks_body)
            else:
                self.send_response(404); self.end_headers()
        def log_message(self, *a, **kw): pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return {
        "private_pem": pem_priv,
        "kid": "e2e-key-1",
        "jwks_url": f"http://127.0.0.1:{port}/.well-known/jwks.json",
        "server": srv,
    }


def make_token(idp, claims):
    return jwt.encode(
        claims, idp["private_pem"], algorithm="RS256",
        headers={"kid": idp["kid"]})


# ── Backend setup ──────────────────────────────────────────────────


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
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_principal_trust", "kya_user_trust"):
                try: conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception: pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


def run_scenarios(db, label, idp):
    reset_jwks_cache()
    now = int(time.time())

    # ── A. end-to-end: token → claims → bind → lookup ────────────
    record_principal_signal(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"alice_internal_{label}",
        signal_kind="oos_tool")
    token = make_token(idp, {
        "sub": f"okta|alice_{label}@acme.com",
        "iss": "https://acme.okta.com",
        "iat": now, "exp": now + 3600,
        "email": f"alice_{label}@acme.com",
        "groups": ["finance", "admin"],
    })
    claims = bind_principal_from_token(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"alice_internal_{label}",
        bearer_token=token, jwks_url=idp["jwks_url"])
    _check(f"{label}/A: bind succeeded with valid token",
           claims is not None)
    _check(f"{label}/A: claims include sub + email + groups",
           claims["sub"] == f"okta|alice_{label}@acme.com"
           and claims["email"] == f"alice_{label}@acme.com"
           and claims["groups"] == ["finance", "admin"])
    found = lookup_principal_by_idp(
        db, tenant_id=TENANT_A,
        idp_subject=f"okta|alice_{label}@acme.com")
    _check(f"{label}/A: lookup finds bound principal",
           found is not None
           and found["principal_id"] == f"alice_internal_{label}"
           and found["idp_kind"] == "okta"
           and found["idp_issuer"] == "https://acme.okta.com")

    # ── B. token rejected never reaches DB ───────────────────────
    bad_claims = bind_principal_from_token(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"alice_internal_{label}",
        bearer_token="not.a.real.jwt",
        jwks_url=idp["jwks_url"])
    _check(f"{label}/B: malformed token rejected", bad_claims is None)

    # ── C. token valid but no principal row exists ───────────────
    token_for_ghost = make_token(idp, {
        "sub": f"okta|ghost_{label}",
        "iat": now, "exp": now + 3600,
    })
    ghost_claims = bind_principal_from_token(
        db, tenant_id=TENANT_A,
        principal_kind="user",
        principal_id=f"never_signaled_{label}",
        bearer_token=token_for_ghost, jwks_url=idp["jwks_url"])
    _check(f"{label}/C: valid token + missing principal -> None",
           ghost_claims is None)

    # ── D. Multi-IdP-kind classification ─────────────────────────
    idp_kinds_to_test = [
        ("https://acme.okta.com", "okta"),
        ("https://acme.us.auth0.com/", "auth0"),
        ("https://login.microsoftonline.com/tenant1/v2.0", "microsoft"),
        ("spiffe://acme/svc/agent", "spiffe"),
    ]
    for iss, expected_kind in idp_kinds_to_test:
        pid = f"multi_{expected_kind}_{label}"
        record_principal_signal(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id=pid,
            signal_kind="oos_tool")
        tk = make_token(idp, {
            "sub": f"sub_{expected_kind}_{label}",
            "iss": iss,
            "iat": now, "exp": now + 3600,
        })
        c = bind_principal_from_token(
            db, tenant_id=TENANT_A,
            principal_kind="user", principal_id=pid,
            bearer_token=tk, jwks_url=idp["jwks_url"])
        _check(f"{label}/D: {expected_kind} token verified",
               c is not None)
        row = lookup_principal_by_idp(
            db, tenant_id=TENANT_A,
            idp_subject=f"sub_{expected_kind}_{label}")
        _check(f"{label}/D: {expected_kind} idp_kind correctly inferred",
               row is not None and row["idp_kind"] == expected_kind,
               f"got idp_kind={row['idp_kind'] if row else 'None'}")

    # ── E. JWKS cache — rapid repeated calls ─────────────────────
    cache_token = make_token(idp, {
        "sub": f"cache_test_{label}",
        "iat": now, "exp": now + 3600,
    })
    t0 = time.time()
    for _ in range(20):
        c = verify_jwt(cache_token, jwks_url=idp["jwks_url"])
        assert c is not None
    elapsed = time.time() - t0
    _check(f"{label}/E: 20 cached verifications fast (<2s)",
           elapsed < 2.0,
           f"took {elapsed:.2f}s")

    # ── F. Cross-tenant isolation with same idp_subject ──────────
    shared_sub = f"shared_subject_{label}"
    for tid, pid in ((TENANT_A, "tenantA_user"), (TENANT_B, "tenantB_user")):
        record_principal_signal(
            db, tenant_id=tid, principal_kind="user",
            principal_id=pid, signal_kind="oos_tool")
        tk = make_token(idp, {
            "sub": shared_sub,
            "iat": now, "exp": now + 3600,
        })
        bind_principal_from_token(
            db, tenant_id=tid, principal_kind="user",
            principal_id=pid, bearer_token=tk,
            jwks_url=idp["jwks_url"])
    fa = lookup_principal_by_idp(
        db, tenant_id=TENANT_A, idp_subject=shared_sub)
    fb = lookup_principal_by_idp(
        db, tenant_id=TENANT_B, idp_subject=shared_sub)
    _check(f"{label}/F: tenant A sees its own principal",
           fa is not None and fa["principal_id"] == "tenantA_user")
    _check(f"{label}/F: tenant B sees its own principal",
           fb is not None and fb["principal_id"] == "tenantB_user")
    _check(f"{label}/F: no cross-tenant leak",
           fa["principal_id"] != fb["principal_id"])


def main():
    idp = setup_idp()
    print(f"\n  In-process IdP started on {idp['jwks_url']}")

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
            run_scenarios(db, label, idp)
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

    idp["server"].shutdown(); idp["server"].server_close()

    _hdr("CROSS-BACKEND SUMMARY")
    for label, status in results.items():
        print(f"  {label:15s} {status}")
    all_pass = all(s == "PASS" for s in results.values())
    if all_pass:
        _hdr("JWT AUTH E2E - ALL BACKENDS PASSED")
        return 0
    _hdr("JWT AUTH E2E - FAILURES ABOVE")
    return 2


if __name__ == "__main__":
    sys.exit(main())
