"""Phase 4a.2 -- LIVE integration test against a REAL Keycloak.

Drives the Phase 4a JWT verification + Phase 4b external-ID binding
against a live Keycloak server. This is the answer to "the unit
tests mock JWKS fetch entirely -- prove KYA actually works with a
real IdP's actual JWT-emitting flow."

What this script does
---------------------
1. Bootstraps a fresh realm `veldt-kya-test` on a running Keycloak
   (creates client + user via admin API; deletes + recreates if it
   already exists from a previous run)
2. Gets a REAL access token via OAuth2 password grant
3. Decodes the token to show its actual SPIFFE-free shape
4. Calls KYA's verify_jwt against the live JWKS endpoint -- this
   exercises the FULL crypto path (signature verify against the
   realm's actual signing key, audience/issuer enforcement)
5. Exercises bind_principal_from_token + lookup_principal_by_idp
6. Negative cases (tampered, wrong audience, wrong issuer, expired)

Required setup
--------------
A Keycloak running on http://localhost:17080 (the vd-keycloak
container in the local docker compose stack). Override with:
  KYA_KC_URL=https://your-keycloak/  (must end with /)
  KYA_KC_ADMIN_USER=admin            (default: admin)
  KYA_KC_ADMIN_PASS=...              (default: veldt_kc_2026)

If your Keycloak isn't running, this script SKIPS rather than fails
-- letting CI exclude it without breaking the build.
"""

from __future__ import annotations

import json
import os
import sys
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

import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kya import (
    bind_principal_from_token,
    init_storage,
    lookup_principal_by_idp,
    verify_jwt,
)
from kya.auth import reset_jwks_cache


KC_URL = os.environ.get("KYA_KC_URL", "http://localhost:17080/").rstrip("/") + "/"
KC_ADMIN_USER = os.environ.get("KYA_KC_ADMIN_USER", "admin")
KC_ADMIN_PASS = os.environ.get("KYA_KC_ADMIN_PASS", "veldt_kc_2026")

REALM_NAME = "veldt-kya-test"
CLIENT_ID = "veldt-kya-test-client"
TEST_USER = "kya-test@example.com"
TEST_USER_PASS = "VeldtKYA_2026!"
TENANT = "11111111-2222-3333-4444-aaaaaaaa4a2a"


def _hdr(t):
    print(); print("=" * 78); print(f"  {t}"); print("=" * 78)


def _check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          f"{(' - ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(2)


def _skip(msg):
    print(f"\n  [SKIP] {msg}")
    print("  (Keycloak isn't running. Start with `docker start vd-keycloak`")
    print("   or set KYA_KC_URL to a running instance.)")
    sys.exit(0)


# ── Keycloak Admin REST helpers ───────────────────────────────────


def _kc_admin_token() -> str | None:
    """Get a master-realm admin token. Returns None if Keycloak is
    unreachable -- script will skip rather than fail."""
    try:
        r = requests.post(
            KC_URL + "realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": KC_ADMIN_USER,
                "password": KC_ADMIN_PASS,
            },
            timeout=5.0)
    except (requests.ConnectionError, requests.Timeout):
        return None
    if r.status_code != 200:
        return None
    return r.json().get("access_token")


def _kc_admin(token: str):
    """Return a requests Session pre-loaded with the admin Bearer."""
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    s.headers["Content-Type"] = "application/json"
    return s


def _ensure_realm(s, name: str):
    """Idempotent realm creation: delete-if-exists, then create
    fresh with short token lifespan + the dynamic test client/user."""
    # Check existence
    r = s.get(f"{KC_URL}admin/realms/{name}")
    if r.status_code == 200:
        s.delete(f"{KC_URL}admin/realms/{name}")
        time.sleep(1)
    # Create realm with 60s access-token lifespan (so we can exercise
    # the expired-token path within the test runtime)
    body = {
        "realm": name,
        "enabled": True,
        # Keycloak min accessTokenLifespan is 1s in API but realistic
        # is 60+. We use 10s -- gives a real-Keycloak-issued token that
        # actually expires fast enough for the test to exercise the
        # expiry case without waiting minutes. Combined with the test
        # passing leeway_seconds=0 on the expired-check, we don't have
        # to wait past the 30s default leeway either.
        "accessTokenLifespan": 10,
    }
    r = s.post(f"{KC_URL}admin/realms", data=json.dumps(body))
    assert r.status_code in (201, 409), \
        f"realm create failed: {r.status_code} {r.text}"


def _ensure_client(s, realm: str, client_id: str):
    """Idempotent client: create a confidential client with
    direct-access-grants enabled (so we can use password grant)."""
    body = {
        "clientId": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": True,  # no client secret needed
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [],
        "webOrigins": [],
    }
    r = s.post(
        f"{KC_URL}admin/realms/{realm}/clients", data=json.dumps(body))
    assert r.status_code in (201, 409), \
        f"client create failed: {r.status_code} {r.text}"


def _ensure_user(s, realm: str, username: str, password: str):
    """Idempotent user with a known password."""
    body = {
        "username": username,
        "email": username,
        "firstName": "KYA",
        "lastName": "TestUser",
        "enabled": True,
        "emailVerified": True,
        # Clear default required actions (VERIFY_EMAIL, UPDATE_PASSWORD)
        # otherwise Keycloak returns "Account is not fully set up"
        # on the password grant.
        "requiredActions": [],
        "credentials": [{
            "type": "password",
            "value": password,
            "temporary": False,
        }],
    }
    r = s.post(
        f"{KC_URL}admin/realms/{realm}/users", data=json.dumps(body))
    if r.status_code == 409:  # already exists, that's fine after realm reset
        return
    assert r.status_code == 201, \
        f"user create failed: {r.status_code} {r.text}"


def _get_user_token(realm: str, client_id: str,
                    username: str, password: str) -> dict:
    """Password-grant a real access token. Returns the full token
    response (access_token, id_token if scope=openid, etc.)."""
    r = requests.post(
        f"{KC_URL}realms/{realm}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": "openid",
        },
        timeout=5.0)
    assert r.status_code == 200, \
        f"token grant failed: {r.status_code} {r.text}"
    return r.json()


# ── Test scenarios ────────────────────────────────────────────────


def main():
    _hdr(f"Phase 4a.2 real-IdP integration -- Keycloak @ {KC_URL}")

    # ── Setup: bootstrap realm + client + user ───────────────────
    admin_tok = _kc_admin_token()
    if not admin_tok:
        _skip(f"Cannot reach Keycloak at {KC_URL}")
    print("  Keycloak reachable, admin token acquired")

    s = _kc_admin(admin_tok)
    _ensure_realm(s, REALM_NAME)
    _ensure_client(s, REALM_NAME, CLIENT_ID)
    _ensure_user(s, REALM_NAME, TEST_USER, TEST_USER_PASS)
    print(f"  bootstrapped realm '{REALM_NAME}', client '{CLIENT_ID}', "
          f"user '{TEST_USER}'")

    issuer = f"{KC_URL.rstrip('/')}/realms/{REALM_NAME}"
    jwks_url = f"{issuer}/protocol/openid-connect/certs"

    # ── A. Get a real token + inspect its shape ──────────────────
    tok_resp = _get_user_token(
        REALM_NAME, CLIENT_ID, TEST_USER, TEST_USER_PASS)
    access_token = tok_resp["access_token"]
    print(f"  obtained real access_token (len={len(access_token)})")

    # Decode WITHOUT verifying to inspect the shape (educational only)
    import base64
    head_b64, payload_b64, _ = access_token.split(".")
    pad = "=" * (-len(payload_b64) % 4)
    claims_raw = json.loads(
        base64.urlsafe_b64decode(payload_b64 + pad).decode("utf-8"))
    _check("A: token has iss claim",
           claims_raw.get("iss") == issuer,
           f"got={claims_raw.get('iss')}")
    _check("A: token has sub claim",
           claims_raw.get("sub") is not None)
    _check("A: token has aud claim", "aud" in claims_raw,
           f"aud={claims_raw.get('aud')}")
    _check("A: token has exp claim",
           isinstance(claims_raw.get("exp"), int))

    # ── B. KYA verifies the real token against the real JWKS ─────
    reset_jwks_cache()
    # Keycloak's token has aud="account" by default (the realm
    # management client). Set up KYA to expect that audience.
    expected_aud = claims_raw["aud"] if isinstance(
        claims_raw["aud"], str) else claims_raw["aud"][0]
    claims = verify_jwt(
        access_token,
        jwks_url=jwks_url,
        audience=expected_aud,
        issuer=issuer)
    _check("B: verify_jwt returns claims dict (FULL CRYPTO PATH)",
           claims is not None,
           f"got={None if claims is None else 'dict'}")
    _check("B: claims['sub'] matches",
           claims and claims["sub"] == claims_raw["sub"])
    _check("B: claims['iss'] matches",
           claims and claims["iss"] == issuer)

    # ── C. Tampered token rejected ───────────────────────────────
    head_b64, payload_b64, sig_b64 = access_token.split(".")
    tampered_sig = ("a" + sig_b64[1:]) if sig_b64[0] != "a" else ("b" + sig_b64[1:])
    tampered = f"{head_b64}.{payload_b64}.{tampered_sig}"
    _check("C: tampered signature -> None",
           verify_jwt(tampered, jwks_url=jwks_url,
                      audience=expected_aud, issuer=issuer) is None)

    # ── D. Wrong audience rejected ───────────────────────────────
    _check("D: wrong audience -> None",
           verify_jwt(access_token, jwks_url=jwks_url,
                      audience="bogus-audience",
                      issuer=issuer) is None)

    # ── E. Wrong issuer rejected ─────────────────────────────────
    _check("E: wrong issuer -> None",
           verify_jwt(access_token, jwks_url=jwks_url,
                      audience=expected_aud,
                      issuer="https://attacker.evil/realms/x") is None)

    # ── F. bind_principal_from_token uses real claims ────────────
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None})
    db = sessionmaker(bind=eng)()
    init_storage(db)

    from kya import record_principal_signal
    record_principal_signal(
        db, tenant_id=TENANT, principal_kind="user",
        principal_id=claims_raw["sub"],
        signal_kind="clean_invocation")

    bound_claims = bind_principal_from_token(
        db, tenant_id=TENANT, principal_kind="user",
        principal_id=claims_raw["sub"], bearer_token=access_token,
        jwks_url=jwks_url,
        audience=expected_aud,
        issuer=issuer)
    _check("F: bind_principal_from_token returns claims dict",
           bound_claims is not None,
           f"got={None if bound_claims is None else 'dict'}")

    found = lookup_principal_by_idp(
        db, tenant_id=TENANT, idp_subject=claims_raw["sub"])
    _check("F: lookup finds the binding",
           found is not None
           and found["principal_id"] == claims_raw["sub"]
           and found["idp_issuer"] == issuer)
    _check("F: idp_kind correctly inferred",
           found and found.get("idp_kind") == "keycloak",
           f"got={found.get('idp_kind') if found else 'None'}")

    # ── G. Expired token rejected ────────────────────────────────
    # Realm lifespan is 10s; KYA's default leeway is 30s -- a real
    # default-config caller would wait 40s+ here. To keep the test
    # fast (and to exercise the "tight leeway" production path), pass
    # leeway_seconds=0 explicitly and only wait 15s (past lifespan).
    print("  G: waiting 15s for the access_token to expire "
          "(realm lifespan=10s, using leeway_seconds=0)...")
    time.sleep(15)
    reset_jwks_cache()
    _check("G: expired token (leeway=0) -> None",
           verify_jwt(access_token, jwks_url=jwks_url,
                      audience=expected_aud, issuer=issuer,
                      leeway_seconds=0) is None)

    _hdr("Phase 4a.2 real-IdP integration: SUMMARY")
    print("  scenarios A-G  (10 assertions, REAL Keycloak)")
    print(f"  realm:       {issuer}")
    print(f"  jwks_url:    {jwks_url}")
    print(f"  client_id:   {CLIENT_ID}")
    print(f"  test user:   {TEST_USER}")
    print("  result: ALL ASSERTIONS PASS")
    print()
    print("  Proves the Phase 4a verify_jwt path works end-to-end")
    print("  against a real Keycloak realm's signing keys. The unit-")
    print("  test JWKS mocking is justified -- real-IdP path is")
    print("  independently exercised by THIS script.")


if __name__ == "__main__":
    main()
