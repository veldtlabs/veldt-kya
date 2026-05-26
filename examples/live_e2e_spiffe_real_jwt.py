"""Phase 4c -- LIVE real-JWT integration test for SPIFFE.

This is the answer to "your unit tests mock verify_jwt entirely --
how do we know the real crypto path works end-to-end?". This script:

  1. Generates a REAL RSA-2048 keypair (cryptography lib)
  2. Mints a JWT-SVID shaped exactly as SPIRE Server would emit it
     (proper sub, iss, aud, iat, exp, kid, signed with RS256)
  3. Serves the JWKS on a local HTTP server (background thread)
  4. Calls KYA's verify_jwt_svid -- which hits the FULL Phase 4a +
     Phase 4c path: JWKS fetch, signature verify, claims check,
     SPIFFE ID parse, iss/sub parity, trust-domain allowlist
  5. Asserts: VALID SVID -> dict returned with correct fields
  6. Asserts: tampered SVID -> None
  7. Asserts: wrong key in JWKS -> None
  8. Asserts: expired SVID -> None
  9. Asserts: iss/sub mismatch -> None
 10. Asserts: trust domain not in allowlist -> None
 11. Asserts: real bind+lookup roundtrip with the real SVID

No SPIRE binaries required. The output is byte-identical to what a
SPIRE Server would emit per the JWT-SVID spec (SPIFFE WG draft 1.0).

If THIS test passes, the unit-test mocking is justified -- the real
crypto path is proven to work, and the unit tests can mock verify_jwt
to focus on SPIFFE-specific decoration logic.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
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

import jwt as pyjwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kya import (
    bind_principal_from_svid,
    init_storage,
    lookup_principal_by_spiffe_id,
    record_principal_signal,
    verify_jwt_svid,
)
from kya.auth import reset_jwks_cache


TRUST_DOMAIN = "prod.example.org"
SPIFFE_ID = f"spiffe://{TRUST_DOMAIN}/ns/payments/sa/billing"
KEY_ID = "spire-jwt-svid-key-1"
AUDIENCE = "kya"
TENANT = "11111111-2222-3333-4444-444c44c44c44"


def _hdr(t):
    print(); print("=" * 78); print(f"  {t}"); print("=" * 78)


def _check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          f"{(' - ' + detail) if detail else ''}")
    if not ok:
        raise SystemExit(2)


# ── Real RSA keypair + JWKS ───────────────────────────────────────


def make_keypair():
    """Generate an RSA-2048 keypair. SPIRE typically uses RSA-2048
    or EC-P256 for JWT-SVID signing -- we pick RSA-2048 for clarity.
    cryptography backend handles the actual ASN.1 / DER encoding."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return priv, priv_pem


def public_key_to_jwk(priv_key, kid: str) -> dict:
    """Convert an RSA public key to JWK (JSON Web Key) format -- this
    is the on-the-wire format SPIRE Server serves at its JWKS
    endpoint. Mirrors RFC 7518 §6.3.1."""
    import base64

    pub = priv_key.public_key()
    nums = pub.public_numbers()

    def _b64u(i: int) -> str:
        b = i.to_bytes((i.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64u(nums.n),
        "e": _b64u(nums.e),
    }


def mint_jwt_svid(priv_key, *, sub: str, iss: str | None = None,
                  aud: str | None = AUDIENCE, kid: str = KEY_ID,
                  exp_delta_seconds: int = 300) -> str:
    """Mint a JWT-SVID exactly as SPIRE Server would.

    Per JWT-SVID spec:
      - alg=RS256 (or ES256)
      - kid in header matches the JWKS entry
      - sub = workload SPIFFE ID
      - iss = trust-domain SPIFFE ID (optional but required by SPIRE)
      - aud = intended recipient
      - exp, iat enforced
    """
    now = datetime.now(timezone.utc)
    claims: dict = {
        "sub": sub,
        "aud": aud,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=exp_delta_seconds))
                   .timestamp()),
    }
    if iss is not None:
        claims["iss"] = iss
    return pyjwt.encode(
        claims,
        priv_key,
        algorithm="RS256",
        headers={"kid": kid})


# ── JWKS HTTP server (background thread) ──────────────────────────


class _JWKSHandler(BaseHTTPRequestHandler):
    """Tiny HTTP server that serves a fixed JWKS at any path."""

    jwks_payload: dict = {}

    def do_GET(self):
        body = json.dumps(self.jwks_payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args, **kwargs):
        pass  # silence


def start_jwks_server(jwks: dict, port: int = 0) -> tuple[HTTPServer, str]:
    """Start the JWKS server on a random port. Returns (server, url)."""
    _JWKSHandler.jwks_payload = jwks
    server = HTTPServer(("127.0.0.1", port), _JWKSHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actual_port = server.server_address[1]
    return server, f"http://127.0.0.1:{actual_port}/jwks.json"


# ── Test scenarios ────────────────────────────────────────────────


def main():
    # Cross-backend exercise (sqlite only -- the real-JWT verification
    # is backend-agnostic; SQLite suffices to prove the path works
    # end-to-end. Other backends are covered by examples/live_e2e_spiffe.py
    # which uses mocked verify_jwt.)
    _hdr("Phase 4c real-JWT integration test")

    # Setup: real keypair + JWKS server
    priv_key, _ = make_keypair()
    jwks = {"keys": [public_key_to_jwk(priv_key, KEY_ID)]}
    server, jwks_url = start_jwks_server(jwks)
    try:
        os.environ["KYA_SPIFFE_JWKS_URL"] = jwks_url
        os.environ["KYA_SPIFFE_AUDIENCE"] = AUDIENCE
        os.environ["KYA_SPIFFE_TRUST_DOMAINS"] = TRUST_DOMAIN
        reset_jwks_cache()  # ensure no carry-over from prior tests

        # DB for bind/lookup
        eng = create_engine("sqlite:///:memory:").execution_options(
            schema_translate_map={"prov_schema": None})
        db = sessionmaker(bind=eng)()
        init_storage(db)

        # ── A. Valid JWT-SVID end-to-end ──────────────────────
        svid = mint_jwt_svid(
            priv_key, sub=SPIFFE_ID,
            iss=f"spiffe://{TRUST_DOMAIN}")
        result = verify_jwt_svid(svid)
        _check("A: valid SVID returns dict (real crypto)",
               result is not None,
               f"got={result}")
        _check("A: extracted spiffe_id matches",
               result and result["spiffe_id"] == SPIFFE_ID)
        _check("A: extracted trust_domain matches",
               result and result["trust_domain"] == TRUST_DOMAIN)
        _check("A: claims dict contains exp / aud",
               result and "exp" in result["claims"]
               and result["claims"]["aud"] == AUDIENCE)

        # ── B. Tampered SVID ──────────────────────────────────
        # Flip a single byte in the signature segment
        head, payload, sig = svid.split(".")
        tampered_sig = ("a" + sig[1:]) if sig[0] != "a" else ("b" + sig[1:])
        tampered = f"{head}.{payload}.{tampered_sig}"
        _check("B: tampered signature -> None",
               verify_jwt_svid(tampered) is None)

        # ── C. Different key in JWKS ──────────────────────────
        # Restart JWKS with a DIFFERENT keypair. JWKS cache should
        # be reset between scenarios.
        other_priv, _ = make_keypair()
        _JWKSHandler.jwks_payload = {
            "keys": [public_key_to_jwk(other_priv, KEY_ID)]}
        reset_jwks_cache()
        _check("C: SVID signed by wrong key -> None",
               verify_jwt_svid(svid) is None)
        # Restore original JWKS
        _JWKSHandler.jwks_payload = jwks
        reset_jwks_cache()

        # ── D. Expired SVID ───────────────────────────────────
        expired = mint_jwt_svid(
            priv_key, sub=SPIFFE_ID,
            iss=f"spiffe://{TRUST_DOMAIN}",
            exp_delta_seconds=-60)  # expired 60s ago
        _check("D: expired SVID -> None",
               verify_jwt_svid(expired) is None)

        # ── E. iss/sub trust-domain mismatch ──────────────────
        # This is the security fix #4 from code review. SUB is
        # for our allowed trust domain, IS for a different one.
        # KYA_SPIFFE_TRUST_DOMAINS allows prod.example.org only.
        os.environ["KYA_SPIFFE_TRUST_DOMAINS"] = (
            f"{TRUST_DOMAIN},attacker.evil")  # both allowed
        mismatch = mint_jwt_svid(
            priv_key, sub=SPIFFE_ID,
            iss="spiffe://attacker.evil")  # iss in different td
        # JWT itself is valid (signature good, exp good, aud good)
        # but iss trust domain != sub trust domain -- must reject.
        _check("E: iss/sub trust-domain mismatch -> None",
               verify_jwt_svid(mismatch) is None)
        os.environ["KYA_SPIFFE_TRUST_DOMAINS"] = TRUST_DOMAIN

        # ── F. Wrong audience ──────────────────────────────────
        wrong_aud = mint_jwt_svid(
            priv_key, sub=SPIFFE_ID,
            iss=f"spiffe://{TRUST_DOMAIN}",
            aud="someone-else")
        _check("F: wrong audience -> None",
               verify_jwt_svid(wrong_aud) is None)

        # ── G. Trust domain NOT in allowlist ──────────────────
        # Switch allowlist to exclude TRUST_DOMAIN
        os.environ["KYA_SPIFFE_TRUST_DOMAINS"] = "only-this.example"
        _check("G: trust domain not in allowlist -> None",
               verify_jwt_svid(svid) is None)
        os.environ["KYA_SPIFFE_TRUST_DOMAINS"] = TRUST_DOMAIN

        # ── H. Real bind + lookup roundtrip ──────────────────
        record_principal_signal(
            db, tenant_id=TENANT, principal_kind="service_account",
            principal_id="billing", signal_kind="clean_invocation")
        ok = bind_principal_from_svid(
            db, tenant_id=TENANT,
            principal_kind="service_account",
            principal_id="billing",
            svid=svid)
        _check("H: bind_principal_from_svid succeeds with real SVID",
               ok)
        found = lookup_principal_by_spiffe_id(
            db, tenant_id=TENANT, spiffe_id=SPIFFE_ID)
        _check("H: lookup finds the binding",
               found is not None
               and found["principal_id"] == "billing"
               and found["idp_kind"] == "spiffe")

        # ── I. No iss claim is fine (spec optional) ───────────
        no_iss = mint_jwt_svid(
            priv_key, sub=SPIFFE_ID, iss=None)  # no iss
        _check("I: SVID without iss claim verifies",
               verify_jwt_svid(no_iss) is not None)

        # ── J. Malformed SPIFFE ID in sub ──────────────────────
        bad_sub = mint_jwt_svid(
            priv_key, sub="not-a-spiffe-id",
            iss=f"spiffe://{TRUST_DOMAIN}")
        _check("J: non-SPIFFE sub claim -> None",
               verify_jwt_svid(bad_sub) is None)

        # ── K. SPIFFE ID with invalid path chars ──────────────
        bad_path = mint_jwt_svid(
            priv_key,
            sub=f"spiffe://{TRUST_DOMAIN}/foo bar/sa/x",  # space
            iss=f"spiffe://{TRUST_DOMAIN}")
        _check("K: SPIFFE ID with bad path char -> None",
               verify_jwt_svid(bad_path) is None)

        _hdr("Phase 4c real-JWT integration: SUMMARY")
        print("  scenarios: A-K  (11 cases, real crypto, no mocks)")
        print("  result: ALL ASSERTIONS PASS")
        print(f"  jwks_url used: {jwks_url}")
        print(f"  trust_domain: {TRUST_DOMAIN}")
        print(f"  spiffe_id:    {SPIFFE_ID}")
        print()
        print("  This proves the FULL Phase 4a + Phase 4c crypto path")
        print("  works end-to-end. The unit-test mocking of verify_jwt")
        print("  is justified -- SPIFFE-specific logic in unit tests,")
        print("  full crypto path proven by THIS script.")

    finally:
        server.shutdown()
        server.server_close()
        # Restore env
        for k in ("KYA_SPIFFE_JWKS_URL", "KYA_SPIFFE_AUDIENCE",
                  "KYA_SPIFFE_TRUST_DOMAINS"):
            os.environ.pop(k, None)
        reset_jwks_cache()


if __name__ == "__main__":
    main()
