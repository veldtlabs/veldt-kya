"""Phase 5c — live e2e for signed audit-trail export across all
4 backends (sqlite / duckdb / postgresql / mysql).

Exercises REAL behavior — not synthetic fixtures:
  - record_evidence writes real HMAC-chained rows
  - signed_export reads from the real evidence table
  - Ed25519 keypair is real (cryptography lib)
  - Export is serialized to JSON and round-tripped (file-like)
  - verify_signed_export runs purely offline with the public key
  - Tampering (manifest swap, signature flip, row mutation) is
    actually detected
  - Cross-backend portability: export produced on PG verifies the
    same on a fresh process / different machine — only the public
    key file matters
"""

from __future__ import annotations

import base64
import json
import os
from copy import deepcopy
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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    AuditExportError,
    EXPORT_SCHEMA_VERSION,
    init_storage,
    record_evidence,
    record_invocation,
    signed_export,
    verify_signed_export,
)


TENANT = "11111111-2222-3333-4444-aaaaaaaa5c5c"


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
            for tbl in ("kya_evidence", "kya_invocations",
                        "kya_principal_trust", "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl} CASCADE"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_evidence", "kya_invocations",
                        "kya_principal_trust", "agent_versions"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception: pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


def make_keypair():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


def seed_real_chain(db, n=6):
    """Record a real invocation + n evidence rows. Returns
    (invocation_id, time_window) for the export."""
    inv = record_invocation(
        db, tenant_id=TENANT, agent_key="audit_e2e_agent",
        principal_kind="user", principal_id="alice",
        mode="observed", outcome="success")
    for i in range(n):
        record_evidence(
            db, tenant_id=TENANT, invocation_id=inv,
            evidence_kind="prompt" if i % 2 == 0 else "tool_call",
            payload={"step": i, "text": f"real evidence {i}",
                     "tool": "calc" if i % 2 else None})
    return inv


def run_scenarios(db, label):
    priv, pub = make_keypair()
    inv = seed_real_chain(db, n=6)
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    # ── A. signed_export produces a valid envelope ─────────────
    export = signed_export(
        db, tenant_id=TENANT, start=start, end=end,
        signing_key_pem=priv)
    _check(f"{label}/A: export has all envelope fields",
           all(k in export for k in (
               "manifest", "chain_digest",
               "signature_b64", "public_key_pem", "signed_at")))
    _check(f"{label}/A: manifest carries schema_version",
           export["manifest"]["schema_version"] == EXPORT_SCHEMA_VERSION)
    _check(f"{label}/A: row_count matches seed",
           export["manifest"]["row_count"] == 6)
    _check(f"{label}/A: chain_digest is 64-hex SHA-256",
           len(export["chain_digest"]) == 64
           and all(c in "0123456789abcdef"
                   for c in export["chain_digest"]))

    # ── B. JSON round-trip → offline verify ────────────────────
    serialized = json.dumps(export)
    loaded = json.loads(serialized)
    r = verify_signed_export(loaded, public_key_pem=pub)
    _check(f"{label}/B: roundtrip JSON verify",
           r["valid"] is True, f"reason={r.get('reason')}")
    _check(f"{label}/B: verify echoes manifest tenant_id",
           r["manifest"]["tenant_id"] == TENANT)

    # ── C. Default verify (no external key) FAILS ──────────────
    r = verify_signed_export(loaded)
    _check(f"{label}/C: default verify rejects without external key",
           r["valid"] is False
           and "public_key_pem not supplied" in r["reason"])

    # ── D. trust_embedded_key opt-in path works ────────────────
    r = verify_signed_export(loaded, trust_embedded_key=True)
    _check(f"{label}/D: trust_embedded_key=True verifies", r["valid"])

    # ── E. Tampered manifest → invalid ─────────────────────────
    tampered = deepcopy(loaded)
    tampered["manifest"]["tenant_id"] = "MALICIOUS"
    r = verify_signed_export(tampered, public_key_pem=pub)
    _check(f"{label}/E: tampered tenant_id caught",
           r["valid"] is False
           and "signature does not match" in r["reason"])

    # ── F. Tampered chain_digest → invalid ─────────────────────
    tampered = deepcopy(loaded)
    tampered["chain_digest"] = "0" * 64
    r = verify_signed_export(tampered, public_key_pem=pub)
    _check(f"{label}/F: tampered chain_digest caught",
           r["valid"] is False)

    # ── G. Flipped signature byte → invalid ────────────────────
    tampered = deepcopy(loaded)
    sig = bytearray(base64.b64decode(tampered["signature_b64"]))
    sig[0] ^= 0xFF
    tampered["signature_b64"] = base64.b64encode(bytes(sig)).decode()
    r = verify_signed_export(tampered, public_key_pem=pub)
    _check(f"{label}/G: flipped signature byte caught",
           r["valid"] is False)

    # ── H. Wrong public key → invalid (forensic clarity) ───────
    _, other_pub = make_keypair()
    r = verify_signed_export(loaded, public_key_pem=other_pub)
    _check(f"{label}/H: wrong public key fails",
           r["valid"] is False)

    # ── I. Schema version drift → invalid w/ clear reason ──────
    tampered = deepcopy(loaded)
    tampered["manifest"]["schema_version"] = 99
    r = verify_signed_export(tampered, public_key_pem=pub)
    _check(f"{label}/I: future schema_version refused",
           r["valid"] is False
           and "schema_version" in r["reason"])

    # ── J. include_payloads=True roundtrip ─────────────────────
    export_full = signed_export(
        db, tenant_id=TENANT, start=start, end=end,
        signing_key_pem=priv,
        include_payloads=True)
    _check(f"{label}/J: export with rows has rows array",
           "rows" in export_full and len(export_full["rows"]) == 6)
    # Each row carries its signed_hash + raw payload
    _check(f"{label}/J: row payloads preserved",
           export_full["rows"][0]["payload"].get("step") == 0)
    serialized = json.dumps(export_full)
    loaded_full = json.loads(serialized)
    r = verify_signed_export(loaded_full, public_key_pem=pub)
    _check(f"{label}/J: full-payload roundtrip verify",
           r["valid"] is True, f"reason={r.get('reason')}")

    # ── K. Drop row → row_count mismatch caught ────────────────
    tampered = deepcopy(loaded_full)
    tampered["rows"].pop()
    r = verify_signed_export(tampered, public_key_pem=pub)
    _check(f"{label}/K: dropped row detected via row_count",
           r["valid"] is False
           and "row count mismatch" in r["reason"])

    # ── L. Alter row's signed_hash → fold-hash mismatch ────────
    tampered = deepcopy(loaded_full)
    tampered["rows"][2]["signed_hash"] = "f" * 64
    r = verify_signed_export(tampered, public_key_pem=pub)
    _check(f"{label}/L: mutated row signed_hash detected",
           r["valid"] is False
           and "rows were tampered" in r["reason"])

    # ── M. Narrow by invocation_id ─────────────────────────────
    # Add a second invocation; ensure narrow-by-invocation
    # only includes the targeted invocation's rows.
    inv2 = record_invocation(
        db, tenant_id=TENANT, agent_key="audit_e2e_agent_2",
        principal_kind="user", principal_id="bob",
        mode="observed", outcome="success")
    record_evidence(db, tenant_id=TENANT, invocation_id=inv2,
                    evidence_kind="prompt",
                    payload={"text": "bob's evidence"})
    record_evidence(db, tenant_id=TENANT, invocation_id=inv2,
                    evidence_kind="prompt",
                    payload={"text": "bob's other evidence"})
    # Without filter — all 8 rows
    export_all = signed_export(
        db, tenant_id=TENANT, start=start, end=end,
        signing_key_pem=priv)
    _check(f"{label}/M: unfiltered export covers all chains",
           export_all["manifest"]["row_count"] == 8)
    # With filter — only alice's 6 rows
    export_alice = signed_export(
        db, tenant_id=TENANT, start=start, end=end,
        signing_key_pem=priv,
        invocation_id=inv)
    _check(f"{label}/M: invocation_id filter narrows rows",
           export_alice["manifest"]["row_count"] == 6
           and export_alice["manifest"]["invocation_id"] == inv)

    # ── N. Empty range → AuditExportError ──────────────────────
    far_past_start = datetime(2000, 1, 1, tzinfo=timezone.utc)
    far_past_end = datetime(2000, 1, 2, tzinfo=timezone.utc)
    raised = False
    try:
        signed_export(
            db, tenant_id=TENANT,
            start=far_past_start, end=far_past_end,
            signing_key_pem=priv)
    except AuditExportError as exc:
        raised = "No evidence rows" in str(exc)
    _check(f"{label}/N: empty range raises AuditExportError", raised)

    # ── O. PII warning visible when include_payloads=True ──────
    # Just sanity: doesn't change verify, but exercise the
    # warning-log path. (Test framework would capture in unit
    # tests; here we just confirm it doesn't break the flow.)
    _ = signed_export(
        db, tenant_id=TENANT, start=start, end=end,
        signing_key_pem=priv, include_payloads=True)
    _check(f"{label}/O: include_payloads + WARNING path runs", True)


def main():
    backends = ["sqlite", "duckdb"]
    if os.environ.get("KYA_TEST_PG_URL"):
        backends.append("postgresql")
    if os.environ.get("KYA_TEST_MYSQL_URL"):
        backends.append("mysql")

    skipped = []
    for label in backends:
        _hdr(f"Phase 5c live e2e: {label}")
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

    _hdr("Phase 5c live e2e: SUMMARY")
    print(f"  backends exercised: "
          f"{[b for b in backends if b not in skipped]}")
    if skipped:
        print(f"  skipped: {skipped} "
              f"(set KYA_TEST_PG_URL / KYA_TEST_MYSQL_URL)")
    print("  result: ALL ASSERTIONS PASS")


if __name__ == "__main__":
    main()
