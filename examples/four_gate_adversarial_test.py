"""Four-gate adversarial test against kya/inbound.py.

For each of the four apply-pipeline gates, send an input crafted to
trigger that gate and confirm the gate rejects it. Reports
{gate, outcome, p50, p95, p99} as a latency distribution.

Methodology: N=100 trials per gate, first 10 discarded as warmup
(SQLAlchemy statement cache + JIT cold start), remaining 90 used
for percentile statistics.

Gates:
  G1  Ed25519 signature verification          → SignatureVerificationError
  G2  Persist-time expires_at check           → ("expired_at_fetch")
  G3  Only-tighten composition algebra        → OverrideLoosensError
  G4  Operator-approval-as-default            → row stays 'pending', no apply

Run:  python examples/four_gate_adversarial_test.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone


def _setup_ed25519():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    pub_bytes = pub.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    return priv, base64.b64encode(pub_bytes).decode("ascii")


def _sign_envelope(priv, envelope: dict) -> dict:
    from kya._inbound_signing import canonical_bytes
    msg = canonical_bytes(envelope)
    sig = priv.sign(msg)
    out = dict(envelope)
    out["signature"] = "ed25519:" + base64.b64encode(sig).decode("ascii")
    return out


def _build_envelope(*, key_id: str, expires_in_s: int, recs: list[dict]) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "v": 1,
        "kind": "weight_recommendations",
        "signing_key_id": key_id,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=expires_in_s)).isoformat(),
        "recommendations": recs,
    }


def _setup_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    # schema_translate_map at the engine level: rewrites prov_schema.* to
    # default namespace for SQLite (mirrors `create_legacy_tables` behavior
    # but applied to every session-level query, not just DDL).
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None}
    )
    Session = sessionmaker(bind=eng)
    return Session()


def _register_test_scope():
    """Register a 'class_weights' scope with one key, 'pii' at value 15."""
    from kya import tenant_weights
    DEFAULTS = {"pii": 15}
    tenant_weights.register_scope("class_weights", DEFAULTS)
    return DEFAULTS


def _gate1_once(priv, key_id) -> tuple[bool, float]:
    """G1: tamper the signature; expect SignatureVerificationError."""
    from kya._inbound_signing import (
        SignatureVerificationError, verify_envelope,
    )
    env = _build_envelope(
        key_id=key_id, expires_in_s=3600,
        recs=[{"id": "g1-rec", "scope": "class_weights",
               "key": "pii", "recommended_value": 20}],
    )
    env = _sign_envelope(priv, env)
    env["signature"] = env["signature"][:-2] + "AA"  # tamper
    t0 = time.perf_counter_ns()
    try:
        verify_envelope(env)
        rejected = False
    except SignatureVerificationError:
        rejected = True
    t1 = time.perf_counter_ns()
    return rejected, (t1 - t0) / 1000.0


def _gate2_once(db, priv, key_id, iteration: int) -> tuple[bool, float]:
    """G2: expires_at in the past; expect ('expired_at_fetch')."""
    from kya import inbound
    env = _build_envelope(
        key_id=key_id, expires_in_s=-3600,
        recs=[{"id": f"g2-rec-{iteration}", "scope": "class_weights",
               "key": "pii", "recommended_value": 20}],
    )
    env = _sign_envelope(priv, env)
    t0 = time.perf_counter_ns()
    ok, reason = inbound._persist_one(db, env, env["recommendations"][0])
    t1 = time.perf_counter_ns()
    return ((not ok) and reason == "expired_at_fetch", (t1 - t0) / 1000.0)


def _gate3_once(db, tenant_iteration: int) -> tuple[bool, float]:
    """G3: tenant override below platform default; expect OverrideLoosensError.

    Uses a fresh tenant UUID per iteration so each attempt is the same
    code path (first-time write that triggers _check_only_tighten),
    not a subsequent upsert.
    """
    from kya import tenant_weights
    tid = f"{tenant_iteration:08d}-1111-1111-1111-111111111111"
    t0 = time.perf_counter_ns()
    try:
        tenant_weights.set_override(
            db, scope="class_weights", key="pii", value=10,
            tenant_id=tid, changed_by="adversary", reason="loosen-attempt",
        )
        rejected = False
    except tenant_weights.OverrideLoosensError:
        rejected = True
    t1 = time.perf_counter_ns()
    return rejected, (t1 - t0) / 1000.0


def _gate4_once(db, priv, key_id, iteration: int) -> tuple[bool, float]:
    """G4: valid envelope, allowlist=None; row stays 'pending', no apply."""
    from kya import inbound
    from sqlalchemy import select
    from kya._legacy_tables import kya_inbound_recommendations as _T
    ext_id = f"g4-rec-{iteration}"
    env = _build_envelope(
        key_id=key_id, expires_in_s=3600,
        recs=[{"id": ext_id, "scope": "class_weights",
               "key": "pii", "recommended_value": 25}],
    )
    env = _sign_envelope(priv, env)
    t0 = time.perf_counter_ns()
    ok, reason = inbound._persist_one(db, env, env["recommendations"][0])
    auto_applied = inbound._auto_apply_if_allowed(
        db, rec_external_id=ext_id,
        scope="class_weights", key="pii", recommended_value=25,
        allowlist=None,
    )
    t1 = time.perf_counter_ns()
    row = db.execute(select(_T.c.status).where(_T.c.external_id == ext_id)).scalar()
    rejected_apply = (ok and row == "pending" and auto_applied is False)
    return rejected_apply, (t1 - t0) / 1000.0


def _percentiles(values: list[float]) -> tuple[float, float, float]:
    s = sorted(values)
    n = len(s)
    def pct(p: float) -> float:
        if n == 0:
            return 0.0
        idx = min(n - 1, max(0, int(round(p * (n - 1)))))
        return s[idx]
    return pct(0.50), pct(0.95), pct(0.99)


def main():
    print("Four-Gate Adversarial Test — kya/inbound.py")
    print("Methodology: N=100 trials, first 10 discarded as warmup")
    print("=" * 76)
    priv, pub_b64 = _setup_ed25519()
    key_id = "test-key-2026-q2"
    os.environ["KYA_INBOUND_PUBLIC_KEY"] = f"{key_id}:{pub_b64}"

    _register_test_scope()
    db = _setup_db()

    # Seed platform default for Gate 3
    from kya import tenant_weights, inbound
    tenant_weights.ensure_tables(db)
    inbound.ensure_inbound_table(db)
    tenant_weights.set_override(
        db, scope="class_weights", key="pii", value=15,
        tenant_id=None, changed_by="platform", reason="platform-default",
    )

    N = 100
    WARMUP = 10

    gates = [
        ("Gate 1 forged-sig",            lambda i: _gate1_once(priv, key_id)),
        ("Gate 2 expired",               lambda i: _gate2_once(db, priv, key_id, i)),
        ("Gate 3 loosens",               lambda i: _gate3_once(db, i)),
        ("Gate 4 default (no allowlist)",lambda i: _gate4_once(db, priv, key_id, i)),
    ]

    print()
    print(f"{'Gate':<32} {'Rejected':<10} {'p50 (µs)':<10} {'p95 (µs)':<10} {'p99 (µs)':<10}")
    print("-" * 76)

    all_passed = True
    for name, fn in gates:
        rejections = 0
        latencies = []
        for i in range(N):
            rejected, lat_us = fn(i)
            if rejected:
                rejections += 1
            latencies.append(lat_us)
        # Discard warmup
        measured = latencies[WARMUP:]
        p50, p95, p99 = _percentiles(measured)
        if rejections != N:
            all_passed = False
        print(f"{name:<32} {f'{rejections}/{N}':<10} "
              f"{p50:>8.1f}  {p95:>8.1f}  {p99:>8.1f}")
    print("-" * 76)
    print("ALL FOUR GATES FIRED CORRECTLY ON EVERY TRIAL" if all_passed else "FAILURE")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
