"""Phase 3c live e2e -- declarative attack-chain rules end-to-end.

Cross-backend (sqlite/duckdb/postgresql/mysql). Loads the YAML rules
from kya/attack_chains/rules/, feeds REAL evidence sequences through
the engine, and asserts that:

  A. Single-step rules fire on the first matching event
  B. Multi-step rules require ALL steps in order
  C. Out-of-order events don't advance
  D. Time-window violations drop the partial match
  E. The full match emits the correct KYA signal (trust decay)
  F. Cross-principal isolation: principal A's recon doesn't fire
     a chain that needs principal B's exfil
  G. State expiry: stale partial matches don't linger forever
  H. Bundled starter rules load without error

Real evidence rows written. Real signals recorded. Real DB state
asserted. No mocks.
"""

from __future__ import annotations

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

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    init_storage, record_invocation, record_evidence,
    get_principal_trust,
)
from kya.attack_chains import (
    AttackChainEngine,
    InMemoryStateStore,
    load_rule,
    load_rules_from_dir,
)


TENANT = "11111111-2222-3333-4444-acdcacdcacdc"
RULES_DIR = (Path(__file__).resolve().parent.parent
             / "kya" / "attack_chains" / "rules")


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
            for tbl in ("kya_invocations", "kya_evidence",
                        "kya_principal_trust", "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl} CASCADE"))
    elif label == "mysql":
        url = os.environ.get("KYA_TEST_MYSQL_URL")
        if not url: return None, None
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for tbl in ("kya_invocations", "kya_evidence",
                        "kya_principal_trust", "agent_versions"):
                try: conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception: pass
    else:
        return None, None
    return sessionmaker(bind=eng)(), eng.dispose


# ── Per-scenario evidence sequences (the meat of the test) ─────────


def _ts_offset(base_ts: float, seconds: float) -> float:
    return base_ts + seconds


def run_scenarios(db, label):
    """Returns dict of {scenario_id: pass/fail}. Each scenario
    constructs its own engine + state so failures don't bleed."""

    # ── A. SINGLE-STEP rule fires immediately ─────────────────
    single_step_rule = load_rule({
        "version": 1,
        "id": "single_step",
        "description": "Fires on any file_read of /etc/*",
        "severity": "medium",
        "emits_signal": "rogue_pattern_high_severity",
        "correlate_by": ["tenant_id", "principal_id"],
        "steps": [{
            "id": "read",
            "evidence_kind": "tool_call",
            "match": {"payload.tool": "file_read",
                      "payload.path": "glob:/etc/*"},
        }],
    })
    engine_a = AttackChainEngine(
        rules=[single_step_rule], state_store=InMemoryStateStore())
    matched = engine_a.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-a",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/etc/passwd"})
    _check(f"{label}/A: single-step rule fires on match",
           matched == ["single_step"])
    matched_neg = engine_a.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-a",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/var/log/syslog"})
    _check(f"{label}/A: non-matching event does NOT fire",
           matched_neg == [])

    # ── B. MULTI-STEP rule requires ALL steps in order ────────
    multi_rule = load_rule({
        "version": 1,
        "id": "exfil_chain",
        "description": "recon + exfil within 60s",
        "severity": "high",
        "emits_signal": "rogue_filesystem_exfiltration",
        "correlate_by": ["tenant_id", "principal_id"],
        "steps": [
            {"id": "recon", "evidence_kind": "tool_call",
             "match": {"payload.tool": "file_read",
                       "payload.path": "glob:/etc/*"}},
            {"id": "exfil", "evidence_kind": "tool_call",
             "match": {"payload.tool": "http",
                       "payload.method": "POST"},
             "after": "recon", "within_seconds": 60},
        ],
    })
    engine_b = AttackChainEngine(
        rules=[multi_rule], state_store=InMemoryStateStore())
    # Step 1 alone -- no fire yet
    m1 = engine_b.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-b",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/etc/shadow"})
    _check(f"{label}/B: step 1 alone does NOT fire", m1 == [])
    # Step 2 -- chain completes
    m2 = engine_b.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-b",
        evidence_kind="tool_call",
        payload={"tool": "http", "method": "POST"})
    _check(f"{label}/B: step 2 completes chain",
           m2 == ["exfil_chain"], f"got={m2}")

    # ── C. Out-of-order events don't advance ─────────────────
    engine_c = AttackChainEngine(
        rules=[multi_rule], state_store=InMemoryStateStore())
    # Send exfil-shape event FIRST. Step 0 expects recon, not exfil.
    m = engine_c.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-c",
        evidence_kind="tool_call",
        payload={"tool": "http", "method": "POST"})
    _check(f"{label}/C: exfil-without-recon doesn't fire",
           m == [])
    # Now send recon -- this starts step 0 (since it matches the
    # first step's spec); no chain completion yet.
    m = engine_c.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-c",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/etc/passwd"})
    _check(f"{label}/C: recon-after-exfil starts partial match",
           m == [])

    # ── D. Time-window violation aborts partial match ─────────
    # Rule with a very tight 1s window for step 2.
    tight_rule = load_rule({
        "version": 1,
        "id": "tight_window",
        "description": "1s window between steps",
        "severity": "high",
        "emits_signal": "rogue_pattern_high_severity",
        "correlate_by": ["tenant_id", "principal_id"],
        "steps": [
            {"id": "s1", "evidence_kind": "tool_call",
             "match": {"payload.k": "1"}},
            {"id": "s2", "evidence_kind": "tool_call",
             "match": {"payload.k": "2"},
             "after": "s1", "within_seconds": 1},
        ],
    })
    engine_d = AttackChainEngine(
        rules=[tight_rule], state_store=InMemoryStateStore())
    base_ts = time.monotonic()
    engine_d.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-d",
        evidence_kind="tool_call",
        payload={"k": "1"}, occurred_at_ts=base_ts)
    # 5 seconds later -> past the 1s window
    m = engine_d.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-d",
        evidence_kind="tool_call",
        payload={"k": "2"},
        occurred_at_ts=_ts_offset(base_ts, 5))
    _check(f"{label}/D: time-window violation aborts chain",
           m == [])

    # ── E. Full match -> KYA signal emitted (trust decay) ────
    engine_e = AttackChainEngine(
        rules=[multi_rule], state_store=InMemoryStateStore())
    # Seed agent so trust row exists
    from kya import record_principal_signal
    record_principal_signal(
        db, tenant_id=TENANT, principal_kind="user",
        principal_id="agent-e", signal_kind="clean_invocation")
    pre = get_principal_trust(db, TENANT, "user", "agent-e")
    # Fire the chain
    engine_e.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-e",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/etc/passwd"})
    matched = engine_e.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-e",
        evidence_kind="tool_call",
        payload={"tool": "http", "method": "POST"})
    _check(f"{label}/E: chain matched", matched == ["exfil_chain"])
    post = get_principal_trust(db, TENANT, "user", "agent-e")
    _check(f"{label}/E: trust decayed after chain match",
           post.trust_score < pre.trust_score,
           f"pre={pre.trust_score} post={post.trust_score}")

    # ── F. Cross-principal isolation ──────────────────────────
    engine_f = AttackChainEngine(
        rules=[multi_rule], state_store=InMemoryStateStore())
    # Principal X does recon; principal Y does exfil. Should NOT fire.
    engine_f.process_evidence(
        db, tenant_id=TENANT, principal_id="principal-x",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/etc/x"})
    m = engine_f.process_evidence(
        db, tenant_id=TENANT, principal_id="principal-y",
        evidence_kind="tool_call",
        payload={"tool": "http", "method": "POST"})
    _check(f"{label}/F: cross-principal recon+exfil does NOT fire",
           m == [])

    # ── G. State expiry drops stale partial matches ──────────
    state = InMemoryStateStore()
    engine_g = AttackChainEngine(rules=[multi_rule], state_store=state)
    engine_g.process_evidence(
        db, tenant_id=TENANT, principal_id="agent-g",
        evidence_kind="tool_call",
        payload={"tool": "file_read", "path": "/etc/x"})
    _check(f"{label}/G: partial match exists before expiry",
           state.get("exfil_chain",
                     (TENANT, "agent-g")) is not None)
    # Strict < semantics: an entry with updated_at == cutoff is age=0,
    # not OLDER than 0, so expire_older_than(0) preserves it.
    # Sleep a few ms so updated_at < cutoff in the next call.
    time.sleep(0.05)
    n = state.expire_older_than(0.01)
    _check(f"{label}/G: expire_older_than() drops stale partial",
           n >= 1)
    _check(f"{label}/G: partial match gone after expiry",
           state.get("exfil_chain",
                     (TENANT, "agent-g")) is None)

    # ── H. Bundled starter rules load without error ──────────
    bundled = load_rules_from_dir(RULES_DIR)
    _check(f"{label}/H: starter rules dir loads",
           len(bundled) >= 1,
           f"loaded {len(bundled)} rules: "
           f"{[r.id for r in bundled]}")
    # Engine wires up against the bundle
    engine_h = AttackChainEngine(rules=bundled)
    _check(f"{label}/H: engine accepts bundled rules",
           len(engine_h.rules) == len(bundled))


def main():
    backends = ["sqlite", "duckdb"]
    if os.environ.get("KYA_TEST_PG_URL"):
        backends.append("postgresql")
    if os.environ.get("KYA_TEST_MYSQL_URL"):
        backends.append("mysql")

    skipped: list[str] = []
    for label in backends:
        _hdr(f"Phase 3c live e2e: {label}")
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

    _hdr("Phase 3c live e2e: SUMMARY")
    print(f"  exercised: {[b for b in backends if b not in skipped]}")
    if skipped:
        print(f"  skipped: {skipped} "
              "(set KYA_TEST_PG_URL / KYA_TEST_MYSQL_URL)")
    print("  result: ALL ASSERTIONS PASS")


if __name__ == "__main__":
    main()
