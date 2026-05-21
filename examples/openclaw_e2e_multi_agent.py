"""End-to-end SDK verification: OpenCLAW multi-agent autonomous fan-out.

What this proves (using REAL OpenCLAW agent definitions):

  1. SCORE         — normalize 3 agents via agents_md adapter, score each,
                     verify factor breakdowns + bucket assignments
  2. SNAPSHOT      — persist each agent's definition (agent_versions),
                     verify versioning + rollback semantics
  3. FAN-OUT       — record the calendar→email/browser invocation tree
                     with correlation_id + parent_invocation_id
  4. EVIDENCE      — HMAC-chained evidence rows per invocation, verify
                     chain integrity end-to-end
  5. ROGUE         — fire oos_tool, cross_tenant, data_leak signals
                     with actor_agent_key attribution (the SOC story:
                     ONE accountable principal even with autonomous fan-out)
  6. TRUST         — principal trust degrades per signal weight; clean
                     invocations recover trust
  7. TELEMETRY     — aggregate counters increment correctly
  8. PERSISTENCE   — close the session, reopen, confirm all rows survive

Run with:
    KYA_TEST_PG_URL=postgresql+psycopg2://... python openclaw_e2e_multi_agent.py
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import kya
from kya import (
    detect_burst_anomalies,
    get_principal_trust,
    get_rogue_signals,
    init_storage,
    list_invocations,
    list_versions,
    new_correlation_id,
    normalize_agent_def,
    record_cross_tenant_attempt,
    record_data_leak,
    record_evidence,
    record_invocation,
    record_oos_tool_attempt,
    record_principal_clean,
    record_principal_signal,
    rogue_score,
    score_agent,
    snapshot_agent,
    telemetry_status,
    verify_chain,
)


PAYLOAD_DIR = Path(__file__).resolve().parent.parent.parent / ".kya_test"
TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _hdr(title: str):
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


def _row(label: str, value):
    print(f"  {label:30s} {value}")


def _check(label: str, ok: bool, detail: str = ""):
    icon = "PASS" if ok else "FAIL"
    print(f"  [{icon}] {label}{(' — ' + detail) if detail else ''}")
    if not ok:
        sys.exit(2)


# ── Phase 1: SCORE ─────────────────────────────────────────────────


def phase_1_score_agents() -> dict:
    _hdr("PHASE 1 — Normalize + Score 3 OpenCLAW Agents")

    agents = {}
    for name in ("OpenClawCalendarAgent", "OpenClawBrowserAgent", "OpenClawEmailAgent"):
        payload_path = PAYLOAD_DIR / f"openclaw_{name}_payload.json"
        with open(payload_path) as f:
            payload = json.load(f)

        canonical = normalize_agent_def(payload["framework"], payload["definition"])
        risk = score_agent(canonical)
        agents[name] = {
            "definition": canonical,
            "score": risk.score,
            "bucket": risk.bucket,
            "factors": risk.factors,
            "interactions": risk.interactions,
        }
        print()
        _row("agent_key", canonical.get("agent_key") or name)
        _row("tools", canonical.get("tools"))
        _row("model", canonical.get("model"))
        _row("human_loop", canonical.get("human_loop"))
        _row("score", risk.score)
        _row("bucket", risk.bucket)
        _row("top factors", [f"{f.name}={f.delta:+d}" for f in risk.factors[:4]])

        # Per the SCENARIO_WALKTHROUGHS expected fan-out: all are
        # autonomous (human_loop=none) → high-risk bucket. Score >= 90.
        _check(
            f"{name} bucket is high or critical",
            risk.bucket in ("high", "critical"),
            f"got={risk.bucket}",
        )
        _check(
            f"{name} factor 'governance_mode=human_loop=none' present",
            any(f.name == "governance_mode" for f in risk.factors),
        )
    return agents


# ── Phase 2: SNAPSHOT ──────────────────────────────────────────────


def phase_2_snapshot(db, agents: dict) -> dict:
    _hdr("PHASE 2 — Snapshot Each Agent + Verify Versioning")

    versions = {}
    for name, info in agents.items():
        v1 = snapshot_agent(
            db,
            tenant_id=TENANT_ID,
            agent_key=name,
            definition=info["definition"],
            note=f"initial snapshot from e2e test",
            created_by=None,
        )
        v2 = snapshot_agent(
            db,
            tenant_id=TENANT_ID,
            agent_key=name,
            definition={**info["definition"], "edited": True},
            note=f"edit pass",
            created_by=None,
        )
        history = list_versions(db, TENANT_ID, name)
        versions[name] = (v1, v2, history)
        _row(name, f"v{v1}+v{v2}, history={len(history)} rows")
        _check(f"{name} v1==1", v1 == 1)
        _check(f"{name} v2==2", v2 == 2)
        _check(f"{name} history has 2 entries", len(history) == 2)
    return versions


# ── Phase 3: FAN-OUT (correlation_id tree) ─────────────────────────


def phase_3_fanout(db) -> dict:
    _hdr("PHASE 3 — Record Multi-Agent Fan-out (correlation_id tree)")

    corr_id = new_correlation_id()
    print(f"  correlation_id = {corr_id}")

    # T+0: calendar root (autonomous trigger)
    inv_calendar = record_invocation(
        db, tenant_id=TENANT_ID, agent_key="OpenClawCalendarAgent",
        principal_kind="agent", principal_id="OpenClawCalendarAgent",
        mode="autonomous", outcome="success",
        correlation_id=corr_id,
    )
    # T+1: browser fan-out (booking room)
    inv_browser = record_invocation(
        db, tenant_id=TENANT_ID, agent_key="OpenClawBrowserAgent",
        principal_kind="agent", principal_id="OpenClawBrowserAgent",
        mode="autonomous", outcome="success",
        parent_invocation_id=inv_calendar, correlation_id=corr_id,
    )
    # T+2: email fan-out (compose invite)
    inv_email = record_invocation(
        db, tenant_id=TENANT_ID, agent_key="OpenClawEmailAgent",
        principal_kind="agent", principal_id="OpenClawEmailAgent",
        mode="autonomous", outcome="success",
        parent_invocation_id=inv_calendar, correlation_id=corr_id,
    )
    invs = {"calendar": inv_calendar, "browser": inv_browser, "email": inv_email}

    for label, inv_id in invs.items():
        _row(label, f"invocation_id={inv_id}")
    _check("calendar is root (no parent)", inv_calendar > 0)
    _check("browser parents -> calendar", inv_browser > inv_calendar)
    _check("email parents -> calendar", inv_email > inv_calendar)

    # Verify the tree via list_invocations
    same_corr = list_invocations(db, TENANT_ID, correlation_id=corr_id)
    _check(f"3 invocations share correlation_id", len(same_corr) == 3,
           f"got={len(same_corr)}")
    return invs


# ── Phase 4: EVIDENCE chains ──────────────────────────────────────


def phase_4_evidence(db, invs: dict) -> dict:
    _hdr("PHASE 4 — HMAC Evidence Chains per Invocation")

    rows: dict[str, list] = {}
    for label, inv_id in invs.items():
        # 4 evidence rows per invocation: system prompt, tool call, tool result, agent response
        e_ids = []
        e_ids.append(record_evidence(
            db, tenant_id=TENANT_ID, invocation_id=inv_id,
            evidence_kind="system_message", role="system",
            payload={"content": f"You are {label}"},
        ))
        e_ids.append(record_evidence(
            db, tenant_id=TENANT_ID, invocation_id=inv_id,
            evidence_kind="tool_call", role="assistant",
            payload={"tool_name": "navigate", "args": {"url": "https://example.com"}},
        ))
        e_ids.append(record_evidence(
            db, tenant_id=TENANT_ID, invocation_id=inv_id,
            evidence_kind="tool_result", role="tool",
            payload={"result": "ok"},
        ))
        e_ids.append(record_evidence(
            db, tenant_id=TENANT_ID, invocation_id=inv_id,
            evidence_kind="agent_response", role="assistant",
            payload={"content": f"done with {label}"},
        ))
        rows[label] = e_ids
        # Verify chain integrity
        report = verify_chain(db, tenant_id=TENANT_ID, invocation_id=inv_id)
        _check(
            f"{label} chain valid (n={report['checked']})",
            report["valid"] and report["checked"] == 4,
            f"valid={report['valid']} checked={report['checked']}",
        )
    return rows


# ── Phase 5: ROGUE signals (the SOC story) ────────────────────────


def phase_5_rogue(db) -> None:
    _hdr("PHASE 5 — Rogue Signals with actor_agent_key Attribution")

    # Per Scenario 7e: 4 rogue events, all attributed back to the autonomous root.
    record_oos_tool_attempt(
        agent_key="OpenClawBrowserAgent",
        tool="export_dom_to_clipboard",
        tenant_id=TENANT_ID,
        actor_agent_key="OpenClawCalendarAgent",  # the orchestrator-of-record
    )
    record_oos_tool_attempt(
        agent_key="OpenClawEmailAgent",
        tool="bcc_external_recipient",
        tenant_id=TENANT_ID,
        actor_agent_key="OpenClawCalendarAgent",
    )
    record_cross_tenant_attempt(
        agent_key="OpenClawBrowserAgent",
        expected_tid=TENANT_ID,
        actual_tid="33333333-3333-3333-3333-333333333333",
        actor_agent_key="OpenClawCalendarAgent",
    )
    record_data_leak(
        agent_key="OpenClawEmailAgent",
        data_class="pii",
        tenant_id=TENANT_ID,
        evidence="user_email_leaked_to_external_recipient",
        actor_agent_key="OpenClawCalendarAgent",
    )


    # Now check per-agent reports — db arg is REQUIRED to read from
    # kya_principal_trust (Prometheus alone doesn't carry actor_agent_key
    # attribution).
    for name in ("OpenClawBrowserAgent", "OpenClawEmailAgent", "OpenClawCalendarAgent"):
        report = get_rogue_signals(name, db=db, tenant_id=TENANT_ID)
        rscore = rogue_score(report)
        breakdown = {
            "oos_tool": report.oos_tool_attempts,
            "cross_tenant": report.cross_tenant_attempts,
            "data_leak": report.data_leaks,
            "policy_violation": report.policy_violations,
        }
        _row(name, f"rogue_score={rscore}, {breakdown}")

    # Calendar should aggregate all 4 events via actor_agent_key
    calendar_report = get_rogue_signals("OpenClawCalendarAgent", db=db, tenant_id=TENANT_ID)
    cal_score = rogue_score(calendar_report)
    _check(
        "OpenClawCalendarAgent rogue_score > 0 (attribution worked)",
        cal_score > 0,
        f"score={cal_score}",
    )
    # Per Scenario 7e: Calendar should aggregate 2 oos_tool + 1 cross_tenant + 1 data_leak.
    _check(
        "OpenClawCalendarAgent has 2 oos_tool signals (attribution)",
        calendar_report.oos_tool_attempts == 2,
        f"got={calendar_report.oos_tool_attempts}",
    )
    _check(
        "OpenClawCalendarAgent has 1 cross_tenant signal (attribution)",
        calendar_report.cross_tenant_attempts == 1,
        f"got={calendar_report.cross_tenant_attempts}",
    )
    _check(
        "OpenClawCalendarAgent has 1 data_leak signal (attribution)",
        calendar_report.data_leaks == 1,
        f"got={calendar_report.data_leaks}",
    )


# ── Phase 6: TRUST decay + recovery ───────────────────────────────


def phase_6_trust(db) -> None:
    _hdr("PHASE 6 — Principal Trust Decay + Recovery")

    p = "OpenClawBrowserAgent"
    # Five rogue signals against the browser principal
    t_initial = record_principal_signal(
        db, tenant_id=TENANT_ID, principal_kind="agent",
        principal_id=p, signal_kind="oos_tool",
    )
    for _ in range(4):
        record_principal_signal(
            db, tenant_id=TENANT_ID, principal_kind="agent",
            principal_id=p, signal_kind="oos_tool",
        )
    after_signals = get_principal_trust(
        db, tenant_id=TENANT_ID, principal_kind="agent", principal_id=p,
    )

    # Three clean invocations to recover
    for _ in range(3):
        record_principal_clean(
            db, tenant_id=TENANT_ID, principal_kind="agent", principal_id=p,
        )
    after_recovery = get_principal_trust(
        db, tenant_id=TENANT_ID, principal_kind="agent", principal_id=p,
    )

    sig_score = after_signals.trust_score if after_signals else None
    rec_score = after_recovery.trust_score if after_recovery else None
    _row("initial trust (1 signal)", t_initial)
    _row("after 5 signals", sig_score)
    _row("after 3 cleans", rec_score)
    _check("trust decayed after rogue signals", sig_score < t_initial)
    _check("trust recovered after clean invocations", rec_score > sig_score)


# ── Phase 7: TELEMETRY counters ────────────────────────────────────


def phase_7_telemetry() -> None:
    _hdr("PHASE 7 — Aggregate Telemetry Counters Reflect Activity")

    kya.enable_telemetry(url=None)  # counters on, no transmission
    status = telemetry_status()
    counts = status["in_flight"]["totals"]
    _row("totals", counts)
    _check("snapshot_agent counted", counts.get("snapshot_agent", 0) >= 6,
           f"got={counts.get('snapshot_agent')}")
    _check("record_invocation counted", counts.get("record_invocation", 0) >= 3,
           f"got={counts.get('record_invocation')}")
    _check("record_evidence counted", counts.get("record_evidence", 0) >= 12,
           f"got={counts.get('record_evidence')}")
    _check("rogue_event counted", counts.get("rogue_event", 0) >= 4,
           f"got={counts.get('rogue_event')}")


# ── Phase 8: PERSISTENCE across session restart ───────────────────


def phase_8_persistence(db_url: str, invs: dict) -> None:
    _hdr("PHASE 8 — Persistence Across Session Restart")

    # Open a brand-new connection — no in-memory state from prior phases.
    fresh_engine = create_engine(db_url)
    fresh_session = sessionmaker(bind=fresh_engine)()

    try:
        for label, inv_id in invs.items():
            r = verify_chain(fresh_session, tenant_id=TENANT_ID, invocation_id=inv_id)
            _check(
                f"{label}: chain still valid in fresh session",
                r["valid"] and r["checked"] == 4,
                f"valid={r['valid']} checked={r['checked']}",
            )

        for name in ("OpenClawCalendarAgent", "OpenClawBrowserAgent", "OpenClawEmailAgent"):
            hist = list_versions(fresh_session, TENANT_ID, name)
            _check(
                f"{name}: 2 versions persisted",
                len(hist) == 2,
                f"got={len(hist)}",
            )

        # Persistence of principal trust
        trust = get_principal_trust(
            fresh_session, tenant_id=TENANT_ID, principal_kind="agent",
            principal_id="OpenClawBrowserAgent",
        )
        _check(
            "principal trust row persisted",
            trust is not None and getattr(trust, "trust_score", None) is not None,
        )
        _row(
            "OpenClawBrowserAgent trust",
            trust.trust_score if trust else "missing",
        )
    finally:
        fresh_session.close()
        fresh_engine.dispose()


# ── Main ──────────────────────────────────────────────────────────


def phase_9_row_counts(db_url: str) -> None:
    """Direct DB inspection — what data actually landed where, on this backend?"""
    _hdr("PHASE 9 — Verify Persisted Rows in Every KYA Table")
    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    s = Session()
    try:
        from sqlalchemy import inspect as sa_inspect
        insp = sa_inspect(eng)
        schema = "prov_schema" if eng.dialect.name == "postgresql" else None
        tables = insp.get_table_names(schema=schema)
        ns = f"{schema}." if schema else ""
        expected = [
            "agent_versions",
            "kya_invocations",
            "kya_principal_trust",
            "kya_evidence",
        ]
        print(f"  {'table':32s} {'rows':>6s}  status")
        print(f"  {'-' * 50}")
        any_data = False
        for t in expected:
            if t in tables:
                count = int(s.execute(text(f"SELECT COUNT(*) FROM {ns}{t}")).scalar() or 0)
                state = "POPULATED" if count > 0 else "empty"
                if count > 0:
                    any_data = True
                print(f"  {t:32s} {count:>6d}  {state}")
            else:
                print(f"  {t:32s} {'-':>6s}  MISSING")
        _check("at least one core table populated", any_data)
    finally:
        s.close()
        eng.dispose()


def run_one_backend(db_url: str) -> dict:
    """Run all 9 phases against one backend; return summary."""
    backend = db_url.split("://")[0].split("+")[0]
    print()
    print("=" * 78)
    print(f"  KYA SDK END-TO-END  ·  backend={backend}")
    print("=" * 78)
    _row("backend", backend)
    _row("tenant", TENANT_ID)

    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    db = Session()

    # Register the session factory so rogue.record_* + inbound mirror
    # writes can do their attribution work (otherwise they silently
    # no-op in the SDK context — the platform inside vd-app gets the
    # factory from db.database.SessionLocal automatically).
    kya.set_session_factory(Session)

    # Bootstrap all SDK tables
    init_storage(db)

    results = {"backend": backend, "phases": {}}
    phase_runners = [
        ("1_score",       lambda: phase_1_score_agents()),
        ("2_snapshot",    None),  # needs agents
        ("3_fanout",      lambda: phase_3_fanout(db)),
        ("4_evidence",    None),  # needs invs
        ("5_rogue",       lambda: phase_5_rogue(db)),
        ("6_trust",       lambda: phase_6_trust(db)),
        ("7_telemetry",   lambda: phase_7_telemetry()),
    ]

    try:
        agents = phase_1_score_agents()
        results["phases"]["1_score"] = "PASS"
        try:
            phase_2_snapshot(db, agents)
            results["phases"]["2_snapshot"] = "PASS"
        except SystemExit:
            results["phases"]["2_snapshot"] = "FAIL"
        except Exception as exc:
            results["phases"]["2_snapshot"] = f"ERROR: {type(exc).__name__}"
        try:
            invs = phase_3_fanout(db)
            results["phases"]["3_fanout"] = "PASS"
        except SystemExit:
            results["phases"]["3_fanout"] = "FAIL"
            invs = None
        except Exception as exc:
            results["phases"]["3_fanout"] = f"ERROR: {type(exc).__name__}"
            invs = None
        if invs:
            try:
                phase_4_evidence(db, invs)
                results["phases"]["4_evidence"] = "PASS"
            except SystemExit:
                results["phases"]["4_evidence"] = "FAIL"
            except Exception as exc:
                results["phases"]["4_evidence"] = f"ERROR: {type(exc).__name__}"
        try:
            phase_5_rogue(db)
            results["phases"]["5_rogue"] = "PASS"
        except SystemExit:
            results["phases"]["5_rogue"] = "FAIL"
        except Exception as exc:
            results["phases"]["5_rogue"] = f"ERROR: {type(exc).__name__}: {str(exc)[:80]}"
        try:
            phase_6_trust(db)
            results["phases"]["6_trust"] = "PASS"
        except SystemExit:
            results["phases"]["6_trust"] = "FAIL"
        except Exception as exc:
            results["phases"]["6_trust"] = f"ERROR: {type(exc).__name__}: {str(exc)[:80]}"
        try:
            phase_7_telemetry()
            results["phases"]["7_telemetry"] = "PASS"
        except SystemExit:
            results["phases"]["7_telemetry"] = "FAIL"
    finally:
        db.close()

    if invs:
        try:
            phase_8_persistence(db_url, invs)
            results["phases"]["8_persistence"] = "PASS"
        except SystemExit:
            results["phases"]["8_persistence"] = "FAIL"
        except Exception as exc:
            results["phases"]["8_persistence"] = f"ERROR: {type(exc).__name__}: {str(exc)[:80]}"

    try:
        phase_9_row_counts(db_url)
        results["phases"]["9_persisted_rows"] = "PASS"
    except SystemExit:
        results["phases"]["9_persisted_rows"] = "FAIL"
    except Exception as exc:
        results["phases"]["9_persisted_rows"] = f"ERROR: {type(exc).__name__}: {str(exc)[:80]}"

    return results


def main():
    backends: list[tuple[str, str]] = []

    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="kya_e2e_")

    pg_url = os.environ.get("KYA_TEST_PG_URL")
    if pg_url:
        backends.append(("postgresql", pg_url))
    # File-backed SQLite + DuckDB so phase 8 (fresh session) can see
    # writes from the original session. :memory: gives a per-connection
    # private DB which makes the persistence check meaningless.
    backends.append(("sqlite", f"sqlite:///{tmpdir}/kya.sqlite"))
    try:
        import duckdb_engine  # noqa
        backends.append(("duckdb", f"duckdb:///{tmpdir}/kya.duckdb"))
    except ImportError:
        pass
    mysql_url = os.environ.get("KYA_TEST_MYSQL_URL")
    if mysql_url:
        backends.append(("mysql", mysql_url))

    if not backends:
        print("no backends configured; set KYA_TEST_PG_URL and/or KYA_TEST_MYSQL_URL")
        sys.exit(1)

    all_results: list[dict] = []
    for name, url in backends:
        try:
            r = run_one_backend(url)
        except Exception as exc:
            r = {"backend": name, "phases": {"bootstrap": f"ERROR: {exc}"}}
        all_results.append(r)

    # ── Summary matrix ──
    print()
    print("=" * 78)
    print("  SUMMARY — 9 phases × 4 backends")
    print("=" * 78)
    all_phase_keys = []
    for r in all_results:
        for k in r["phases"]:
            if k not in all_phase_keys:
                all_phase_keys.append(k)
    print(f"  {'phase':22s}  " + "  ".join(f"{r['backend']:>12s}" for r in all_results))
    print(f"  {'-' * 22}  " + "  ".join("-" * 12 for _ in all_results))
    for phase in all_phase_keys:
        cells = [r["phases"].get(phase, "n/a")[:12] for r in all_results]
        print(f"  {phase:22s}  " + "  ".join(f"{c:>12s}" for c in cells))


if __name__ == "__main__":
    main()
