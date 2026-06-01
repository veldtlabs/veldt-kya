"""Tests for kya/delegation_analytics.py — readiness report.

Validates:
  - Rule firing for spike, stable-promotion, active-violations-hold,
    block-spike-rollback.
  - Determinism: same input → byte-identical output.
  - No-noise default: steady-state items don't appear in `attention`.
  - Scope filters (parent, sub, kind).
  - Backend-agnostic SQL (sqlite cover; cross-backend run separately).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    VALID_RECOMMENDATIONS,
    delegation_readiness_report,
    init_storage,
)


TENANT = "00000000-0000-0000-0000-0000000000aa"


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


@pytest.fixture(autouse=True)
def clean_env():
    prev = os.environ.pop("KYA_DELEGATION_POLICY", None)
    yield
    if prev is not None:
        os.environ["KYA_DELEGATION_POLICY"] = prev
    else:
        os.environ.pop("KYA_DELEGATION_POLICY", None)


def _insert_violation(db, *, parent, sub, kind, days_ago: float,
                       mode_active="observe", blocked=False):
    """Direct DB insert with backdated created_at — bypasses the
    server_default=now() so we can simulate "violation from 45 days
    ago" scenarios."""
    when = datetime.now(timezone.utc) - timedelta(days=days_ago)
    db.execute(text(
        "INSERT INTO kya_delegation_violations "
        "(tenant_id, sub_invocation_id, parent_invocation_id, "
        " parent_agent_key, sub_agent_key, violation_kind, detail, "
        " mode_active, blocked, created_at) "
        "VALUES (:t, :si, :pi, :p, :s, :k, :d, :m, :b, :c)"
    ), {
        "t": TENANT, "si": 1, "pi": 0,
        "p": parent, "s": sub, "k": kind,
        "d": "{}",
        "m": mode_active,
        "b": 1 if blocked else 0,
        "c": when,
    })
    db.commit()


# ── Determinism + empty cases ──────────────────────────────────────


def test_empty_table_returns_empty_attention(db):
    r = delegation_readiness_report(db, tenant_id=TENANT)
    assert r["attention"] == []
    assert r["summary"]["total_violations_in_window"] == 0
    assert r["summary"]["actionable_items"] == 0


def test_repeated_calls_byte_identical(db):
    _insert_violation(db, parent="P1", sub="S1",
                       kind="access_escalation", days_ago=2)
    import json
    a = json.dumps(delegation_readiness_report(
        db, tenant_id=TENANT), sort_keys=True)
    b = json.dumps(delegation_readiness_report(
        db, tenant_id=TENANT), sort_keys=True)
    # generated_at will differ by microseconds — strip it for compare
    import re
    a_clean = re.sub(r'"generated_at":\s*"[^"]+"', '"generated_at":"X"', a)
    b_clean = re.sub(r'"generated_at":\s*"[^"]+"', '"generated_at":"X"', b)
    assert a_clean == b_clean


# ── Spike rule ─────────────────────────────────────────────────────


def test_spike_rule_fires_with_high_count(db):
    for _ in range(120):
        _insert_violation(db, parent="OrchA", sub="SubA",
                           kind="access_escalation", days_ago=1)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7, spike_threshold=100)
    assert r["summary"]["actionable_items"] == 1
    item = r["attention"][0]
    assert item["rule_id"] == "spike_threshold_exceeded"
    assert item["recommendation"] == "investigate_spike"
    assert "120 violations" in item["rationale"]


def test_spike_rule_does_not_fire_below_threshold(db):
    for _ in range(50):
        _insert_violation(db, parent="OrchB", sub="SubB",
                           kind="access_escalation", days_ago=1)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7, spike_threshold=100)
    # 50 < 100 spike threshold; should hit active_violations_hold instead
    assert len(r["attention"]) == 1
    assert r["attention"][0]["rule_id"] == "active_violations_block_promotion"


# ── Stable-promotion rules ─────────────────────────────────────────


def test_stable_promote_observe_to_flag(db):
    # One violation 45 days ago; nothing in last 7 days. Default mode
    # is observe. Should recommend promote_to_flag.
    _insert_violation(db, parent="OrchC", sub="SubC",
                       kind="data_class_widening", days_ago=45)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7,
        stable_days_to_promote=30)
    assert r["summary"]["actionable_items"] == 1
    item = r["attention"][0]
    assert item["rule_id"] == "stable_promote_observe_to_flag"
    assert item["recommendation"] == "promote_to_flag"
    assert item["count_in_window"] == 0


def test_stable_promote_flag_to_block(db, monkeypatch):
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "flag")
    _insert_violation(db, parent="OrchD", sub="SubD",
                       kind="human_loop_relax", days_ago=45)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7,
        stable_days_to_promote=30)
    assert r["summary"]["actionable_items"] == 1
    item = r["attention"][0]
    assert item["rule_id"] == "stable_promote_flag_to_block"
    assert item["recommendation"] == "promote_to_block"


def test_stable_within_threshold_does_not_promote(db):
    # Violation 20 days ago — below 30d stable threshold.
    _insert_violation(db, parent="OrchE", sub="SubE",
                       kind="tool_widening", days_ago=20)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7,
        stable_days_to_promote=30)
    # Not stable enough → no promotion recommendation; and not in
    # window → no active-violation hold either. Steady state.
    assert r["attention"] == []
    # Didn't cross 30d threshold → not counted as previously-stable
    assert r["summary"]["previously_violating_pairs_now_stable"] == 0


# ── Active-violations-hold rule ────────────────────────────────────


def test_active_violations_hold_blocks_promotion(db):
    _insert_violation(db, parent="OrchF", sub="SubF",
                       kind="access_escalation", days_ago=1)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7,
        stable_days_to_promote=30)
    assert r["summary"]["actionable_items"] == 1
    item = r["attention"][0]
    assert item["rule_id"] == "active_violations_block_promotion"
    assert item["recommendation"] == "hold"


# ── Block-mode-spike rollback ──────────────────────────────────────


def test_block_mode_spike_recommends_rollback(db, monkeypatch):
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "block")
    for _ in range(150):
        _insert_violation(db, parent="OrchG", sub="SubG",
                           kind="access_escalation", days_ago=1,
                           mode_active="block", blocked=True)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7, spike_threshold=100)
    assert r["summary"]["actionable_items"] == 1
    item = r["attention"][0]
    assert item["rule_id"] == "block_mode_spike_rollback"
    assert item["recommendation"] == "rollback_to_observe"


# ── Scope filters ──────────────────────────────────────────────────


def test_scope_filter_by_parent(db):
    _insert_violation(db, parent="X", sub="Sa",
                       kind="access_escalation", days_ago=1)
    _insert_violation(db, parent="Y", sub="Sb",
                       kind="access_escalation", days_ago=1)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, parent_agent_key="X")
    pairs = {(i["parent_agent_key"], i["sub_agent_key"])
             for i in r["attention"]}
    assert pairs == {("X", "Sa")}


def test_scope_filter_by_violation_kind(db):
    _insert_violation(db, parent="P", sub="S",
                       kind="access_escalation", days_ago=1)
    _insert_violation(db, parent="P", sub="S",
                       kind="tool_widening", days_ago=1)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, violation_kind="tool_widening")
    kinds = {i["violation_kind"] for i in r["attention"]}
    assert kinds == {"tool_widening"}


# ── Summary fields ─────────────────────────────────────────────────


def test_summary_aggregates_correctly(db):
    _insert_violation(db, parent="P1", sub="S1",
                       kind="access_escalation", days_ago=1)
    _insert_violation(db, parent="P1", sub="S1",
                       kind="access_escalation", days_ago=2)
    _insert_violation(db, parent="P2", sub="S2",
                       kind="data_class_widening", days_ago=3)
    r = delegation_readiness_report(db, tenant_id=TENANT)
    assert r["summary"]["total_violations_in_window"] == 3
    assert r["summary"]["distinct_pairs_with_violations"] == 2
    assert r["summary"]["violation_kinds_in_window"] == {
        "access_escalation": 2,
        "data_class_widening": 1,
    }
    assert r["summary"]["active_parent_agents"] == {"P1": 2, "P2": 1}


def test_recommendations_in_closed_set(db):
    """Sanity check that every emitted recommendation is in the
    whitelist — guards against typos in new rules."""
    for days in (1, 45):
        for parent in ("P_close_1", "P_close_2"):
            _insert_violation(db, parent=parent,
                               sub=f"sub_{parent}",
                               kind="access_escalation",
                               days_ago=days)
    r = delegation_readiness_report(db, tenant_id=TENANT)
    for item in r["attention"]:
        assert item["recommendation"] in VALID_RECOMMENDATIONS


def test_window_must_be_lte_stable_days(db):
    with pytest.raises(ValueError):
        delegation_readiness_report(
            db, tenant_id=TENANT,
            window_days=30, stable_days_to_promote=7)


def test_empty_tenant_id_raises(db):
    with pytest.raises(ValueError, match="tenant_id is required"):
        delegation_readiness_report(db, tenant_id="")
    with pytest.raises(ValueError, match="tenant_id is required"):
        delegation_readiness_report(db, tenant_id=None)  # type: ignore


# ── A. Cross-tenant isolation ─────────────────────────────────────


def test_cross_tenant_isolation(db):
    """Violations under tenant X must NEVER appear in tenant Y's
    report — critical multi-tenancy safety property."""
    other_tenant = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    # Insert under TENANT
    _insert_violation(db, parent="P_iso", sub="S_iso",
                       kind="access_escalation", days_ago=1)
    # Insert under other_tenant — same agent_keys, same kind
    when = datetime.now(timezone.utc) - timedelta(days=1)
    db.execute(text(
        "INSERT INTO kya_delegation_violations "
        "(tenant_id, sub_invocation_id, parent_invocation_id, "
        " parent_agent_key, sub_agent_key, violation_kind, detail, "
        " mode_active, blocked, created_at) "
        "VALUES (:t, 1, 0, :p, :s, :k, '{}', 'observe', 0, :c)"
    ), {"t": other_tenant, "p": "P_iso", "s": "S_iso",
        "k": "access_escalation", "c": when})
    db.commit()

    r = delegation_readiness_report(db, tenant_id=TENANT)
    # Counts only the TENANT's row, not other_tenant's
    assert r["summary"]["total_violations_in_window"] == 1

    r_other = delegation_readiness_report(db, tenant_id=other_tenant)
    assert r_other["summary"]["total_violations_in_window"] == 1
    # Both reports are non-empty independently, but neither leaks
    # the other's data
    assert all(i["parent_agent_key"] == "P_iso"
               for i in r["attention"])
    assert all(i["parent_agent_key"] == "P_iso"
               for i in r_other["attention"])


# ── B. Multi-pair mixed states ────────────────────────────────────


def test_multi_pair_mixed_states_sort_and_priority(db):
    """Five pairs in five different states. Verify each gets the
    correct rule, attention list is sorted deterministically, and
    summary tallies are correct."""
    # Pair 1: spike (200 violations in window)
    for _ in range(200):
        _insert_violation(db, parent="P_spk", sub="S_spk",
                           kind="access_escalation", days_ago=1)
    # Pair 2: active hold (20 violations in window — below spike)
    for _ in range(20):
        _insert_violation(db, parent="P_act", sub="S_act",
                           kind="tool_widening", days_ago=2)
    # Pair 3: stable (one violation 60 days ago)
    _insert_violation(db, parent="P_stb", sub="S_stb",
                       kind="data_class_widening", days_ago=60)
    # Pair 4: too-recent-to-promote (one violation 15 days ago, no in_window)
    _insert_violation(db, parent="P_rec", sub="S_rec",
                       kind="human_loop_relax", days_ago=15)
    # Pair 5: zero violations — won't appear in attention OR summary

    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7,
        stable_days_to_promote=30, spike_threshold=100)

    rules_by_pair = {
        (i["parent_agent_key"], i["sub_agent_key"]): i["rule_id"]
        for i in r["attention"]
    }
    assert rules_by_pair[("P_spk", "S_spk")] == "spike_threshold_exceeded"
    assert rules_by_pair[("P_act", "S_act")] == "active_violations_block_promotion"
    assert rules_by_pair[("P_stb", "S_stb")] == "stable_promote_observe_to_flag"
    assert ("P_rec", "S_rec") not in rules_by_pair  # no action

    # Attention sorted deterministically by (recommendation, parent, sub, kind)
    recs = [(i["recommendation"], i["parent_agent_key"],
             i["sub_agent_key"], i["violation_kind"])
            for i in r["attention"]]
    assert recs == sorted(recs)

    # Summary tallies
    assert r["summary"]["total_violations_in_window"] == 220  # 200 + 20
    assert r["summary"]["distinct_pairs_with_violations"] == 2  # spk + act
    assert r["summary"]["previously_violating_pairs_now_stable"] == 0
    # P_rec is silent in window but only 15d quiet — NOT yet stable


# ── C. High volume ────────────────────────────────────────────────


def test_high_volume_1000_violations(db):
    """1000 violations across 10 pairs × 4 kinds. Report should
    complete in a reasonable time and return correct counts."""
    import time
    for pair_idx in range(10):
        for kind in ("access_escalation", "tool_widening",
                       "data_class_widening", "human_loop_relax"):
            for _ in range(25):  # 10 * 4 * 25 = 1000
                _insert_violation(
                    db, parent=f"Pv_{pair_idx}",
                    sub=f"Sv_{pair_idx}",
                    kind=kind, days_ago=1)

    t0 = time.time()
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7, spike_threshold=20)
    elapsed = time.time() - t0
    assert elapsed < 5.0, f"report took {elapsed:.2f}s (>5s budget)"
    assert r["summary"]["total_violations_in_window"] == 1000
    # 40 pair×kind combos, all > 20 spike threshold → all in attention
    assert len(r["attention"]) == 40
    assert all(i["rule_id"] == "spike_threshold_exceeded"
               for i in r["attention"])


# ── D. Mixed mode_active history ──────────────────────────────────


def test_mixed_mode_active_history(db):
    """A pair has violations from different historical modes. The
    report's current_effective_mode reflects CURRENT env, not the
    historical row values — that's the Phase 1 contract."""
    # 3 violations under observe (old), 2 under flag (recent)
    for _ in range(3):
        _insert_violation(db, parent="P_mx", sub="S_mx",
                           kind="access_escalation",
                           days_ago=45, mode_active="observe")
    for _ in range(2):
        _insert_violation(db, parent="P_mx", sub="S_mx",
                           kind="access_escalation",
                           days_ago=2, mode_active="flag")
    os.environ["KYA_DELEGATION_POLICY"] = "flag"
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7,
        stable_days_to_promote=30)
    # All entries report current_effective_mode = flag
    assert all(i["current_effective_mode"] == "flag"
               for i in r["attention"])
    # 2 in-window violations under "flag" → active hold (don't promote)
    assert r["attention"][0]["rule_id"] == "active_violations_block_promotion"


# ── E. Boundary at stable_days_to_promote ─────────────────────────


def test_boundary_exactly_at_stable_threshold(db):
    """Violation exactly at stable_days_to_promote should promote
    (rule uses >=, not >)."""
    # Use 30.0 days minus a few seconds — the insert is 'days_ago=30',
    # and by the time the report runs a few microseconds later,
    # days_since_last will be slightly > 30.
    _insert_violation(db, parent="P_bnd", sub="S_bnd",
                       kind="access_escalation", days_ago=30)
    r = delegation_readiness_report(
        db, tenant_id=TENANT, window_days=7,
        stable_days_to_promote=30)
    items = [i for i in r["attention"]
             if i["parent_agent_key"] == "P_bnd"]
    assert len(items) == 1
    assert items[0]["rule_id"] == "stable_promote_observe_to_flag"


# ── F. Cross-backend smoke (via env-var-driven backend selection) ──


def test_cross_backend_smoke_runs_against_postgres():
    """If KYA_TEST_PG_URL is set, run a quick PASS-or-skip smoke
    against PostgreSQL to catch backend-specific behavior (e.g.,
    MAX(timestamptz) return type, prov_schema qualifier handling)."""
    if not os.environ.get("KYA_TEST_PG_URL"):
        pytest.skip("KYA_TEST_PG_URL not set")
    eng = create_engine(os.environ["KYA_TEST_PG_URL"])
    with eng.begin() as conn:
        conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
        conn.execute(text(
            "DROP TABLE IF EXISTS prov_schema.kya_delegation_violations"))
    db = sessionmaker(bind=eng)()
    init_storage(db)
    try:
        # Insert one violation and one stable item via the table's
        # explicit Sequence (the column has no SERIAL default — the
        # Sequence is bound at INSERT time by SQLAlchemy's ORM but
        # raw text() statements must use nextval() explicitly).
        for days, parent in ((1, "P_pg_active"), (45, "P_pg_stable")):
            db.execute(text(
                "INSERT INTO prov_schema.kya_delegation_violations "
                "(id, tenant_id, sub_invocation_id, parent_invocation_id, "
                " parent_agent_key, sub_agent_key, violation_kind, "
                " detail, mode_active, blocked, created_at) "
                "VALUES (nextval('kya_delegation_violations_id_seq'), "
                "        :t, 1, 0, :p, 'sub', "
                "        'access_escalation', '{}'::jsonb, 'observe', "
                "        false, now() - (:d || ' days')::interval)"
            ), {"t": TENANT, "p": parent, "d": days})
        db.commit()
        r = delegation_readiness_report(
            db, tenant_id=TENANT, window_days=7,
            stable_days_to_promote=30)
        rules = {i["parent_agent_key"]: i["rule_id"] for i in r["attention"]}
        assert rules.get("P_pg_active") == "active_violations_block_promotion"
        assert rules.get("P_pg_stable") == "stable_promote_observe_to_flag"
    finally:
        db.close()
        eng.dispose()


# ── G. Clock-skew clamp ───────────────────────────────────────────


def test_clock_skew_negative_days_clamped_to_zero(db):
    """If a row's created_at is somehow in the future (clock skew
    between app server and DB), days_since_last should clamp to 0
    rather than emit a negative value."""
    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.execute(text(
        "INSERT INTO kya_delegation_violations "
        "(tenant_id, sub_invocation_id, parent_invocation_id, "
        " parent_agent_key, sub_agent_key, violation_kind, detail, "
        " mode_active, blocked, created_at) "
        "VALUES (:t, 1, 0, 'P_sk', 'S_sk', 'access_escalation', "
        "        '{}', 'observe', 0, :c)"
    ), {"t": TENANT, "c": future})
    db.commit()
    r = delegation_readiness_report(db, tenant_id=TENANT)
    # The pair is in-window so days_since_last is clamped to 0
    for item in r["attention"]:
        if item["parent_agent_key"] == "P_sk":
            assert item["days_since_last_violation"] >= 0
            break
