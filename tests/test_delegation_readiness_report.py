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
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None})
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
    assert r["summary"]["stable_pairs"] == 0  # didn't cross 30d threshold


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
