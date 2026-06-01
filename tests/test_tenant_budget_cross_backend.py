"""End-to-end integration tests for kya.tenant_budget + kya.cost_analytics
against real database backends.

Coverage:
  * ensure_tables creates kya_tenant_cost_budgets + kya_budget_changes
    + kya_cost_events on every supported dialect
  * Full set → get → list → delete → list_changes lifecycle
  * Only-tighten enforcement (BudgetLoosensError on loosen attempts)
  * record_cost_event persists + idempotency on request_id
  * Analytics rollups return correct aggregates (cost_by_dimension,
    cost_over_time, top_cost_agents, cost_of_failure, cache_efficiency,
    cost_per_invocation, attribution_summary)
  * Provider auto-derivation from model strings

Parameterized backends:
  * sqlite (in-memory, always-on)
  * duckdb (in-memory, always-on)
  * postgresql (skipif KYA_TEST_PG_URL not set)
  * mysql (skipif KYA_TEST_MYSQL_URL not set)
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


# ── Backend parameterization ────────────────────────────────────────


def _duckdb_available() -> bool:
    try:
        import duckdb_engine  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param("duckdb", marks=pytest.mark.skipif(
            not _duckdb_available(),
            reason="duckdb_engine not installed"
        )),
        pytest.param("pg", marks=pytest.mark.skipif(
            "KYA_TEST_PG_URL" not in os.environ,
            reason="PG integration — set KYA_TEST_PG_URL"
        )),
        pytest.param("mysql", marks=pytest.mark.skipif(
            "KYA_TEST_MYSQL_URL" not in os.environ,
            reason="MySQL integration — set KYA_TEST_MYSQL_URL"
        )),
    ],
    ids=["sqlite", "duckdb", "pg", "mysql"],
)
def db(request):
    """Yield a session bound to a fresh DB on the requested backend."""
    if request.param == "sqlite":
        eng = create_engine("sqlite:///:memory:")
    elif request.param == "duckdb":
        eng = create_engine("duckdb:///:memory:")
    elif request.param == "pg":
        from sqlalchemy import text
        eng = create_engine(os.environ["KYA_TEST_PG_URL"])
        with eng.begin() as conn:
            # Some PG installs preload AGE (ag_catalog) which breaks
            # DROP SCHEMA CASCADE. Truncate-and-leave is safer + faster.
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            for tbl in ("kya_cost_events", "kya_budget_changes",
                        "kya_tenant_cost_budgets"):
                # No CASCADE: AGE-loaded PG instances (ag_catalog
                # preload) error on CASCADE walks. Tables don't depend
                # on each other so explicit non-cascading drop is fine.
                conn.execute(text(
                    f"DROP TABLE IF EXISTS {tbl} CASCADE"
                ))
    else:  # mysql
        from sqlalchemy import text
        eng = create_engine(os.environ["KYA_TEST_MYSQL_URL"])
        # MySQL has no schemas in the PG sense — truncate the three
        # tables at fixture start to isolate each test.
        with eng.begin() as conn:
            for tbl in ("kya_cost_events", "kya_budget_changes",
                        "kya_tenant_cost_budgets"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception:
                    pass

    Session = sessionmaker(bind=eng)
    session = Session()

    # Auto-create our tables — same as init_storage() does in production.
    from kya.tenant_budget import ensure_tables
    ensure_tables(session)

    try:
        yield session
    finally:
        session.rollback()
        session.close()
        eng.dispose()


# Convenience IDs
TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"


# ── ensure_tables — tables actually exist after init ────────────────


def test_ensure_tables_creates_three_tables(db):
    """All three tables must come up: budgets, budget_changes, events."""
    from sqlalchemy import inspect
    insp = inspect(db.connection())
    # PG keeps tables in prov_schema; other dialects strip via the
    # fixture's schema_translate_map and use the default namespace.
    dialect = db.get_bind().dialect.name
    schema = None  # v0.1.6: tables go to dialect default (public on PG)
    table_names = insp.get_table_names(schema=schema)
    assert "kya_tenant_cost_budgets" in table_names
    assert "kya_budget_changes" in table_names
    assert "kya_cost_events" in table_names


# ── Budget config lifecycle ─────────────────────────────────────────


def test_set_and_get_budget_round_trip(db):
    """set_budget → get_budget — values round-trip without loss."""
    from kya.tenant_budget import set_budget, get_budget

    set_budget(
        db, tenant_id=None, scope="tenant", scope_key="*",
        window="24h", threshold_usd=1000.0, hard_refuse=True,
        forecast_horizon_sec=7200,
    )
    cfg = get_budget(db, tenant_id=None, scope="tenant",
                     scope_key="*", window="24h")
    assert cfg is not None
    assert cfg["threshold_usd"] == 1000.0
    assert cfg["hard_refuse"] is True
    assert cfg["forecast_horizon_sec"] == 7200


def test_tenant_override_resolves_over_platform_default(db):
    """Tenant override wins over platform default when both exist.

    Regression test for v0.1.1 #1: ``get_budget`` previously returned
    ``tenant_id=<requested>`` even when falling back to the platform
    default — making callers unable to distinguish 'I have my own cap'
    from 'I'm using the platform cap' without a second query."""
    from kya.tenant_budget import set_budget, get_budget

    # Platform default $1000
    set_budget(db, tenant_id=None, scope="tenant", scope_key="*",
               window="24h", threshold_usd=1000.0)
    # Tenant tightens to $500
    set_budget(db, tenant_id=TENANT_A, scope="tenant", scope_key="*",
               window="24h", threshold_usd=500.0)

    cfg_tenant = get_budget(db, tenant_id=TENANT_A, scope="tenant",
                            scope_key="*", window="24h")
    assert cfg_tenant["threshold_usd"] == 500.0
    # PG returns native UUID — cast for cross-dialect equality
    assert str(cfg_tenant["tenant_id"]) == TENANT_A

    # Other tenant falls back to platform default — and the returned
    # tenant_id MUST be None (not TENANT_B) so the caller can tell
    # which row matched.
    cfg_other = get_budget(db, tenant_id=TENANT_B, scope="tenant",
                           scope_key="*", window="24h")
    assert cfg_other["threshold_usd"] == 1000.0
    assert cfg_other["tenant_id"] is None  # ← regression assertion


def test_only_tighten_rejects_loosen_attempt(db):
    """Tenant cannot raise their cap above the platform default."""
    from kya.tenant_budget import BudgetLoosensError, set_budget

    set_budget(db, tenant_id=None, scope="tenant", scope_key="*",
               window="24h", threshold_usd=500.0)
    with pytest.raises(BudgetLoosensError):
        set_budget(db, tenant_id=TENANT_A, scope="tenant", scope_key="*",
                   window="24h", threshold_usd=1000.0)  # > platform default


def test_only_tighten_allows_lower_or_equal(db):
    """Tenant tightening (below or equal to platform default) is OK."""
    from kya.tenant_budget import set_budget

    set_budget(db, tenant_id=None, scope="tenant", scope_key="*",
               window="24h", threshold_usd=500.0)
    # equal is fine
    set_budget(db, tenant_id=TENANT_A, scope="tenant", scope_key="*",
               window="24h", threshold_usd=500.0)
    # tighter is fine
    set_budget(db, tenant_id=TENANT_A, scope="tenant", scope_key="*",
               window="24h", threshold_usd=100.0)


def test_list_budgets_includes_platform_and_tenant(db):
    from kya.tenant_budget import list_budgets, set_budget

    set_budget(db, tenant_id=None, scope="tenant", scope_key="*",
               window="24h", threshold_usd=1000.0)
    set_budget(db, tenant_id=TENANT_A, scope="tenant", scope_key="*",
               window="24h", threshold_usd=500.0)

    rows = list_budgets(db, tenant_id=TENANT_A)
    assert len(rows) == 2
    # Each row has the required dashboard fields
    for r in rows:
        assert {"tenant_id", "scope", "scope_key", "window",
                "threshold_usd", "hard_refuse"} <= set(r.keys())


def test_delete_budget_removes_and_audits(db):
    from kya.tenant_budget import (
        delete_budget, get_budget, list_changes, set_budget,
    )

    set_budget(db, tenant_id=TENANT_A, scope="tenant", scope_key="*",
               window="24h", threshold_usd=500.0, reason="initial setup")
    assert delete_budget(
        db, tenant_id=TENANT_A, scope="tenant",
        scope_key="*", window="24h", reason="decommission",
    ) is True
    assert get_budget(db, tenant_id=TENANT_A, scope="tenant",
                      scope_key="*", window="24h") is None

    changes = list_changes(db, tenant_id=TENANT_A)
    actions = [c["action"] for c in changes]
    assert "set" in actions
    assert "delete" in actions


def test_budget_change_audit_captures_old_new(db):
    """The audit log shows old → new transition on every update."""
    from kya.tenant_budget import list_changes, set_budget

    set_budget(db, tenant_id=TENANT_A, scope="tenant", scope_key="*",
               window="24h", threshold_usd=500.0, reason="first")
    set_budget(db, tenant_id=TENANT_A, scope="tenant", scope_key="*",
               window="24h", threshold_usd=400.0, reason="tightening")

    changes = list_changes(db, tenant_id=TENANT_A)
    # Most recent first
    second = changes[0]
    first = changes[1]
    assert first["old_threshold_usd"] is None
    assert first["new_threshold_usd"] == 500.0
    assert second["old_threshold_usd"] == 500.0
    assert second["new_threshold_usd"] == 400.0


# ── Cost event recorder ─────────────────────────────────────────────


def test_record_cost_event_persists_full_row(db):
    """Every analytics column round-trips correctly."""
    from sqlalchemy import select

    from kya._legacy_tables import kya_cost_events as t
    from kya.tenant_budget import record_cost_event

    event_id = record_cost_event(
        db, tenant_id=TENANT_A, agent_key="loan-triage",
        usd_amount=0.234, model_used="claude-3-5-sonnet-20241022",
        input_tokens=400, output_tokens=80, cached_tokens=200,
        latency_ms=850, outcome="success",
        cost_center="loan-ops", business_unit="banking",
        environment="prod", invocation_id=42,
        tags={"abtest": "control"}, request_id="req-abc-1",
    )
    assert event_id > 0

    row = db.execute(select(t).where(t.c.id == event_id)).first()
    # PG returns UUID objects; other dialects return strings — cast
    # both to str so the comparison is dialect-agnostic.
    assert str(row.tenant_id) == TENANT_A
    assert row.agent_key == "loan-triage"
    assert float(row.usd_amount) == pytest.approx(0.234)
    assert row.model_used == "claude-3-5-sonnet-20241022"
    assert row.provider == "anthropic"
    assert row.cost_center == "loan-ops"
    assert row.outcome == "success"
    assert row.invocation_id == 42
    assert row.latency_ms == 850


def test_record_cost_event_idempotent_on_request_id(db):
    """Same request_id twice → first wins, second is a no-op."""
    from kya.tenant_budget import record_cost_event

    eid1 = record_cost_event(
        db, tenant_id=TENANT_A, agent_key="a", usd_amount=1.0,
        request_id="req-idempotent",
    )
    eid2 = record_cost_event(
        db, tenant_id=TENANT_A, agent_key="a", usd_amount=99.0,
        request_id="req-idempotent",
    )
    assert eid1 > 0
    assert eid2 == 0  # ON CONFLICT DO NOTHING-style behavior


def test_record_cost_event_provider_derivation(db):
    """Provider derived from model_used when not explicit."""
    from kya._legacy_tables import kya_cost_events as t
    from kya.tenant_budget import record_cost_event
    from sqlalchemy import select

    cases = [
        ("gpt-4o-mini", "openai"),
        ("claude-3-5-sonnet", "anthropic"),
        ("gemini-1.5-pro", "google"),
        ("llama-3.1-70b", "self_hosted"),
        ("anthropic.claude-v2", "bedrock"),
        ("totally-custom-model-x", "other"),
    ]
    for i, (model, expected_provider) in enumerate(cases):
        record_cost_event(
            db, tenant_id=TENANT_A, agent_key=f"agent-{i}",
            usd_amount=0.01, model_used=model,
            request_id=f"req-provider-{i}",
        )
    rows = db.execute(select(t.c.model_used, t.c.provider)
                       .where(t.c.tenant_id == TENANT_A)).fetchall()
    by_model = {r[0]: r[1] for r in rows}
    for model, expected in cases:
        assert by_model[model] == expected


# ── Analytics rollups ───────────────────────────────────────────────


def _seed_analytics_fixture(db):
    """Insert a small but diverse dataset for analytics tests."""
    from kya.tenant_budget import record_cost_event

    # Agent A on Claude — high spend, success
    record_cost_event(db, tenant_id=TENANT_A, agent_key="agent-A",
                     usd_amount=0.50, model_used="claude-3-5",
                     cost_center="cc-1", business_unit="bu-x",
                     environment="prod", outcome="success",
                     input_tokens=100, output_tokens=200, cached_tokens=50,
                     latency_ms=500, invocation_id=1,
                     request_id="seed-1")
    record_cost_event(db, tenant_id=TENANT_A, agent_key="agent-A",
                     usd_amount=0.40, model_used="claude-3-5",
                     cost_center="cc-1", business_unit="bu-x",
                     environment="prod", outcome="success",
                     input_tokens=100, output_tokens=200, cached_tokens=80,
                     latency_ms=450, invocation_id=2,
                     request_id="seed-2")
    # Agent B on GPT — failures
    record_cost_event(db, tenant_id=TENANT_A, agent_key="agent-B",
                     usd_amount=0.30, model_used="gpt-4o",
                     cost_center="cc-2", business_unit="bu-y",
                     environment="prod", outcome="failure",
                     input_tokens=200, output_tokens=50,
                     latency_ms=1200, invocation_id=3,
                     request_id="seed-3")
    record_cost_event(db, tenant_id=TENANT_A, agent_key="agent-B",
                     usd_amount=0.20, model_used="gpt-4o",
                     cost_center="cc-2", business_unit="bu-y",
                     environment="prod", outcome="refused",
                     input_tokens=50, output_tokens=0,
                     latency_ms=10, invocation_id=4,
                     request_id="seed-4")


def test_cost_by_dimension_provider(db):
    from kya.cost_analytics import cost_by_dimension

    _seed_analytics_fixture(db)
    rollup = cost_by_dimension(db, "provider", tenant_id=TENANT_A)
    assert "anthropic" in rollup
    assert "openai" in rollup
    assert rollup["anthropic"]["usd"] == pytest.approx(0.90)
    assert rollup["openai"]["usd"] == pytest.approx(0.50)
    assert rollup["anthropic"]["events"] == 2
    assert rollup["openai"]["events"] == 2


def test_cost_by_dimension_cost_center(db):
    from kya.cost_analytics import cost_by_dimension

    _seed_analytics_fixture(db)
    rollup = cost_by_dimension(db, "cost_center", tenant_id=TENANT_A)
    assert rollup["cc-1"]["usd"] == pytest.approx(0.90)
    assert rollup["cc-2"]["usd"] == pytest.approx(0.50)


def test_cost_by_dimension_rejects_unsafe_input(db):
    """Caller-supplied dimension strings must be closed-set."""
    from kya.cost_analytics import cost_by_dimension

    with pytest.raises(ValueError):
        cost_by_dimension(db, "tenant_id; DROP TABLE", tenant_id=TENANT_A)


def test_cost_of_failure_reports_waste_ratio(db):
    from kya.cost_analytics import cost_of_failure

    _seed_analytics_fixture(db)
    report = cost_of_failure(db, tenant_id=TENANT_A)
    assert report["total_usd"] == pytest.approx(1.40)
    # failure + refused = wasted = 0.30 + 0.20 = 0.50
    assert report["wasted_usd"] == pytest.approx(0.50)
    assert report["waste_ratio"] == pytest.approx(0.50 / 1.40, abs=1e-4)


def test_cache_efficiency(db):
    from kya.cost_analytics import cache_efficiency

    _seed_analytics_fixture(db)
    eff = cache_efficiency(db, tenant_id=TENANT_A)
    # cached = 50 + 80 = 130
    # input (NON-cached) = 100 + 100 + 200 + 50 = 450
    # output = 200 + 200 + 50 + 0 = 450
    assert eff["cached_tokens"] == 130
    assert eff["input_tokens"] == 450
    assert eff["output_tokens"] == 450
    # cache_ratio = 130 / (130 + 450) ≈ 0.2241
    assert eff["cache_ratio"] == pytest.approx(130 / 580, abs=1e-4)


def test_top_cost_agents(db):
    from kya.cost_analytics import top_cost_agents

    _seed_analytics_fixture(db)
    top = top_cost_agents(db, tenant_id=TENANT_A, limit=10)
    # Sorted desc by usd
    assert top[0]["agent_key"] == "agent-A"
    assert top[0]["usd"] == pytest.approx(0.90)
    assert top[1]["agent_key"] == "agent-B"
    assert top[1]["usd"] == pytest.approx(0.50)


def test_cost_per_invocation(db):
    from kya.cost_analytics import cost_per_invocation

    _seed_analytics_fixture(db)
    inv = cost_per_invocation(db, tenant_id=TENANT_A, invocation_id=1)
    assert inv is not None
    assert inv["usd_amount"] == pytest.approx(0.50)
    assert inv["events"] == 1
    # Non-existent invocation returns None
    assert cost_per_invocation(db, tenant_id=TENANT_A, invocation_id=999) is None


def test_attribution_summary_one_shot(db):
    from kya.cost_analytics import attribution_summary

    _seed_analytics_fixture(db)
    summary = attribution_summary(db, tenant_id=TENANT_A)
    # All sections present
    assert "by_provider" in summary
    assert "by_cost_center" in summary
    assert "by_business_unit" in summary
    assert "by_environment" in summary
    assert "top_agents" in summary
    assert "outcomes" in summary
    assert "cache" in summary
    # Top-level totals consistent
    assert summary["outcomes"]["total_usd"] == pytest.approx(1.40)


# ── End-to-end: budget refusal scenario ─────────────────────────────


def test_e2e_budget_breach_triggers_refuse(db, monkeypatch):
    """Simulate the action gate: set a budget, fake-bump the Valkey
    counter via the recorder code path (so current_spend doesn't need
    real Valkey), then assert should_refuse returns refuse."""
    from kya import tenant_budget

    tenant_budget.set_budget(
        db, tenant_id=None, scope="tenant", scope_key="*",
        window="1h", threshold_usd=10.0, hard_refuse=True,
        forecast_horizon_sec=60,
    )

    # Force-mock current_spend to simulate Valkey-reported burn
    monkeypatch.setattr(
        "kya.tenant_budget.current_spend",
        lambda t, s, sk, w: 9.50 if w == "1h" else 0.0,
    )
    monkeypatch.setattr(
        "kya.tenant_budget._burn_rate_per_sec",
        lambda t, s, sk: 0.0,
    )

    decision = tenant_budget.should_refuse(
        db, tenant_id=TENANT_A, scope_key="*", intended_cost_usd=1.0,
    )
    assert decision.verdict == "refuse"
    assert "budget_exhausted" in decision.reason
    assert decision.threshold_usd == 10.0


# ── Cost-center + business-unit as enforcement scopes ───────────────


def test_budget_scopes_include_cost_center_and_business_unit():
    """v0.1.1 promotion: cost_center and business_unit are first-class
    budget enforcement targets, not just analytics dimensions."""
    from kya.tenant_budget import BUDGET_SCOPES, _PRINCIPAL_KINDS
    assert "cost_center" in BUDGET_SCOPES
    assert "business_unit" in BUDGET_SCOPES
    # But NOT principal kinds — caller cannot pass principal_kind="cost_center"
    assert "cost_center" not in _PRINCIPAL_KINDS
    assert "business_unit" not in _PRINCIPAL_KINDS


def test_set_budget_accepts_cost_center_scope(db):
    """A marketing-team cap is configurable like any other budget."""
    from kya.tenant_budget import get_budget, set_budget
    set_budget(
        db, tenant_id=None, scope="cost_center",
        scope_key="marketing-team",
        window="30d", threshold_usd=5000.0, hard_refuse=True,
    )
    cfg = get_budget(db, tenant_id=None, scope="cost_center",
                     scope_key="marketing-team", window="30d")
    assert cfg is not None
    assert cfg["threshold_usd"] == 5000.0
    assert cfg["hard_refuse"] is True


def test_set_budget_accepts_business_unit_scope(db):
    from kya.tenant_budget import get_budget, set_budget
    set_budget(
        db, tenant_id=None, scope="business_unit",
        scope_key="banking", window="7d", threshold_usd=2000.0,
    )
    cfg = get_budget(db, tenant_id=None, scope="business_unit",
                     scope_key="banking", window="7d")
    assert cfg is not None
    assert cfg["threshold_usd"] == 2000.0


def test_record_cost_event_normalizes_invalid_principal_kind(db):
    """principal_kind="cost_center" is not a principal kind — normalize
    to "agent" so the analytic attribute (cost_center=...) is the
    correct surface to use."""
    from sqlalchemy import select

    from kya._legacy_tables import kya_cost_events as t
    from kya.tenant_budget import record_cost_event

    eid = record_cost_event(
        db, tenant_id=TENANT_A, agent_key="agent-x",
        usd_amount=1.0, principal_kind="cost_center",  # invalid as principal
        request_id="req-norm",
    )
    assert eid > 0
    row = db.execute(select(t.c.principal_kind).where(t.c.id == eid)).first()
    assert row[0] == "agent"  # normalized


def test_short_window_budget_set_and_get(db):
    """Anomaly-tier windows (1m/5m/15m) work the same as enforcement
    windows — same DB row shape, same get/set roundtrip."""
    from kya.tenant_budget import get_budget, set_budget
    set_budget(
        db, tenant_id=None, scope="tenant", scope_key="*",
        window="5m", threshold_usd=10.0, hard_refuse=False,
    )
    cfg = get_budget(db, tenant_id=None, scope="tenant",
                     scope_key="*", window="5m")
    assert cfg is not None
    assert cfg["threshold_usd"] == 10.0
    assert cfg["window"] == "5m"


@pytest.mark.parametrize("window,threshold", [
    ("14d", 1500.0),    # bi-weekly sprint cap
    ("45d", 7500.0),    # FinOps 1.5-month cycle
    ("60d", 10000.0),   # bi-monthly
    ("90d", 15000.0),   # quarterly
    ("365d", 60000.0),  # annual
])
def test_long_enforcement_windows_set_and_get(db, window, threshold):
    """Each new long-horizon enforcement window must round-trip the
    same way the standard 30d window does."""
    from kya.tenant_budget import get_budget, set_budget
    set_budget(
        db, tenant_id=None, scope="cost_center",
        scope_key="engineering", window=window,
        threshold_usd=threshold, hard_refuse=True,
    )
    cfg = get_budget(db, tenant_id=None, scope="cost_center",
                     scope_key="engineering", window=window)
    assert cfg is not None
    assert cfg["threshold_usd"] == threshold
    assert cfg["window"] == window
    assert cfg["hard_refuse"] is True


def test_cost_center_budget_decision_via_mocked_spend(db, monkeypatch):
    """End-to-end: cost_center budget breach triggers refuse the same
    way tenant/agent budgets do — the scope is just a discriminator."""
    from kya import tenant_budget

    tenant_budget.set_budget(
        db, tenant_id=None, scope="cost_center",
        scope_key="marketing-team",
        window="30d", threshold_usd=5000.0, hard_refuse=True,
    )

    monkeypatch.setattr(
        "kya.tenant_budget.current_spend",
        lambda t, s, sk, w: 4990.0 if (s == "cost_center"
                                       and sk == "marketing-team"
                                       and w == "30d") else 0.0,
    )
    monkeypatch.setattr("kya.tenant_budget._burn_rate_per_sec",
                        lambda t, s, sk: 0.0)

    decision = tenant_budget.should_refuse(
        db, tenant_id=TENANT_A, scope="cost_center",
        scope_key="marketing-team",
        intended_cost_usd=20.0, window="30d",
    )
    assert decision.verdict == "refuse"
    assert "5000.00" in decision.reason
    assert "30d" in decision.reason
