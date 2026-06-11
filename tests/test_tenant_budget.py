"""Tests for kya.tenant_budget — direct economic governance primitive.

Covers:
  * Forecaster contract + default LinearExtrapolationForecaster math
  * Forecaster swap via set_forecaster() + KYA_BUDGET_FORECASTER env
  * Closed-set whitelisting (BUDGET_SCOPES / BUDGET_WINDOWS)
  * Only-tighten enforcement on tenant overrides
  * should_refuse() decision matrix (allow / warn / throttle / refuse)
  * Fail-soft contract when Valkey is unavailable (which is the default
    in this test process — no Valkey running, just verify nothing raises)

These tests intentionally do NOT require Valkey or PG. PG-only schema
behavior is exercised in the integration suite via KYA_TEST_PG_URL.
"""

from __future__ import annotations

import pytest

from kya.tenant_budget import (
    BUDGET_SCOPES,
    BUDGET_WINDOWS,
    DECISIONS,
    BudgetLoosensError,
    Decision,
    Forecast,
    LinearExtrapolationForecaster,
    current_spend,
    forecast_spend,
    get_forecaster,
    record_cost_event,
    set_forecaster,
    should_refuse,
)

# ── Forecaster math (pure-function) ─────────────────────────────────


def test_linear_forecaster_no_breach():
    """Burn rate insufficient to cross threshold within horizon → not breached."""
    f = LinearExtrapolationForecaster()
    out = f.forecast(
        current_usd=10.0,
        threshold_usd=100.0,
        burn_rate_usd_per_sec=0.001,
        horizon_sec=3600,
    )
    assert isinstance(out, Forecast)
    assert out.projected_usd == pytest.approx(10.0 + 3.6, rel=1e-3)
    assert out.breach_predicted is False
    assert out.breach_in_sec is None
    assert out.method == "linear"


def test_linear_forecaster_breach_within_horizon():
    """Burn rate sufficient to cross threshold → breach predicted with ETA."""
    f = LinearExtrapolationForecaster()
    out = f.forecast(
        current_usd=80.0,
        threshold_usd=100.0,
        burn_rate_usd_per_sec=1.0,
        horizon_sec=60,
    )
    assert out.breach_predicted is True
    assert out.breach_in_sec == 20  # (100-80)/1 = 20s


def test_linear_forecaster_zero_burn_below_threshold_no_breach():
    """Zero burn rate + room below threshold → no projected breach."""
    f = LinearExtrapolationForecaster()
    out = f.forecast(
        current_usd=50.0,
        threshold_usd=100.0,
        burn_rate_usd_per_sec=0.0,
        horizon_sec=3600,
    )
    assert out.breach_predicted is False
    assert out.breach_in_sec is None


def test_linear_forecaster_at_threshold_is_breach():
    """At threshold IS a breach — budget enforcement is inclusive."""
    f = LinearExtrapolationForecaster()
    out = f.forecast(
        current_usd=100.0,
        threshold_usd=100.0,
        burn_rate_usd_per_sec=0.0,
        horizon_sec=3600,
    )
    assert out.breach_predicted is True
    assert out.breach_in_sec is None  # zero burn → no ETA


def test_forecaster_swap_round_trip():
    """set_forecaster swaps the active impl; get_forecaster returns it."""
    original = get_forecaster()

    class _CountingForecaster:
        name = "test_counting"
        calls = 0
        def forecast(self, **kw):
            type(self).calls += 1
            return Forecast(
                current_usd=kw["current_usd"],
                projected_usd=kw["current_usd"],
                threshold_usd=kw["threshold_usd"],
                horizon_sec=kw["horizon_sec"],
                breach_predicted=False,
                breach_in_sec=None,
                method=self.name,
            )

    try:
        impl = _CountingForecaster()
        set_forecaster(impl)
        assert get_forecaster() is impl
        # forecast_spend uses the active forecaster
        out = forecast_spend("t", "tenant", "*", "1h",
                             horizon_sec=60, threshold_usd=100.0)
        assert out.method == "test_counting"
        assert _CountingForecaster.calls == 1
    finally:
        set_forecaster(original)


# ── Closed-set whitelisting ─────────────────────────────────────────


def test_budget_scopes_closed_set():
    """BUDGET_SCOPES covers 4 principal kinds + 2 organizational
    attributes promoted to enforcement scopes in v0.1.1."""
    assert frozenset({
        "tenant", "agent", "user", "service_account",
        "cost_center", "business_unit",
    }) == BUDGET_SCOPES


def test_budget_windows_closed_set():
    """v0.1.1 covers 12 windows total: 3 anomaly + 9 enforcement.
    Long-horizon presets (14d/45d/60d/90d/365d) address FinOps
    cycle requests that don't fit the standard month/week split."""
    assert frozenset({
        "1m", "5m", "15m",                            # anomaly
        "1h", "24h", "7d", "14d", "30d",              # enforcement (short)
        "45d", "60d", "90d", "365d",                  # enforcement (long)
    }) == BUDGET_WINDOWS


def test_long_enforcement_windows_have_ttl_and_seconds():
    """Every BUDGET_WINDOWS entry must have a matching Valkey TTL +
    forecast-horizon seconds mapping. Without this, ``_increment_windows``
    silently skips writes."""
    from kya.tenant_budget import (
        _VALKEY_TTL_SECONDS,
        _WINDOW_SECONDS,
        BUDGET_WINDOWS,
    )
    for w in BUDGET_WINDOWS:
        assert w in _WINDOW_SECONDS, (
            f"window {w!r} missing from _WINDOW_SECONDS"
        )
        assert w in _VALKEY_TTL_SECONDS, (
            f"window {w!r} missing from _VALKEY_TTL_SECONDS"
        )
        # TTL must exceed its window so boundary writes don't expire
        assert _VALKEY_TTL_SECONDS[w] > _WINDOW_SECONDS[w], (
            f"window {w!r} TTL ({_VALKEY_TTL_SECONDS[w]}s) "
            f"not greater than its duration ({_WINDOW_SECONDS[w]}s)"
        )


def test_window_tiers_disjoint_and_cover_budget_windows():
    """ANOMALY_WINDOWS ∪ ENFORCEMENT_WINDOWS == BUDGET_WINDOWS, and
    the two tiers must not overlap (every window is either anomaly
    OR enforcement, never both)."""
    from kya.tenant_budget import ANOMALY_WINDOWS, ENFORCEMENT_WINDOWS
    assert ANOMALY_WINDOWS.isdisjoint(ENFORCEMENT_WINDOWS)
    assert (ANOMALY_WINDOWS | ENFORCEMENT_WINDOWS) == BUDGET_WINDOWS


def test_anomaly_windows_aligned_with_realtime():
    """Anomaly tier must match realtime.WINDOWS for the shared windows
    so operators see consistent semantics across rogue + cost."""
    from kya.realtime import WINDOWS as RT_WINDOWS
    from kya.tenant_budget import ANOMALY_WINDOWS
    for w in ANOMALY_WINDOWS:
        assert w in RT_WINDOWS, f"anomaly window {w!r} missing from realtime"


def test_decisions_closed_set():
    assert frozenset({"allow", "warn", "throttle", "refuse"}) == DECISIONS


def test_current_spend_rejects_unknown_scope_or_window():
    """Caller-supplied strings must not silently widen the namespace."""
    assert current_spend("t", "bogus_scope", "*", "1h") == 0.0
    assert current_spend("t", "tenant", "*", "bogus_window") == 0.0


# ── Fail-soft contract (no Valkey, no DB in this process) ───────────


def test_record_cost_event_fail_soft_without_db():
    """record_cost_event with db=None and no Valkey must not raise."""
    # Pass a sentinel `db` that can't be used; the function must swallow.
    class _Dud:
        def execute(self, *a, **k):
            raise RuntimeError("no db here")
        def rollback(self):
            pass
    out = record_cost_event(
        _Dud(),
        tenant_id="t-001",
        agent_key="agent-a",
        usd_amount=1.50,
        request_id="req-1",
    )
    assert out == 0


def test_record_cost_event_skips_zero_or_negative():
    """Defensive: zero / negative amounts are silently skipped."""
    class _Dud:
        called = 0
        def execute(self, *a, **k):
            type(self).called += 1
            raise RuntimeError("must not be called")
    d = _Dud()
    assert record_cost_event(d, tenant_id="t", agent_key="a", usd_amount=0) == 0
    assert record_cost_event(d, tenant_id="t", agent_key="a", usd_amount=-5) == 0
    assert _Dud.called == 0


def test_current_spend_fail_soft_without_redis():
    """No Valkey → current_spend returns 0.0, never raises."""
    assert current_spend("any", "tenant", "*", "1h") == 0.0
    assert current_spend("any", "agent", "x", "24h") == 0.0


def test_increment_windows_rejects_invalid_scope():
    """_increment_windows must silently drop scope strings outside
    BUDGET_SCOPES so caller-supplied bad input cannot pollute the
    Valkey keyspace. Regression for v0.1.1 #5."""
    from kya.tenant_budget import _increment_windows
    # Should not raise + should not call Valkey (we have no Valkey
    # here anyway, so the test is structural — just verify it
    # short-circuits without iteration).
    _increment_windows("t-1", "bogus_scope_name", "key", 1.0)
    _increment_windows("t-1", "tenant", "", 1.0)        # empty scope_key
    _increment_windows("t-1", "tenant", "x" * 500, 1.0)  # too long


def test_micro_dollar_precision_preserves_sub_cent_amounts():
    """Sub-cent amounts ($0.0001 embedding calls) must NOT round to
    zero in the Valkey encoding. Regression for v0.1.1 #3."""
    from kya.tenant_budget import _USD_PRECISION
    # _USD_PRECISION is micro-dollars; $0.0001 → 100 μUSD (well > 0)
    assert _USD_PRECISION == 1_000_000
    assert int(round(0.0001 * _USD_PRECISION)) == 100
    assert int(round(0.000001 * _USD_PRECISION)) == 1
    # Below 1 μUSD still rounds to 0 — that's $0.0000005 which is
    # below any real LLM unit cost.
    assert int(round(0.0000004 * _USD_PRECISION)) == 0


def test_valkey_cost_key_carries_version():
    """The Valkey key path must include a schema-version segment so
    encoding-incompatible upgrades leave old data orphaned at old
    paths instead of being read with the wrong encoding.

    Bumping the encoding without bumping ``_COST_KEY_VERSION`` would
    silently produce wrong cost numbers — this test fails fast in
    that scenario."""
    from kya.tenant_budget import _COST_KEY_VERSION, _cost_key

    # Current encoding is micro-dollars → version must be v2 or higher.
    # If you change the storage encoding (e.g., to nano-dollars),
    # BUMP THIS CONSTANT to v3 and update the asserted prefix below.
    assert _COST_KEY_VERSION == "v2"

    key = _cost_key("tenant-x", "tenant", "*", "1h")
    assert key.startswith("kya:cost:v2:")
    assert key == "kya:cost:v2:tenant-x:tenant:*:1h"

    # Distinct namespaces for distinct scopes — no key collisions across
    # tenant / agent / user / cost_center / business_unit / service_account
    keys = {
        _cost_key("t", "tenant", "*", "1h"),
        _cost_key("t", "agent", "x", "1h"),
        _cost_key("t", "cost_center", "marketing", "1h"),
        _cost_key("t", "business_unit", "banking", "1h"),
        _cost_key("t", "user", "alice", "1h"),
        _cost_key("t", "service_account", "nightly", "1h"),
    }
    assert len(keys) == 6  # all distinct, no collisions


def test_should_refuse_allows_when_no_budget_configured(monkeypatch):
    """KYA is opt-in for budgets — unconfigured → allow."""
    class _Dud:
        def execute(self, *a, **k):
            class _R:
                def first(self_inner): return None
            return _R()
    decision = should_refuse(_Dud(), tenant_id="t", scope_key="*",
                             intended_cost_usd=10.0)
    assert isinstance(decision, Decision)
    assert decision.verdict == "allow"
    assert decision.reason == ""


# ── Only-tighten semantics (unit, in-memory) ────────────────────────


def test_budget_loosens_error_is_value_error_subclass():
    """Callers catching ValueError or OverrideLoosensError must still
    catch BudgetLoosensError."""
    from kya.tenant_weights import OverrideLoosensError
    assert issubclass(BudgetLoosensError, OverrideLoosensError)
    assert issubclass(BudgetLoosensError, ValueError)
    err = BudgetLoosensError("test")
    assert isinstance(err, ValueError)


# ── Decision aggregation (strictness ordering) ──────────────────────


def _fake_configs_for_windows(budgets_by_window):
    """Build a monkeypatched _get_budgets_for_windows that ignores db
    and returns the same fixture regardless of the windows requested.

    Mirrors v0.1.1 should_refuse semantics: should_refuse calls
    _get_budgets_for_windows ONCE per decision (no longer per-window)."""
    def _impl(db, *, tenant_id, scope, scope_key, windows):
        out = {}
        for w in windows:
            b = budgets_by_window.get(w)
            if b is None:
                continue
            out[w] = {"tenant_id": tenant_id, "scope": scope,
                      "scope_key": scope_key, "window": w, **b}
        return out
    return _impl


def test_should_refuse_strictness_picks_strongest_window(monkeypatch):
    """When multiple windows configure budgets, the strictest verdict wins."""
    budgets = {
        "1h":  {"threshold_usd": 100.0,  "hard_refuse": True,
                "forecast_horizon_sec": 60},
        "24h": {"threshold_usd": 1000.0, "hard_refuse": False,
                "forecast_horizon_sec": 3600},
    }
    spends = {"1h": 99.0, "24h": 50.0}

    monkeypatch.setattr("kya.tenant_budget._get_budgets_for_windows",
                        _fake_configs_for_windows(budgets))
    monkeypatch.setattr("kya.tenant_budget.current_spend",
                        lambda t, s, sk, w: spends.get(w, 0.0))
    monkeypatch.setattr("kya.tenant_budget._burn_rate_per_sec",
                        lambda t, s, sk: 0.0)

    decision = should_refuse(object(), tenant_id="t", scope_key="*",
                             intended_cost_usd=2.0)
    assert decision.verdict == "refuse"
    assert "1h" in decision.reason
    assert "budget_exhausted" in decision.reason


def test_should_refuse_warn_below_threshold_but_forecast_breach(monkeypatch):
    """Spend below threshold, but forecaster predicts breach → warn (soft)."""
    budgets = {
        "1h": {"threshold_usd": 100.0, "hard_refuse": False,
               "forecast_horizon_sec": 3600},
    }
    monkeypatch.setattr("kya.tenant_budget._get_budgets_for_windows",
                        _fake_configs_for_windows(budgets))
    monkeypatch.setattr("kya.tenant_budget.current_spend",
                        lambda t, s, sk, w: 50.0 if w == "1h" else 0.0)
    monkeypatch.setattr("kya.tenant_budget._burn_rate_per_sec",
                        lambda t, s, sk: 1.0)  # $1/sec → ~$3600 in 1h

    decision = should_refuse(object(), tenant_id="t", scope_key="*",
                             intended_cost_usd=0.0)
    assert decision.verdict == "warn"
    assert "budget_forecast_breach" in decision.reason
