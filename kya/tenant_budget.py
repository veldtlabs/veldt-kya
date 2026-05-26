"""
Tenant cost budgets — direct economic governance primitive.

Closes the Economic Control gap in KYA's four-pillar story. Where
``cost.py`` elevates risk (via the static score → critical bucket →
action_gate flag_for_review), ``tenant_budget.py`` adds DIRECT spend
enforcement with first-class primitives:

    * Per-(tenant, scope, window) running spend counters in Valkey
    * Configurable thresholds with only-tighten composition
    * Swappable forecaster interface for "will we breach in N hours?"
    * Single ``should_refuse()`` predicate the embedding layer
      (FastAPI route, framework hook, or in-process action gate)
      consults

Architecture fit
----------------
- Cross-backend (PG / MySQL / SQLite / DuckDB) via ``_legacy_tables``
  Table definitions + ``_dialect_helpers`` portable upsert /
  returning-id dispatchers
- Reuses ``realtime._get_redis()`` + the WINDOWS / TTL pattern
- Reuses ``tenant_weights.OverrideLoosensError`` (re-exported here as
  ``BudgetLoosensError`` for clarity at the call site)
- Reuses ``_emit.emit()`` so budget breaches fan out to configured
  external SIEM/GRC sinks alongside other findings
- Fail-soft contract: Valkey unreachable → degrades to DB rollup; DB
  unreachable → returns "allow" with a logged warning so the request
  path is never broken by the budget subsystem

Public API
----------
    ensure_tables(db)
    set_budget(db, *, threshold_usd, ...) -> dict
    get_budget(db, ...) -> dict | None
    list_budgets(db, ...) -> list[dict]
    delete_budget(db, ...) -> bool
    record_cost_event(db, *, tenant_id, agent_key, usd_amount, ...) -> int
    current_spend(tenant_id, scope, scope_key, window) -> float
    forecast_spend(tenant_id, scope, scope_key, window, horizon_sec,
                   threshold_usd) -> Forecast
    should_refuse(db, tenant_id, scope_key, intended_cost_usd=0.0) -> Decision
    budget_status(db, tenant_id, scope_key) -> dict
    set_forecaster(impl: BudgetForecaster) -> None
    get_forecaster() -> BudgetForecaster
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from ._emit import emit
from .realtime import WINDOWS, _get_redis
from .tenant_weights import OverrideLoosensError

# ── Observability counters ──────────────────────────────────────────
# Prometheus-style metrics — registered lazily so the dependency is
# soft. Operators inspecting /metrics see budget decisions + audit
# anomalies without writing instrumentation themselves.

_METRICS: dict[str, Any] = {}


def _get_counter(name: str, doc: str, labels: tuple[str, ...] = ()):
    """Lazy-register a Counter; degrade to a no-op if prometheus_client
    isn't installed."""
    if name in _METRICS:
        return _METRICS[name]
    try:  # pragma: no cover — exercised in prod with prometheus_client
        from prometheus_client import Counter
        counter = Counter(name, doc, labels) if labels else Counter(name, doc)
    except ImportError:
        class _Noop:
            def labels(self, *a, **k): return self
            def inc(self, *a, **k): pass
        counter = _Noop()
    _METRICS[name] = counter
    return counter


def _bump(metric_name: str, doc: str, **labels) -> None:
    """Increment a counter with the given labels. Cheap + fail-soft."""
    try:
        counter = _get_counter(metric_name, doc, tuple(labels.keys()))
        if labels:
            counter.labels(**labels).inc()
        else:
            counter.inc()
    except Exception:  # pragma: no cover
        pass

try:  # SQLAlchemy is optional at module import; functions error at call time
    from sqlalchemy import and_, or_, select
    from sqlalchemy import delete as _sa_delete
    _SA_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SA_AVAILABLE = False
    and_ = or_ = select = _sa_delete = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# ── Closed sets ─────────────────────────────────────────────────────
# Caller-supplied strings cannot expand any of these. Same discipline
# as ALLOWED_SIGNAL_KINDS / VALID_EVIDENCE_KINDS elsewhere.
#
# Two distinct universes:
#
#   _PRINCIPAL_KINDS — values valid as ``record_cost_event(
#                        principal_kind=...)``. Matches KYP's three
#                        principal kinds plus "tenant" for tenant-wide
#                        roll-up writes.
#
#   BUDGET_SCOPES    — values valid as ``set_budget(scope=...)`` and
#                        ``should_refuse(scope=...)``. Includes the
#                        principal kinds AND organizational attributes
#                        (cost_center, business_unit) that aren't
#                        themselves principal types but ARE legitimate
#                        budget enforcement targets.
#
# A cost event tagged with cost_center="marketing-team" increments
# both the agent and cost_center Valkey counters, so the
# marketing-team budget enforcement is data-driven rather than
# requiring a separate write path.
_PRINCIPAL_KINDS = frozenset({"tenant", "agent", "user", "service_account"})
BUDGET_SCOPES = frozenset(
    _PRINCIPAL_KINDS | {"cost_center", "business_unit"}
)

# Budget windows are split into two semantic tiers:
#
#   * ANOMALY tier (1m / 5m / 15m) — burst-detection windows aligned
#     with realtime.WINDOWS. Best paired with hard_refuse=False
#     (warn / throttle) because 60-second linear forecasts are noisy;
#     these catch prompt-injection-driven cost bursts and runaway
#     loops faster than waiting for the 1h signal.
#
#   * ENFORCEMENT tier (1h / 24h / 7d / 30d) — operational governance
#     windows. Suitable for hard_refuse=True; aligned with FinOps and
#     monthly-budget cycles.
#
# Operators don't need to configure every window — budgets are opt-in
# per (scope, scope_key, window). A typical deployment configures
# 5m + 1h + 30d caps and leaves the others untouched.
BUDGET_WINDOWS = frozenset({
    # Anomaly tier — burst detection (warn / throttle pairing)
    "1m", "5m", "15m",
    # Enforcement tier — operational governance (hard-refuse pairing)
    "1h", "24h", "7d",
    "14d",      # bi-weekly sprint cycle
    "30d",      # monthly (most common)
    "45d",      # 1.5-month FinOps cycle
    "60d",      # bi-monthly
    "90d",      # quarterly
    "365d",     # annual
})
ANOMALY_WINDOWS = frozenset({"1m", "5m", "15m"})
ENFORCEMENT_WINDOWS = frozenset({
    "1h", "24h", "7d", "14d", "30d", "45d", "60d", "90d", "365d",
})

DECISIONS = frozenset({"allow", "warn", "throttle", "refuse"})

# Window → seconds for forecast horizon arithmetic.
_DAY = 86_400
_WINDOW_SECONDS: dict[str, int] = {
    "1m":   60,
    "5m":   300,
    "15m":  900,
    "1h":   3600,
    "24h":  _DAY,
    "7d":   7   * _DAY,
    "14d":  14  * _DAY,
    "30d":  30  * _DAY,
    "45d":  45  * _DAY,
    "60d":  60  * _DAY,
    "90d":  90  * _DAY,
    "365d": 365 * _DAY,
}

# Valkey TTLs. Reuses realtime.WINDOWS where they overlap (1m/5m/15m/
# 1h/24h/7d); long-horizon enforcement windows derive their own TTL
# as window-seconds + 1h grace so an event hitting the boundary
# doesn't expire before a read can see it.
_GRACE_SEC = 3600
_VALKEY_TTL_SECONDS: dict[str, int] = {
    "1m":   WINDOWS.get("1m",  (60, 90))[1],
    "5m":   WINDOWS.get("5m",  (300, 360))[1],
    "15m":  WINDOWS.get("15m", (900, 1020))[1],
    "1h":   WINDOWS.get("1h",  (3600, 4200))[1],
    "24h":  WINDOWS.get("24h", (_DAY, _DAY + 3600))[1],
    "7d":   WINDOWS.get("7d",  (7 * _DAY, 7 * _DAY + 3600))[1],
    "14d":  14  * _DAY + _GRACE_SEC,
    "30d":  30  * _DAY + _GRACE_SEC,
    "45d":  45  * _DAY + _GRACE_SEC,
    "60d":  60  * _DAY + _GRACE_SEC,
    "90d":  90  * _DAY + _GRACE_SEC,
    "365d": 365 * _DAY + _GRACE_SEC,
}


# ── Re-export for clarity at the call site ──────────────────────────

class BudgetLoosensError(OverrideLoosensError):
    """Raised when a budget update would relax the effective cap.

    Subclass of ``tenant_weights.OverrideLoosensError`` so callers
    catching the parent class get budget violations for free.
    """


# ── Schema (cross-backend via _legacy_tables) ───────────────────────

def ensure_tables(db) -> None:
    """Idempotent — runs on PG / MySQL / SQLite / DuckDB.

    Same pattern as every other legacy table: defer to
    ``create_legacy_tables`` which applies the right
    ``schema_translate_map`` for the bound dialect.
    """
    from ._legacy_tables import (
        create_legacy_tables,
        kya_budget_changes,
        kya_cost_events,
        kya_tenant_cost_budgets,
    )

    create_legacy_tables(
        db,
        [kya_tenant_cost_budgets, kya_budget_changes, kya_cost_events],
    )
    db.commit()


# ── Forecaster — modular, swappable ─────────────────────────────────

@dataclass(frozen=True)
class Forecast:
    """Outcome of ``forecast_spend()`` — the embedding layer turns this
    into a decision."""
    current_usd: float
    projected_usd: float
    threshold_usd: float
    horizon_sec: int
    breach_predicted: bool
    breach_in_sec: int | None  # None if no breach within horizon
    method: str                # forecaster identifier for audit


class BudgetForecaster(Protocol):
    """Swap interface. Default is LinearExtrapolation; drop-in
    replacements (EWMA, Prophet, LLM-judge) implement the same shape.
    """

    name: str

    def forecast(
        self,
        *,
        current_usd: float,
        threshold_usd: float,
        burn_rate_usd_per_sec: float,
        horizon_sec: int,
    ) -> Forecast: ...


class LinearExtrapolationForecaster:
    """Project current burn rate forward. Cheap, deterministic, no deps.

    Sufficient for v1 — most cost-runaway events have monotone burn
    profiles over the forecast horizon (1h / 24h). For non-stationary
    workloads, swap in an EWMA or LLM-judge forecaster via
    ``set_forecaster()``.
    """

    name = "linear"

    def forecast(
        self,
        *,
        current_usd: float,
        threshold_usd: float,
        burn_rate_usd_per_sec: float,
        horizon_sec: int,
    ) -> Forecast:
        projected = current_usd + max(0.0, burn_rate_usd_per_sec) * horizon_sec
        breach = projected >= threshold_usd
        breach_in_sec: int | None = None
        if breach and burn_rate_usd_per_sec > 0:
            remaining = max(0.0, threshold_usd - current_usd)
            breach_in_sec = int(remaining / burn_rate_usd_per_sec)
        return Forecast(
            current_usd=current_usd,
            projected_usd=projected,
            threshold_usd=threshold_usd,
            horizon_sec=horizon_sec,
            breach_predicted=breach,
            breach_in_sec=breach_in_sec,
            method=self.name,
        )


_forecaster: BudgetForecaster = LinearExtrapolationForecaster()
_forecaster_lock = threading.Lock()


def set_forecaster(impl: BudgetForecaster) -> None:
    """Swap the active forecaster. Thread-safe via lock; assignment is
    atomic in CPython but the lock keeps semantics explicit for
    multi-threaded callers."""
    global _forecaster
    with _forecaster_lock:
        _forecaster = impl


def get_forecaster() -> BudgetForecaster:
    return _forecaster


# ── Valkey accounting ───────────────────────────────────────────────
# Key shape mirrors realtime._window_key() but in its own namespace so
# rogue-signal counters and cost counters cannot collide.
#
# Storage unit: micro-dollars (μUSD = USD × 10⁶). Chosen over cents to
# preserve precision below the $0.01 threshold — embedding-call costs
# (~$0.0001/1K tokens), prompt-cache reads, and high-volume small
# completions are sub-cent and would otherwise round to zero. Valkey
# INCRBY is integer-only, so we multiply at write time and divide at
# read time. Max representable amount per single increment: 2^63-1 μUSD
# ≈ $9.2 trillion (Valkey INCRBY uses int64), so overflow is not a
# practical concern.
_USD_PRECISION = 1_000_000  # micro-dollars

# Cost-key schema version. The version segment is embedded in the
# Valkey key path so an in-place upgrade between encoding-incompatible
# releases leaves the old keys orphaned at their old paths — they
# expire naturally via the existing TTL (max 30d + grace) without any
# operator coordination, migration script, or FLUSHDB step.
#
#   v1 (KYA 0.1.0 — DEPRECATED): cents (USD × 10²)
#       Key:  kya:cost:<tenant>:<scope>:<key>:<window>
#       Read with float(cents) / 100.0
#
#   v2 (KYA 0.1.1 — CURRENT):    micro-dollars (USD × 10⁶)
#       Key:  kya:cost:v2:<tenant>:<scope>:<key>:<window>
#       Read with float(micros) / 1_000_000.0
#
# Operators upgrading mid-window see a one-time gap (the new pod
# starts at zero spend) but no incorrect data — v1 keys are not
# read by v2 code; v2 keys are not present in old code. A safe
# zero-downtime rollout is therefore Just A Restart.
_COST_KEY_VERSION = "v2"
_COST_KEY_PREFIX = f"kya:cost:{_COST_KEY_VERSION}"

# Max length of caller-supplied scope_key — must fit
# kya_tenant_cost_budgets.scope_key VARCHAR(200) and avoids Valkey
# keyspace pollution from runaway-long identifiers.
_MAX_SCOPE_KEY_LEN = 200


def _cost_key(tenant_id: str, scope: str, scope_key: str, window: str) -> str:
    return f"{_COST_KEY_PREFIX}:{tenant_id}:{scope}:{scope_key}:{window}"


def _increment_windows(
    tenant_id: str,
    scope: str,
    scope_key: str,
    usd_amount: float,
) -> None:
    """Increment every cost window for (scope, scope_key). Fail-soft.

    Validates ``scope`` against ``BUDGET_SCOPES`` and bounds
    ``scope_key`` length so caller-supplied strings cannot pollute the
    Valkey keyspace. Sub-cent amounts (e.g. embedding calls at
    $0.0001) are preserved via micro-dollar storage.
    """
    # Closed-set + length-bound validation — defense in depth.
    # _increment_windows is internal but scope_key originates from
    # caller input (cost_center, business_unit, agent_key, etc.).
    if scope not in BUDGET_SCOPES:
        return
    if not scope_key or len(scope_key) > _MAX_SCOPE_KEY_LEN:
        return
    if usd_amount <= 0:
        return

    r = _get_redis()
    if r is None:
        return

    # Micro-dollars: preserves precision down to $0.000001 per event.
    micros = int(round(usd_amount * _USD_PRECISION))
    if micros <= 0:
        return
    try:
        pipe = r.pipeline()
        for window, ttl in _VALKEY_TTL_SECONDS.items():
            key = _cost_key(tenant_id, scope, scope_key, window)
            pipe.incrby(key, micros)
            pipe.expire(key, ttl)
        pipe.execute()
    except Exception as exc:  # noqa: BLE001
        logger.debug("[kya-budget] _increment_windows: %s", exc)


def current_spend(
    tenant_id: str,
    scope: str,
    scope_key: str,
    window: str,
) -> float:
    """Read running spend in USD for (scope, scope_key, window).
    Returns 0.0 on Valkey miss; the caller can fall back to a DB
    rollup if it needs ground-truth (rare on the hot path)."""
    if scope not in BUDGET_SCOPES or window not in BUDGET_WINDOWS:
        return 0.0
    r = _get_redis()
    if r is None:
        return 0.0
    try:
        raw = r.get(_cost_key(tenant_id, scope, scope_key, window))
    except Exception as exc:  # noqa: BLE001
        logger.debug("[kya-budget] current_spend: %s", exc)
        return 0.0
    if raw is None:
        return 0.0
    try:
        return float(int(raw)) / _USD_PRECISION  # micro-dollars → USD
    except (TypeError, ValueError):
        return 0.0


def _burn_rate_per_sec(
    tenant_id: str,
    scope: str,
    scope_key: str,
) -> float:
    """Derive recent burn rate from the 1h window. Cheap, matches how
    ``cost.py`` reasons about hourly bursts."""
    hourly = current_spend(tenant_id, scope, scope_key, "1h")
    return hourly / _WINDOW_SECONDS["1h"]


# ── Cost-event recorder ─────────────────────────────────────────────

# Provider auto-detection from model id. Order matters: routed-provider
# prefixes (with a dot — bedrock/azure routing) match FIRST because they
# include vendor brand names ("anthropic.claude") that would otherwise
# match the direct-vendor entries below.
_PROVIDER_PREFIXES: tuple[tuple[str, str], ...] = (
    # Bedrock routing first — "anthropic.claude" should attribute to
    # bedrock, not anthropic, since cost is billed by AWS.
    ("amazon.", "bedrock"),
    ("anthropic.", "bedrock"),
    ("meta.", "bedrock"),
    ("mistral.", "bedrock"),
    ("ai21.", "bedrock"),
    ("cohere.", "bedrock"),
    # Azure-routed OpenAI second
    ("azureopenai", "azure"),
    # Direct-vendor prefixes
    ("claude", "anthropic"),
    ("gpt-", "openai"),
    ("o1-", "openai"),
    ("o3-", "openai"),
    ("o4-", "openai"),
    ("text-embedding", "openai"),
    ("gemini", "google"),
    ("palm", "google"),
    ("text-bison", "google"),
    ("chat-bison", "google"),
    ("command", "cohere"),
    ("mixtral", "mistral"),
    ("mistral-", "mistral"),
    ("llama", "self_hosted"),
    ("qwen", "self_hosted"),
    ("deepseek", "self_hosted"),
)

_VALID_OUTCOMES = frozenset({
    "success", "failure", "refused", "partial", "unknown",
})


def derive_provider(model_used: str | None) -> str | None:
    """Best-effort provider attribution from a model identifier.

    Used by record_cost_event when ``provider`` isn't supplied. Pure
    function; exposed as public API so callers can normalize before
    persisting elsewhere."""
    if not model_used:
        return None
    m = model_used.lower()
    for prefix, provider in _PROVIDER_PREFIXES:
        if m.startswith(prefix) or prefix in m:
            return provider
    return "other"


def record_cost_event(
    db,
    *,
    tenant_id: str,
    agent_key: str,
    usd_amount: float,
    principal_kind: str = "agent",
    principal_id: str | None = None,
    # Token breakdown (analytics + cache-efficiency dashboards)
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cached_tokens: int | None = None,
    input_token_cost_usd: float | None = None,
    output_token_cost_usd: float | None = None,
    # Model + provider (FinOps dashboards)
    model_used: str | None = None,
    provider: str | None = None,
    # Chargeback + business reporting
    cost_center: str | None = None,
    business_unit: str | None = None,
    environment: str | None = None,
    # Causal-chain linkage
    invocation_id: int | None = None,
    parent_request_id: str | None = None,
    # Performance + outcome
    latency_ms: int | None = None,
    outcome: str | None = None,
    # Flexible
    tags: dict | None = None,
    request_id: str | None = None,
) -> int:
    """Append-only cost event + Valkey window increments + fan-out emit.

    Analytics-ready: provider is auto-derived from ``model_used`` when
    not supplied; outcome is validated against ``_VALID_OUTCOMES``;
    cost_center / business_unit / environment flow into indexed columns
    so chargeback dashboards run a single GROUP BY.

    Returns the inserted event id (or ``0`` on DB unavailable / dup).
    Idempotent on (request_id) when supplied. Fail-soft: a DB hiccup
    does NOT raise — it logs and returns 0 so request flow continues.
    """
    if usd_amount <= 0:
        return 0
    # Phase 4a.1 — rate limit. Off-by-default; opt in via
    # KYA_RATE_LIMIT_RPS_RECORD_COST_EVENT etc.
    try:
        from .rate_limit import maybe_rate_limit
        maybe_rate_limit(tenant_id, "record_cost_event")
    except Exception as exc:
        logger.debug(
            "[KYA-COST] rate-limit check raised: %s", exc)
    # principal_kind must be a PRINCIPAL kind, not an enforcement
    # scope. cost_center / business_unit aren't principal types, so a
    # caller passing them here is normalized to "agent".
    if principal_kind not in _PRINCIPAL_KINDS:
        principal_kind = "agent"
    principal_id = principal_id or agent_key

    # Derive provider if not supplied — caller may explicitly pass
    # provider="self_hosted" or similar to override.
    if provider is None:
        provider = derive_provider(model_used)

    # Validate outcome (closed set, NULL allowed)
    if outcome is not None and outcome not in _VALID_OUTCOMES:
        outcome = "unknown"

    # Hot-path counters first (Valkey), then DB ledger. Order matters:
    # losing a DB row is recoverable from emit fanout; losing a Valkey
    # increment leaks budget across windows.
    #
    # Increment every applicable scope so a single cost event updates
    # tenant + agent + principal + organizational-attribute counters
    # in one Valkey pipeline. Attributes are only incremented when
    # the caller actually tagged the event with them.
    _increment_windows(tenant_id, "tenant", "*", usd_amount)
    _increment_windows(tenant_id, "agent", agent_key, usd_amount)
    if principal_kind != "agent":
        _increment_windows(tenant_id, principal_kind, principal_id, usd_amount)
    if cost_center:
        _increment_windows(tenant_id, "cost_center", cost_center, usd_amount)
    if business_unit:
        _increment_windows(tenant_id, "business_unit", business_unit,
                           usd_amount)

    event_id = 0
    if _SA_AVAILABLE and db is not None:
        try:
            from ._dialect_helpers import insert_returning_id
            from ._legacy_tables import kya_cost_events
            event_id = insert_returning_id(
                db,
                kya_cost_events,
                {
                    "tenant_id": tenant_id,
                    "agent_key": agent_key,
                    "principal_kind": principal_kind,
                    "principal_id": principal_id,
                    "usd_amount": usd_amount,
                    "input_token_cost_usd": input_token_cost_usd,
                    "output_token_cost_usd": output_token_cost_usd,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cached_tokens": cached_tokens,
                    "model_used": model_used,
                    "provider": provider,
                    "cost_center": cost_center,
                    "business_unit": business_unit,
                    "environment": environment,
                    "invocation_id": invocation_id,
                    "parent_request_id": parent_request_id,
                    "latency_ms": latency_ms,
                    "outcome": outcome,
                    "tags": tags,
                    "request_id": request_id,
                },
            ) or 0
            db.commit()
        except Exception as exc:  # noqa: BLE001
            # Idempotency conflict on request_id, or transient DB issue.
            # Either way: don't fail the request path.
            logger.debug("[kya-budget] record_cost_event: %s", exc)
            try:
                db.rollback()
            except Exception:  # pragma: no cover
                pass

    # Bidirectional emit — external SIEM / cost-observability sinks see
    # this. Emitter errors never propagate to the request path.
    try:
        emit("kya_cost_events", {
            "tenant_id": tenant_id,
            "agent_key": agent_key,
            "principal_kind": principal_kind,
            "principal_id": principal_id,
            "usd_amount": usd_amount,
            "model_used": model_used,
            "provider": provider,
            "cost_center": cost_center,
            "business_unit": business_unit,
            "environment": environment,
            "invocation_id": invocation_id,
            "latency_ms": latency_ms,
            "outcome": outcome,
            "request_id": request_id,
            "ts": time.time(),
        })
    except Exception:  # pragma: no cover
        pass

    return event_id


# ── Budget configuration (only-tighten) ─────────────────────────────

def _platform_default_threshold(
    db,
    *,
    scope: str,
    scope_key: str,
    window: str,
) -> float | None:
    """Look up the platform default (tenant_id IS NULL) for a slot.
    Cross-backend safe: uses ORM ``IS NULL`` rather than PG-specific
    ``IS NOT DISTINCT FROM``."""
    from ._legacy_tables import kya_tenant_cost_budgets as t
    stmt = select(t.c.threshold_usd).where(
        t.c.tenant_id.is_(None),
        t.c.scope == scope,
        t.c.scope_key == scope_key,
        t.c.time_window == window,
    )
    row = db.execute(stmt).first()
    return float(row[0]) if row else None


def _check_only_tighten(
    db,
    tenant_id: str | None,
    scope: str,
    scope_key: str,
    window: str,
    new_threshold: float,
) -> None:
    """Reject any tenant override that would RAISE the effective cap
    above the platform default. 'Tighten' for budgets means a smaller
    number (lower cap = stricter)."""
    if tenant_id is None:
        return  # platform admin freely sets the platform default
    pd = _platform_default_threshold(db, scope=scope, scope_key=scope_key,
                                     window=window)
    if pd is None:
        return  # no platform default → any tenant value is fine
    if new_threshold > pd:
        raise BudgetLoosensError(
            f"budget loosen rejected: tenant cap ${new_threshold:.2f} > "
            f"platform default ${pd:.2f} "
            f"(scope={scope}, key={scope_key}, window={window})"
        )


def _log_change(
    db,
    *,
    tenant_id: str | None,
    scope: str,
    scope_key: str,
    window: str,
    old_threshold: float | None,
    new_threshold: float | None,
    old_hard_refuse: bool | None,
    new_hard_refuse: bool | None,
    action: str,
    changed_by: str | None,
    reason: str | None,
) -> None:
    """Append-only audit entry for budget config mutations. Same shape
    as ``tenant_weights.kya_weight_changes``.

    Audit failures are logged at WARNING (not debug) and surface a
    Prometheus counter — silent audit gaps are an attack surface, not
    a backgroundable concern."""
    if not _SA_AVAILABLE:
        return
    try:
        from ._legacy_tables import kya_budget_changes
        db.execute(kya_budget_changes.insert().values(
            tenant_id=tenant_id, scope=scope, scope_key=scope_key,
            time_window=window,
            old_threshold_usd=old_threshold,
            new_threshold_usd=new_threshold,
            old_hard_refuse=old_hard_refuse,
            new_hard_refuse=new_hard_refuse,
            action=action,
            changed_by=changed_by,
            reason=reason,
        ))
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "[kya-budget] AUDIT GAP — _log_change failed for "
            "(tenant=%s, scope=%s, key=%s, window=%s, action=%s): %s",
            tenant_id, scope, scope_key, window, action, exc,
        )
        _bump("kya_budget_audit_failures_total",
              "Budget audit-log write failures (each one is a forensic gap)",
              action=action)


def set_budget(
    db,
    *,
    tenant_id: str | None,
    scope: str,
    scope_key: str,
    window: str,
    threshold_usd: float,
    hard_refuse: bool = False,
    forecast_horizon_sec: int = 3600,
    created_by: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Create / update a budget. Tenant-scoped writes are checked
    against the platform default via ``_check_only_tighten``. Every
    mutation logs to ``kya_budget_changes`` for tamper-evident audit
    of who-changed-what-when (no payload deletion / mutation possible
    after the row lands)."""
    if scope not in BUDGET_SCOPES:
        raise ValueError(f"scope must be one of {sorted(BUDGET_SCOPES)}")
    if window not in BUDGET_WINDOWS:
        raise ValueError(f"window must be one of {sorted(BUDGET_WINDOWS)}")
    if threshold_usd <= 0:
        raise ValueError("threshold_usd must be > 0")
    if not _SA_AVAILABLE:
        raise RuntimeError("SQLAlchemy required for set_budget()")

    _check_only_tighten(db, tenant_id, scope, scope_key, window, threshold_usd)

    # Read current row (if any) before the upsert so the audit log
    # captures the old → new transition in one row.
    prior = get_budget(db, tenant_id=tenant_id, scope=scope,
                       scope_key=scope_key, window=window)
    old_threshold = float(prior["threshold_usd"]) if prior else None
    old_hard_refuse = bool(prior["hard_refuse"]) if prior else None

    from ._dialect_helpers import portable_upsert
    from ._legacy_tables import kya_tenant_cost_budgets
    portable_upsert(
        db,
        kya_tenant_cost_budgets,
        {
            "tenant_id": tenant_id,
            "scope": scope,
            "scope_key": scope_key,
            "time_window": window,
            "threshold_usd": threshold_usd,
            "hard_refuse": hard_refuse,
            "forecast_horizon_sec": forecast_horizon_sec,
            "created_by": created_by,
        },
        conflict_cols=["tenant_id", "scope", "scope_key", "time_window"],
        update_cols=["threshold_usd", "hard_refuse",
                     "forecast_horizon_sec"],
    )
    _log_change(
        db,
        tenant_id=tenant_id, scope=scope, scope_key=scope_key, window=window,
        old_threshold=old_threshold, new_threshold=threshold_usd,
        old_hard_refuse=old_hard_refuse, new_hard_refuse=hard_refuse,
        action="set", changed_by=created_by, reason=reason,
    )
    db.commit()
    return {
        "tenant_id": tenant_id, "scope": scope, "scope_key": scope_key,
        "window": window, "threshold_usd": threshold_usd,
        "hard_refuse": hard_refuse,
        "forecast_horizon_sec": forecast_horizon_sec,
    }


def get_budget(
    db,
    *,
    tenant_id: str | None,
    scope: str,
    scope_key: str,
    window: str,
) -> dict[str, Any] | None:
    """Resolve effective budget: tenant override first, then platform
    default (tenant_id IS NULL).

    The returned ``tenant_id`` field reflects WHICH row matched —
    the caller's tenant id when an override exists, ``None`` when the
    request fell back to the platform default. This lets the caller
    distinguish "I have my own cap" from "I'm using the platform cap"
    without a second query.
    """
    if not _SA_AVAILABLE or db is None:
        return None
    from ._legacy_tables import kya_tenant_cost_budgets as t

    # Two-step lookup: tenant override → platform default. The
    # ``effective_tenant`` variable tracks which step matched so the
    # returned dict shows the truth (not the caller's request).
    candidates: list[tuple[Any, str | None]] = []
    if tenant_id is not None:
        candidates.append((t.c.tenant_id == tenant_id, tenant_id))
    candidates.append((t.c.tenant_id.is_(None), None))

    for tid_filter, effective_tenant in candidates:
        stmt = select(
            t.c.threshold_usd, t.c.hard_refuse, t.c.forecast_horizon_sec,
        ).where(
            tid_filter,
            t.c.scope == scope,
            t.c.scope_key == scope_key,
            t.c.time_window == window,
        )
        row = db.execute(stmt).first()
        if row:
            return {
                "tenant_id": effective_tenant,
                "scope": scope, "scope_key": scope_key, "window": window,
                "threshold_usd": float(row[0]),
                "hard_refuse": bool(row[1]),
                "forecast_horizon_sec": int(row[2]),
            }
    return None


def list_budgets(db, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
    """List budgets visible to a tenant: platform defaults plus the
    tenant's own overrides. ``tenant_id=None`` returns ONLY platform
    defaults."""
    if not _SA_AVAILABLE or db is None:
        return []
    from ._legacy_tables import kya_tenant_cost_budgets as t

    # Platform defaults are always included; tenant rows added only if
    # a tenant id was supplied.
    if tenant_id is None:
        where_clause = t.c.tenant_id.is_(None)
    else:
        where_clause = or_(t.c.tenant_id.is_(None), t.c.tenant_id == tenant_id)

    stmt = select(
        t.c.tenant_id, t.c.scope, t.c.scope_key, t.c.time_window,
        t.c.threshold_usd, t.c.hard_refuse, t.c.forecast_horizon_sec,
    ).where(where_clause).order_by(
        t.c.scope, t.c.scope_key, t.c.time_window,
    )
    return [
        {
            "tenant_id": r[0], "scope": r[1], "scope_key": r[2],
            "window": r[3], "threshold_usd": float(r[4]),
            "hard_refuse": bool(r[5]), "forecast_horizon_sec": int(r[6]),
        }
        for r in db.execute(stmt).fetchall()
    ]


def delete_budget(
    db, *, tenant_id: str | None, scope: str, scope_key: str, window: str,
    deleted_by: str | None = None, reason: str | None = None,
) -> bool:
    """Hard-delete a budget. Logs the prior values to
    ``kya_budget_changes`` so the deletion is traceable."""
    if not _SA_AVAILABLE or db is None:
        return False
    from ._legacy_tables import kya_tenant_cost_budgets as t

    # Read-then-delete pattern: DuckDB doesn't reliably populate
    # result.rowcount for DELETE, so we determine deletion success
    # from the pre-read instead of trusting cursor.rowcount.
    prior = get_budget(db, tenant_id=tenant_id, scope=scope,
                       scope_key=scope_key, window=window)
    if prior is None:
        return False

    tid_filter = t.c.tenant_id.is_(None) if tenant_id is None \
        else t.c.tenant_id == tenant_id
    stmt = _sa_delete(t).where(
        tid_filter,
        t.c.scope == scope,
        t.c.scope_key == scope_key,
        t.c.time_window == window,
    )
    db.execute(stmt)
    _log_change(
        db,
        tenant_id=tenant_id, scope=scope, scope_key=scope_key,
        window=window,
        old_threshold=float(prior["threshold_usd"]),
        new_threshold=None,
        old_hard_refuse=bool(prior["hard_refuse"]),
        new_hard_refuse=None,
        action="delete", changed_by=deleted_by, reason=reason,
    )
    db.commit()
    return True


def list_changes(
    db, *, tenant_id: str | None = None, limit: int = 100,
) -> list[dict[str, Any]]:
    """Read the budget-change audit log. Append-only by construction
    (no UPDATE/DELETE path for ``kya_budget_changes``)."""
    if not _SA_AVAILABLE or db is None:
        return []
    from ._legacy_tables import kya_budget_changes as c

    tid_filter = c.c.tenant_id.is_(None) if tenant_id is None \
        else or_(c.c.tenant_id == tenant_id, c.c.tenant_id.is_(None))
    # Order by id desc — created_at on SQLite has second-resolution
    # which ties when rows land in the same second; id is monotone.
    stmt = select(
        c.c.tenant_id, c.c.scope, c.c.scope_key, c.c.time_window,
        c.c.old_threshold_usd, c.c.new_threshold_usd,
        c.c.old_hard_refuse, c.c.new_hard_refuse,
        c.c.action, c.c.changed_by, c.c.reason, c.c.created_at,
    ).where(tid_filter).order_by(c.c.id.desc()).limit(limit)
    return [
        {
            "tenant_id": r[0], "scope": r[1], "scope_key": r[2],
            "window": r[3],
            "old_threshold_usd": float(r[4]) if r[4] is not None else None,
            "new_threshold_usd": float(r[5]) if r[5] is not None else None,
            "old_hard_refuse": r[6], "new_hard_refuse": r[7],
            "action": r[8], "changed_by": r[9], "reason": r[10],
            "created_at": r[11],
        }
        for r in db.execute(stmt).fetchall()
    ]


# ── Forecast + decision ─────────────────────────────────────────────

def forecast_spend(
    tenant_id: str,
    scope: str,
    scope_key: str,
    window: str,
    horizon_sec: int,
    threshold_usd: float,
) -> Forecast:
    """Pure-function projection — uses Valkey-derived burn rate. No DB
    hit on the hot path."""
    cur = current_spend(tenant_id, scope, scope_key, window)
    rate = _burn_rate_per_sec(tenant_id, scope, scope_key)
    return _forecaster.forecast(
        current_usd=cur,
        threshold_usd=threshold_usd,
        burn_rate_usd_per_sec=rate,
        horizon_sec=horizon_sec,
    )


@dataclass(frozen=True)
class Decision:
    """Returned by ``should_refuse``. The embedding layer translates
    ``verdict`` into its own gate vocabulary."""
    verdict: str           # one of DECISIONS
    reason: str            # human-readable; "" when allow
    current_usd: float
    threshold_usd: float
    forecast: Forecast | None


# strictness ordering — higher number wins on aggregation
_STRICTNESS = {"allow": 0, "warn": 1, "throttle": 2, "refuse": 3}


def _get_budgets_for_windows(
    db,
    *,
    tenant_id: str | None,
    scope: str,
    scope_key: str,
    windows: list[str],
) -> dict[str, dict[str, Any]]:
    """Batch-fetch budget config for multiple windows in one DB round
    trip. Returns ``{window: cfg}`` honoring tenant-override-over-
    platform-default precedence per window.

    Replaces N separate ``get_budget`` calls in ``should_refuse``
    with a single SELECT. For 12 windows this cuts the action-gate
    decision from ~12 round trips to 1.
    """
    if not _SA_AVAILABLE or db is None or not windows:
        return {}
    from ._legacy_tables import kya_tenant_cost_budgets as t

    # Single query covers BOTH tenant and platform-default rows for
    # the requested windows. We resolve precedence in-Python after.
    if tenant_id is not None:
        tid_predicate = or_(t.c.tenant_id.is_(None),
                            t.c.tenant_id == tenant_id)
    else:
        tid_predicate = t.c.tenant_id.is_(None)

    stmt = select(
        t.c.tenant_id, t.c.time_window, t.c.threshold_usd,
        t.c.hard_refuse, t.c.forecast_horizon_sec,
    ).where(
        tid_predicate,
        t.c.scope == scope,
        t.c.scope_key == scope_key,
        t.c.time_window.in_(windows),
    )
    # Fail-soft: a DB hiccup must not crash the action gate. The
    # contract is "no budget visible → allow" — which is the same
    # outcome the embedding layer gets if it can't reach the DB.
    try:
        rows = db.execute(stmt).fetchall()
    except Exception as exc:  # noqa: BLE001
        logger.debug("[kya-budget] _get_budgets_for_windows: %s", exc)
        return {}

    # Precedence: tenant-specific row wins over platform default for
    # the same window.
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        row_tid = r[0]
        w = r[1]
        is_tenant_row = (row_tid is not None)
        existing = out.get(w)
        if existing is not None and not is_tenant_row:
            # Don't overwrite a tenant override with a platform default.
            continue
        out[w] = {
            "tenant_id": row_tid,
            "scope": scope, "scope_key": scope_key, "window": w,
            "threshold_usd": float(r[2]),
            "hard_refuse": bool(r[3]),
            "forecast_horizon_sec": int(r[4]),
        }
    return out


def should_refuse(
    db,
    *,
    tenant_id: str,
    scope_key: str,
    intended_cost_usd: float = 0.0,
    scope: str = "tenant",
    window: str | None = None,
) -> Decision:
    """The decision predicate. Resolves effective budgets for the
    (tenant, scope, scope_key) tuple across one or all windows,
    consults the forecaster, and returns the strictest verdict.

    No budget configured → ``allow`` (KYA is opt-in).

    Implementation notes:
      * One batched DB query fetches all window configs at once
        (vs. N round trips before v0.1.1).
      * ``burn_rate_usd_per_sec`` is computed once outside the loop;
        it doesn't depend on the window being evaluated.
    """
    windows = [window] if window in BUDGET_WINDOWS else sorted(BUDGET_WINDOWS)
    best = Decision(verdict="allow", reason="", current_usd=0.0,
                    threshold_usd=0.0, forecast=None)

    configs = _get_budgets_for_windows(
        db, tenant_id=tenant_id, scope=scope,
        scope_key=scope_key, windows=windows,
    )
    if not configs:
        # Fast path — no budgets to consult; emit metric + return.
        _bump("kya_budget_decisions_total",
              "Budget decisions issued by should_refuse()",
              verdict=best.verdict, scope=scope)
        return best

    # Burn rate is window-independent; hoist out of the loop so the
    # 1h Valkey GET happens once per decision, not once per window.
    burn_rate = _burn_rate_per_sec(tenant_id, scope, scope_key)

    for w in windows:
        cfg = configs.get(w)
        if not cfg:
            continue
        cur = current_spend(tenant_id, scope, scope_key, w)
        projected_cur = cur + max(0.0, intended_cost_usd)
        threshold = float(cfg["threshold_usd"])
        fc = _forecaster.forecast(
            current_usd=projected_cur,
            threshold_usd=threshold,
            burn_rate_usd_per_sec=burn_rate,
            horizon_sec=int(cfg["forecast_horizon_sec"]),
        )
        if projected_cur >= threshold:
            verdict = "refuse" if cfg["hard_refuse"] else "warn"
            reason = (f"budget_exhausted ({w}): "
                      f"${projected_cur:.2f} / ${threshold:.2f}")
        elif fc.breach_predicted:
            verdict = "throttle" if cfg["hard_refuse"] else "warn"
            reason = (f"budget_forecast_breach ({w}): projected "
                      f"${fc.projected_usd:.2f} / ${threshold:.2f} "
                      f"in {fc.breach_in_sec or fc.horizon_sec}s")
        else:
            continue
        if _STRICTNESS[verdict] > _STRICTNESS[best.verdict]:
            best = Decision(verdict=verdict, reason=reason,
                            current_usd=projected_cur,
                            threshold_usd=threshold, forecast=fc)

    # Counter every decision (including allows) for SLO dashboards.
    _bump("kya_budget_decisions_total",
          "Budget decisions issued by should_refuse()",
          verdict=best.verdict, scope=scope)

    if best.verdict in ("refuse", "throttle"):
        # Bidirectional emit — fan out to SIEM / GRC sinks
        try:
            emit("kya_budget_decisions", {
                "tenant_id": tenant_id, "scope": scope, "scope_key": scope_key,
                "verdict": best.verdict, "reason": best.reason,
                "current_usd": best.current_usd,
                "threshold_usd": best.threshold_usd,
                "ts": time.time(),
            })
        except Exception:  # pragma: no cover
            pass
    return best


# ── Health check ────────────────────────────────────────────────────

def health_check(db) -> dict[str, Any]:
    """Operational visibility into the budget subsystem.

    Returns:
        {
            "ok":            bool,                 # overall health
            "db":            "ok" | str(error),
            "valkey":        "ok" | str(error),
            "forecaster":    {"name": str, ...},
            "tables_exist":  {table: bool, ...},
        }

    Cheap (no writes, ~2 round trips). Suitable for /readyz endpoints.
    """
    out: dict[str, Any] = {
        "ok": True,
        "db": "ok",
        "valkey": "ok",
        "forecaster": {"name": _forecaster.name},
        "tables_exist": {},
    }

    # DB check: SELECT 1 + table presence
    if not _SA_AVAILABLE or db is None:
        out["db"] = "sqlalchemy unavailable"
        out["ok"] = False
    else:
        try:
            from sqlalchemy import inspect as _inspect
            insp = _inspect(db.connection())
            dialect = db.get_bind().dialect.name
            schema = "prov_schema" if dialect == "postgresql" else None
            existing = set(insp.get_table_names(schema=schema))
            for name in ("kya_tenant_cost_budgets", "kya_budget_changes",
                         "kya_cost_events"):
                out["tables_exist"][name] = name in existing
                if name not in existing:
                    out["ok"] = False
        except Exception as exc:  # noqa: BLE001
            out["db"] = f"error: {exc}"
            out["ok"] = False

    # Valkey check: PING
    r = _get_redis()
    if r is None:
        out["valkey"] = "unavailable (cost windows degrade to DB rollup)"
        # Not flagged as overall-unhealthy — Valkey is performance, not
        # correctness. The DB ledger is the source of truth.
    else:
        try:
            r.ping()
        except Exception as exc:  # noqa: BLE001
            out["valkey"] = f"error: {exc}"
    return out


def budget_status(
    db, *, tenant_id: str, scope: str = "tenant", scope_key: str = "*",
) -> dict[str, Any]:
    """Operator dashboard view — every window's current spend + threshold
    + forecast, in one structured payload."""
    out: dict[str, Any] = {
        "tenant_id": tenant_id, "scope": scope, "scope_key": scope_key,
        "windows": {},
    }
    for w in sorted(BUDGET_WINDOWS):
        cfg = get_budget(db, tenant_id=tenant_id, scope=scope,
                         scope_key=scope_key, window=w)
        cur = current_spend(tenant_id, scope, scope_key, w)
        if cfg:
            fc = _forecaster.forecast(
                current_usd=cur,
                threshold_usd=float(cfg["threshold_usd"]),
                burn_rate_usd_per_sec=_burn_rate_per_sec(tenant_id, scope,
                                                        scope_key),
                horizon_sec=int(cfg["forecast_horizon_sec"]),
            )
            out["windows"][w] = {
                "current_usd": cur,
                "threshold_usd": float(cfg["threshold_usd"]),
                "hard_refuse": cfg["hard_refuse"],
                "projected_usd": fc.projected_usd,
                "breach_predicted": fc.breach_predicted,
                "breach_in_sec": fc.breach_in_sec,
                "forecast_method": fc.method,
            }
        else:
            out["windows"][w] = {"current_usd": cur, "threshold_usd": None}
    return out


# ── Env-driven forecaster swap (optional) ───────────────────────────
# Allows production operators to wire in an EWMA / Prophet / LLM
# forecaster without code changes. Imported once at module-load.

def _maybe_swap_forecaster_from_env() -> None:
    impl_path = os.environ.get("KYA_BUDGET_FORECASTER", "").strip()
    if not impl_path or ":" not in impl_path:
        return
    module_name, class_name = impl_path.split(":", 1)
    try:
        mod = __import__(module_name, fromlist=[class_name])
        cls = getattr(mod, class_name)
        set_forecaster(cls())
        logger.info("[kya-budget] forecaster swapped to %s", impl_path)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[kya-budget] env forecaster swap failed: %s", exc)


_maybe_swap_forecaster_from_env()
