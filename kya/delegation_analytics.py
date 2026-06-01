"""
Delegation-policy readiness report — operator-facing aggregation over
kya_delegation_violations.

Goal
----
Surface ONLY the (parent, sub, kind) combinations that need an
operator decision today. The raw table grows without bound; humans
can't read it row-by-row at production scale (100s-1000s of agents).
This module summarizes the table and applies deterministic rules
that produce structured recommendations like "promote_to_flag"
or "investigate_spike" — each tagged with the rule that fired and
a human-readable rationale.

Determinism contract
--------------------
Every recommendation comes from a fixed rule predicate with constant
thresholds. No probabilistic ranking, no LLM judgment, no
"score-based" magic. The set of rules is closed (RULES below) and
each carries:

    rule_id        — stable string identifier
    predicate      — pure function of (window_count, stable_days, ...)
    recommendation — one of {promote_to_flag, promote_to_block,
                              rollback_to_observe, investigate_spike,
                              hold, no_action}
    rationale_template — fixed string with {placeholder} slots

If the predicate fires, the rule's recommendation + rationale are
attached to the entry. Multiple rules can match — they're returned
in fixed priority order so report output is byte-deterministic
for the same input.

No-noise default
----------------
The `attention` list ONLY contains entries with a non-default
recommendation. Stable items (zero violations in window, last seen
beyond stable_days_to_promote) appear in `summary.stable_pairs`
count but NOT in `attention` — operators don't review the silent
majority.

Cross-backend portability
-------------------------
Uses only ANSI SQL plus the schema-prefix convention shared with the
rest of the package (the configured KYA schema on PG, default ns
elsewhere — controlled by ``KYA_VERSIONS_SCHEMA``).
The aggregation step is done in Python on the already-narrow result
set (filtered to the longer of window_days vs stable_days_to_promote)
so dialect-specific date arithmetic is avoided.

Usage
-----
::

    from kya import delegation_readiness_report
    report = delegation_readiness_report(
        db, tenant_id="...", window_days=7,
        stable_days_to_promote=30,
    )
    for item in report["attention"]:
        print(item["recommendation"], "-", item["rationale"])
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)


# Closed set of recommendations — keeps downstream consumers
# (dashboards, alerters) from having to handle ad-hoc strings.
VALID_RECOMMENDATIONS = frozenset({
    "promote_to_flag",
    "promote_to_block",
    "rollback_to_observe",
    "investigate_spike",
    "hold",
    "no_action",
})


# Default thresholds — overridable per-call. Conservative on purpose:
# the right defaults err toward "don't auto-promote yet".
DEFAULT_WINDOW_DAYS = 7
DEFAULT_STABLE_DAYS_TO_PROMOTE = 30
DEFAULT_SPIKE_THRESHOLD = 100


def _schema_prefix(db) -> str:
    try:
        from ._portable import qual_for_raw_sql
        return qual_for_raw_sql(db)
    except Exception:
        return ""


# ── Deterministic rules ────────────────────────────────────────────


def _rule_spike(item: dict, spike_threshold: int) -> dict | None:
    """If the in-window count exceeds the spike threshold, raise the
    investigation flag. Pre-empts any promotion logic — spikes
    deserve human eyes before mode changes."""
    if item["count_in_window"] > spike_threshold:
        return {
            "rule_id": "spike_threshold_exceeded",
            "recommendation": "investigate_spike",
            "rationale": (
                f"{item['count_in_window']} violations of kind "
                f"'{item['violation_kind']}' from parent="
                f"'{item['parent_agent_key']}' → sub="
                f"'{item['sub_agent_key']}' in last "
                f"{item['_window_days']}d (threshold: {spike_threshold})."
            ),
        }
    return None


def _rule_active_violations_hold(item: dict) -> dict | None:
    """Any violations in the current window AND mode is non-block →
    hold. Don't promote a kind that's actively misbehaving (whether
    we'd otherwise promote observe→flag or flag→block). In block
    mode, active violations are handled by the block_mode_spike_rollback
    rule instead."""
    if (item["count_in_window"] > 0
            and item["current_effective_mode"] in ("observe", "flag")):
        return {
            "rule_id": "active_violations_block_promotion",
            "recommendation": "hold",
            "rationale": (
                f"{item['count_in_window']} active violations in last "
                f"{item['_window_days']}d while in "
                f"'{item['current_effective_mode']}' mode — wait until "
                f"surface stabilizes before promoting."
            ),
        }
    return None


def _rule_stable_promote_observe_to_flag(item: dict,
                                          stable_days: int) -> dict | None:
    """No violations in stable window AND current mode is observe →
    safe to promote to flag (logs warnings without raising)."""
    if (item["count_in_window"] == 0
            and item["current_effective_mode"] == "observe"
            and item["days_since_last_violation"] is not None
            and item["days_since_last_violation"] >= stable_days):
        return {
            "rule_id": "stable_promote_observe_to_flag",
            "recommendation": "promote_to_flag",
            "rationale": (
                f"Zero violations for {item['days_since_last_violation']}d "
                f"(threshold: {stable_days}d). Safe to promote "
                f"observe → flag for this pair × kind."
            ),
        }
    return None


def _rule_stable_promote_flag_to_block(item: dict,
                                        stable_days: int) -> dict | None:
    """No violations in stable window AND current mode is flag →
    safe to promote to block (now actively rejects)."""
    if (item["count_in_window"] == 0
            and item["current_effective_mode"] == "flag"
            and item["days_since_last_violation"] is not None
            and item["days_since_last_violation"] >= stable_days):
        return {
            "rule_id": "stable_promote_flag_to_block",
            "recommendation": "promote_to_block",
            "rationale": (
                f"Zero violations for {item['days_since_last_violation']}d "
                f"in flag mode (threshold: {stable_days}d). Safe to "
                f"escalate to block — actual delegation rejection."
            ),
        }
    return None


def _rule_spike_in_block_mode_rollback(item: dict,
                                        spike_threshold: int) -> dict | None:
    """If block mode is active AND we're seeing violations (which means
    real production callers are being blocked) at high rate, recommend
    rollback to flag for triage."""
    if (item["count_in_window"] > spike_threshold
            and item["current_effective_mode"] == "block"):
        return {
            "rule_id": "block_mode_spike_rollback",
            "recommendation": "rollback_to_observe",
            "rationale": (
                f"In block mode with {item['count_in_window']} blocked "
                f"delegations in last {item['_window_days']}d — likely "
                f"breaking legitimate workflows. Roll back to observe "
                f"for triage."
            ),
        }
    return None


# Priority order: highest-impact rule wins. The first rule whose
# predicate fires is the entry's recommendation. Other rules might
# also fire but only the winner is reported in the attention list
# (other matches available via `_all_matches` if needed).
_RULES_IN_PRIORITY_ORDER = (
    _rule_spike_in_block_mode_rollback,
    _rule_spike,
    _rule_active_violations_hold,
    _rule_stable_promote_flag_to_block,
    _rule_stable_promote_observe_to_flag,
)


def _evaluate_rules(
    item: dict,
    *,
    stable_days: int,
    spike_threshold: int,
) -> dict | None:
    """Apply rules in priority order; return the first match (or None
    if no rule fires, in which case the item is in steady state and
    doesn't surface in `attention`)."""
    for rule in _RULES_IN_PRIORITY_ORDER:
        # Each rule introspects what it needs from item + the
        # constants — pass both explicitly. _ALL must come back to
        # None when no action is warranted.
        if rule in (_rule_spike, _rule_spike_in_block_mode_rollback):
            match = rule(item, spike_threshold)
        elif rule in (_rule_stable_promote_observe_to_flag,
                       _rule_stable_promote_flag_to_block):
            match = rule(item, stable_days)
        else:
            match = rule(item)
        if match:
            assert match["recommendation"] in VALID_RECOMMENDATIONS, \
                f"rule {rule.__name__} produced unknown recommendation"
            return match
    return None


# ── Effective-mode resolver (Phase-2-aware stub) ───────────────────


def _resolve_current_mode(
    db,
    *,
    tenant_id: str,
    parent_agent_key: str,
    sub_agent_key: str,
    violation_kind: str,
) -> str:
    """Resolve the effective mode for a specific pair × kind.

    Phase 2: consults kya_delegation_policy_overrides via
    specificity-ordered lookup (most-specific override wins; ties
    broken by created_at DESC). Falls back to the global env var
    when no override matches. Fail-soft on any DB / module error —
    we always degrade to the env value, never raise.
    """
    try:
        from .delegation_overrides import resolve_effective_mode
        mode, _source = resolve_effective_mode(
            db, tenant_id=tenant_id,
            parent_agent_key=parent_agent_key,
            sub_agent_key=sub_agent_key,
            violation_kind=violation_kind,
        )
        return mode
    except Exception as exc:
        logger.debug(
            "[KYA-DELEG-RPT] override resolve failed (%s) — env fallback",
            exc)
        from .delegation_policy import _current_mode
        return _current_mode()


# ── Public API ─────────────────────────────────────────────────────


def delegation_readiness_report(
    db,
    *,
    tenant_id: str,
    window_days: int = DEFAULT_WINDOW_DAYS,
    stable_days_to_promote: int = DEFAULT_STABLE_DAYS_TO_PROMOTE,
    spike_threshold: int = DEFAULT_SPIKE_THRESHOLD,
    parent_agent_key: str | None = None,
    sub_agent_key: str | None = None,
    violation_kind: str | None = None,
) -> dict[str, Any]:
    """Operator-facing aggregation over kya_delegation_violations.

    Returns a structured dict ready to render in a dashboard or POST
    to an alerter. The `attention` list contains ONLY entries with a
    rule-driven recommendation — stable items are counted but not
    listed.

    Parameters
    ----------
    db : SQLAlchemy Session
    tenant_id : str
        Required. Reports are always per-tenant.
    window_days : int
        Activity window (last N days) for spike detection and
        "in_window" counts. Default 7.
    stable_days_to_promote : int
        How long a pair × kind must be silent before promotion is
        recommended. Default 30. Must be >= window_days.
    spike_threshold : int
        Per-pair-kind count in window above which the spike rule
        fires. Default 100.
    parent_agent_key / sub_agent_key / violation_kind : optional
        Scope filters. Useful for drill-down dashboards.
    """
    if not tenant_id:
        raise ValueError("tenant_id is required (got empty or None)")
    if stable_days_to_promote < window_days:
        raise ValueError(
            "stable_days_to_promote must be >= window_days "
            f"(got {stable_days_to_promote} < {window_days})")

    now = datetime.now(timezone.utc)
    window_cutoff = now - timedelta(days=window_days)

    schema = _schema_prefix(db)

    # Query 1 — in-window rows (full detail for count + blocked count).
    # Bounded to last `window_days`; small even at scale.
    sql_window = (
        f"SELECT parent_agent_key, sub_agent_key, violation_kind, "
        f"       created_at, blocked, mode_active "
        f"FROM {schema}kya_delegation_violations "
        f"WHERE tenant_id = :t AND created_at >= :c"
    )
    params: dict[str, Any] = {"t": tenant_id, "c": window_cutoff}
    if parent_agent_key:
        sql_window += " AND parent_agent_key = :p"
        params["p"] = parent_agent_key
    if sub_agent_key:
        sql_window += " AND sub_agent_key = :s"
        params["s"] = sub_agent_key
    if violation_kind:
        sql_window += " AND violation_kind = :k"
        params["k"] = violation_kind
    sql_window += (" ORDER BY parent_agent_key, sub_agent_key, "
                    "violation_kind, created_at")

    # Query 2 — overall last-seen per (parent, sub, kind), all time.
    # One row per distinct pair × kind (bounded by agents × kinds —
    # cheap to read even with millions of total violation rows).
    sql_overall = (
        f"SELECT parent_agent_key, sub_agent_key, violation_kind, "
        f"       MAX(created_at) AS last_seen_overall "
        f"FROM {schema}kya_delegation_violations "
        f"WHERE tenant_id = :t"
    )
    overall_params: dict[str, Any] = {"t": tenant_id}
    if parent_agent_key:
        sql_overall += " AND parent_agent_key = :p"
        overall_params["p"] = parent_agent_key
    if sub_agent_key:
        sql_overall += " AND sub_agent_key = :s"
        overall_params["s"] = sub_agent_key
    if violation_kind:
        sql_overall += " AND violation_kind = :k"
        overall_params["k"] = violation_kind
    sql_overall += (" GROUP BY parent_agent_key, sub_agent_key, "
                     "violation_kind")

    try:
        window_rows = db.execute(text(sql_window), params).fetchall()
        overall_rows = db.execute(
            text(sql_overall), overall_params).fetchall()
    except Exception as exc:
        logger.debug("[KYA-DELEG-RPT] query failed: %s", exc)
        window_rows = []
        overall_rows = []

    # Bootstrap groups from the overall query (so steady-state items
    # also appear and can be evaluated for stable-promotion).
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for r in overall_rows:
        key = (r[0], r[1], r[2])
        grouped[key] = {
            "parent_agent_key": r[0],
            "sub_agent_key": r[1],
            "violation_kind": r[2],
            "_last_seen_overall": _coerce_datetime(r[3]),
            "_in_window_created_at": [],
            "blocked_count": 0,
        }

    # Layer in in-window detail
    for r in window_rows:
        key = (r[0], r[1], r[2])
        entry = grouped.get(key)
        if entry is None:
            continue  # shouldn't happen — overall query covers all keys
        ts = _coerce_datetime(r[3])
        if ts is not None:
            entry["_in_window_created_at"].append(ts)
        if r[4]:
            entry["blocked_count"] += 1

    # Derive per-group stats + apply rules
    attention: list[dict] = []
    kind_counts: dict[str, int] = {}
    parent_counts: dict[str, int] = {}
    stable_pairs = 0
    total_in_window = 0

    for (p_key, s_key, kind), entry in grouped.items():
        in_window = len(entry["_in_window_created_at"])
        last_seen = entry["_last_seen_overall"]
        first_in_window = (min(entry["_in_window_created_at"])
                            if entry["_in_window_created_at"] else None)
        # Clock-skew safe: if DB clock is ahead of app clock,
        # last_seen > now produces a negative delta. Clamp to 0 so
        # the report doesn't surface confusing negative
        # days_since_last. Rule predicates check >= stable_days so
        # the clamped value still won't trigger false promotion.
        if last_seen is not None:
            raw_delta = (now - last_seen).total_seconds() / 86400
            days_since_last = max(0.0, raw_delta)
        else:
            days_since_last = None

        effective_mode = _resolve_current_mode(
            db, tenant_id=tenant_id,
            parent_agent_key=p_key,
            sub_agent_key=s_key,
            violation_kind=kind,
        )

        item = {
            "parent_agent_key": p_key,
            "sub_agent_key": s_key,
            "violation_kind": kind,
            "count_in_window": in_window,
            "blocked_count": entry["blocked_count"],
            "first_seen_in_window": _iso(first_in_window),
            "last_seen": _iso(last_seen),
            "days_since_last_violation": (
                round(days_since_last, 2)
                if days_since_last is not None else None),
            "current_effective_mode": effective_mode,
            "_window_days": window_days,
        }

        # Tally summary stats regardless of rule fire
        total_in_window += in_window
        if in_window > 0:
            kind_counts[kind] = kind_counts.get(kind, 0) + in_window
            parent_counts[p_key] = parent_counts.get(p_key, 0) + in_window

        match = _evaluate_rules(
            item,
            stable_days=stable_days_to_promote,
            spike_threshold=spike_threshold,
        )
        if match:
            # Strip internal scratch fields before emitting
            public_item = {k: v for k, v in item.items()
                            if not k.startswith("_")}
            public_item.update(match)
            attention.append(public_item)
        else:
            # Steady-state entry — count toward "previously violated
            # but quiet long enough to be considered stable". This is
            # NOT a count of pairs that never violated (those don't
            # appear in the violations table at all); it's a count of
            # pairs that USED TO violate and have been silent past
            # the stable threshold.
            if in_window == 0 and (days_since_last or 0) >= stable_days_to_promote:
                stable_pairs += 1

    # Stable sort for deterministic byte-identical output
    attention.sort(key=lambda x: (
        x["recommendation"], x["parent_agent_key"],
        x["sub_agent_key"], x["violation_kind"]))

    return {
        "tenant_id": tenant_id,
        "generated_at": _iso(now),
        "window_days": window_days,
        "stable_days_to_promote": stable_days_to_promote,
        "spike_threshold": spike_threshold,
        "current_global_mode": _global_mode(),
        "summary": {
            "total_violations_in_window": total_in_window,
            "distinct_pairs_with_violations": len(
                [e for e in grouped.values()
                 if len(e["_in_window_created_at"]) > 0]),
            "violation_kinds_in_window": dict(sorted(kind_counts.items())),
            "active_parent_agents": dict(sorted(parent_counts.items())),
            # `previously_violating_pairs_now_stable` is the count of
            # (parent, sub, kind) groups that have at least one
            # historical violation but have been silent for
            # >= stable_days_to_promote. Pairs that NEVER violated
            # are not tracked here (they don't exist in the table).
            "previously_violating_pairs_now_stable": stable_pairs,
            "actionable_items": len(attention),
        },
        "attention": attention,
    }


def _global_mode() -> str:
    from .delegation_policy import _current_mode
    return _current_mode()


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _coerce_datetime(v: Any) -> datetime | None:
    """SQLite (and DuckDB-via-some-drivers) hand back ISO strings for
    DateTime(timezone=True) columns. Normalize to a UTC-aware
    datetime."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, str):
        try:
            # Handle both "2026-05-25T12:00:00+00:00" and naive ISO.
            s = v.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None
