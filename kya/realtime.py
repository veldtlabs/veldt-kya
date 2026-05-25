"""
Real-time rogue tracking via Valkey — sliding-window counters + pub/sub alerts.

Why this exists
---------------
Prometheus counters are MONOTONIC — they go up forever. Useful for
all-time totals; useless for "has this agent had a burst in the last
hour?". Valkey/Redis keys with TTLs give us exact bucketed windows for
behavioral baselining and rate-based anomaly detection.

Storage shape
-------------
For every rogue signal we also write to Valkey:

    Per-window counter (incrby + TTL):
        kya:rogue:{tenant_id}:{agent_key}:{signal}:{window}
        e.g. kya:rogue:t-001:decision:oos_tool:1h

    Pub/sub channel (notify subscribers in real time):
        kya:alerts:{tenant_id}
        payload: {"agent": "...", "signal": "...", "severity": "...", "ts": "..."}

Windows
-------
We maintain three rolling windows — 1h / 24h / 7d — using time-bucketed
keys so each counter only contains events within that window. TTL set
slightly longer than the window so the very-edge events don't drop
prematurely.

Public API
----------
    record_signal(tenant_id, agent_key, signal_kind, severity="warning")
    get_window_counts(tenant_id, agent_key) -> dict[window, dict[signal, int]]
    subscribe_alerts(tenant_id, callback)   — convenience pub/sub helper

Fail-soft contract
------------------
Valkey unreachable → every helper here logs and returns gracefully. The
real-time layer is a *bonus* over Prometheus + governance_audit_log; it
never breaks request flow.
"""

import json
import logging
import time
from collections.abc import Callable

logger = logging.getLogger(__name__)


# Window definitions: name → (window seconds, TTL seconds with grace).
# TTL > window so a counter hit at the very end doesn't expire before
# the read can see it.
#
# Why short windows matter: a coordinated attack (or runaway agent) can
# fire dozens of rogue events in <60s. Waiting for the 1h boundary to
# alert means damage is already done. The 1m / 5m / 15m windows give
# real-time burst detection; the 1h / 24h / 7d windows give context for
# trend analysis and behavioral baselining.
WINDOWS = {
    "1m": (60, 90),  # real-time burst
    "5m": (60 * 5, 60 * 6),  # near real-time
    "15m": (60 * 15, 60 * 17),  # short-horizon
    "1h": (60 * 60, 60 * 70),  # operational
    "24h": (60 * 60 * 24, 60 * 60 * 25),  # daily baseline
    "7d": (60 * 60 * 24 * 7, 60 * 60 * 24 * 7 + 3600),  # weekly trend
}


def _get_redis():
    """Lazy import — KYA standalone shouldn't require Veldt's db module."""
    try:
        from db.redis import get_redis

        return get_redis()
    except Exception as exc:
        logger.debug("[KYA-RT] redis import failed: %s", exc)
        return None


def _window_key(tenant_id: str, agent_key: str, signal: str, window: str) -> str:
    return f"kya:rogue:{tenant_id}:{agent_key}:{signal}:{window}"


def _alerts_channel(tenant_id: str) -> str:
    return f"kya:alerts:{tenant_id}"


# Whitelist — only these kinds can be written. Prevents caller-controlled
# strings from spawning unbounded Valkey keys (caller could fire a signal
# called "...long-string..." per request and DoS the keyspace).
ALLOWED_SIGNAL_KINDS = frozenset(
    {
        "oos_tool",
        "cross_tenant",
        "data_leak",
        "rbac_refusal",
        "governance_block",
        "hallucination",
        "injection_attempt",
        "definition_drift",
        "policy_violation",
        # A previously-unseen agent_key was just snapshotted (v1 written).
        # Emitted from kya.versioning.snapshot_on_first_sight when the
        # write is genuinely new — NOT on idempotent re-calls. Lets
        # operators detect novel agents appearing in production
        # (rogue dev, supply-chain injection, drift from registration
        # workflow) without polling agent_versions.
        "agent_first_sight",
    }
)


def record_signal(
    tenant_id: str,
    agent_key: str,
    signal_kind: str,
    severity: str = "warning",
    detail: dict | None = None,
) -> None:
    """Record a real-time rogue signal — increments per-window counters and
    publishes to the tenant's alerts channel.

    `signal_kind` MUST be a member of `ALLOWED_SIGNAL_KINDS`. Unknown
    names are silently dropped (logged at debug) — extend the whitelist
    explicitly if you want a new signal type, don't open the namespace.

    Exception-safe: Valkey hiccups are logged at debug, never raised.
    """
    if signal_kind not in ALLOWED_SIGNAL_KINDS:
        logger.debug(
            "[KYA-RT] rejected unknown signal_kind=%s (not in ALLOWED_SIGNAL_KINDS)",
            signal_kind,
        )
        return
    r = _get_redis()
    if r is None:
        return
    try:
        # Atomic-ish: pipeline three INCRs + SETEXes
        pipe = r.pipeline()
        for window, (_window_sec, ttl_sec) in WINDOWS.items():
            key = _window_key(tenant_id, agent_key, signal_kind, window)
            pipe.incr(key)
            pipe.expire(key, ttl_sec)
        # Publish alert event for live dashboards
        payload = json.dumps(
            {
                "agent_key": agent_key,
                "signal": signal_kind,
                "severity": severity,
                "tenant_id": tenant_id,
                "ts": time.time(),
                "detail": detail or {},
            }
        )
        pipe.publish(_alerts_channel(tenant_id), payload)
        pipe.execute()
    except Exception as exc:
        logger.debug("[KYA-RT] record_signal failed: %s", exc)


def get_window_counts(tenant_id: str, agent_key: str, signals: list[str] | None = None) -> dict:
    """Read the current count of each signal in each window for an agent.

    Returns a dict shaped:
        {
            "1h":  {"oos_tool": 0, "cross_tenant": 0, ...},
            "24h": {...},
            "7d":  {...},
        }

    Default signals: oos_tool, cross_tenant, data_leak, rbac_refusal,
    governance_block. Pass `signals=[...]` to scope a subset.
    """
    signals = signals or [
        "oos_tool",
        "cross_tenant",
        "data_leak",
        "rbac_refusal",
        "governance_block",
    ]
    out = {w: {s: 0 for s in signals} for w in WINDOWS}
    r = _get_redis()
    if r is None:
        return out
    try:
        pipe = r.pipeline()
        keys: list[tuple[str, str, str]] = []
        for window in WINDOWS:
            for sig in signals:
                k = _window_key(tenant_id, agent_key, sig, window)
                pipe.get(k)
                keys.append((window, sig, k))
        results = pipe.execute()
        for (window, sig, _k), val in zip(keys, results):
            out[window][sig] = int(val) if val else 0
    except Exception as exc:
        logger.debug("[KYA-RT] get_window_counts failed: %s", exc)
    return out


def detect_burst_anomalies(
    tenant_id: str,
    agent_key: str,
    burst_threshold_1h: int = 10,
    burst_threshold_24h: int = 50,
) -> list[dict]:
    """Return list of burst-window anomalies for the agent.

    A "burst" here is conservative — any signal exceeding the thresholds
    in the corresponding window. Cross-tenant + data_leak burst at any
    count are flagged critical (those should never happen in normal
    operation).
    """
    counts = get_window_counts(tenant_id, agent_key)
    anomalies: list[dict] = []

    # Always-critical signals — any count is anomalous
    for sig in ("cross_tenant", "data_leak"):
        if counts["1h"].get(sig, 0) > 0:
            anomalies.append(
                {
                    "severity": "critical",
                    "code": f"burst_{sig}_1h",
                    "message": f"{counts['1h'][sig]} {sig} event(s) in the last hour.",
                    "detail": {"window": "1h", "count": counts["1h"][sig]},
                }
            )
        elif counts["24h"].get(sig, 0) > 0:
            anomalies.append(
                {
                    "severity": "critical",
                    "code": f"burst_{sig}_24h",
                    "message": f"{counts['24h'][sig]} {sig} event(s) in the last 24h.",
                    "detail": {"window": "24h", "count": counts["24h"][sig]},
                }
            )

    # Threshold-driven warnings
    for sig in ("oos_tool", "rbac_refusal"):
        if counts["1h"].get(sig, 0) >= burst_threshold_1h:
            anomalies.append(
                {
                    "severity": "warning",
                    "code": f"burst_{sig}_1h",
                    "message": f"{counts['1h'][sig]} {sig} signals in the last hour (>= {burst_threshold_1h}).",
                    "detail": {"window": "1h", "count": counts["1h"][sig]},
                }
            )
        if counts["24h"].get(sig, 0) >= burst_threshold_24h:
            anomalies.append(
                {
                    "severity": "warning",
                    "code": f"burst_{sig}_24h",
                    "message": f"{counts['24h'][sig]} {sig} signals in the last 24h (>= {burst_threshold_24h}).",
                    "detail": {"window": "24h", "count": counts["24h"][sig]},
                }
            )

    return anomalies


def subscribe_alerts(tenant_id: str, callback: Callable[[dict], None]) -> None:
    """Subscribe to live alerts for a tenant. BLOCKING — call from a
    dedicated thread / async task. Each message yields a dict to `callback`.

    Returns None on Valkey-unreachable. Designed for dashboard SSE bridges
    and external SIEM forwarders.
    """
    r = _get_redis()
    if r is None:
        logger.warning("[KYA-RT] subscribe_alerts: no Valkey connection")
        return
    try:
        pubsub = r.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_alerts_channel(tenant_id))
        for msg in pubsub.listen():
            try:
                data = json.loads(
                    msg.get("data", "{}")
                    if isinstance(msg.get("data"), str)
                    else msg.get("data", b"{}").decode("utf-8")
                )
                callback(data)
            except Exception as exc:
                logger.debug("[KYA-RT] subscriber callback failed: %s", exc)
    except Exception as exc:
        logger.warning("[KYA-RT] subscriber loop failed: %s", exc)
