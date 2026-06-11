"""
Shared security-event emission for the hardening modules.

DRY collector used by `rate_limit`, `payload_caps`,
`replay_protection` (and any future hardening primitive) to record
a violation in three places at once:

  1. **Structured WARNING log** — always. Visible in any log
     aggregator (Splunk, Datadog, ELK) without configuration.
  2. **realtime.record_signal** — when Valkey is configured.
     Bumps sliding-window counters for burst detection, fires
     subscribe_alerts pub/sub channel for live dashboards.
  3. **principals.record_principal_signal** — when a DB session
     + principal_kind + principal_id are supplied. Persists the
     event to kya_principal_trust (drops the trust score per
     `users.SIGNAL_DELTAS`) so the audit chain has a permanent
     row, even if Valkey loses its sliding-window counters.

All three paths are fail-soft: a failure in any one logs at
DEBUG and continues. The caller's request path is NEVER blocked
by security-event emission — emission is best-effort audit, not
the security boundary itself (the security boundary is the
ACTUAL denial from the calling module).

Why split persistence between Valkey + DB?
------------------------------------------
- Valkey gives fast burst detection windows (1m / 5m / 1h /
  24h / 7d) but is ephemeral; events can fall out of the window.
- DB gives durable audit (HMAC-chained eventually) for compliance.
- Both wanted in production — Valkey for live dashboards, DB
  for "what happened 6 months ago when the auditor asks."
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# Closed set of hardening event kinds this module knows how to
# emit. Must match entries in:
#   - kya/realtime.py ALLOWED_SIGNAL_KINDS
#   - kya/users.py SIGNAL_DELTAS
# Mismatches cause the realtime path to silently drop the signal.
_HARDENING_EVENT_KINDS = frozenset({
    "rate_limit_exceeded",
    "payload_too_large",
    "replay_detected",
    # Phase 5b — RBAC denial. Already exists in realtime
    # ALLOWED_SIGNAL_KINDS + users.SIGNAL_DELTAS so the realtime
    # + DB paths fire correctly once whitelisted here too.
    "rbac_refusal",
    # Phase 5g — runtime identity-layer events. Gateway + issuer-API
    # call emit_security_event() with these to debit principal trust
    # + feed attack-chain windows via the existing paths. Operators
    # may need to add matching entries in `kya/realtime.py:
    # ALLOWED_SIGNAL_KINDS` and `kya/users.py:SIGNAL_DELTAS` to
    # enable trust-score deltas; the WARNING log + DB row fire
    # without them.
    "revocation_blocked",
    "dpop_replay",
    "dpop_forge_attempt",
    "dpop_expired",
    "issuer_rotation_pending",
    # Phase 5h — burst of denials from same requester suggests
    # attempted misuse of the issuance approval flow.
    "vc_approval_denied",
})


def emit_security_event(
    event_kind: str,
    *,
    tenant_id: str,
    primitive: str | None = None,
    principal_kind: str | None = None,
    principal_id: str | None = None,
    detail: dict | None = None,
    db: Any | None = None,
) -> None:
    """Record a hardening-violation event in up-to-three places.

    Args
    ----
    event_kind : str
        One of `_HARDENING_EVENT_KINDS`. Unknown kinds log at
        DEBUG and skip (no realtime signal, no DB row).
    tenant_id : str
        Required for log + realtime emission. The events fall to
        log-only if tenant_id is empty.
    primitive : str | None
        Which KYA primitive triggered (record_invocation,
        record_evidence, ...). Included in log + detail dict.
    principal_kind, principal_id : str | None
        When BOTH provided, the event is also persisted via
        record_principal_signal (debits trust). Omit if the
        violation isn't attributable to a specific principal.
    detail : dict | None
        Extra structured context (rps_limit, actual_bytes vs
        max_bytes, replay reason, etc.) for log + signal payload.
    db : SQLAlchemy session | None
        Required for the DB-persist branch. If omitted, only
        the log + realtime paths fire.

    Returns
    -------
    None. All errors swallowed.
    """
    detail = dict(detail or {})
    if primitive:
        detail.setdefault("primitive", primitive)

    # Path 1 — structured WARNING log. Always fires.
    try:
        logger.warning(
            "[KYA-SEC] event=%s tenant=%s primitive=%s "
            "principal=%s:%s detail=%s",
            event_kind, tenant_id or "<unset>",
            primitive or "<unset>",
            principal_kind or "<unset>",
            principal_id or "<unset>",
            detail,
        )
    except Exception:
        pass  # log emission must never raise

    if event_kind not in _HARDENING_EVENT_KINDS:
        logger.debug(
            "[KYA-SEC] unknown event_kind=%r — skipping persistence",
            event_kind)
        return

    if not tenant_id:
        return  # tenant scope required for persistence

    # Path 2 — realtime signal. Bumps Valkey windowed counters +
    # publishes to pub/sub. Fail-soft.
    try:
        from .realtime import record_signal
        record_signal(
            tenant_id=tenant_id,
            agent_key=principal_id or "<unset>",
            signal_kind=event_kind,
            severity="warning",
            detail=detail,
        )
    except Exception as exc:
        logger.debug("[KYA-SEC] realtime emit failed: %s", exc)

    # Path 3 — durable DB persistence via principal trust. Fail-soft.
    # Only fires when we have both DB session AND a specific
    # principal to attribute the event to. Events that can't be
    # attributed (e.g., rate-limit hit from a token with no
    # principal context) stay in the log-only path.
    if db is None or not principal_kind or not principal_id:
        return
    try:
        from .principals import record_principal_signal
        record_principal_signal(
            db, tenant_id=tenant_id,
            principal_kind=principal_kind,
            principal_id=principal_id,
            signal_kind=event_kind,
            attributes={"hardening": detail},
        )
    except Exception as exc:
        logger.debug(
            "[KYA-SEC] DB persistence failed for event=%s: %s",
            event_kind, exc)
