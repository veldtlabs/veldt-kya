"""
Replay protection for KYA write APIs.

A nonce-based anti-replay primitive scoped per (tenant_id,
principal_id). Same usage pattern as rate_limit.py — single
`verify_request_nonce()` helper called by mutating primitives at
entry. Off by default (no behavior change unless operator opts in).

Why KYA-semantic
----------------
A reverse proxy can't enforce replay protection on KYA writes
because the nonce + timestamp must be tenant- and principal-scoped
— the proxy doesn't parse KYA's payload to find them. This
decision lives here.

Storage backend
---------------
Valkey SET with TTL (default 5 min — `KYA_REPLAY_TTL_SECONDS`).
Each (tenant, principal, nonce) combination gets a key with TTL
matching `max_age_s`. If the key already exists, the request is a
replay. Atomic SET-IF-NOT-EXISTS (`SETNX` + EXPIRE → SET with NX
+ EX flags in modern redis) is used to make the check race-free.

Failure modes
-------------
- Valkey unavailable → fail-soft (returns True, no replay check).
  Same contract as rate_limit.py — replay protection is best-
  effort hardening, not a security boundary.
- Nonce missing / empty / >256 chars → reject (raises ValueError
  on programmer error; soft-rejects with False from
  `is_valid_nonce`).
- Timestamp outside the window → reject as expired.

Two-axis check
--------------
KYA needs BOTH:
  1. Nonce uniqueness (no two requests with the same nonce within
     the TTL window)
  2. Timestamp freshness (no requests with a timestamp outside the
     acceptable skew window)

(1) without (2) lets attackers replay old requests as long as
they're within the TTL — bad. (2) without (1) lets attackers
replay the same request multiple times within the window —
also bad. Together, an attacker needs both a fresh timestamp
AND a not-previously-used nonce. Standard pattern.

Public API
----------
  verify_request_nonce(tenant_id, principal_id, nonce,
                        timestamp_iso, max_age_s=300) -> bool
      Returns True if accepted (nonce now reserved for TTL).
      Returns False if replayed or expired. Raises ValueError
      on malformed inputs.

  generate_nonce() -> str
      Convenience for client-side nonce generation (UUID4 hex).
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Public errors ──────────────────────────────────────────────────


class ReplayDetectedError(RuntimeError):
    """Raised in HARD mode when a request is replayed.
    Carries the context (tenant, principal, nonce, ttl_remaining)
    so HTTP layers can emit a 409/400 with useful detail."""

    def __init__(
        self,
        tenant_id: str,
        principal_id: str,
        nonce: str,
        reason: str,
    ):
        self.tenant_id = tenant_id
        self.principal_id = principal_id
        self.nonce = nonce[:32] + "..." if len(nonce) > 32 else nonce
        self.reason = reason
        super().__init__(
            f"Replay detected for tenant={tenant_id} "
            f"principal={principal_id} nonce={self.nonce} "
            f"reason={reason}")


# ── Defaults ───────────────────────────────────────────────────────


_DEFAULT_MAX_AGE_SECONDS = 300        # 5 min default acceptance window
_DEFAULT_TTL_SECONDS = 300            # match max_age
_MAX_NONCE_LEN = 256
_MIN_NONCE_LEN = 8                    # short enough for UUID hex


def _sanitize_env_segment(s: str) -> str:
    """Strict whitelist for env-var name segments — same defense as
    rate_limit._sanitize_env_segment. Prevents env-var injection /
    namespace collision if tenant_ids ever come from caller-controlled
    sources."""
    return "".join(
        c if c.isalnum() or c == "_" else "_" for c in (s or "")
    ).upper()


def _resolve_max_age(tenant_id: str | None = None) -> int:
    """Per-tenant > global env > default."""
    if tenant_id:
        safe_tid = _sanitize_env_segment(tenant_id)
        v = os.environ.get(f"KYA_REPLAY_MAX_AGE_SECONDS_{safe_tid}")
        if v:
            try:
                return max(1, int(v))
            except (ValueError, TypeError):
                pass
    v = os.environ.get("KYA_REPLAY_MAX_AGE_SECONDS")
    if v:
        try:
            return max(1, int(v))
        except (ValueError, TypeError):
            pass
    return _DEFAULT_MAX_AGE_SECONDS


def _resolve_enabled() -> bool:
    """Off by default. Operators set KYA_REPLAY_PROTECTION=on/1/true
    to enable."""
    v = os.environ.get("KYA_REPLAY_PROTECTION", "").lower().strip()
    return v in ("on", "1", "true", "yes", "enabled")


# ── Public helpers ─────────────────────────────────────────────────


def generate_nonce() -> str:
    """Generate a fresh nonce — 32 hex chars from a cryptographically
    strong RNG. Callers can use any UUID-shape or other identifier;
    this is the recommended default."""
    return secrets.token_hex(16)


def is_valid_nonce(nonce: str) -> bool:
    """Validate a nonce string structurally — non-empty, within
    length bounds, contains no whitespace. Does NOT check uniqueness;
    that's verify_request_nonce's job."""
    if not isinstance(nonce, str):
        return False
    if not (_MIN_NONCE_LEN <= len(nonce) <= _MAX_NONCE_LEN):
        return False
    if any(c.isspace() for c in nonce):
        return False
    return True


def verify_request_nonce(
    *,
    tenant_id: str,
    principal_id: str,
    nonce: str,
    timestamp_iso: str | None = None,
    max_age_s: int | None = None,
    mode: str = "soft",
    principal_kind: str = "user",
    db: Any = None,
) -> bool:
    """Verify a request is not a replay. Returns True if accepted
    (nonce now reserved for TTL), False if replayed or expired.

    `mode="soft"` → returns False on replay (caller decides).
    `mode="hard"` → raises ReplayDetectedError on replay.

    Off by default — when KYA_REPLAY_PROTECTION is not enabled,
    returns True immediately without contacting Valkey. Operators
    opt in tenant-by-tenant or globally.

    `timestamp_iso` is the client-supplied request time (ISO-8601).
    If supplied, must be within ±max_age_s of server clock. If None,
    only nonce-uniqueness is checked.

    Args
    ----
    tenant_id : str        Required. Scopes the nonce namespace.
    principal_id : str     Required. Sub-scope within tenant — lets
                           two different agents use overlapping
                           nonces without colliding.
    nonce : str            Required. 8-256 chars, no whitespace.
                           Recommended: secrets.token_hex(16).
    timestamp_iso : str    Optional. ISO-8601 timestamp from client.
                           Rejects if outside ±max_age_s skew window.
    max_age_s : int        Window size. Defaults to KYA_REPLAY_MAX_AGE_SECONDS
                           env or 300 (5 min).
    """
    if not _resolve_enabled():
        return True

    if not tenant_id:
        raise ValueError("tenant_id is required")
    if not principal_id:
        raise ValueError("principal_id is required")
    if not is_valid_nonce(nonce):
        if mode == "hard":
            raise ReplayDetectedError(
                tenant_id, principal_id, nonce or "<empty>",
                "malformed_nonce")
        return False

    max_age = max_age_s if max_age_s is not None else _resolve_max_age(
        tenant_id)

    # Timestamp window check (if supplied)
    if timestamp_iso is not None:
        try:
            ts = datetime.fromisoformat(
                timestamp_iso.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            if mode == "hard":
                raise ReplayDetectedError(
                    tenant_id, principal_id, nonce,
                    "malformed_timestamp")
            return False
        now = datetime.now(timezone.utc)
        delta = abs((now - ts).total_seconds())
        if delta > max_age:
            if mode == "hard":
                raise ReplayDetectedError(
                    tenant_id, principal_id, nonce,
                    f"timestamp_skew_{delta:.0f}s_exceeds_{max_age}s")
            return False

    # Nonce uniqueness check via Valkey SETNX with TTL.
    key = f"kya:nonce:{tenant_id}:{principal_id}:{nonce}"
    try:
        # Use the SDK-friendly accessor (env-driven, redis-py based).
        # Falls back to a registered factory if the parent app
        # wired one up (e.g., Veldt platform's db.redis shim).
        from ._valkey import get_valkey
        rds = get_valkey()
        if rds is None:
            # Fail-open — same contract as rate_limit.py. Replay
            # protection is best-effort hardening, not a security
            # boundary on the request path.
            logger.debug(
                "[KYA-REPLAY] Valkey unavailable; fail-open")
            return True
    except Exception as exc:
        logger.debug(
            "[KYA-REPLAY] Valkey helper unavailable (%s); fail-open",
            exc)
        return True

    try:
        # SET NX EX — atomic "set if not exists, with TTL".
        # Returns True if the key was newly created (= accepted),
        # None / False if the key already existed (= replay).
        accepted = rds.set(key, "1", nx=True, ex=max_age)
    except Exception as exc:
        logger.debug(
            "[KYA-REPLAY] SET NX raised (%s); fail-open", exc)
        return True

    if not accepted:
        # Replay detected — emit security event regardless of mode.
        # The audit trail captures the attempt even when soft mode
        # returns False without raising.
        try:
            from ._security_events import emit_security_event
            emit_security_event(
                "replay_detected",
                tenant_id=tenant_id,
                primitive="verify_request_nonce",
                principal_kind=principal_kind,
                principal_id=principal_id, db=db,
                detail={
                    "reason": "nonce_already_seen_within_window",
                    "max_age_s": max_age,
                })
        except Exception as exc:
            logger.debug(
                "[KYA-REPLAY] security-event emit failed: %s", exc)
        if mode == "hard":
            raise ReplayDetectedError(
                tenant_id, principal_id, nonce,
                "nonce_already_seen_within_window")
        return False
    return True


# ── Test helpers ───────────────────────────────────────────────────


def reset_replay_state() -> None:
    """Test helper — purge nonce keys for the current process scope.
    No-op when Valkey unreachable."""
    try:
        from ._valkey import get_valkey
        rds = get_valkey()
        if rds is None:
            return
        for k in rds.scan_iter(match="kya:nonce:*"):
            try: rds.delete(k)
            except Exception: pass
    except Exception:
        pass
