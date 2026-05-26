"""
KYA-semantic rate limiting on write primitives.

The reverse proxy in front of KYA can rate-limit by URL or IP. It
*cannot* rate-limit by KYA-semantic dimensions ("agent X calling
record_invocation 1000/sec") because it doesn't parse KYA payloads.
That decision lives here.

Design contract
---------------
- **Off by default.** No rate limit unless `KYA_RATE_LIMIT_DEFAULT_RPS`
  or a more specific env var is set. KYA never adds latency you
  didn't ask for.
- **Modular.** A single `maybe_rate_limit()` is the only public
  surface. Write primitives call it once at entry. Fail-soft on
  Valkey unavailability (degrades to "no limit" rather than
  breaking the request path).
- **DRY.** Reuses the existing Valkey token-bucket helper
  `kya_redteam.runtime.acquire_rate_token` (production-tested by
  the red-team module). No duplicate implementation.
- **Per-tenant, per-primitive granularity.** Operators can set
  different limits for different primitives (e.g., evidence writes
  rate-limited tighter than invocation reads) and per-tenant
  overrides (`KYA_RATE_LIMIT_RPS_<TENANT_ID>_<PRIMITIVE>`).

Two enforcement modes
---------------------
- **"soft" (default):** if the rate is exceeded, the call BLOCKS up
  to `max_wait_s` waiting for a token. Use for background / batch
  paths where you'd rather sleep than fail.
- **"hard":** if the rate is exceeded and no token becomes available
  within `max_wait_s`, raise `RateLimitExceededError`. Use for the
  HTTP path where the caller should get a 429 response.

Resolution order for `rps`
--------------------------
Most-specific to least-specific env var:
  1. KYA_RATE_LIMIT_RPS_<TENANT_UPPER>_<PRIMITIVE_UPPER>
  2. KYA_RATE_LIMIT_RPS_<PRIMITIVE_UPPER>
  3. KYA_RATE_LIMIT_DEFAULT_RPS
  4. 0 (no limit — call proceeds immediately)

Tenant UUID is sanitized to env-safe form (hyphens → underscores)
because env var names can't contain hyphens.

Failure modes
-------------
- Valkey unavailable → fail-open (returns True without limiting).
  Preserves KYA's fail-soft contract; rate-limiter is best-effort
  protection, not a security boundary.
- Invalid env (non-numeric rps) → ignored, falls through to next
  resolution step. Logged at DEBUG.
- Unknown primitive name → no error; just no env match, no limit.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


# ── Public errors ──────────────────────────────────────────────────


class RateLimitExceededError(RuntimeError):
    """Raised in HARD mode when no token is available within
    `max_wait_s`. Carries the structured context (tenant, primitive,
    rps_limit, retry_after_s) so HTTP layers can emit a 429 with
    correct `Retry-After` headers."""

    def __init__(
        self,
        tenant_id: str,
        primitive: str,
        rps_limit: float,
        retry_after_s: float,
    ):
        self.tenant_id = tenant_id
        self.primitive = primitive
        self.rps_limit = rps_limit
        self.retry_after_s = retry_after_s
        super().__init__(
            f"Rate limit exceeded for tenant={tenant_id} "
            f"primitive={primitive}: {rps_limit} rps "
            f"(retry after {retry_after_s:.1f}s)")


# ── Public API ─────────────────────────────────────────────────────


def maybe_rate_limit(
    tenant_id: str,
    primitive: str,
    *,
    mode: str = "soft",
    max_wait_s: float = 5.0,
    principal_kind: str | None = None,
    principal_id: str | None = None,
    db: Any | None = None,
) -> bool:
    """Apply rate limit for this (tenant, primitive). Returns True
    if the call should proceed.

    `mode="soft"`  — exceeds → blocks up to max_wait_s, then proceeds.
                     Useful for batch / background paths.
    `mode="hard"`  — exceeds → raises RateLimitExceededError after
                     max_wait_s of waiting. Useful for HTTP paths
                     where caller should get a 429.

    `principal_kind` + `principal_id` + `db` (all three required
    together) enable security-event emission to kya_principal_trust
    on denial — events get a permanent audit row + trust-score debit
    (per users.SIGNAL_DELTAS["rate_limit_exceeded"]). Omit any of the
    three to fall back to log-only.

    No limit configured (env unset or rps == 0) → returns True
    immediately, no Valkey call, no overhead. KYA stays cheap when
    operators haven't opted in.
    """
    rps = _resolve_rps(tenant_id, primitive)
    if rps <= 0:
        return True
    target_id = f"kya:{tenant_id}:{primitive}"
    try:
        # DRY — reuses the production-tested token-bucket helper
        # already shipping with kya_redteam. Same Valkey backend,
        # same backoff semantics, same fail-soft contract.
        from kya_redteam.runtime import acquire_rate_token
    except Exception as exc:
        logger.debug(
            "[KYA-RL] rate-limit helper unavailable (%s); fail-open",
            exc)
        return True
    try:
        wait_s = acquire_rate_token(
            target_id, rps, max_wait_s=max_wait_s)
    except Exception as exc:
        logger.debug(
            "[KYA-RL] acquire_rate_token raised (%s); fail-open", exc)
        return True
    # Emit a security event for EVERY call that incurred a wait,
    # not just budget-exhausted ones. Operators want the audit
    # signal to reflect "rate limit fired N times" — same count
    # whether the call was delayed 50ms or exhausted the budget.
    # When wait_s is 0, the call was within budget; no event fires.
    if wait_s > 0:
        try:
            from ._security_events import emit_security_event
            emit_security_event(
                "rate_limit_exceeded",
                tenant_id=tenant_id, primitive=primitive,
                principal_kind=principal_kind,
                principal_id=principal_id, db=db,
                detail={"rps_limit": rps,
                        "wait_s": round(wait_s, 3),
                        "mode": mode,
                        "budget_exhausted": wait_s >= max_wait_s})
        except Exception as exc:
            logger.debug(
                "[KYA-RL] security-event emit failed: %s", exc)
        if mode == "hard" and wait_s >= max_wait_s:
            raise RateLimitExceededError(
                tenant_id=tenant_id, primitive=primitive,
                rps_limit=rps, retry_after_s=wait_s)
    return True


def _sanitize_env_segment(s: str) -> str:
    """Strict whitelist for env-var name segments: only alphanumerics
    and underscores. Anything else (hyphens, dots, equals, colons,
    spaces, ...) → underscore. Defeats env-var injection / collision
    if tenant_ids or primitive names ever come from caller-controlled
    input. The .upper() at the end mirrors env-var convention."""
    return "".join(
        c if c.isalnum() or c == "_" else "_" for c in (s or "")
    ).upper()


def _resolve_rps(tenant_id: str, primitive: str) -> float:
    """Specificity-ordered env lookup. First match wins."""
    safe_tid = _sanitize_env_segment(tenant_id)
    prim_upper = _sanitize_env_segment(primitive)
    keys = [
        f"KYA_RATE_LIMIT_RPS_{safe_tid}_{prim_upper}",
        f"KYA_RATE_LIMIT_RPS_{prim_upper}",
        "KYA_RATE_LIMIT_DEFAULT_RPS",
    ]
    for key in keys:
        raw = os.environ.get(key)
        if not raw:
            continue
        try:
            v = float(raw)
            return max(0.0, v)
        except (ValueError, TypeError):
            logger.debug(
                "[KYA-RL] ignoring non-numeric env %s=%r", key, raw)
            continue
    return 0.0


# ── Test helpers ───────────────────────────────────────────────────


def reset_rate_limit_state() -> None:
    """Test helper — clears the Valkey rate-limit keys for this
    KYA process scope. Safe to call repeatedly; no-op if Valkey
    unreachable."""
    try:
        from kya_redteam.runtime import _get_valkey
        rds = _get_valkey()
        if rds is None:
            return
        for key in rds.scan_iter(match="kya:redteam:rl:kya:*"):
            try: rds.delete(key)
            except Exception: pass
    except Exception:
        pass
