"""Runtime gates — budget enforcement + rate limiting.

Two things every red-team run does that the operator must control:

  1. **Monthly budget** — total target calls per tenant per month. The
     operator caps this in kya_redteam_tenant_policy.budget_monthly_prompts.
     Each target call atomically INCRs a Valkey counter; if the counter
     exceeds the cap, the call is rejected and the orchestrator finalizes
     the run with 'failed' / error='budget_exhausted'.

  2. **Rate limit per target** — to avoid DoSing the customer's
     production agent endpoint. Per-target rate_limit_rps drives a
     Valkey-backed token bucket. Each send() acquires one token before
     proceeding; when empty, it sleeps until the bucket refills.

Both gates are Valkey-first with no-op fallback when Valkey is
unavailable. Refusing to send because Valkey is down is more disruptive
than letting a request through — the budget/rate cap is a SAFETY belt,
not a SECURITY boundary. (The security boundary is the tenant's auth
on the target endpoint itself.)
"""
from __future__ import annotations

import datetime as _dt
import logging
import os
import time

logger = logging.getLogger(__name__)


# ── Valkey accessor (cached) ────────────────────────────────────────

def _get_valkey():
    """Resolve a Valkey/Redis client. Tries two paths:

    1. `db.redis.get_redis` — the Veldt platform's existing shim.
       Wins when the parent app provides it (backward compat).
    2. `kya._valkey.get_valkey` — the SDK-friendly env-based
       accessor (KYA_VALKEY_URL / REDIS_URL). Used when KYA is
       installed standalone via `pip install veldt-kya`.

    Returns None when neither path produces a working client —
    hardening features then fail-open per the documented contract.
    """
    # Path 1: Veldt platform shim (backward compat)
    try:
        from db.redis import get_redis  # type: ignore
        return get_redis()
    except (ImportError, ModuleNotFoundError):
        pass
    except Exception:
        # Other errors from db.redis shouldn't fall through —
        # the platform shim was found but malfunctioning. Log
        # and degrade gracefully.
        import logging as _log
        _log.getLogger(__name__).debug(
            "[KYA-REDTEAM] db.redis raised non-import error; "
            "falling through to SDK default accessor")
    # Path 2: SDK env-based default
    try:
        from kya._valkey import get_valkey
        return get_valkey()
    except Exception:
        return None


# ── Budget (monthly) ────────────────────────────────────────────────

_BUDGET_TTL_S = 35 * 24 * 3600   # 35 days — long enough to cover end-of-month grace


def _budget_key(tenant_id: str, now: _dt.datetime | None = None) -> str:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return f"kya:redteam:budget:{tenant_id}:{now.strftime('%Y%m')}"


def check_budget(tenant_id: str, limit: int) -> dict:
    """Read-only check — no INCR. Returns {used, limit, allowed}."""
    rds = _get_valkey()
    if rds is None:
        # Fail open when Valkey unavailable — don't break runs because
        # the cache is down. Operator alerting should catch this.
        return {"used": 0, "limit": limit, "allowed": True,
                "valkey_unavailable": True}
    try:
        val = rds.get(_budget_key(tenant_id))
        used = int(val) if val else 0
        return {"used": used, "limit": limit,
                "allowed": used < limit, "valkey_unavailable": False}
    except Exception as exc:
        logger.debug("[REDTEAM-RT] budget read failed: %s", exc)
        return {"used": 0, "limit": limit, "allowed": True,
                "valkey_unavailable": True}


def consume_budget(tenant_id: str, limit: int, n: int = 1) -> dict:
    """Atomic INCR + check. Returns {used, limit, allowed}.

    `allowed=False` means the post-INCR value crossed the cap — the
    caller should stop. Note: we INCR first then compare, so the
    final used value MAY exceed limit by up to (concurrent_callers - 1).
    Acceptable for a budget gate (the overage is bounded and small).
    """
    rds = _get_valkey()
    if rds is None:
        return {"used": 0, "limit": limit, "allowed": True,
                "valkey_unavailable": True}
    try:
        key = _budget_key(tenant_id)
        new_value = rds.incrby(key, n)
        # Refresh TTL on each write — survives month-boundary edge cases.
        rds.expire(key, _BUDGET_TTL_S)
        return {"used": int(new_value), "limit": limit,
                "allowed": int(new_value) <= limit,
                "valkey_unavailable": False}
    except Exception as exc:
        logger.debug("[REDTEAM-RT] budget incr failed: %s", exc)
        return {"used": 0, "limit": limit, "allowed": True,
                "valkey_unavailable": True}


# ── Token budget (attacker + judge LLM cost) ────────────────────────
# The prompt-count budget caps target calls. But each multi-turn
# conversation also fires attacker-LLM + judge-LLM calls per turn, and
# those LLM tokens cost real money. A separate token counter prevents
# a campaign with a small prompt budget from running up large LLM bills.
#
# Default cap is intentionally generous (10M tokens/month ≈ $100 of
# Sonnet-4.6 inference) so legitimate Standard-tier customers don't
# hit it. Premium tenants who actually need higher caps override via
# kya_redteam_tenant_policy.attacker_tokens_monthly_cap (Phase 3.5
# adds the column) or the env default.

_DEFAULT_ATTACKER_TOKEN_CAP = int(os.environ.get(
    "KYA_REDTEAM_ATTACKER_TOKENS_MONTHLY_CAP_DEFAULT", "10000000",
))


def _token_budget_key(tenant_id: str, now: _dt.datetime | None = None) -> str:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return f"kya:redteam:tokens:{tenant_id}:{now.strftime('%Y%m')}"


def check_token_budget(tenant_id: str, cap: int | None = None) -> dict:
    """Read-only check of attacker/judge token usage this month.

    M7 — cap=0 is treated as "explicit zero" (no tokens allowed); only
    cap=None falls back to the env default. This lets an operator set
    `attacker_tokens_monthly_cap=0` to freeze attacker LLM usage for
    a tenant without us silently overriding to 10M.
    """
    if cap is None:
        cap = _DEFAULT_ATTACKER_TOKEN_CAP
    rds = _get_valkey()
    if rds is None:
        return {"used": 0, "cap": cap, "allowed": True,
                "valkey_unavailable": True}
    try:
        val = rds.get(_token_budget_key(tenant_id))
        used = int(val) if val else 0
        return {"used": used, "cap": cap, "allowed": used < cap,
                "valkey_unavailable": False}
    except Exception as exc:
        logger.debug("[REDTEAM-RT] token budget read failed: %s", exc)
        return {"used": 0, "cap": cap, "allowed": True,
                "valkey_unavailable": True}


def consume_attacker_tokens(
    tenant_id: str, tokens: int, cap: int | None = None,
) -> dict:
    """INCRBY the monthly attacker-token counter. Returns the standard
    {used, cap, allowed} dict. `allowed=False` means the cap has been
    crossed; the orchestrator should stop the conversation cleanly.
    Fail-open on Valkey unavailable — same semantics as consume_budget.

    M7 — cap=0 is treated as "explicit zero" (cap reached on the first
    non-zero charge); only cap=None falls back to the env default.
    """
    if cap is None:
        cap = _DEFAULT_ATTACKER_TOKEN_CAP
    rds = _get_valkey()
    if rds is None or tokens <= 0:
        return {"used": 0, "cap": cap, "allowed": True,
                "valkey_unavailable": rds is None}
    try:
        key = _token_budget_key(tenant_id)
        new_value = rds.incrby(key, int(tokens))
        rds.expire(key, _BUDGET_TTL_S)
        return {"used": int(new_value), "cap": cap,
                "allowed": int(new_value) <= cap,
                "valkey_unavailable": False}
    except Exception as exc:
        logger.debug("[REDTEAM-RT] token budget incr failed: %s", exc)
        return {"used": 0, "cap": cap, "allowed": True,
                "valkey_unavailable": True}


# ── Rate limit (per target, token bucket) ───────────────────────────
# Simple sliding-window: each send() INCRs a per-second counter; when
# the count exceeds rate_limit_rps, the caller sleeps until the next
# second window. Coarser than a true token bucket but cheap and
# Valkey-friendly. For rps < 1, switch to a 'last-call-at' Valkey key.

def _rate_key(target_id: str, now_s: int) -> str:
    return f"kya:redteam:rl:{target_id}:{now_s}"


def _rate_last_key(target_id: str) -> str:
    return f"kya:redteam:rl_last:{target_id}"


def acquire_rate_token(target_id: str, rate_limit_rps: float,
                        max_wait_s: float = 30.0) -> float:
    """Block until a rate-limit token is available. Returns the wait
    time in seconds.

    `target_id` is any stable string identifying the target — typically
    f"{tenant_id}:{persistent_target_id}" or
    f"{tenant_id}:adhoc:{endpoint_hash}". Distinct strings get distinct
    budgets so multiple targets don't share a single bucket.
    """
    if rate_limit_rps <= 0:
        return 0.0
    rds = _get_valkey()
    if rds is None:
        return 0.0   # fail open

    total_wait = 0.0
    # Choose strategy by rps. For rps >= 1, use a per-second bucket;
    # for rps < 1, enforce a minimum interval since last call.
    if rate_limit_rps >= 1.0:
        cap = max(1, int(rate_limit_rps))
        backoff = 0.05
        while total_wait < max_wait_s:
            now_s = int(time.time())
            key = _rate_key(target_id, now_s)
            try:
                count = rds.incr(key)
                # Set TTL on first INCR (returns 1) — 2-second window
                # to outlive any clock skew on the consumer side.
                if int(count) == 1:
                    rds.expire(key, 2)
                if int(count) <= cap:
                    return total_wait
            except Exception as exc:
                logger.debug("[REDTEAM-RT] rate incr failed: %s", exc)
                return total_wait   # fail open
            # Sleep + retry. Exponential up to 0.4s to avoid hammering Valkey.
            time.sleep(backoff)
            total_wait += backoff
            backoff = min(0.4, backoff * 1.5)
        return total_wait

    # rps < 1: enforce minimum interval since last call.
    min_interval = 1.0 / rate_limit_rps
    try:
        last = rds.get(_rate_last_key(target_id))
        last_t = float(last) if last else 0.0
    except Exception:
        last_t = 0.0
    wait = max(0.0, last_t + min_interval - time.time())
    if wait > 0:
        time.sleep(min(wait, max_wait_s))
        total_wait += min(wait, max_wait_s)
    try:
        rds.set(_rate_last_key(target_id), str(time.time()), ex=300)
    except Exception:
        pass
    return total_wait


# ── Status summary (for the dashboard) ──────────────────────────────

def runtime_status(tenant_id: str, limit: int) -> dict:
    """Surface the current month's budget + token-budget consumption +
    Valkey reachability. Used by the dashboard's red-team page."""
    rds = _get_valkey()
    out: dict = {
        "valkey_reachable": rds is not None,
        "budget": check_budget(tenant_id, limit),
        "token_budget": check_token_budget(tenant_id),
        "current_month": _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m"),
    }
    return out
