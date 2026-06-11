"""The KYA decision stack — assembled, not invented.

For each MCP ``tools/call`` the gateway intercepts, this pipeline:

    1. RBAC check (allow / deny / require_human)
    2. payload-cap check
    3. rate-limit + burst-anomaly check
    4. replay-protection check
    5. tenant-budget check
    6. min_trust gate (via require_action)

Every step delegates to the existing primitive in :mod:`kya` — there is
zero policy logic in this module. If a check fails, the pipeline returns
a :class:`Verdict` with verdict="deny" and a structured ``reason_codes``
list the gateway puts onto the audit record.

This module's job is **orchestration**: order, fail-closed semantics,
and turning exceptions from the primitives into a single typed return
value the gateway can act on without try/except scattered everywhere.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from kya_gateway.config import PolicyConfig, RBACConfig
from kya_gateway.identity import BoundPrincipal

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Verdict:
    """The result of running an MCP request through the policy stack.

    ``verdict`` is one of:
        ``"allow"``          — KYA recommends the customer platform proceed
        ``"deny"``           — KYA recommends the customer platform stop
        ``"require_human"``  — KYA recommends escalation to a human approver

    Always assume the customer platform is the one that **enforces**.
    KYA's role is to **score, sign, and record** — never to block by
    itself.

    ``reason_codes`` is a stable enum-like list (no free-form strings)
    so downstream consumers (attack chain rules, dashboards) can match
    on them. Examples:
        ``RBAC_DENY``, ``MIN_TRUST_NOT_MET``, ``BUDGET_EXCEEDED``,
        ``REPLAY_DETECTED``, ``RATE_LIMIT``, ``PAYLOAD_TOO_LARGE``,
        ``REQUIRES_HUMAN``.

    ``signal_kind`` is the trust signal the gateway will record on the
    principal's trust ledger.
    """

    verdict: str
    reason_codes: list[str] = field(default_factory=list)
    signal_kind: str = "clean_invocation"
    rich: dict[str, Any] = field(default_factory=dict)


def evaluate(
    *,
    db,
    tenant_id: str,
    principal: BoundPrincipal,
    action: str,
    payload_bytes: int,
    invocation_id: int | None,
    cfg: PolicyConfig,
) -> Verdict:
    """Run an MCP request through the configured policy stack.

    Args:
        db: A KYA session.
        tenant_id: KYA tenant the request belongs to.
        principal: The resolved BoundPrincipal.
        action: A canonical action string like ``mcp.filesystem.read``.
        payload_bytes: Size of the request payload.
        invocation_id: The KYA invocation row the gateway has already
            recorded for this request (used by replay protection).
        cfg: The policy block from the gateway config.

    Returns:
        A :class:`Verdict`. Always returns — never raises.
    """
    reasons: list[str] = []

    # ─── RBAC ───────────────────────────────────────────────────
    if cfg.rbac is not None:
        rbac_outcome = _rbac_evaluate(cfg.rbac, principal.principal_kind, action)
        if rbac_outcome == "deny":
            return Verdict(
                verdict="deny",
                reason_codes=["RBAC_DENY"],
                signal_kind="rbac_refusal",
            )
        if rbac_outcome == "require_human":
            reasons.append("REQUIRES_HUMAN")

    # ─── Payload caps ───────────────────────────────────────────
    if cfg.payload_caps is not None and payload_bytes > cfg.payload_caps.max_bytes:
        return Verdict(
            verdict="deny",
            reason_codes=["PAYLOAD_TOO_LARGE"],
            signal_kind="payload_too_large",
        )

    # ─── Rate limit ─────────────────────────────────────────────
    # Fail-closed contract: ImportError → primitive not installed → skip
    # with debug log. Any OTHER exception (DB/network/etc.) → deny with
    # a "_ERROR" reason code so the audit chain captures the operational
    # state and the caller doesn't silently slip through.
    if cfg.rate_limit is not None:
        try:
            from kya.rate_limit import check_rate
        except ImportError:
            logger.debug("[KYA-GATEWAY] kya.rate_limit unavailable; skipping rate check")
        else:
            try:
                rate_ok = check_rate(
                    db,
                    tenant_id=tenant_id,
                    principal_kind=principal.principal_kind,
                    principal_id=principal.principal_id,
                    requests_per_minute=cfg.rate_limit.requests_per_minute,
                )
            except Exception as exc:
                logger.warning("[KYA-GATEWAY] check_rate raised: %s", exc)
                return Verdict(
                    verdict="deny",
                    reason_codes=["RATE_LIMIT_ERROR"],
                    signal_kind="rate_limit_exceeded",
                )
            if not rate_ok:
                return Verdict(
                    verdict="deny",
                    reason_codes=["RATE_LIMIT"],
                    signal_kind="rate_limit_exceeded",
                )

    # ─── Replay protection ─────────────────────────────────────
    if invocation_id is not None:
        try:
            from kya.replay_protection import check_invocation_replay
        except ImportError:
            logger.debug("[KYA-GATEWAY] kya.replay_protection unavailable; skipping")
        else:
            try:
                replay_ok = check_invocation_replay(db, invocation_id=invocation_id)
            except Exception as exc:
                logger.warning("[KYA-GATEWAY] check_invocation_replay raised: %s", exc)
                return Verdict(
                    verdict="deny",
                    reason_codes=["REPLAY_ERROR"],
                    signal_kind="replay_detected",
                )
            if not replay_ok:
                return Verdict(
                    verdict="deny",
                    reason_codes=["REPLAY_DETECTED"],
                    signal_kind="replay_detected",
                )

    # ─── Tenant budget ─────────────────────────────────────────
    if cfg.tenant_budget and cfg.tenant_budget.daily_usd is not None:
        try:
            from kya.tenant_budget import should_refuse
        except ImportError:
            logger.debug("[KYA-GATEWAY] kya.tenant_budget unavailable; skipping")
        else:
            try:
                refuse = should_refuse(
                    db,
                    tenant_id=tenant_id,
                    daily_cap_usd=cfg.tenant_budget.daily_usd,
                )
            except Exception as exc:
                logger.warning("[KYA-GATEWAY] should_refuse raised: %s", exc)
                return Verdict(
                    verdict="deny",
                    reason_codes=["BUDGET_ERROR"],
                    signal_kind="budget_error",
                )
            if refuse == "refuse":
                return Verdict(
                    verdict="deny",
                    reason_codes=["BUDGET_EXCEEDED"],
                    signal_kind="budget_exceeded",
                )

    # ─── min_trust gate ────────────────────────────────────────
    if cfg.min_trust > 0:
        try:
            from kya import AccessDeniedError, require_action
        except ImportError:
            logger.debug("[KYA-GATEWAY] kya.require_action unavailable; skipping")
            AccessDeniedError = None  # type: ignore[assignment]
            require_action = None     # type: ignore[assignment]
        if require_action is not None:
            try:
                require_action(
                    db,
                    tenant_id=tenant_id,
                    principal_kind=principal.principal_kind,
                    principal_id=principal.principal_id,
                    action=action,
                    min_trust=cfg.min_trust,
                )
            except AccessDeniedError:
                return Verdict(
                    verdict="deny",
                    reason_codes=["MIN_TRUST_NOT_MET"],
                    signal_kind="governance_block",
                )
            except Exception as exc:
                logger.warning("[KYA-GATEWAY] require_action raised: %s", exc)
                return Verdict(
                    verdict="deny",
                    reason_codes=["MIN_TRUST_ERROR"],
                    signal_kind="governance_block",
                )

    # ─── All checks passed ─────────────────────────────────────
    if "REQUIRES_HUMAN" in reasons:
        return Verdict(
            verdict="require_human",
            reason_codes=reasons,
            signal_kind="governance_block",
        )
    return Verdict(verdict="allow", reason_codes=[], signal_kind="clean_invocation")


# ─── RBAC helper ────────────────────────────────────────────────────


def _rbac_evaluate(rbac: RBACConfig, principal_kind: str, action: str) -> str:
    """Evaluate the rule list for a principal_kind + action pair.

    Returns one of "allow" / "deny" / "require_human".
    """
    for rule in rbac.rules:
        if rule.principal_kind != principal_kind:
            continue
        if _action_matches(action, rule.actions):
            return rule.verdict
    return rbac.default


def _action_matches(action: str, patterns: list[str]) -> bool:
    """Action matcher with `.` namespacing and `*` wildcard support.

    ``mcp.filesystem.read`` matches:
        * ``mcp.filesystem.read``
        * ``mcp.filesystem.*``
        * ``mcp.*``
        * ``*``
    """
    for p in patterns:
        if p == action:
            return True
        if p.endswith(".*") and action.startswith(p[:-1]):
            return True
        if p == "*":
            return True
    return False
