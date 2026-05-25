"""
Delegation policy enforcement — principal-of-least-privilege chain.

When one agent delegates to another (orchestrator spawns sub-agents),
KYA already records the parent_invocation_id + principal pointer so
the audit chain reaches back to the originating user. This module
adds the second axis: whether the sub-agent's *capabilities* are
allowed to be broader than the parent's.

We treat the parent's properties as a *ceiling*. A sub-agent may be:
  - More restrictive than the parent (always fine — defense in depth)
  - Identical to the parent (fine)
  - Broader on a dimension we track (a violation — logged or blocked)

Dimensions tracked (each has its own ranking / subset rule):

    access_level    — read < write < admin
                      sub > parent => access_escalation
    data_classes    — set membership
                      sub - parent != empty => data_class_widening
    human_loop      — in_the_loop (high oversight)
                      > on_the_loop / hybrid
                      > observed
                      > autonomous / out_of_loop / none (low oversight)
                      parent supplies higher rank than sub => human_loop_relax
    tools           — admin/write subset
                      sub has admin/write tool parent doesn't => tool_widening

Modes (env: KYA_DELEGATION_POLICY)
----------------------------------
    "observe" (DEFAULT)
        Detect, write a row to kya_delegation_violations, return list.
        record_invocation succeeds.
    "flag"
        Same as observe, plus a logger.warning. record_invocation succeeds.
    "block"
        Raise DelegationPolicyError. The row is STILL written (with
        blocked=True) before the raise so the audit trail captures
        every attempt — even rejected ones.

The mode is read at every call (live env updates take effect mid-process).

Fail-soft contract
------------------
Snapshots not found, table missing, transient DB error → log at DEBUG,
return empty list, do not propagate. Observability MUST NOT break the
request path. The exception to this is `block` mode with a genuine
violation — that's the policy contract talking, not an error.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


# ── Public exception hierarchy ──────────────────────────────────────


class DelegationPolicyError(Exception):
    """Base — raised in `block` mode when a sub-agent's capabilities
    exceed the orchestrator's. The instance carries a structured
    `violations` list describing every dimension that failed."""

    def __init__(self, violations: list[dict[str, Any]],
                 parent_agent_key: str, sub_agent_key: str):
        self.violations = violations
        self.parent_agent_key = parent_agent_key
        self.sub_agent_key = sub_agent_key
        kinds = ", ".join(v["violation_kind"] for v in violations)
        super().__init__(
            f"Delegation policy violation: sub-agent '{sub_agent_key}' "
            f"under parent '{parent_agent_key}' — {kinds}")


# ── Rankings + closed sets ──────────────────────────────────────────


# access_level: lower index = lower privilege.
_ACCESS_RANK = {
    "read": 0,
    "write": 1,
    "admin": 2,
}


# human_loop: higher index = MORE oversight (= more restrictive).
# Relaxation = sub has LOWER index than parent.
_HUMAN_LOOP_RANK = {
    "none":         0,
    "autonomous":   0,
    "out_of_loop":  0,
    "observed":     1,
    "on_the_loop":  2,
    "hybrid":       2,
    "in_the_loop":  3,
}


# Modes
DELEGATION_POLICY_MODES = frozenset({"observe", "flag", "block"})


_VIOLATION_KINDS = frozenset({
    "access_escalation",
    "data_class_widening",
    "human_loop_relax",
    "tool_widening",
    "trust_low_under_parent",
})


def _current_mode() -> str:
    raw = (os.environ.get("KYA_DELEGATION_POLICY") or "observe").lower()
    if raw not in DELEGATION_POLICY_MODES:
        logger.debug(
            "[KYA-DELEG] unknown KYA_DELEGATION_POLICY=%s — defaulting to 'observe'",
            raw)
        return "observe"
    return raw


# ── Per-dimension check helpers (pure) ──────────────────────────────


def _check_access_level(parent_def: dict, sub_def: dict) -> dict | None:
    p = (parent_def.get("access_level") or "").lower()
    s = (sub_def.get("access_level") or "").lower()
    if not p or not s:
        return None
    p_rank = _ACCESS_RANK.get(p)
    s_rank = _ACCESS_RANK.get(s)
    if p_rank is None or s_rank is None:
        return None
    if s_rank > p_rank:
        return {
            "violation_kind": "access_escalation",
            "parent_value": p,
            "sub_value": s,
        }
    return None


def _check_data_classes(parent_def: dict, sub_def: dict) -> dict | None:
    p = set(parent_def.get("data_classes") or [])
    s = set(sub_def.get("data_classes") or [])
    if not p and not s:
        return None
    extra = s - p
    if extra:
        return {
            "violation_kind": "data_class_widening",
            "parent_value": sorted(p),
            "sub_value": sorted(s),
            "extra": sorted(extra),
        }
    return None


def _check_human_loop(parent_def: dict, sub_def: dict) -> dict | None:
    p = (parent_def.get("human_loop") or "").lower()
    s = (sub_def.get("human_loop") or "").lower()
    if not p or not s:
        return None
    p_rank = _HUMAN_LOOP_RANK.get(p)
    s_rank = _HUMAN_LOOP_RANK.get(s)
    if p_rank is None or s_rank is None:
        return None
    if s_rank < p_rank:
        return {
            "violation_kind": "human_loop_relax",
            "parent_value": p,
            "sub_value": s,
        }
    return None


def _admin_or_write_tools(tools: list[str]) -> set[str]:
    """Filter to admin/write tools using the catalog from kya.risk."""
    try:
        from .risk import is_admin_tool, is_write_tool
    except Exception:
        return set()
    out: set[str] = set()
    for t in tools or []:
        try:
            if is_admin_tool(t) or is_write_tool(t):
                out.add(t)
        except Exception:
            continue
    return out


def _check_tools(parent_def: dict, sub_def: dict) -> dict | None:
    p = _admin_or_write_tools(parent_def.get("tools") or [])
    s = _admin_or_write_tools(sub_def.get("tools") or [])
    extra = s - p
    if extra:
        return {
            "violation_kind": "tool_widening",
            "parent_value": sorted(p),
            "sub_value": sorted(s),
            "extra": sorted(extra),
        }
    return None


# ── Top-level public check ──────────────────────────────────────────


def check_delegation(
    parent_def: dict,
    sub_def: dict,
) -> list[dict[str, Any]]:
    """Pure function — returns a list of violation dicts (possibly empty).

    Does NOT consult the env mode and does NOT touch the database.
    Callers (record_invocation, ad-hoc audits, tests) use this to get
    a structured diff between parent and sub capabilities. Persistence
    + raise-vs-log behavior lives in `enforce_delegation_policy()`.
    """
    if not isinstance(parent_def, dict) or not isinstance(sub_def, dict):
        return []
    out: list[dict] = []
    for fn in (_check_access_level, _check_data_classes,
               _check_human_loop, _check_tools):
        try:
            v = fn(parent_def, sub_def)
        except Exception as exc:
            logger.debug("[KYA-DELEG] dimension check %s raised: %s",
                          fn.__name__, exc)
            continue
        if v:
            out.append(v)
    return out


# ── DB-aware enforcement ────────────────────────────────────────────


def _latest_snapshot(db, tenant_id: str, agent_key: str) -> dict | None:
    """Return the latest snapshotted definition for an agent_key, or
    None if no snapshot exists. Fail-soft on DB errors."""
    try:
        from .versioning import get_version, list_versions
    except Exception:
        return None
    try:
        versions = list_versions(db, tenant_id=tenant_id,
                                  agent_key=agent_key, limit=1)
    except Exception as exc:
        logger.debug("[KYA-DELEG] list_versions(%s) failed: %s",
                      agent_key, exc)
        return None
    if not versions:
        return None
    latest_no = versions[0]["version_no"]
    try:
        row = get_version(db, tenant_id, agent_key, latest_no)
    except Exception as exc:
        logger.debug("[KYA-DELEG] get_version(%s,%d) failed: %s",
                      agent_key, latest_no, exc)
        return None
    if row is None:
        return None
    defn = row.get("definition")
    if not isinstance(defn, dict):
        return None
    return defn


def _persist_violations(
    db, *,
    tenant_id: str,
    sub_invocation_id: int,
    parent_invocation_id: int | None,
    parent_agent_key: str,
    sub_agent_key: str,
    violations: list[dict],
    mode: str,
    blocked: bool,
) -> None:
    """Insert one row per violation. Fail-soft."""
    if not violations:
        return
    try:
        from ._legacy_tables import kya_delegation_violations
    except Exception:
        return
    try:
        # Use raw insert via the bound connection so we honor whatever
        # schema_translate_map the caller has on the session.
        conn = db.connection()
        for v in violations:
            try:
                stmt = kya_delegation_violations.insert().values(
                    tenant_id=tenant_id,
                    sub_invocation_id=sub_invocation_id,
                    parent_invocation_id=parent_invocation_id,
                    parent_agent_key=parent_agent_key,
                    sub_agent_key=sub_agent_key,
                    violation_kind=v["violation_kind"],
                    detail=v,
                    mode_active=mode,
                    blocked=blocked,
                )
                conn.execute(stmt)
            except Exception as exc:
                logger.debug(
                    "[KYA-DELEG] persist violation row failed: %s", exc)
        db.commit()
    except Exception as exc:
        logger.debug("[KYA-DELEG] persist_violations outer failed: %s", exc)
        try: db.rollback()
        except Exception: pass


def enforce_delegation_policy(
    db, *,
    tenant_id: str,
    sub_invocation_id: int,
    parent_invocation_id: int | None,
    parent_agent_key: str,
    sub_agent_key: str,
    parent_def: dict | None = None,
    sub_def: dict | None = None,
    mode: str | None = None,
) -> list[dict]:
    """Compare parent vs sub agent definitions, persist any violations,
    optionally raise. Designed to be called from record_invocation
    when principal_kind=='agent'.

    Returns the list of violations found (empty == clean).

    If `parent_def` / `sub_def` are not supplied, the function fetches
    the latest snapshot from agent_versions. If either snapshot is
    missing, the function logs at DEBUG and returns [] — fail-soft.
    """
    if mode is None:
        mode = _current_mode()

    if parent_def is None:
        parent_def = _latest_snapshot(db, tenant_id, parent_agent_key)
    if sub_def is None:
        sub_def = _latest_snapshot(db, tenant_id, sub_agent_key)

    if not parent_def or not sub_def:
        logger.debug(
            "[KYA-DELEG] missing snapshot (parent=%s sub=%s) — skipping check",
            parent_agent_key, sub_agent_key)
        return []

    violations = check_delegation(parent_def, sub_def)
    if not violations:
        return []

    blocked = (mode == "block")
    _persist_violations(
        db,
        tenant_id=tenant_id,
        sub_invocation_id=sub_invocation_id,
        parent_invocation_id=parent_invocation_id,
        parent_agent_key=parent_agent_key,
        sub_agent_key=sub_agent_key,
        violations=violations,
        mode=mode,
        blocked=blocked,
    )

    if mode == "flag":
        kinds = ", ".join(v["violation_kind"] for v in violations)
        logger.warning(
            "[KYA-DELEG] delegation policy violation: parent=%s sub=%s kinds=%s",
            parent_agent_key, sub_agent_key, kinds)
    elif mode == "block":
        raise DelegationPolicyError(
            violations=violations,
            parent_agent_key=parent_agent_key,
            sub_agent_key=sub_agent_key,
        )

    return violations


# ── Table provisioning ──────────────────────────────────────────────


def ensure_delegation_violations_table(db) -> None:
    """Idempotent create_all of kya_delegation_violations.
    Shares MetaData with the other legacy tables; portable across
    PG/SQLite/DuckDB/MySQL via the same schema_translate_map flow."""
    from ._legacy_tables import (create_legacy_tables,
                                  kya_delegation_violations)
    create_legacy_tables(db, [kya_delegation_violations])
