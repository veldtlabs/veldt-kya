"""
KYA HTTP client — minimal, dep-light, reusable across frameworks.

Only depends on `requests`. Framework-specific hooks layer on top.
"""

from __future__ import annotations

import logging
import os
from typing import Any

try:
    import requests
except ImportError as e:  # pragma: no cover
    raise RuntimeError(
        "kya_hooks.client requires the `requests` library. pip install requests"
    ) from e

logger = logging.getLogger(__name__)


class KyaClientError(Exception):
    """Raised when KYA returns a non-2xx response."""


class KyaClient:
    """Minimal HTTP client for KYA observability events.

    Authentication: bearer token (typically a JWT minted via /api/auth/token).
    Tenant_id is enforced server-side from the token — do NOT pass it in
    request bodies (KYA explicitly ignores body.tenant_id to prevent spoof).

    All methods return the parsed response dict OR raise KyaClientError.
    Network/transport errors are also wrapped as KyaClientError.

    Defaults:
      - 10s request timeout
      - default actor_agent_key = agent_key (autonomous attribution).
        Real-run experience showed that integrators frequently forget to
        set actor_agent_key, breaking principal trust updates. Defaulting
        it to agent_key is the safer behavior.
    """

    DEFAULT_TIMEOUT_S = 10.0

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_S,
        session: Any | None = None,
    ):
        self.base_url = (base_url or os.environ.get("KYA_BASE") or "http://localhost:17000").rstrip(
            "/"
        )
        self.token = token or os.environ.get("KYA_TOKEN", "")
        self.timeout = float(timeout)
        # Allow injecting a session (e.g. for mocking in tests) or share one
        # across calls (HTTP keepalive).
        self._session = session or requests.Session()
        if not self.token:
            logger.warning(
                "KyaClient initialized without a token — calls will get 401. "
                "Pass token= or set KYA_TOKEN."
            )

    # ── internals ─────────────────────────────────────────────────────

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self.base_url}{path}"
        try:
            resp = self._session.post(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise KyaClientError(f"POST {url} failed: {exc}") from exc
        if not (200 <= resp.status_code < 300):
            raise KyaClientError(f"POST {url} -> {resp.status_code}: {resp.text[:300]}")
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ── public API ────────────────────────────────────────────────────

    def record_rogue(
        self,
        event_type: str,
        agent_key: str,
        *,
        tool: str | None = None,
        data_class: str | None = None,
        actual_tid: str | None = None,
        expected_tid: str | None = None,
        user_id: str | None = None,
        actor_agent_key: str | None = None,
        principal_kind: str | None = None,
        principal_id: str | None = None,
        evidence: str | None = None,
        violation_kind: str | None = None,
        severity: str | None = None,
        source: str | None = None,
    ) -> dict:
        """Post a rogue event to /events/rogue.

        `event_type` ∈ {oos_tool, cross_tenant, data_leak, policy_violation}.
        For oos_tool:         `tool` required.
        For cross_tenant:     `actual_tid` required.
        For data_leak:        `data_class` required.
        For policy_violation: `violation_kind` required; `severity` and
                              `source` optional (defaults: medium, observed).

        `actor_agent_key` defaults to `agent_key` when not provided —
        this is the convention discovered during real-run experience
        for autonomous attribution to update the principal trust record.
        """
        if event_type not in {"oos_tool", "cross_tenant", "data_leak", "policy_violation"}:
            raise ValueError(
                "event_type must be oos_tool|cross_tenant|data_leak|policy_violation, "
                f"got '{event_type}'"
            )
        # Fix I3: enforce per-event-type required fields client-side so
        # SDK users don't have to debug 400s from the server.
        if event_type == "oos_tool" and not tool:
            raise ValueError("record_rogue('oos_tool', ...) requires `tool=...`")
        if event_type == "data_leak" and not data_class:
            raise ValueError("record_rogue('data_leak', ...) requires `data_class=...`")
        if event_type == "cross_tenant" and not actual_tid:
            raise ValueError("record_rogue('cross_tenant', ...) requires `actual_tid=...`")
        if event_type == "policy_violation" and not violation_kind:
            raise ValueError(
                "record_rogue('policy_violation', ...) requires `violation_kind=...` "
                "(e.g. 'jailbreak', 'harmful_output', 'refusal_failure', 'prompt_injection')"
            )
        if not agent_key:
            raise ValueError("record_rogue requires a non-empty agent_key")
        body: dict[str, Any] = {
            "event_type": event_type,
            "agent_key": agent_key,
            "actor_agent_key": actor_agent_key or agent_key,
        }
        if user_id:
            body["user_id"] = user_id
        if tool:
            body["tool"] = tool
        if data_class:
            body["data_class"] = data_class
        if actual_tid:
            body["actual_tid"] = actual_tid
        if expected_tid:
            body["expected_tid"] = expected_tid
        if principal_kind:
            body["principal_kind"] = principal_kind
        if principal_id:
            body["principal_id"] = principal_id
        if evidence:
            body["evidence"] = evidence
        if violation_kind:
            body["violation_kind"] = violation_kind
        if severity:
            body["severity"] = severity
        if source:
            body["source"] = source
        return self._post("/api/v1/admin/agents/events/rogue", body)

    def record_invocation(
        self,
        agent_key: str,
        *,
        mode: str = "observed",
        outcome: str = "success",
        duration_ms: int | None = None,
        principal_kind: str | None = None,
        principal_id: str | None = None,
        parent_invocation_id: int | None = None,
        correlation_id: str | None = None,
    ) -> dict:
        """Post a clean invocation to /events/invocation. Returns the row
        including the assigned `invocation_id` so subsequent calls can
        wire `parent_invocation_id` for multi-agent trees."""
        body: dict[str, Any] = {
            "agent_key": agent_key,
            "mode": mode,
            "outcome": outcome,
        }
        if duration_ms is not None:
            body["duration_ms"] = duration_ms
        if principal_kind:
            body["principal_kind"] = principal_kind
        if principal_id:
            body["principal_id"] = principal_id
        if parent_invocation_id is not None:
            body["parent_invocation_id"] = parent_invocation_id
        if correlation_id:
            body["correlation_id"] = correlation_id
        return self._post("/api/v1/admin/agents/events/invocation", body)

    # ── convenience wrappers (cleaner call sites in framework adapters) ──

    def record_oos_tool(self, agent_key: str, tool: str, **kw) -> dict:
        return self.record_rogue("oos_tool", agent_key, tool=tool, **kw)

    def record_data_leak(self, agent_key: str, data_class: str, **kw) -> dict:
        return self.record_rogue("data_leak", agent_key, data_class=data_class, **kw)

    def record_cross_tenant(self, agent_key: str, actual_tid: str, **kw) -> dict:
        return self.record_rogue("cross_tenant", agent_key, actual_tid=actual_tid, **kw)
