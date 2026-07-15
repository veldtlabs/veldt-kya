"""HTTP client for the KYA gateway with HITL resume support (#101 layer 3).

Two entry points:

* :func:`invoke` — normal POST to the gateway's ``/mcp`` endpoint.
* :func:`invoke_with_hitl` — same, but on a 428 flag_for_review, polls
  the Pro dashboard-api's HITL status endpoint and resumes the paused
  invocation once an approver decides. Blocks until approval, denial,
  expiry, or a caller-configured timeout.

Why a dedicated client
----------------------
Existing agents call ``httpx`` / ``requests`` directly. Every framework
integration in ``kya_hooks`` would otherwise need its own poll-and-resume
loop, and each would drift. This module owns the round-trip: 428 →
capture pending id → poll → resume → return the actual response as if
the caller had never seen the 428.

Framework hooks (``kya_hooks.langchain``, ``kya_hooks.openai_agents``,
``kya_hooks.claude_agent``) will call this client instead of the raw
HTTP path so HITL becomes transparent from the agent's perspective.

Deliberately dependency-light
-----------------------------
Uses ``urllib`` from the standard library rather than adding ``httpx``
or ``requests`` to KYA's core dependency set. The kya wheel ships small;
downstream users who prefer an async client can wrap ``invoke`` /
``invoke_with_hitl`` in ``asyncio.to_thread`` or similar. Correctness
matters more than raw speed here — HITL loops are inherently high-latency
(human in the middle).
"""
from __future__ import annotations

import json as _json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ── Exceptions ──────────────────────────────────────────────────────


class KyaGatewayError(RuntimeError):
    """Base class for all gateway-client errors."""


class KyaGatewayTransportError(KyaGatewayError):
    """Network / socket / connection error hitting the gateway."""


class KyaHitlDeniedError(KyaGatewayError):
    """The approver denied the paused invocation.

    ``pending_id`` and ``reason_codes`` are populated so the caller can
    log or surface the denial context. The original invocation is
    terminal — a caller wanting to retry must submit fresh.
    """
    def __init__(self, pending_id: str, reason_codes: list[str], detail: str = ""):
        super().__init__(detail or f"pending {pending_id[:8]}… denied")
        self.pending_id = pending_id
        self.reason_codes = list(reason_codes)


class KyaHitlExpiredError(KyaGatewayError):
    """The pending row expired before an approver decided.

    Same terminal semantics as denial. Caller may retry with a fresh
    invocation but must not assume the same body will re-approve.
    """
    def __init__(self, pending_id: str, detail: str = ""):
        super().__init__(detail or f"pending {pending_id[:8]}… expired")
        self.pending_id = pending_id


class KyaHitlTimeoutError(KyaGatewayError):
    """The caller's ``wait_timeout_sec`` elapsed before the approver decided.

    The pending row is still alive on the server — a subsequent
    ``poll_status`` or ``resume`` call by another process would still
    work. Caller is signaling "I've given up waiting synchronously."
    """
    def __init__(self, pending_id: str, waited_sec: float):
        super().__init__(
            f"pending {pending_id[:8]}… did not decide within "
            f"{waited_sec:.0f}s"
        )
        self.pending_id = pending_id


# ── Response wrappers ───────────────────────────────────────────────


@dataclass(frozen=True)
class GatewayResponse:
    """A completed gateway invocation (post-HITL if applicable)."""
    status_code: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        """Parse ``body`` as JSON. Raises ``ValueError`` on malformed input."""
        return _json.loads(self.body.decode("utf-8"))


@dataclass(frozen=True)
class PendingStatus:
    """Result of polling ``GET /api/v1/pending/{id}/status``."""
    id: str
    status: str  # pending / approved / denied / expired / resumed
    reason_codes: list[str]


# ── Client ──────────────────────────────────────────────────────────


class KyaGatewayClient:
    """Thin blocking HTTP client for the KYA gateway.

    Two-URL configuration: ``gateway_url`` for the /mcp endpoint;
    ``dashboard_url`` (Pro) for the pending-status + resume endpoints.
    In an OSS-only deploy, ``dashboard_url`` is None and
    :func:`invoke_with_hitl` degrades to raising immediately on 428
    (no way to poll or resume). Non-HITL :func:`invoke` still works.
    """
    def __init__(
        self,
        gateway_url: str,
        *,
        dashboard_url: str | None = None,
        default_headers: dict[str, str] | None = None,
        request_timeout_sec: float = 30.0,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.dashboard_url = dashboard_url.rstrip("/") if dashboard_url else None
        self.default_headers = dict(default_headers or {})
        self.request_timeout_sec = float(request_timeout_sec)

    # ─── Non-HITL invoke ────────────────────────────────────────────

    def invoke(
        self,
        *,
        path: str = "/mcp",
        body: bytes,
        headers: dict[str, str] | None = None,
    ) -> GatewayResponse:
        """POST to the gateway. Returns the raw response.

        Never raises on non-2xx — the caller inspects ``status_code``
        to decide what to do (a 428 is a "you got HITL, use
        invoke_with_hitl" hint, not an error).
        """
        url = self.gateway_url + path
        req_headers = {**self.default_headers, **(headers or {})}
        req = urllib.request.Request(
            url, data=body, method="POST", headers=req_headers,
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self.request_timeout_sec,
            ) as resp:
                return GatewayResponse(
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    body=resp.read(),
                )
        except urllib.error.HTTPError as exc:
            # HTTPError carries the response — capture headers + body
            # so 428s (which arrive as HTTPError under urllib) can be
            # inspected by invoke_with_hitl.
            return GatewayResponse(
                status_code=exc.code,
                headers=dict(exc.headers or {}),
                body=exc.read() or b"",
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise KyaGatewayTransportError(
                f"transport error hitting {url}: {exc}"
            ) from exc

    # ─── Pending status polling ─────────────────────────────────────

    def poll_status(self, pending_id: str) -> PendingStatus:
        """Fetch the current state of a pending invocation from Pro.

        Requires ``dashboard_url`` to be set (Pro-only endpoint).
        Raises ``KyaGatewayError`` if dashboard_url is unset.
        """
        if not self.dashboard_url:
            raise KyaGatewayError(
                "dashboard_url not configured; cannot poll HITL status "
                "in an OSS-only deployment"
            )
        url = (
            f"{self.dashboard_url}/api/v1/pending/"
            f"{pending_id}/status"
        )
        req = urllib.request.Request(
            url, method="GET", headers=self.default_headers,
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self.request_timeout_sec,
            ) as resp:
                data = _json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = (exc.read() or b"").decode("utf-8", "replace")
            raise KyaGatewayError(
                f"pending status query failed: HTTP {exc.code} {body[:200]}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise KyaGatewayTransportError(
                f"transport error polling pending {pending_id[:8]}…: {exc}"
            ) from exc
        return PendingStatus(
            id=data.get("id", pending_id),
            status=str(data.get("status", "unknown")),
            reason_codes=list(data.get("reason_codes") or []),
        )

    # ─── Resume ─────────────────────────────────────────────────────

    def resume(self, pending_id: str) -> GatewayResponse:
        """Replay an approved pending invocation.

        Server-side flow (see kya_pro.dashboard_api._hitl_router):
          - SELECT the pending row FOR UPDATE
          - Verify status='approved' AND not expired AND not already
            resumed
          - Replay body + headers through the same ingest path a fresh
            invocation would take
          - Record resume-result evidence with parent_invocation_id
            linking back to the 428 emission's invocation
          - Flip status to 'resumed'
          - Return the replayed result as the response

        The caller sees a normal successful gateway response as if the
        428 had never happened.
        """
        if not self.dashboard_url:
            raise KyaGatewayError(
                "dashboard_url not configured; cannot resume in an "
                "OSS-only deployment"
            )
        url = (
            f"{self.dashboard_url}/api/v1/invocations/"
            f"{pending_id}/resume"
        )
        req = urllib.request.Request(
            url, data=b"", method="POST", headers=self.default_headers,
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self.request_timeout_sec,
            ) as resp:
                return GatewayResponse(
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    body=resp.read(),
                )
        except urllib.error.HTTPError as exc:
            return GatewayResponse(
                status_code=exc.code,
                headers=dict(exc.headers or {}),
                body=exc.read() or b"",
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise KyaGatewayTransportError(
                f"transport error resuming pending {pending_id[:8]}…: {exc}"
            ) from exc

    # ─── invoke_with_hitl — the top-level primitive ────────────────

    def invoke_with_hitl(
        self,
        *,
        path: str = "/mcp",
        body: bytes,
        headers: dict[str, str] | None = None,
        wait_timeout_sec: float = 600.0,
        poll_interval_sec: float = 5.0,
        retry_after_respect: bool = True,
    ) -> GatewayResponse:
        """Invoke + wait-and-resume in one call.

        Semantics:
          1. POST the invocation.
          2. If status_code != 428 → return the response as-is (allow,
             deny, transport-level error, ordinary success).
          3. If 428 without ``X-Kya-Pending-Id`` → the gateway
             couldn't persist the pending row. Raise
             ``KyaGatewayError`` — no resume is possible.
          4. If 428 with ``X-Kya-Pending-Id`` → poll ``dashboard_url``
             until:
                * status='approved' → call resume, return that response
                * status='denied' → raise ``KyaHitlDeniedError``
                * status='expired' → raise ``KyaHitlExpiredError``
                * ``wait_timeout_sec`` elapses → raise
                  ``KyaHitlTimeoutError`` (pending row unchanged
                  server-side)

        If the 428 response has a ``Retry-After`` header AND
        ``retry_after_respect`` is True, that value seeds the first
        sleep. Subsequent polls use ``poll_interval_sec``.
        """
        first = self.invoke(path=path, body=body, headers=headers)
        if first.status_code != 428:
            return first

        pending_id = (
            first.headers.get("X-Kya-Pending-Id")
            or first.headers.get("x-kya-pending-id")
        )
        if not pending_id:
            # Gateway couldn't persist. No resume path.
            raise KyaGatewayError(
                "gateway returned 428 without X-Kya-Pending-Id — "
                "pending row could not be persisted, HITL flow "
                "cannot proceed"
            )

        started = time.monotonic()
        # First-sleep seeding: honor Retry-After if present.
        first_sleep = poll_interval_sec
        if retry_after_respect:
            retry_after = (
                first.headers.get("Retry-After")
                or first.headers.get("retry-after")
            )
            if retry_after:
                # RFC 7231 §7.1.3 allows either seconds or HTTP-date.
                # Try seconds first (common case), fall back to date
                # parse (L2 fix).
                try:
                    first_sleep = max(0.5, float(retry_after))
                except (TypeError, ValueError):
                    try:
                        from email.utils import parsedate_to_datetime
                        target = parsedate_to_datetime(retry_after)
                        # parsedate_to_datetime returns tz-aware or
                        # naive UTC — normalize both to a delta.
                        from datetime import datetime, timezone
                        now = datetime.now(timezone.utc)
                        if target.tzinfo is None:
                            target = target.replace(tzinfo=timezone.utc)
                        delta = (target - now).total_seconds()
                        first_sleep = max(0.5, delta)
                    except Exception:  # noqa: BLE001
                        pass  # garbage input → poll_interval_sec fallback

        time.sleep(first_sleep)
        while True:
            elapsed = time.monotonic() - started
            if elapsed >= wait_timeout_sec:
                raise KyaHitlTimeoutError(pending_id, elapsed)
            # L1 fix — transient network blips (dropped packet, DNS
            # flap, dashboard reboot) shouldn't kill a 10-minute human
            # wait. Catch transport errors in the loop, log WARNING,
            # continue polling. Any non-transport error still bubbles
            # (e.g., 4xx from dashboard = terminal).
            try:
                status = self.poll_status(pending_id)
            except KyaGatewayTransportError as exc:
                logger.warning(
                    "[gateway_client] poll_status transport blip for "
                    "pending %s — will retry: %s",
                    pending_id[:8], exc,
                )
                time.sleep(poll_interval_sec)
                continue
            if status.status == "approved":
                return self.resume(pending_id)
            if status.status == "denied":
                raise KyaHitlDeniedError(
                    pending_id, status.reason_codes,
                )
            if status.status == "expired":
                raise KyaHitlExpiredError(pending_id)
            if status.status == "resumed":
                # Someone else already resumed while we were polling
                # (possible with concurrent SDK clients). Treat as
                # success — the row is closed. The result body isn't
                # available to us here since resume was consumed by
                # the other caller. Surface a specific error so the
                # caller can decide (retry? give up? log?)
                raise KyaGatewayError(
                    f"pending {pending_id[:8]}… already resumed by "
                    "another caller — result not retrievable from "
                    "this client"
                )
            # status == "pending" or unknown → keep waiting.
            time.sleep(poll_interval_sec)


__all__ = [
    "KyaGatewayClient",
    "GatewayResponse",
    "PendingStatus",
    "KyaGatewayError",
    "KyaGatewayTransportError",
    "KyaHitlDeniedError",
    "KyaHitlExpiredError",
    "KyaHitlTimeoutError",
]
