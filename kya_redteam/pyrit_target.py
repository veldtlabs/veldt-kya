"""Target abstractions — what a red-team campaign attacks.

The MVP ships a generic HTTP target that wraps any agent endpoint. The
PyRIT-backed runner (Phase 3) will lazily wrap this in a
`pyrit.prompt_target.PromptTarget` subclass; the HTTP target stays
framework-agnostic.

A target's `send(prompt)` returns a `TargetResponse` with the raw output
plus optional tool/event lineage. The scorer + orchestrator only see
this normalized shape, so swapping PyRIT in/out doesn't change the
scoring path.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

try:
    import requests
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "kya_redteam.pyrit_target requires `pip install requests`."
    ) from exc

logger = logging.getLogger(__name__)


import re as _re

# Single-pass placeholder substitution. Replaces {prompt} and
# {session_id} in tenant-controlled templates WITHOUT interpreting
# braces as format specs (defends against str.format attribute
# traversal). Single-pass via re.sub means a prompt that itself
# contains "{session_id}" survives unmangled.
_TEMPLATE_RE = _re.compile(r"\{(prompt|session_id)\}")


def _substitute_template(value, params: dict):
    """Walk a JSON-shaped template, replacing {prompt} / {session_id}
    placeholders with the supplied values. Single pass so the order
    of replacements doesn't matter.

    Security: re.sub does NOT interpret format specs. A template like
    "{prompt.__class__.__mro__[1].__subclasses__()}" is left intact
    (no match against the simple regex).
    """
    if isinstance(value, str):
        return _TEMPLATE_RE.sub(lambda m: params.get(m.group(1), m.group(0)), value)
    if isinstance(value, dict):
        return {k: _substitute_template(v, params) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_template(v, params) for v in value]
    return value


@dataclass
class TargetResponse:
    """One agent response in normalized form.

    `tools_used` and `events` let the scorer see lineage — needed to map
    findings like "the prompt-injection caused the agent to call a tool
    outside its allowlist" into an oos_tool KYA event with the right
    tool name attached. When the target endpoint doesn't expose this
    detail, they stay empty and the scorer falls back to text-only
    matching against `output`.
    """
    output: str
    status_code: int = 200
    duration_ms: int = 0
    tools_used: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    raw_payload: dict | None = None
    error: str | None = None


class HttpAgentTarget:
    """Sends prompts to an HTTP agent endpoint and normalizes the response.

    Endpoint contract (the simplest case the MVP supports):
      POST {url}                       Authorization: Bearer <token>
      body: {"prompt": "...", "session_id": "..."}
      reply: {"output": "...", "tools_used": [...]}    (200 OK)

    `response_parser` lets a customer plug in a function that extracts
    output + tools from a non-standard reply shape (e.g. their endpoint
    returns {"messages": [...]} instead).
    """

    def __init__(
        self,
        endpoint_url: str,
        token: str,
        *,
        agent_key: str,
        timeout_s: float = 30.0,
        response_parser: Any | None = None,
        session_id: str | None = None,
        extra_headers: dict | None = None,
        body_template: dict | None = None,
        rate_limit_rps: float = 0.0,
        rate_limit_key: str | None = None,
    ):
        self.endpoint_url = endpoint_url
        self.token = token
        self.agent_key = agent_key
        self.timeout_s = timeout_s
        self.response_parser = response_parser
        self.session_id = session_id or str(uuid.uuid4())
        self.extra_headers = extra_headers or {}
        # body_template lets customers override the request shape.
        # Variables: {prompt} and {session_id} are .format()-substituted.
        self.body_template = body_template
        # Per-target throttle. 0 = no limit. Key namespaces the Valkey
        # bucket — typically f"{tenant_id}:{target_id}" or
        # f"{tenant_id}:adhoc:{hash(endpoint_url)}" so different
        # targets don't share a bucket.
        self.rate_limit_rps = rate_limit_rps
        self.rate_limit_key = rate_limit_key or self._default_rate_key()

    def _default_rate_key(self) -> str:
        import hashlib
        h = hashlib.sha1((self.endpoint_url or "").encode()).hexdigest()[:12]
        return f"adhoc:{h}"

    def send(self, prompt: str) -> TargetResponse:
        """Send one prompt to the target. Always returns a TargetResponse —
        even on transport failure, with error= set and status_code=0.
        That lets the scorer/orchestrator treat 'no response' as a
        scoreable outcome (some scorers count timeouts as findings).

        Honors `rate_limit_rps` via the Valkey-backed token bucket from
        runtime.py. Fail-open: if Valkey is unreachable, sends without
        throttling (the rate cap is a safety belt, not a hard SLA).
        """
        if self.rate_limit_rps and self.rate_limit_rps > 0:
            try:
                from .runtime import acquire_rate_token
                acquire_rate_token(self.rate_limit_key, self.rate_limit_rps)
            except Exception:
                pass
        headers = {"Authorization": f"Bearer {self.token}",
                   "Content-Type": "application/json",
                   **self.extra_headers}
        if self.body_template:
            body = _substitute_template(
                self.body_template,
                {"prompt": prompt, "session_id": self.session_id},
            )
        else:
            body = {"prompt": prompt, "session_id": self.session_id}

        start = time.monotonic()
        try:
            resp = requests.post(
                self.endpoint_url, headers=headers, json=body, timeout=self.timeout_s,
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            try:
                payload = resp.json() if resp.text else {}
            except ValueError:
                payload = {"output": resp.text}

            if self.response_parser is not None:
                try:
                    parsed = self.response_parser(payload)
                    out_text = parsed.get("output", "")
                    tools_used = parsed.get("tools_used", []) or []
                    events = parsed.get("events", []) or []
                except Exception as exc:
                    logger.warning("[REDTEAM] response_parser raised: %s", exc)
                    out_text, tools_used, events = "", [], []
            else:
                out_text = payload.get("output") or payload.get("response") or payload.get("text") or ""
                tools_used = payload.get("tools_used") or []
                events = payload.get("events") or []

            return TargetResponse(
                output=str(out_text),
                status_code=resp.status_code,
                duration_ms=duration_ms,
                tools_used=list(tools_used),
                events=list(events),
                raw_payload=payload if isinstance(payload, dict) else None,
                error=None if resp.ok else f"http_{resp.status_code}",
            )
        except requests.RequestException as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            return TargetResponse(
                output="", status_code=0, duration_ms=duration_ms,
                error=f"transport: {exc}",
            )
