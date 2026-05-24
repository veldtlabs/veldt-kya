"""Thin HTTP client vd-app uses to talk to the red-team sidecar.

Two-way switch: when `KYA_REDTEAM_SIDECAR_URL` is set, vd-app routes
async campaign runs through the sidecar; when unset, it falls back to
the in-process thread pool. Failure to reach the sidecar ALSO falls
back to in-process (with a logged warning) — "production grade" means
the service degrades, doesn't collapse, when one piece is unhappy.
"""
from __future__ import annotations

import json as _json
import logging
import os
from dataclasses import dataclass
from datetime import date as _date
from datetime import datetime as _datetime
from decimal import Decimal as _Decimal

try:
    import requests
except ImportError as exc:  # pragma: no cover
    raise RuntimeError(
        "kya_redteam.sidecar_client requires `pip install requests`"
    ) from exc


def _json_default(o):
    """Serializer for types that show up on DB rows but aren't
    JSON-native: datetimes (campaign.created_at), Decimals (threshold,
    rate_limit_rps), UUIDs (already strs in our dict but defense in
    depth). Anything else falls back to str()."""
    if isinstance(o, (_datetime, _date)):
        return o.isoformat()
    if isinstance(o, _Decimal):
        return float(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", errors="replace")
    return str(o)


def _post_json(url: str, body: dict, *, headers: dict, timeout: float):
    """requests.post with a JSON-default that survives the wire types
    DB rows actually return. Bypasses requests' built-in json= path
    because that has no default= hook."""
    serialized = _json.dumps(body, default=_json_default)
    return requests.post(
        url, data=serialized, headers=headers, timeout=timeout,
    )

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_S = float(os.environ.get("KYA_REDTEAM_SIDECAR_TIMEOUT", "10"))


@dataclass
class SidecarConfig:
    base_url: str | None
    secret: str | None
    timeout_s: float = _DEFAULT_TIMEOUT_S

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)


def load_sidecar_config() -> SidecarConfig:
    """Read sidecar env config at call time so deployments can rotate
    without restarting vd-app."""
    return SidecarConfig(
        base_url=os.environ.get("KYA_REDTEAM_SIDECAR_URL", "").strip() or None,
        secret=os.environ.get("KYA_REDTEAM_SIDECAR_SECRET", "").strip() or None,
        timeout_s=_DEFAULT_TIMEOUT_S,
    )


class SidecarUnavailable(RuntimeError):
    """Raised by the client helpers when the sidecar is configured but
    unreachable. Caller decides whether to fall back to in-process."""


def _headers(cfg: SidecarConfig) -> dict:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if cfg.secret:
        h["Authorization"] = f"Bearer {cfg.secret}"
    return h


def submit_run(
    *,
    tenant_id: str,
    campaign: dict,
    target_id: int | None = None,
    target_endpoint: str | None = None,
    target_token: str | None = None,
    target_body_template: dict | None = None,
    target_timeout_s: float = 30.0,
    target_rate_limit_rps: float = 0.0,
    dataset_override: list[dict] | None = None,
    initiated_by: str | None = None,
) -> dict:
    """POST /v1/runs on the sidecar. Returns {run_id, status, ...}.

    Raises SidecarUnavailable when:
      - Sidecar not configured (caller should fall back)
      - Transport error (network down)
      - 5xx from sidecar
    Raises requests.HTTPError on 4xx (caller-fault — surface to user).
    """
    cfg = load_sidecar_config()
    if not cfg.enabled:
        raise SidecarUnavailable("KYA_REDTEAM_SIDECAR_URL not configured")
    body = {
        "tenant_id": tenant_id,
        "initiated_by": initiated_by,
        "campaign": campaign,
        "target_id": target_id,
        "target_endpoint": target_endpoint,
        "target_token": target_token,
        "target_body_template": target_body_template,
        "target_timeout_s": target_timeout_s,
        "target_rate_limit_rps": target_rate_limit_rps,
        "dataset_override": dataset_override,
    }
    url = cfg.base_url.rstrip("/") + "/v1/runs"
    try:
        resp = _post_json(
            url, body, headers=_headers(cfg), timeout=cfg.timeout_s,
        )
    except requests.RequestException as exc:
        raise SidecarUnavailable(f"transport: {exc}") from exc
    if 500 <= resp.status_code < 600:
        raise SidecarUnavailable(
            f"sidecar 5xx: {resp.status_code} {resp.text[:200]}"
        )
    resp.raise_for_status()
    return resp.json()


def cancel_run(run_id: str) -> dict | None:
    """Best-effort cancel via sidecar. Returns the sidecar response or
    None when sidecar isn't configured (caller should still do the
    DB+Valkey cancel locally)."""
    cfg = load_sidecar_config()
    if not cfg.enabled:
        return None
    url = cfg.base_url.rstrip("/") + f"/v1/runs/{run_id}/cancel"
    try:
        resp = requests.post(url, headers=_headers(cfg), timeout=cfg.timeout_s)
        if resp.ok:
            return resp.json()
        logger.warning("[REDTEAM-SIDECAR-CLIENT] cancel %d: %s",
                       resp.status_code, resp.text[:200])
    except requests.RequestException as exc:
        logger.warning("[REDTEAM-SIDECAR-CLIENT] cancel transport: %s", exc)
    return None


def healthcheck() -> dict:
    """For the dashboard's "Sidecar: connected" indicator. Returns
    {ok: bool, reachable: bool, base_url: str, ...}. Never raises."""
    cfg = load_sidecar_config()
    out = {"configured": cfg.enabled,
           "base_url": cfg.base_url, "reachable": False}
    if not cfg.enabled:
        return out
    try:
        resp = requests.get(
            cfg.base_url.rstrip("/") + "/healthz",
            timeout=min(5.0, cfg.timeout_s),
        )
        out["reachable"] = resp.ok
        out["status_code"] = resp.status_code
        if resp.ok:
            out["sidecar_response"] = resp.json()
    except requests.RequestException as exc:
        out["error"] = f"transport: {exc}"
    return out
