"""KYA Gateway FastAPI app + Gateway class.

This module wires identity → policy → forwarder → evidence into the actual
HTTP endpoints. Everything else in the package is supporting infrastructure.

Endpoints (per requirements doc §9):
    POST  /mcp                     JSON-RPC 2.0 main endpoint
    GET   /healthz                 liveness probe
    GET   /readyz                  readiness probe (DB + backends)
    GET   /v1/principals/me        bound principal echo
    GET   /metrics                 Prometheus (when extras installed)
"""
from __future__ import annotations

import json
import logging
import os as _os
import time
from collections import defaultdict, deque
from threading import Lock

try:
    from fastapi import FastAPI, Request, Response
    from fastapi.responses import JSONResponse
except ImportError as exc:   # pragma: no cover
    raise RuntimeError(
        "kya_gateway.server requires `pip install veldt-kya[gateway]`"
    ) from exc

from kya_gateway.config import GatewayConfig
from kya_gateway.errors import (
    BackendUnreachable,
    GatewayError,
    IdentityBindingFailed,
)
from kya_gateway.forwarder import Forwarder, parse_backend_from_tool
from kya_gateway.identity import BoundPrincipal, IdentityResolver
from kya_gateway.mcp_protocol import (
    action_from_tool_call,
    initialize_result,
    make_error,
    make_response,
    parse_request,
)
from kya_gateway.policy_pipeline import Verdict
from kya_gateway.policy_pipeline import evaluate as evaluate_policy

# In-process per-IP sliding-window rate limiter for /v1/principals/me.
# Prevents the endpoint from becoming a free credential-validation oracle.
# Single-process scope; multi-instance deployments should put a real LB
# rate limit in front of the gateway too.
_ME_RATE_LIMIT_PER_MIN = 60
# Hard cap on tracked IPs so a churn-y client (or attacker rotating
# X-Forwarded-For) can't OOM the gateway via dict growth. When the cap
# is hit, the oldest IPs are evicted (LRU-by-last-touch).
_ME_RATE_MAX_TRACKED_IPS = 10_000
_ME_RATE_WINDOWS: dict[str, deque[float]] = {}
_ME_RATE_LOCK = Lock()


def _me_rate_limit_check(client_ip: str) -> bool:
    """Return True if the request is within limits; False to deny with 429.

    Bounded memory: at most ``_ME_RATE_MAX_TRACKED_IPS`` entries — the
    oldest are evicted when the cap is hit.
    """
    now = time.monotonic()
    cutoff = now - 60.0
    with _ME_RATE_LOCK:
        # Periodic GC: when over cap, drop IPs whose window is empty after
        # the cutoff sweep. Worst-case O(n) — only runs when growing past cap.
        if len(_ME_RATE_WINDOWS) >= _ME_RATE_MAX_TRACKED_IPS:
            stale = [ip for ip, win in _ME_RATE_WINDOWS.items()
                     if not win or win[-1] < cutoff]
            for ip in stale:
                _ME_RATE_WINDOWS.pop(ip, None)
            # If still over cap (everyone is active), evict the longest-idle.
            if len(_ME_RATE_WINDOWS) >= _ME_RATE_MAX_TRACKED_IPS:
                oldest_ip = min(_ME_RATE_WINDOWS.items(),
                                key=lambda kv: kv[1][-1] if kv[1] else 0)[0]
                _ME_RATE_WINDOWS.pop(oldest_ip, None)

        window = _ME_RATE_WINDOWS.setdefault(client_ip, deque())
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= _ME_RATE_LIMIT_PER_MIN:
            return False
        window.append(now)
        return True


# Hard ceiling on POST body size BEFORE we read it into memory. Defends
# against 1 GB body DoS that would otherwise exhaust gateway memory
# before policy.payload_caps gets a chance to trip. The gateway-level
# cap is intentionally larger than policy.payload_caps so policy still
# fires for "too large for this tenant" while the HTTP layer catches
# the "trying to OOM the process" case.
_MAX_HTTP_BODY_BYTES = 32 * 1024 * 1024  # 32 MB hard ceiling

logger = logging.getLogger(__name__)


# Map internal exception classes to a stable enum surfaced in
# X-KYA-Reason-Codes. Internal class names are NOT shipped to callers
# (5g-A-04) — they'd both leak internal layering and break the policy
# pipeline's "stable enum-like codes" contract.
_IDENTITY_FAIL_CODES: dict[str, str] = {
    "IdentityCredentialInvalid": "IDENTITY_CRED_INVALID",
    "IdentityBindingFailed": "IDENTITY_MISSING",
    "DPoPError": "IDENTITY_DPOP_INVALID",
    "RevocationBlocked": "IDENTITY_REVOKED",
}

# Phase 5g #3/#4 — map exception types to security-event kinds the
# existing `_HARDENING_EVENT_KINDS` whitelist accepts. Anything not in
# this map fires no event (the identity-failure reason still surfaces
# in X-KYA-Reason-Codes).
_IDENTITY_FAIL_SEC_EVENTS: dict[str, str] = {
    "RevocationBlocked": "revocation_blocked",
}

# 5g-B-01 / 5g-B-05 — DPoPError carries a typed `code` attribute set
# at the raise site so we don't read attacker-controlled message
# strings. Maps DPoPError.code -> emitted security event kind.
_DPOP_CODE_TO_EVENT: dict[str, str] = {
    "missing":       "dpop_forge_attempt",
    "malformed":     "dpop_forge_attempt",
    "kid_unknown":   "dpop_forge_attempt",
    "signature":     "dpop_forge_attempt",
    "iss_mismatch":  "dpop_forge_attempt",
    "htm_mismatch":  "dpop_forge_attempt",
    "htu_mismatch":  "dpop_forge_attempt",
    "iat_future":    "dpop_expired",
    "iat_too_old":   "dpop_expired",
    "iat_invalid":   "dpop_forge_attempt",
    # `replay` is reserved for the future jti-replay layer.
    "replay":        "dpop_replay",
}


def _identity_failure_code(exc: Exception) -> str:
    return _IDENTITY_FAIL_CODES.get(type(exc).__name__, "IDENTITY_INVALID")


def _identity_failure_sec_event(exc: Exception) -> str | None:
    """Return the security-event kind to emit, or None if no event.

    DPoP failures dispatch on the typed ``code`` attribute (set at the
    raise site) — never on the message text, which carries
    attacker-shaped JWS fields. Other identity failures use the class
    name map with an MRO walk for subclasses.

    N-6 — the typed ``code`` path is gated by ``isinstance(exc, DPoPError)``
    so a third-party exception whose ``.code`` happens to collide with
    a DPoP code can't be misclassified as a DPoP event.
    """
    try:
        from kya_gateway._dpop import DPoPError
    except ImportError:
        DPoPError = None  # type: ignore[assignment]
    if DPoPError is not None and isinstance(exc, DPoPError):
        code = getattr(exc, "code", None)
        if isinstance(code, str) and code in _DPOP_CODE_TO_EVENT:
            return _DPOP_CODE_TO_EVENT[code]
    name = type(exc).__name__
    if name in _IDENTITY_FAIL_SEC_EVENTS:
        return _IDENTITY_FAIL_SEC_EVENTS[name]
    # MRO walk so subclasses inherit their parent's mapping.
    for cls in type(exc).__mro__[1:]:
        if cls.__name__ in _IDENTITY_FAIL_SEC_EVENTS:
            return _IDENTITY_FAIL_SEC_EVENTS[cls.__name__]
    return None


def _emit_identity_failure_event(
    *, gw, exc: Exception, headers: dict,
) -> None:
    """Fire emit_security_event for the identity failure, if any.

    Best-effort: any error inside emit_security_event is swallowed by
    the function itself; we never let a security-event failure block
    a request.

    Phase 14a #145 — when the failure carries principal info (today:
    ``RevocationBlocked.principal_kind`` / ``principal_id``), ALSO
    record a ``signal_kind=revocation_blocked`` row into
    ``kya_principal_trust.signal_counts``. That's the table
    ``kya.rogue.get_rogue_signals`` reads, so a detector polling
    ``rogue_score`` can observe the loop closing. Without this the
    event is only visible in ``kya_security_events`` (a separate
    table the rogue subsystem doesn't consult).
    """
    kind = _identity_failure_sec_event(exc)
    if kind is None:
        return
    try:
        from kya._security_events import emit_security_event
    except ImportError:
        return
    try:
        emit_security_event(
            kind,
            tenant_id=gw.cfg.gateway.tenant_id,
            primitive="gateway",
            detail={"reason": str(exc)[:200]},
        )
    except Exception as ev_exc:  # pragma: no cover — defensive
        # 5g-B-10 — surface emission failures via a counter so operators
        # see "DPoP events are being dropped" without grepping logs.
        _METRICS["sec_event_emit_failures"] += 1
        logger.warning(
            "[KYA-GATEWAY] identity-failure event emit failed: %s — "
            "_METRICS['sec_event_emit_failures']=%d",
            ev_exc, _METRICS["sec_event_emit_failures"],
        )

    # Phase 14a #145 — bridge from security event to principal_trust
    # signal counts. Only when the exception carries verified
    # principal info (currently RevocationBlocked sets these in
    # identity.py:_maybe_check_revocation). Best-effort: failure to
    # record the signal is logged + counted, never raised.
    #
    # Review-pass #2 finding: `record_principal_signal` applies a
    # trust-score delta on EVERY call (e.g., -10 for
    # `revocation_blocked` via SIGNAL_DELTAS in users.py). Without
    # debouncing, an attacker can burst-replay a revoked VC and
    # drive an agent's trust_score to the `"blocked"` bucket in ~7
    # calls (-10 each × clamp). To prevent that trust-laundering
    # attack, debounce per (principal_kind, principal_id, kind):
    # only record once per ``_GATEWAY_SIGNAL_DEBOUNCE_S`` seconds.
    # Subsequent failures still surface in `kya_security_events`
    # (already written above) and the HTTP response code, so
    # operators don't lose observability -- they lose the
    # repeated trust-score decrement.
    p_kind = getattr(exc, "principal_kind", None)
    p_id = getattr(exc, "principal_id", None)
    if not (p_kind and p_id):
        return
    try:
        from kya import default_session, record_principal_signal
    except ImportError:
        return
    try:
        with default_session() as db:
            if _gateway_signal_debounced(
                db,
                tenant_id=gw.cfg.gateway.tenant_id,
                principal_kind=p_kind,
                principal_id=p_id,
                signal_kind=kind,
                window_seconds=_GATEWAY_SIGNAL_DEBOUNCE_S,
            ):
                return
            # Phase 14a #147 -- cross-tenant attribution defence.
            # The exception's ``principal_id`` came from a VC's
            # credentialSubject (identity.py:_extract_vc_principal_attr).
            # The VC was signed by a trusted issuer, but "trusted" in
            # a federated multi-tenant setup includes OTHER tenants'
            # issuers -- a revoked VC from tenant T2 presented to
            # gateway tenant T1 would otherwise create a phantom
            # ``(T1, T2_agent_did)`` row with a -10 trust delta,
            # polluting T2's principal namespace in T1's tenant_id
            # space. Setting ``allow_create=False`` drops the signal
            # silently when no row exists under (gateway_tenant,
            # principal); the operator-provisioned same-tenant
            # principals work unchanged. Bump a metric so operators
            # can see drops.
            score = record_principal_signal(
                db,
                tenant_id=gw.cfg.gateway.tenant_id,
                principal_kind=p_kind,
                principal_id=p_id,
                signal_kind=kind,
                attributes={"reason": str(exc)[:200]},
                allow_create=False,
            )
            # Metric increment must happen BEFORE db.commit() so a
            # spurious commit failure on a broken connection doesn't
            # route the drop into the wrong counter (sec_event_emit_
            # failures). Review-pass #1 #5.
            if score == -1:
                _METRICS["cross_tenant_signal_dropped"] += 1
            db.commit()
    except Exception as ev_exc:  # pragma: no cover — defensive
        _METRICS["sec_event_emit_failures"] += 1
        logger.warning(
            "[KYA-GATEWAY] identity-failure signal record failed: "
            "%s — _METRICS['sec_event_emit_failures']=%d",
            ev_exc, _METRICS["sec_event_emit_failures"],
        )


# Phase 14a #145 — debounce window for gateway-emitted identity-
# failure signals (revocation_blocked, dpop_*). 60s suppresses the
# burst-replay attack on trust scores without losing the first
# occurrence in a session.
_GATEWAY_SIGNAL_DEBOUNCE_S = 60


def _gateway_signal_debounced(
    db, *, tenant_id: str, principal_kind: str,
    principal_id: str, signal_kind: str,
    window_seconds: int,
) -> bool:
    """Return True if a signal of this kind was already recorded for
    this principal within the debounce window. Caller short-circuits
    the new `record_principal_signal` call to prevent trust-score
    flooding from repeated revoked-VC replay.

    Read-only and exception-safe -- on any DB read failure returns
    False (i.e., proceed with the write), preserving the original
    fail-open behavior of the surrounding code.
    """
    try:
        from datetime import datetime, timedelta, timezone

        from sqlalchemy import select

        from kya.principals import _PrincipalRow
        stmt = (
            select(_PrincipalRow.signal_counts,
                   _PrincipalRow.last_signal_at)
            .where(_PrincipalRow.tenant_id == tenant_id)
            .where(_PrincipalRow.principal_kind == principal_kind)
            .where(_PrincipalRow.principal_id == principal_id)
        )
        row = db.execute(stmt).first()
        if row is None:
            return False
        counts, last_at = row
        if not counts or signal_kind not in (counts or {}):
            return False
        if last_at is None:
            return False
        # Coerce naive timestamps to UTC for MySQL/SQLite parity.
        if last_at.tzinfo is None:
            last_at = last_at.replace(tzinfo=timezone.utc)
        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=window_seconds,
        )
        return last_at >= cutoff
    except Exception:
        return False


def _anon_principal_for(headers: dict) -> BoundPrincipal:
    """Build a per-credential anonymous principal so distinct bad credentials
    land in distinct rows (5g-A-03). Without this every malformed-cred
    request collides on one ``agent_key`` and replay / rate-limit
    accounting collapses to a single shared lineage."""
    import hashlib
    cred = (headers.get("authorization")
            or headers.get("Authorization")
            or headers.get("x-kya-did")
            or headers.get("X-KYA-DID")
            or "")
    discriminator = (
        hashlib.sha256(cred.encode("utf-8", errors="ignore")).hexdigest()[:16]
        if cred else "noauth"
    )
    return BoundPrincipal(
        principal_kind="agent",
        principal_id=f"kya-unauth-{discriminator}",
        method="anonymous",
        external_subject=None,
        external_issuer=None,
    )


# In-process simple per-IP throttle on unauth evidence writes (5g-A-07).
# A flood of bad-cred traffic in audit_only would otherwise be a 1:1
# write amplifier on the HMAC-chained evidence table. Bounded buckets,
# fail-soft drop on overflow. Configurable via env for high-throughput
# operators.

_UNAUTH_EVIDENCE_RATE_PER_S = max(
    1, int(_os.getenv("KYA_GATEWAY_UNAUTH_EVIDENCE_RATE_PER_S", "5"))
)
_UNAUTH_EVIDENCE_LAST: dict[str, tuple[float, int]] = {}
_UNAUTH_EVIDENCE_LOCK = Lock()
_UNAUTH_EVIDENCE_MAX_IPS = 5000


def _should_record_unauth_evidence(client_ip: str) -> bool:
    """Token-bucket-ish: allow up to N writes/sec/ip; drop the rest.

    F5 fix — eviction sweep is bounded at 50 entries per call so a
    sustained 5000-IP burst can't serialize the gateway under the
    global lock. The remaining stale entries are picked up by later
    calls; if memory pressure persists, the secondary min-eviction
    handles it.
    """
    import time as _t
    now = _t.monotonic()
    _EVICT_BUDGET = 50
    with _UNAUTH_EVIDENCE_LOCK:
        if len(_UNAUTH_EVIDENCE_LAST) >= _UNAUTH_EVIDENCE_MAX_IPS:
            evicted = 0
            for ip in list(_UNAUTH_EVIDENCE_LAST.keys()):
                if evicted >= _EVICT_BUDGET:
                    break
                t, _ = _UNAUTH_EVIDENCE_LAST[ip]
                if now - t > 5.0:
                    _UNAUTH_EVIDENCE_LAST.pop(ip, None)
                    evicted += 1
            if len(_UNAUTH_EVIDENCE_LAST) >= _UNAUTH_EVIDENCE_MAX_IPS:
                oldest = min(_UNAUTH_EVIDENCE_LAST.items(),
                             key=lambda kv: kv[1][0])[0]
                _UNAUTH_EVIDENCE_LAST.pop(oldest, None)
        last_t, count = _UNAUTH_EVIDENCE_LAST.get(client_ip, (0.0, 0))
        if now - last_t >= 1.0:
            _UNAUTH_EVIDENCE_LAST[client_ip] = (now, 1)
            return True
        if count >= _UNAUTH_EVIDENCE_RATE_PER_S:
            return False
        _UNAUTH_EVIDENCE_LAST[client_ip] = (last_t, count + 1)
        return True


# F3 fix — when the operator configures a list of trusted proxy CIDRs
# in `KYA_GATEWAY_TRUSTED_PROXIES`, the gateway honors the LEFTMOST
# `X-Forwarded-For` entry. Without a trusted-proxy config, headers are
# ignored — a malicious caller would otherwise spoof their own IP and
# bypass the unauth-evidence throttle.
_TRUSTED_PROXY_CIDRS_ENV = "KYA_GATEWAY_TRUSTED_PROXIES"


def _client_ip(request) -> str:
    """Extract the source IP, honoring X-Forwarded-For only when the
    immediate connection peer is a configured trusted proxy."""
    direct = (request.client.host if request.client else "") or "unknown"
    trusted_raw = _os.getenv(_TRUSTED_PROXY_CIDRS_ENV, "")
    if not trusted_raw:
        return direct
    import ipaddress
    try:
        addr = ipaddress.ip_address(direct)
    except ValueError:
        return direct
    for cidr in trusted_raw.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                xff = request.headers.get("x-forwarded-for", "")
                first = xff.split(",")[0].strip() if xff else ""
                return first or direct
        except ValueError:
            continue
    return direct


def _shape_response_with_verdict(
    *,
    backend_body: bytes,
    backend_status: int,
    backend_content_type: str,
    verdict_str: str,
    reason_codes: list[str],
    mode: str,
    evidence_signature: str | None = None,
) -> Response:
    """Wrap a backend response with KYA's verdict per the active mode.

    All non-enforce modes set ``X-KYA-Verdict`` and ``X-KYA-Reason-Codes``
    headers. ``advise`` additionally merges a ``kya_verdict`` field into
    the JSON body when the backend returned JSON. For JSON-RPC envelopes
    (5g-A-01) the merge goes UNDER ``result`` (or ``error.data``) so the
    envelope stays spec-conformant — a top-level ``kya_verdict`` would
    poison the envelope for any downstream JSON-RPC consumer.
    """
    out_headers = {
        "X-KYA-Verdict": verdict_str,
        "X-KYA-Reason-Codes": ",".join(reason_codes),
    }
    if evidence_signature:
        out_headers["X-KYA-Evidence-Signature"] = evidence_signature
    if mode == "advise" and "json" in (backend_content_type or "").lower():
        try:
            body_obj = json.loads(backend_body) if backend_body else {}
        except (json.JSONDecodeError, ValueError):
            body_obj = None
        if isinstance(body_obj, dict):
            payload = {"verdict": verdict_str, "reason_codes": reason_codes}
            if evidence_signature:
                payload["signature"] = evidence_signature
            # JSON-RPC envelope detection — keep envelope spec-conformant.
            if body_obj.get("jsonrpc") == "2.0":
                # F1 fix — `result` may be any JSON type (string, list,
                # int, null) per JSON-RPC 2.0 §5.1. Mutating it as a dict
                # would TypeError; wrap non-dict result in {"value": ...,
                # "kya_verdict": ...} so the merge is total without
                # losing the backend's data.
                if isinstance(body_obj.get("result"), dict):
                    body_obj["result"]["kya_verdict"] = payload
                elif "result" in body_obj:
                    body_obj["result"] = {
                        "value": body_obj["result"],
                        "kya_verdict": payload,
                    }
                elif isinstance(body_obj.get("error"), dict):
                    err = body_obj["error"]
                    data = err.get("data")
                    # F9 fix — preserve a non-dict `data` instead of
                    # clobbering it; `data` may be any JSON type per
                    # JSON-RPC 2.0 §5.1.
                    if isinstance(data, dict):
                        data["kya_verdict"] = payload
                    elif data is None:
                        err["data"] = {"kya_verdict": payload}
                    else:
                        err["data"] = {"backend_data": data,
                                        "kya_verdict": payload}
                else:
                    # No result, no error — synthesize a result wrapper.
                    body_obj["result"] = {"kya_verdict": payload}
            else:
                body_obj["kya_verdict"] = payload
            return Response(
                content=json.dumps(body_obj).encode(),
                status_code=backend_status,
                headers=out_headers,
                media_type="application/json",
            )
    return Response(
        content=backend_body,
        status_code=backend_status,
        headers=out_headers,
        media_type=backend_content_type or "application/json",
    )


# ─── Gateway orchestrator ───────────────────────────────────────────


class Gateway:
    """Top-level orchestrator.

    Holds the components shared across requests (identity resolver,
    forwarder, KYA session factory) and provides ``run()`` to start the
    HTTP server.

    Tests can construct a Gateway, hand its ``app`` attribute to
    ``httpx.AsyncClient``, and exercise endpoints without binding a real
    socket.
    """

    def __init__(self, cfg: GatewayConfig):
        self.cfg = cfg
        self.identity = IdentityResolver(cfg.identity)
        self.forwarder = Forwarder(cfg.backends)
        # 5g-A-09 / F4: log the active enforcement mode at WARNING with
        # structured `extra=` fields so JSON-log aggregators can index
        # `mode` and `blocking` directly rather than regex the message.
        _mode_desc = {
            "audit_only":
                "will NOT block; verdict in X-KYA-Verdict header",
            "advise":
                "will NOT block; verdict in body + X-KYA-Verdict header",
            "enforce":
                "will BLOCK on policy deny / identity invalid",
        }.get(cfg.enforcement.mode, cfg.enforcement.mode)
        logger.warning(
            "[KYA-GATEWAY] enforcement.mode=%s — %s",
            cfg.enforcement.mode, _mode_desc,
            extra={
                "kya_enforcement_mode": cfg.enforcement.mode,
                "kya_enforcement_blocking":
                    cfg.enforcement.mode == "enforce",
            },
        )
        # 5g-B-10 — operator footgun warning at construction time:
        # revocation_check=true with kya_pro missing means revocation
        # checks are silent no-ops until first VC arrives. Surface this
        # at startup so a misconfigured deployment is visible
        # immediately, not after a revoked credential is honored.
        did_cfg = cfg.identity.did
        if did_cfg is not None and did_cfg.revocation_check:
            try:
                import kya_pro.revocation  # noqa: F401
            except ImportError:
                logger.warning(
                    "[KYA-GATEWAY] identity.did.revocation_check=true but "
                    "kya_pro is not installed — revocation checks will "
                    "silently no-op. Install veldt-kya-pro or set "
                    "revocation_check=false.",
                )
        self.app = build_app(self)

    def run(self, host: str | None = None, port: int | None = None) -> None:
        """Start uvicorn. Blocking."""
        try:
            import uvicorn
        except ImportError as exc:   # pragma: no cover
            raise RuntimeError(
                "kya_gateway.Gateway.run requires `pip install veldt-kya[gateway]`"
            ) from exc
        if host is None or port is None:
            cfg_host, cfg_port = _parse_bind(self.cfg.gateway.bind)
            host = host or cfg_host
            port = port or cfg_port
        uvicorn.run(self.app, host=host, port=int(port))


def _parse_bind(bind: str) -> tuple[str, int]:
    """Parse a ``host:port`` bind string, including ``[ipv6]:port`` form.

    Raises ``ValueError`` for shapes the gateway can't bind to (e.g., a
    bare port like ``"8080"`` with no host, or a non-numeric port).
    """
    if not bind:
        raise ValueError("bind string is empty")
    # [ipv6]:port form per RFC 3986 §3.2.2.
    if bind.startswith("["):
        end = bind.find("]")
        if end == -1 or len(bind) <= end + 1 or bind[end + 1] != ":":
            raise ValueError(f"bind {bind!r} not a valid [ipv6]:port form")
        host = bind[1:end]
        port_str = bind[end + 2:]
    else:
        # Hostname:port or IPv4:port form.
        if bind.count(":") != 1:
            raise ValueError(
                f"bind {bind!r} must be host:port "
                f"(use [::1]:8080 form for IPv6)"
            )
        host, _, port_str = bind.partition(":")
        if not host:
            raise ValueError(f"bind {bind!r} has empty host")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(
            f"bind {bind!r} port {port_str!r} is not a number"
        ) from None
    if not (1 <= port <= 65535):
        raise ValueError(f"bind {bind!r} port {port} out of range")
    return host, port


# ─── FastAPI app factory ────────────────────────────────────────────


def build_app(gw: Gateway) -> FastAPI:
    """Construct the FastAPI app and bind handlers to the Gateway instance."""
    app = FastAPI(title="KYA Gateway", version="0.1.0")

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await gw.forwarder.aclose()

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok", "service": "kya-gateway", "version": "0.1.0"}

    @app.get("/readyz")
    async def readyz() -> dict:
        # In a fully-fledged install we'd probe each backend; for MVP we
        # just confirm the gateway can construct a KYA session.
        ready = True
        try:
            from kya import default_session
            with default_session() as _db:
                pass
        except Exception as exc:
            logger.warning("[KYA-GATEWAY] readiness probe failed: %s", exc)
            ready = False
        return {"ready": ready}

    @app.get("/v1/principals/me")
    async def me(request: Request) -> JSONResponse:
        # Phase 5f rewire — delegate to KYA's existing Valkey-backed
        # rate limiter. Operators configure via:
        #   KYA_RATE_LIMIT_RPS_PRINCIPALS_ME=...
        # When env unset, the limiter returns True immediately (no
        # overhead). When Valkey unavailable, fail-open per kya policy.
        # The in-process per-IP guard below is the belt-and-suspenders
        # for deployments without Valkey configured.
        try:
            from kya.rate_limit import RateLimitExceededError, maybe_rate_limit
            try:
                maybe_rate_limit(
                    gw.cfg.gateway.tenant_id,
                    "principals_me",
                    mode="hard",
                    max_wait_s=0.0,
                )
            except RateLimitExceededError as exc:
                return JSONResponse(
                    {"error": "rate limit exceeded",
                     "retry_after_s": exc.retry_after_s},
                    status_code=429,
                    headers={"Retry-After": str(int(exc.retry_after_s))},
                )
        except ImportError:
            pass   # kya.rate_limit not available — fall through to in-proc
        client_ip = (request.client.host if request.client else "") or "unknown"
        if not _me_rate_limit_check(client_ip):
            return JSONResponse(
                {"error": "rate limit exceeded"},
                status_code=429,
            )
        try:
            principal = gw.identity.resolve(dict(request.headers))
        except IdentityBindingFailed as exc:
            return JSONResponse(
                {"error": str(exc)},
                status_code=exc.http_status,
            )

        # Phase 6: DPoP requirement for DID-method principals. Replay-
        # grinding the endpoint requires the DID's private key — friction
        # rate limit becomes secondary, not primary defense.
        did_cfg = gw.cfg.identity.did
        if (principal.method == "did"
                and did_cfg is not None
                and did_cfg.require_dpop_on_me):
            try:
                _verify_me_dpop(gw, request, principal)
            except _IdentityCredInvalidLike as exc:
                # 5g-B-01 — dispatch on the typed `code` carried by
                # the underlying DPoPError (passed through via
                # ``_IdentityCredInvalidLike(code=...)``), never on the
                # message text. ``code`` defaults to forge_attempt for
                # unclassified errors.
                try:
                    from kya._security_events import emit_security_event
                    code = getattr(exc, "code", None) or "malformed"
                    kind = _DPOP_CODE_TO_EVENT.get(code, "dpop_forge_attempt")
                    emit_security_event(
                        kind,
                        tenant_id=gw.cfg.gateway.tenant_id,
                        primitive="gateway",
                        principal_kind=principal.principal_kind,
                        principal_id=principal.principal_id,
                        detail={"code": code},
                    )
                except Exception:  # pragma: no cover
                    _METRICS["sec_event_emit_failures"] += 1
                # Use the standard 401 + DPoP hint per RFC 9449 §7.1.
                return JSONResponse(
                    {"error": str(exc)},
                    status_code=401,
                    headers={"WWW-Authenticate":
                             f'DPoP error="invalid_dpop_proof", '
                             f'error_description="{str(exc)}"'},
                )

        return JSONResponse({
            "principal_kind": principal.principal_kind,
            "principal_id": principal.principal_id,
            "method": principal.method,
            "external_subject": principal.external_subject,
            "external_issuer": principal.external_issuer,
        })

    @app.post("/mcp")
    async def mcp_endpoint(request: Request) -> Response:
        # HARD body-size check BEFORE buffering. Uses Content-Length if
        # supplied; otherwise streams up to the cap and rejects on overflow.
        # This trips BEFORE identity / policy / forwarding so we never
        # allocate a 1 GB payload.
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > _MAX_HTTP_BODY_BYTES:
                    return Response(status_code=413,
                                    content=b'{"error":"request body too large"}',
                                    media_type="application/json")
            except ValueError:
                return Response(status_code=400,
                                content=b'{"error":"invalid Content-Length"}',
                                media_type="application/json")
        body_chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > _MAX_HTTP_BODY_BYTES:
                return Response(status_code=413,
                                content=b'{"error":"request body too large"}',
                                media_type="application/json")
            body_chunks.append(chunk)
        body = b"".join(body_chunks)

        # ─── 1. Parse JSON-RPC envelope ──────────────────────────
        from kya_gateway.mcp_protocol import (
            JSONRPCBatchNotSupported,
            MCPMethodNotFound,
        )
        try:
            req = parse_request(body)
        except JSONRPCBatchNotSupported as exc:
            # -32600 Invalid Request — body parsed but shape is wrong.
            return JSONResponse(make_error(None, -32600, str(exc)), status_code=400)
        except MCPMethodNotFound as exc:
            return JSONResponse(make_error(None, -32601, str(exc)), status_code=400)
        except GatewayError as exc:
            msg = str(exc)
            # Distinguish parse-error (-32700) from invalid-request (-32600).
            # JSON-decode failures fire only when json.loads raised → message
            # contains "malformed JSON".
            code = -32700 if "malformed JSON" in msg else -32600
            return JSONResponse(make_error(None, code, msg), status_code=400)

        # ─── 2. Bind identity ────────────────────────────────────
        mode = gw.cfg.enforcement.mode
        identity_failure: tuple[str, list[str]] | None = None
        raw_headers = dict(request.headers)
        try:
            principal = gw.identity.resolve(raw_headers)
        except IdentityBindingFailed as exc:
            # Phase 5g #3/#4 — emit security event for specific failure
            # types (revocation_blocked, dpop_* via DPoPError subclass).
            # Fires in ALL modes so the trust-score + attack-chain see
            # the signal regardless of whether the gateway blocked.
            _emit_identity_failure_event(gw=gw, exc=exc, headers=raw_headers)
            if req.is_notification:
                # Per JSON-RPC 2.0 §4.1, MUST NOT reply to notifications.
                return Response(status_code=204)
            if mode == "enforce":
                return JSONResponse(
                    make_error(req.request_id, exc.jsonrpc_code, str(exc)),
                    status_code=exc.http_status,
                )
            # audit_only / advise — record + forward with verdict.
            # Customer's enforcement layer is the security boundary.
            # Per-cred discriminator (5g-A-03) so distinct bad credentials
            # land in distinct rows; stable-enum reason code (5g-A-04).
            principal = _anon_principal_for(raw_headers)
            identity_failure = ("identity_invalid",
                                [_identity_failure_code(exc)])

        # ─── 3. Method dispatch ──────────────────────────────────
        if req.method == "initialize":
            if req.is_notification:
                return Response(status_code=204)
            return JSONResponse(make_response(req.request_id, initialize_result()))

        if req.method in ("tools/list", "resources/list", "prompts/list"):
            # Discovery passes through without policy — these are read-only
            # capability queries. For MVP we proxy to the default backend.
            if req.is_notification:
                return Response(status_code=204)
            return await _proxy_passthrough(
                gw, req, default_backend="default",
                mode=mode,
                verdict_str=(
                    identity_failure[0] if identity_failure else "allow"
                ),
                reason_codes=(
                    identity_failure[1] if identity_failure else []
                ),
                principal=principal,   # F2 fix
            )

        if req.method != "tools/call":
            # Unknown method: pass through to the default backend so the
            # gateway is forward-compatible with new MCP methods.
            if req.is_notification:
                # Fire-and-forget pass-through to backend, no body return.
                try:
                    await _proxy_passthrough(
                        gw, req, default_backend="default", mode=mode,
                        principal=principal,   # F2 fix
                    )
                except Exception as exc:
                    logger.debug("[KYA-GATEWAY] notification passthrough failed: %s", exc)
                return Response(status_code=204)
            return await _proxy_passthrough(
                gw, req, default_backend="default",
                mode=mode,
                verdict_str=(
                    identity_failure[0] if identity_failure else "allow"
                ),
                reason_codes=(
                    identity_failure[1] if identity_failure else []
                ),
                principal=principal,   # F2 fix
            )

        # ─── 4. Policy pipeline ──────────────────────────────────
        tool_name = req.tool_name or ""
        backend_name, bare_tool = parse_backend_from_tool(tool_name)
        action = action_from_tool_call(backend_name, bare_tool)

        # B8: record_invocation BEFORE policy so replay protection has a
        # real invocation_id to check against. The evidence-recording step
        # then re-uses the same id, keeping the audit trail consistent.
        invocation_id = _record_invocation_pre_policy(
            gw=gw, principal=principal, action=action,
        )

        if identity_failure is None:
            verdict = _run_policy(
                gw=gw,
                principal=principal,
                action=action,
                payload_bytes=len(body),
                invocation_id=invocation_id,
            )
        else:
            # Policy can't meaningfully evaluate an unauth call — synthesize
            # a deny verdict carrying the identity-failure reason. The
            # evidence row still gets written; mode decides response shape.
            verdict = Verdict(
                verdict="deny",
                reason_codes=identity_failure[1],
                signal_kind="rbac_refusal",
            )

        # ─── 5. Record evidence + emit verdict ───────────────────
        # 5g-A-07: for unauth traffic in audit_only / advise, throttle
        # evidence writes per source IP so a flood of bad credentials
        # can't be used as a write-amplifier on the HMAC-chained
        # evidence table. Authenticated traffic and enforce-mode are
        # always recorded.
        skip_evidence = False
        if identity_failure is not None:
            client_ip = _client_ip(request)
            if not _should_record_unauth_evidence(client_ip):
                skip_evidence = True
                _METRICS["unauth_evidence_dropped"] += 1
        if not skip_evidence:
            _record_verdict_evidence(
                gw=gw,
                principal=principal,
                action=action,
                verdict=verdict,
                request_payload=req.raw,
                invocation_id=invocation_id,
            )

        if req.is_notification:
            return Response(status_code=204)

        # The string that appears in X-KYA-Verdict / body. Identity
        # failures surface as "identity_invalid" so the customer's
        # enforcement layer can distinguish them from policy denies.
        display_verdict = (
            identity_failure[0] if identity_failure else verdict.verdict
        )

        # ─── 6a. Enforce mode: KYA blocks (operator opted into liability) ─
        if mode == "enforce":
            if verdict.verdict == "deny":
                return JSONResponse(
                    make_error(
                        req.request_id,
                        -32001,
                        f"KYA verdict: deny ({', '.join(verdict.reason_codes)})",
                        data={"reason_codes": verdict.reason_codes, "verdict": "deny"},
                    ),
                    status_code=403,
                )
            if verdict.verdict == "require_human":
                # Phase 5g-tail — 428 Precondition Required (RFC 6585 §3)
                # is the correct semantic: the action isn't denied, it
                # needs a precondition (human approval) before it can
                # proceed. The WWW-Authenticate hint advertises the
                # KYA-Human-Approval scheme for discovery.
                from kya_gateway.errors import (
                    JSONRPC_ERR_HUMAN_APPROVAL_REQUIRED,
                )
                return JSONResponse(
                    make_error(
                        req.request_id,
                        JSONRPC_ERR_HUMAN_APPROVAL_REQUIRED,
                        "KYA verdict: require_human approval",
                        data={"reason_codes": verdict.reason_codes,
                              "verdict": "require_human"},
                    ),
                    status_code=428,
                    headers={
                        "WWW-Authenticate":
                            'KYA-Human-Approval realm="kya-gateway"',
                    },
                )

        # ─── 6b. Forward to backend (audit_only/advise always; enforce on allow) ─
        # 5g-A-02: signal the upstream verdict to the backend so it can
        # NOT rely on "gateway forwarded → caller is authenticated."
        # Stamped on every non-enforce forward; backends that ignore the
        # headers behave as before.
        outbound_headers: dict[str, str] = {}
        if mode != "enforce":
            outbound_headers["X-KYA-Verdict"] = display_verdict
            outbound_headers["X-KYA-Reason-Codes"] = ",".join(verdict.reason_codes)
            outbound_headers["X-KYA-Principal-Kind"] = principal.principal_kind
            outbound_headers["X-KYA-Principal-Id"] = principal.principal_id
            outbound_headers["X-KYA-Mode"] = mode
        try:
            result = await gw.forwarder.forward_json(
                backend_name, req.raw,
                extra_request_headers=outbound_headers or None,
            )
        except BackendUnreachable as exc:
            return JSONResponse(
                make_error(req.request_id, exc.jsonrpc_code, str(exc)),
                status_code=exc.http_status,
            )

        if mode == "enforce":
            # Allow path — no header/body decoration, matches pre-5g behavior.
            return Response(
                content=result.body,
                status_code=result.status_code,
                media_type=result.headers.get("content-type", "application/json"),
            )

        # audit_only / advise — attach verdict signal for customer enforcement.
        return _shape_response_with_verdict(
            backend_body=result.body,
            backend_status=result.status_code,
            backend_content_type=result.headers.get("content-type", "application/json"),
            verdict_str=display_verdict,
            reason_codes=verdict.reason_codes,
            mode=mode,
        )

    return app


# ─── Internal helpers ───────────────────────────────────────────────


async def _proxy_passthrough(
    gw: Gateway,
    req,
    default_backend: str = "default",
    *,
    mode: str = "enforce",
    verdict_str: str = "allow",
    reason_codes: list[str] | None = None,
    principal=None,
):
    """Forward a request to the default backend without running policy.

    Used for discovery methods (``tools/list`` etc.) that don't change
    state. The gateway still records that the call happened.

    5g-A-06: attaches mode-appropriate X-KYA-Verdict headers / body
    so discovery in audit_only / advise carries the same signal the
    main /mcp tool-call path does. Without this an unauthenticated
    caller could fetch the entire tool catalog with no header on the
    response telling the customer's enforcement layer it was unauth.
    """
    try:
        backend = default_backend if default_backend in gw.forwarder._backends else next(
            iter(gw.forwarder._backends.keys()), None
        )
        if backend is None:
            return JSONResponse(
                make_error(req.request_id, -32603, "no backends configured"),
                status_code=500,
            )
        outbound_headers: dict[str, str] = {}
        if mode != "enforce":
            outbound_headers["X-KYA-Verdict"] = verdict_str
            outbound_headers["X-KYA-Reason-Codes"] = ",".join(reason_codes or [])
            outbound_headers["X-KYA-Mode"] = mode
            if principal is not None:
                outbound_headers["X-KYA-Principal-Kind"] = principal.principal_kind
                outbound_headers["X-KYA-Principal-Id"] = principal.principal_id
        result = await gw.forwarder.forward_json(
            backend, req.raw,
            extra_request_headers=outbound_headers or None,
        )
        if mode == "enforce":
            return Response(
                content=result.body,
                status_code=result.status_code,
                media_type=result.headers.get("content-type", "application/json"),
            )
        return _shape_response_with_verdict(
            backend_body=result.body,
            backend_status=result.status_code,
            backend_content_type=result.headers.get("content-type", "application/json"),
            verdict_str=verdict_str,
            reason_codes=reason_codes or [],
            mode=mode,
        )
    except BackendUnreachable as exc:
        return JSONResponse(
            make_error(req.request_id, exc.jsonrpc_code, str(exc)),
            status_code=exc.http_status,
        )


def _run_policy(
    *,
    gw: Gateway,
    principal,
    action: str,
    payload_bytes: int,
    invocation_id: int | None,
):
    """Run the policy pipeline within a KYA session.

    Wrapped in its own function so failures don't leak DB sessions and
    so tests can stub it.
    """
    try:
        from kya import default_session
    except ImportError:
        # KYA core not installed — fail closed.
        logger.error("[KYA-GATEWAY] kya core not installed; failing closed")
        from kya_gateway.policy_pipeline import Verdict
        return Verdict(
            verdict="deny",
            reason_codes=["KYA_CORE_UNAVAILABLE"],
            signal_kind="rate_limit_exceeded",
        )

    with default_session() as db:
        return evaluate_policy(
            db=db,
            tenant_id=gw.cfg.gateway.tenant_id,
            principal=principal,
            action=action,
            payload_bytes=payload_bytes,
            invocation_id=invocation_id,
            cfg=gw.cfg.policy,
        )


def _short_agent_key(principal_id: str) -> str:
    """Derive a short, stable agent_key from a (possibly long) principal_id.

    Since 0.2.4 the column is VARCHAR(512) (was 100 — that ceiling broke
    DID-shaped principals on Postgres/MySQL, silently truncated on
    SQLite). A full DID URI now fits.

    We still hash for READABILITY reasons:
    * `(tenant_id, agent_key, occurred_at)` index stays compact (32 vs
      ~175 bytes per row → smaller index, faster range scans)
    * dashboards / logs scan more easily with a 32-char handle
    * the full DID is preserved alongside in `principal_id TEXT` — no
      audit information is lost

    Stable per principal; deterministic; recoverable.
    """
    import hashlib
    if not principal_id:
        return "anon"
    return "kya-" + hashlib.sha256(principal_id.encode("utf-8")).hexdigest()[:28]


def _record_invocation_pre_policy(*, gw: Gateway, principal, action: str) -> int | None:
    """Record the invocation row BEFORE policy runs so replay protection
    has a real id to check. Returns None if the KYA core / record_invocation
    is unavailable — replay protection then silently no-ops downstream.

    NOTE: a return of None means replay protection is OFF for this request.
    We log at ERROR level (not warning) so operators have a clear "we
    expected this to be recorded and it wasn't" signal in the audit chain.
    A counter is incremented so dashboards / alerts can fire on a sustained
    no-record situation rather than discovering it post-incident.
    """
    try:
        from kya import default_session, record_invocation
    except ImportError:
        logger.error(
            "[KYA-GATEWAY] kya.record_invocation unavailable — "
            "REPLAY PROTECTION IS OFF for this request"
        )
        _METRICS["invocation_record_failures"] += 1
        return None
    try:
        with default_session() as db:
            inv = record_invocation(
                db,
                tenant_id=gw.cfg.gateway.tenant_id,
                agent_key=_short_agent_key(principal.principal_id),
                principal_kind=principal.principal_kind,
                principal_id=principal.principal_id,
                mode="observed",
                outcome="pending",
            )
            db.commit()
            if inv is None:
                logger.error(
                    "[KYA-GATEWAY] record_invocation returned None — "
                    "REPLAY PROTECTION IS OFF for this request"
                )
                _METRICS["invocation_record_failures"] += 1
            return inv
    except Exception as exc:
        logger.error(
            "[KYA-GATEWAY] pre-policy record_invocation FAILED (%s): %s — "
            "REPLAY PROTECTION IS OFF for this request",
            type(exc).__name__, exc,
        )
        _METRICS["invocation_record_failures"] += 1
        return None


# Process-scoped counters exposed via /metrics (when wired in pro).
# Simple dict so we don't pull in prometheus_client at module load.
_METRICS: dict[str, int] = defaultdict(int)


# Sentinel class used so the /me handler can route DPoP-specific errors
# to a 401-with-WWW-Authenticate response without coupling to internals.
class _IdentityCredInvalidLike(Exception):
    def __init__(self, message: str, *, code: str | None = None):
        super().__init__(message)
        self.code = code


def _verify_me_dpop(gw, request, principal) -> None:
    """Verify the DPoP proof on /v1/principals/me. Raises on any issue."""
    from kya_gateway._dpop import DPoPError, verify_dpop
    headers = dict(request.headers)
    dpop_header = headers.get("dpop") or headers.get("DPoP")
    did_cfg = gw.cfg.identity.did
    # Capability-removal requires a CONFIGURED audience — falling back
    # to request.base_url behind a reverse proxy can let an attacker
    # mint a DPoP for the internal hostname and reuse it across
    # gateways that share that internal name. We accept the fallback
    # only when the operator hasn't set the cfg field, but log loudly.
    if did_cfg.dpop_audience:
        audience = did_cfg.dpop_audience
    else:
        audience = str(request.base_url).rstrip("/")
        logger.warning(
            "[KYA-GATEWAY] dpop_audience not configured; falling back to "
            "request.base_url=%r — behind a reverse proxy this allows "
            "cross-gateway replay. Set identity.did.dpop_audience explicitly.",
            audience,
        )
    expected_htu = audience.rstrip("/") + str(request.url.path)
    # Resolve the bound DID document so we can verify against its keys.
    try:
        from kya.did import resolve_did
        doc = resolve_did(principal.external_subject)
    except Exception as exc:
        raise _IdentityCredInvalidLike(
            f"DPoP cannot resolve DID for the bound principal: {exc}"
        )
    try:
        verify_dpop(
            dpop_header,
            expected_htm=request.method,
            expected_htu=expected_htu,
            doc=doc,
            leeway_seconds=did_cfg.dpop_leeway_seconds,
        )
    except DPoPError as exc:
        # 5g-B-01 — propagate the typed code so the /me handler can
        # dispatch security events without re-reading the message text.
        raise _IdentityCredInvalidLike(
            str(exc), code=getattr(exc, "code", None),
        )


def _record_verdict_evidence(
    *,
    gw: Gateway,
    principal,
    action: str,
    verdict,
    request_payload: dict,
    invocation_id: int | None,
) -> None:
    """Record the verdict on the KYA evidence chain.

    Always records — allow + deny + require_human. The customer platform
    decides what to do with the verdict; KYA's job is to make sure the
    record exists either way.

    Fail-soft: a failure to record evidence is logged but doesn't fail
    the HTTP request. The gateway's promise is "we tried to record."
    """
    try:
        from kya import (
            default_session,
            record_evidence,
            record_principal_signal,
        )
        with default_session() as db:
            # Re-use the invocation_id from _record_invocation_pre_policy
            # so audit + policy share the same row. When that step failed,
            # invocation_id is None and record_evidence stores without
            # a linked invocation row.
            record_evidence(
                db,
                tenant_id=gw.cfg.gateway.tenant_id,
                invocation_id=invocation_id,
                evidence_kind="gateway_verdict",
                payload={
                    "action": action,
                    "verdict": verdict.verdict,
                    "reason_codes": verdict.reason_codes,
                    "tool_call": request_payload.get("params", {}),
                    "method": principal.method,
                    "external_subject": principal.external_subject,
                },
            )
            record_principal_signal(
                db,
                tenant_id=gw.cfg.gateway.tenant_id,
                principal_kind=principal.principal_kind,
                principal_id=principal.principal_id,
                signal_kind=verdict.signal_kind,
                attributes={"action": action, "reason_codes": verdict.reason_codes},
            )
            db.commit()
    except Exception as exc:
        logger.warning("[KYA-GATEWAY] evidence recording failed: %s", exc)
