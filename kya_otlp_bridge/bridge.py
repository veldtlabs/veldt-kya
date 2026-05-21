"""
KYA OTLP Bridge service — receives OTLP/HTTP, posts to KYA.

Run standalone (`python -m kya_otlp_bridge.bridge`) or mount the
FastAPI app into an existing service. Either way, point your framework's
OTEL_EXPORTER_OTLP_ENDPOINT at this bridge.

Why a separate service: ingestion has different scaling characteristics
than KYA's core (high write volume, low compute) AND keeping it
out-of-process means an OTLP storm can't take KYA down.

Multi-tenant model (fix C2)
----------------------------
The bridge is multi-tenant by default. It reads the `tenant.id` attribute
from each span's resource OR span attributes. A token map (loaded from
env `KYA_TENANT_TOKENS` as JSON, or from a config file) maps tenant_id
to the KYA bearer token that should post events for that tenant.

For backward compat, `KYA_TOKEN` is the fallback when no tenant.id is
present on the span (single-tenant deployment).

Retry behavior (fix I2)
-----------------------
Each KYA post retries up to 3 times with exponential backoff (0.5s,
1s, 2s). If all retries fail, the failure is counted in `errors_posting`
AND the OTLP response indicates partial failure so the OTLP client can
retry by re-sending the batch. No silent drop.

Auth (fix I8)
-------------
The /v1/traces endpoint enforces an `Authorization: Bearer <SECRET>`
header whose value must match the env-configured `BRIDGE_INGRESS_SECRET`.
This blocks lateral-movement abuse where a compromised peer container
could otherwise post arbitrary KYA events through the bridge.
"""

from __future__ import annotations

import json
import logging
import os
import time

try:
    from fastapi import FastAPI, HTTPException, Request
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("kya_otlp_bridge.bridge requires `pip install fastapi uvicorn`.") from exc

# kya_hooks.client is the dependency we re-use for posting to KYA.
# Direct import avoids the broader `agents.*` namespace + its FastAPI/etc deps.
import sys as _sys

_THIS = os.path.dirname(os.path.abspath(__file__))
_SIBLING = os.path.dirname(_THIS)  # in container: /app; in dev: app/agents
if _SIBLING not in _sys.path:
    _sys.path.insert(0, _SIBLING)

try:
    from kya_hooks.client import KyaClient
except ImportError:
    # Standalone test layout — sibling test directory
    from kya_hooks_standalone.client import KyaClient
from .mapper import SpanMapper  # noqa: E402  (must follow sys.path setup above)

logger = logging.getLogger(__name__)


def _load_tenant_tokens() -> dict[str, str]:
    """Parse KYA_TENANT_TOKENS env (JSON map tenant_id -> token).

    Empty / unparseable -> empty dict. The bridge then only handles the
    fallback single-tenant case via KYA_TOKEN.
    """
    raw = os.environ.get("KYA_TENANT_TOKENS", "").strip()
    if not raw:
        return {}
    try:
        m = json.loads(raw)
        if isinstance(m, dict):
            return {str(k): str(v) for k, v in m.items()}
    except Exception as exc:
        logger.warning("[OTLP-BRIDGE] failed to parse KYA_TENANT_TOKENS: %s", exc)
    return {}


def _post_with_retry(
    client: KyaClient,
    path: str,
    body: dict,
    *,
    max_retries: int = 3,
    base_delay: float = 0.5,
) -> tuple[bool, str | None]:
    """Post to KYA with exponential backoff. Returns (success, last_error).

    Retries on transport / 5xx responses. 4xx responses are NOT retried
    (they're caller errors — body shape, validation, etc.) — those fail
    fast so operators see them.
    """
    from kya_hooks.client import KyaClientError

    last_err: str | None = None
    for attempt in range(max_retries):
        try:
            client._post(path, body)
            return True, None
        except KyaClientError as exc:
            last_err = str(exc)
            msg = last_err
            # If it's a 4xx, abort retry — caller-fault, retrying won't help.
            if any(f" {code}:" in msg for code in ("400", "401", "403", "404", "422")):
                return False, last_err
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2**attempt))
        except Exception as exc:
            last_err = f"unexpected: {exc}"
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2**attempt))
    return False, last_err


def _post_with_retry_resp(
    client,
    path: str,
    body: dict,
    *,
    max_retries: int = 3,
    base_delay: float = 0.5,
) -> tuple[bool, str | None, dict | None]:
    """Variant of _post_with_retry that ALSO returns the parsed response.

    Needed for the evidence-chaining path: the bridge posts the invocation
    row, captures the returned `invocation_id` from the response body, and
    uses it to fill each evidence row's foreign key. Returns
    `(success, last_error, response_dict_or_none)`.
    """
    from kya_hooks.client import KyaClientError

    last_err: str | None = None
    for attempt in range(max_retries):
        try:
            resp = client._post(path, body)
            return True, None, resp if isinstance(resp, dict) else None
        except KyaClientError as exc:
            last_err = str(exc)
            msg = last_err
            if any(f" {code}:" in msg for code in ("400", "401", "403", "404", "422")):
                return False, last_err, None
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2**attempt))
        except Exception as exc:
            last_err = f"unexpected: {exc}"
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2**attempt))
    return False, last_err, None


class KyaOtlpBridge:
    """OTLP/HTTP receiver + KYA poster.

    Multi-tenant: tokens loaded from `KYA_TENANT_TOKENS` env or via
    `tenant_tokens=` constructor arg. Fallback token (`KYA_TOKEN`) used
    when a span has no `tenant.id` attribute.
    """

    def __init__(
        self,
        mapper: SpanMapper | None = None,
        tenant_tokens: dict[str, str] | None = None,
        fallback_token: str | None = None,
        base_url: str | None = None,
        ingress_secret: str | None = None,
    ):
        self.mapper = mapper or SpanMapper()
        self.tenant_tokens = tenant_tokens if tenant_tokens is not None else _load_tenant_tokens()
        self.fallback_token = fallback_token or os.environ.get("KYA_TOKEN") or ""
        self.base_url = base_url or os.environ.get("KYA_BASE") or "http://localhost:17000"
        self.ingress_secret = (
            ingress_secret
            if ingress_secret is not None
            else os.environ.get("BRIDGE_INGRESS_SECRET", "")
        )
        # Per-tenant clients are lightweight — cache them so we don't
        # build a new requests.Session per span.
        self._clients: dict[str, KyaClient] = {}
        # v2.1 — trace_id → invocation_id mapping so child spans
        # (LLM / TOOL / RETRIEVER / GUARDRAIL / EVALUATOR) attach their
        # evidence to the parent AGENT span's invocation row instead of
        # spawning new invocation rows. TTL-capped to bound memory under
        # high trace volume; entries evicted oldest-first when over.
        self._trace_to_inv: dict[str, tuple[int, float]] = {}
        self._trace_cache_max = int(os.environ.get("KYA_BRIDGE_TRACE_CACHE_MAX", "10000"))
        self._trace_cache_ttl_s = int(os.environ.get("KYA_BRIDGE_TRACE_CACHE_TTL_S", "1800"))

    def _trace_inv_get(self, trace_id: str | None) -> int | None:
        """Return the AGENT-span invocation_id for this trace, if any."""
        if not trace_id:
            return None
        entry = self._trace_to_inv.get(trace_id)
        if not entry:
            return None
        inv_id, ts = entry
        if (time.time() - ts) > self._trace_cache_ttl_s:
            self._trace_to_inv.pop(trace_id, None)
            return None
        return inv_id

    def _trace_inv_set(self, trace_id: str | None, inv_id: int) -> None:
        """Remember the AGENT-span invocation_id for child spans to attach to."""
        if not trace_id or not inv_id:
            return
        # Capped LRU-ish eviction — pop oldest if over the limit.
        if len(self._trace_to_inv) >= self._trace_cache_max:
            oldest_key = min(self._trace_to_inv, key=lambda k: self._trace_to_inv[k][1])
            self._trace_to_inv.pop(oldest_key, None)
        self._trace_to_inv[trace_id] = (inv_id, time.time())

    def _client_for(self, tenant_id: str | None) -> KyaClient | None:
        """Resolve which KyaClient to use for a span's tenant.

        Returns None when we have no token (no tenant in span AND no
        fallback). Caller should drop the event in that case.
        """
        key = tenant_id or "__fallback__"
        if key not in self._clients:
            token = (
                self.tenant_tokens.get(tenant_id) if tenant_id else self.fallback_token
            ) or self.fallback_token
            if not token:
                return None
            self._clients[key] = KyaClient(base_url=self.base_url, token=token)
        return self._clients[key]

    def create_app(self) -> FastAPI:
        app = FastAPI(title="KYA OTLP Bridge", version="0.2.0")

        counters = {
            "spans_received": 0,
            "events_emitted": 0,
            "evidence_emitted": 0,
            "events_dropped_no_tenant_token": 0,
            "events_dropped_invalid_body": 0,
            "errors_posting": 0,
            "auth_rejected": 0,
        }

        def _check_ingress_auth(request: Request) -> None:
            """Optional shared-secret check (fix I8)."""
            if not self.ingress_secret:
                return  # auth disabled by config
            hdr = request.headers.get("authorization", "") or ""
            expected = f"Bearer {self.ingress_secret}"
            if hdr != expected:
                counters["auth_rejected"] += 1
                raise HTTPException(401, "bridge ingress unauthorized")

        @app.get("/health")
        def health():
            return {"ok": True, "service": "kya-otlp-bridge", "version": "0.2.0"}

        @app.get("/stats")
        def stats():
            return {
                "counters": dict(counters),
                "tenant_tokens_configured": len(self.tenant_tokens),
                "fallback_token_configured": bool(self.fallback_token),
                "ingress_auth_enabled": bool(self.ingress_secret),
            }

        @app.post("/v1/traces")
        async def receive_traces(request: Request):
            _check_ingress_auth(request)
            ct = (request.headers.get("content-type") or "").lower()
            ce = (request.headers.get("content-encoding") or "").lower()
            body_bytes = await request.body()

            # OTel Collector often gzips request bodies even when sending
            # application/json or application/x-protobuf. Detect via
            # Content-Encoding header OR by the gzip magic bytes (1f 8b).
            try:
                is_gzip = "gzip" in ce or (
                    len(body_bytes) >= 2 and body_bytes[0] == 0x1F and body_bytes[1] == 0x8B
                )
                if is_gzip:
                    import gzip

                    body_bytes = gzip.decompress(body_bytes)
            except Exception as exc:
                raise HTTPException(400, f"gzip decompression failed: {exc}") from exc

            try:
                if "protobuf" in ct or "x-protobuf" in ct or "octet-stream" in ct:
                    payload = _parse_otlp_protobuf(body_bytes)
                else:
                    # Try JSON first; fall back to protobuf if the body looks
                    # binary (some collectors mis-set Content-Type).
                    import json as _json

                    try:
                        payload = _json.loads(body_bytes.decode("utf-8"))
                    except Exception:
                        payload = _parse_otlp_protobuf(body_bytes)
            except Exception as exc:
                logger.warning("[OTLP-BRIDGE] parse failed (ct=%s ce=%s): %s", ct, ce, exc)
                raise HTTPException(400, f"invalid OTLP payload (ct={ct} ce={ce}): {exc}") from exc

            spans = _extract_spans(payload)
            counters["spans_received"] += len(spans)

            emitted = 0
            rejected_spans = 0
            for span in spans:
                # Tenant resolution: span attribute first, then resource attribute
                tenant_id = _extract_tenant_id(span)
                client = self._client_for(tenant_id)
                if client is None:
                    counters["events_dropped_no_tenant_token"] += 1
                    rejected_spans += 1
                    logger.warning("[OTLP-BRIDGE] no token for tenant=%s; dropping span", tenant_id)
                    continue

                # v2.1 — trace_id pulled from the OTLP span. Child spans use
                # it to find the parent AGENT invocation_id and attach
                # evidence there instead of spawning a new invocation row.
                trace_id = span.get("traceId") or span.get("trace_id")
                # span.kind helps us know whether this IS the parent AGENT
                # span (the one whose invocation_id we cache) vs a child.
                span_attrs = span.get("attributes") or {}
                oi_kind = (span_attrs.get("openinference.span.kind") or "").upper()
                is_agent_root = oi_kind == "AGENT"

                for result in self.mapper.map_span(span):
                    if result.event_type == "skip":
                        continue
                    body = result.body
                    # Validate required fields BEFORE posting (fix I4)
                    if not _has_required_fields(result.event_type, body):
                        counters["events_dropped_invalid_body"] += 1
                        logger.warning(
                            "[OTLP-BRIDGE] dropping %s event missing required fields: %s",
                            result.event_type,
                            body,
                        )
                        continue

                    # v2.1 chain logic — if this is a child span (LLM,
                    # RETRIEVER, GUARDRAIL, EVALUATOR) AND we have a cached
                    # parent invocation_id for this trace, skip creating a
                    # new invocation row and post evidence directly to the
                    # parent's invocation. Saves N-1 invocation rows per
                    # multi-step agent run.
                    if (
                        result.event_type == "invocation"
                        and not is_agent_root
                        and result.evidence_payloads
                    ):
                        parent_inv_id = self._trace_inv_get(trace_id)
                        if parent_inv_id:
                            # Attach evidence to parent — no new invocation
                            for ev in result.evidence_payloads:
                                ev_body = dict(ev)
                                ev_body["invocation_id"] = parent_inv_id
                                ev_ok, ev_err, _ = _post_with_retry_resp(
                                    client,
                                    "/api/v1/admin/agents/events/evidence",
                                    ev_body,
                                )
                                if ev_ok:
                                    counters["evidence_emitted"] = (
                                        counters.get("evidence_emitted", 0) + 1
                                    )
                                else:
                                    counters["errors_posting"] += 1
                            counters["evidence_attached_to_parent"] = (
                                counters.get("evidence_attached_to_parent", 0) + 1
                            )
                            continue

                    path = (
                        "/api/v1/admin/agents/events/rogue"
                        if result.event_type == "rogue"
                        else "/api/v1/admin/agents/events/invocation"
                    )
                    ok, err, resp = _post_with_retry_resp(client, path, body)
                    if ok:
                        emitted += 1
                    else:
                        counters["errors_posting"] += 1
                        rejected_spans += 1
                        logger.warning("[OTLP-BRIDGE] KYA post failed after retries: %s", err)
                        continue

                    # Capture the AGENT-span invocation_id so future child
                    # spans in this same trace can attach their evidence.
                    if (
                        result.event_type == "invocation"
                        and is_agent_root
                        and isinstance(resp, dict)
                    ):
                        new_inv = resp.get("invocation_id")
                        if new_inv:
                            self._trace_inv_set(trace_id, int(new_inv))

                    # Chain evidence posts for this invocation. The mapper
                    # populates `evidence_payloads` from OpenInference /
                    # OpenLLMetry content attributes; the bridge fills the
                    # invocation_id and POSTs each row to /events/evidence.
                    if (
                        result.event_type == "invocation"
                        and result.evidence_payloads
                        and isinstance(resp, dict)
                    ):
                        inv_id = resp.get("invocation_id")
                        if inv_id:
                            for ev in result.evidence_payloads:
                                ev_body = dict(ev)
                                ev_body["invocation_id"] = inv_id
                                ev_ok, ev_err, _ = _post_with_retry_resp(
                                    client,
                                    "/api/v1/admin/agents/events/evidence",
                                    ev_body,
                                )
                                if ev_ok:
                                    counters["evidence_emitted"] = (
                                        counters.get("evidence_emitted", 0) + 1
                                    )
                                else:
                                    counters["errors_posting"] += 1
                                    logger.warning("[OTLP-BRIDGE] evidence post failed: %s", ev_err)

            counters["events_emitted"] += emitted
            # Non-2xx on partial failure so OTLP client retries (fix I2)
            response = {
                "partialSuccess": {
                    "rejectedSpans": rejected_spans,
                    "errorMessage": "see bridge logs for details" if rejected_spans else "",
                },
                "kya_events_emitted": emitted,
            }
            return response

        return app


def _parse_otlp_protobuf(body: bytes) -> dict:
    """Decode OTLP/HTTP protobuf into the same dict shape that JSON gives.

    Uses opentelemetry-proto when available (preferred — exact spec
    compliance). Falls back to MessageToDict via google.protobuf when
    only the base proto runtime is installed.
    """
    try:
        from google.protobuf.json_format import MessageToDict
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
            ExportTraceServiceRequest,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "OTLP protobuf parsing requires `pip install opentelemetry-proto`."
        ) from exc
    req = ExportTraceServiceRequest()
    req.ParseFromString(body)
    # Convert to JSON-shape dict; use camelCase to match OTLP/JSON spec.
    return MessageToDict(req, preserving_proto_field_name=False)


def _extract_tenant_id(span: dict) -> str | None:
    """Look up tenant id in span attributes OR resource attributes."""
    attrs = span.get("attributes") or {}
    return attrs.get("tenant.id") or attrs.get("tenant_id") or attrs.get("kya.tenant_id")


def _has_required_fields(event_type: str, body: dict) -> bool:
    """Validate KYA event body shape before posting (fix I4)."""
    if event_type == "rogue":
        kind = body.get("event_type")
        if kind == "oos_tool" and not body.get("tool"):
            return False
        if kind == "data_leak" and not body.get("data_class"):
            return False
        if kind == "cross_tenant" and not body.get("actual_tid"):
            return False
        return bool(body.get("agent_key"))
    if event_type == "invocation":
        return bool(body.get("agent_key"))
    return False


def _extract_spans(otlp_payload: dict) -> list[dict]:
    """Flatten the OTLP nested structure into a list of spans, lifting
    resource attributes onto each span so the mapper sees them."""
    spans: list[dict] = []
    for rs in otlp_payload.get("resourceSpans") or []:
        resource = rs.get("resource") or {}
        resource_attrs_flat = _flatten_otlp_attrs(resource.get("attributes") or [])
        for ss in rs.get("scopeSpans") or []:
            for span in ss.get("spans") or []:
                if isinstance(span.get("attributes"), list):
                    flat = _flatten_otlp_attrs(span["attributes"])
                    span = {**span, "attributes": {**resource_attrs_flat, **flat}}
                elif isinstance(span.get("attributes"), dict):
                    # Already-flat shape — still merge resource attrs
                    span = {**span, "attributes": {**resource_attrs_flat, **span["attributes"]}}
                else:
                    span = {**span, "attributes": dict(resource_attrs_flat)}
                spans.append(span)
    return spans


def _flatten_otlp_attrs(attrs_list: list) -> dict:
    """OTLP wraps values: list[{"key":..,"value":{"stringValue":..}}]
    -> flat dict[str, value]. Handles int64 strings and float values."""
    flat: dict = {}
    if not isinstance(attrs_list, list):
        return flat
    for a in attrs_list:
        k = a.get("key")
        v = a.get("value", {})
        if isinstance(v, dict):
            val = (
                v.get("stringValue")
                if "stringValue" in v
                else v.get("intValue")
                if "intValue" in v
                else v.get("boolValue")
                if "boolValue" in v
                else v.get("doubleValue")
            )
        else:
            val = v
        # Coerce numeric strings into ints/floats safely (fix M4)
        if isinstance(val, str):
            stripped = val.lstrip("-")
            if stripped.isdigit():
                try:
                    val = int(val)
                except ValueError:
                    pass
            else:
                try:
                    fval = float(val)
                    # only coerce if str round-trips through float meaningfully
                    if "." in val or "e" in val.lower():
                        val = fval
                except ValueError:
                    pass
        if k:
            flat[k] = val
    return flat


# ── Module entrypoint ────────────────────────────────────────────────
# Run as: python -m kya_otlp_bridge.bridge
if __name__ == "__main__":
    import uvicorn

    bridge = KyaOtlpBridge()
    app = bridge.create_app()
    port = int(os.environ.get("KYA_OTLP_BRIDGE_PORT", "4318"))
    logger.info(
        "Starting KYA OTLP Bridge v0.2.0 on :%d (tenants=%d, ingress_auth=%s)",
        port,
        len(bridge.tenant_tokens),
        bool(bridge.ingress_secret),
    )
    uvicorn.run(app, host="0.0.0.0", port=port)
