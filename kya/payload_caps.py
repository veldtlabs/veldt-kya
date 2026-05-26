"""
KYA-semantic payload size limits on write primitives.

A reverse proxy can cap raw bytes per HTTP request — but the
per-primitive KYA-schema-aware limits ("evidence payload max 1MB,
tool_result max 10MB, single tool_call max 100KB") need to live
here because the proxy doesn't parse KYA's payload shape.

Design contract
---------------
- Single, reusable `check_payload_size()` helper called by every
  write primitive that accepts a `payload` dict.
- Per-primitive env-configurable cap.
- Raises `PayloadTooLargeError` on overflow — caller-meaningful
  error with the actual + max byte counts so HTTP layer can emit
  413 / 422 with useful detail.
- Default 1 MB per payload (the common limit for HTTP request
  bodies; aligned with Lambda payload limits, k8s ConfigMap caps,
  etc.). Override per-primitive via env.

Resolution order
----------------
  1. KYA_MAX_<PRIMITIVE>_PAYLOAD_BYTES (per-primitive override)
  2. KYA_MAX_PAYLOAD_BYTES (global override)
  3. 1_048_576 (1 MB default)

Why not in the DB schema?
-------------------------
We could enforce via column types (VARCHAR(N), text length CHECK,
etc.). But:
  - VARCHAR / TEXT lengths differ across PG/MySQL/SQLite/DuckDB
  - DB-level errors come back as opaque IntegrityError without the
    actual size; harder for callers to debug
  - Pre-validating at the Python layer lets KYA emit clean rejection
    *before* opening the DB connection

So we cap at the Python layer and rely on the DB column being
sized generously (JSON/JSONB/Text on every backend supports many
MB).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


# 1 MB default. Aligned with typical HTTP body limits and what most
# HTTP gateways pass through without additional config.
DEFAULT_MAX_PAYLOAD_BYTES = 1 * 1024 * 1024


class PayloadTooLargeError(ValueError):
    """Raised when a payload exceeds the configured size cap.
    Carries actual/max byte counts so HTTP layers can emit 413
    with useful detail and clients can decide to retry-with-trim."""

    def __init__(
        self,
        primitive: str,
        actual_bytes: int,
        max_bytes: int,
    ):
        self.primitive = primitive
        self.actual_bytes = actual_bytes
        self.max_bytes = max_bytes
        super().__init__(
            f"Payload too large for {primitive}: "
            f"{actual_bytes} bytes > {max_bytes} bytes cap. "
            f"Set KYA_MAX_{primitive.upper()}_PAYLOAD_BYTES to raise.")


def check_payload_size(
    payload: Any,
    *,
    primitive: str,
    tenant_id: str | None = None,
    principal_kind: str | None = None,
    principal_id: str | None = None,
    db: Any = None,
) -> int:
    """Validate that the JSON-serialized payload fits within the
    configured cap. Returns the actual byte count on success.

    Raises PayloadTooLargeError on overflow. Re-raises serialization
    failures (non-JSON-serializable types) as TypeError — that's a
    caller bug. Circular references in the payload also surface as
    PayloadTooLargeError (DefaultEncoder raises ValueError for them;
    we treat that as "too complex to safely serialize, reject").

    `primitive` is a short identifier used for env-var lookup and
    the error message. Conventional names: "evidence", "invocation",
    "cost_event", "override", "budget".

    Implementation note: an earlier version tried a str()-based
    fast-path to skip json.dumps on small payloads. It introduced
    THREE separate bugs (bypassing per-primitive caps, bypassing
    type validation, skipping circular-ref detection). Removed —
    json.dumps cost on a 1KB payload is ~10 microseconds; the
    optimization wasn't worth the correctness risk.
    """
    if payload is None:
        return 0
    max_bytes = _resolve_max_bytes(primitive)

    try:
        serialized = json.dumps(payload, separators=(",", ":"))
    except ValueError as exc:
        # Circular references → json.dumps raises ValueError.
        # We treat this as "too complex to serialize safely" and
        # reject as oversize rather than crashing on TypeError.
        if "Circular" in str(exc) or "circular" in str(exc):
            _emit_payload_violation(
                primitive=primitive, actual_bytes=-1,
                max_bytes=max_bytes,
                tenant_id=tenant_id,
                principal_kind=principal_kind,
                principal_id=principal_id, db=db,
                circular=True)
            raise PayloadTooLargeError(
                primitive=primitive,
                actual_bytes=-1,  # unknown size — circular
                max_bytes=max_bytes,
            ) from exc
        # Other ValueErrors from json.dumps are schema issues
        raise TypeError(
            f"payload for {primitive} is not JSON-serializable: {exc}"
        ) from exc
    except TypeError as exc:
        # Not a size issue — caller bug. Surface as-is.
        raise TypeError(
            f"payload for {primitive} is not JSON-serializable: {exc}"
        ) from exc
    actual_bytes = len(serialized.encode("utf-8"))
    if actual_bytes > max_bytes:
        _emit_payload_violation(
            primitive=primitive, actual_bytes=actual_bytes,
            max_bytes=max_bytes,
            tenant_id=tenant_id,
            principal_kind=principal_kind,
            principal_id=principal_id, db=db)
        raise PayloadTooLargeError(
            primitive=primitive,
            actual_bytes=actual_bytes,
            max_bytes=max_bytes,
        )
    return actual_bytes


def _emit_payload_violation(
    *,
    primitive: str,
    actual_bytes: int,
    max_bytes: int,
    tenant_id: str | None,
    principal_kind: str | None,
    principal_id: str | None,
    db: Any = None,
    circular: bool = False,
) -> None:
    """Fire the standardized security-event emission for a payload
    size violation. Fail-soft: never breaks the calling raise path."""
    try:
        from ._security_events import emit_security_event
        emit_security_event(
            "payload_too_large",
            tenant_id=tenant_id or "",
            primitive=primitive,
            principal_kind=principal_kind,
            principal_id=principal_id, db=db,
            detail={
                "actual_bytes": actual_bytes,
                "max_bytes": max_bytes,
                "circular": circular,
            })
    except Exception as exc:
        logger.debug(
            "[KYA-CAP] security-event emit failed: %s", exc)


def _resolve_max_bytes(primitive: str) -> int:
    """Specificity-ordered env lookup. First valid match wins."""
    prim_upper = (primitive or "").upper()
    keys = [
        f"KYA_MAX_{prim_upper}_PAYLOAD_BYTES",
        "KYA_MAX_PAYLOAD_BYTES",
    ]
    for key in keys:
        raw = os.environ.get(key)
        if not raw:
            continue
        try:
            v = int(raw)
            if v > 0:
                return v
        except (ValueError, TypeError):
            logger.debug(
                "[KYA-CAP] ignoring non-numeric env %s=%r", key, raw)
            continue
    return DEFAULT_MAX_PAYLOAD_BYTES
