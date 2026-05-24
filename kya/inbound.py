"""Inbound recommendations — the path that makes KYA smarter from the
platform side over time.

Off by default. Customer calls `enable_inbound(...)` to start. The SDK
then pulls signed recommendations from a configured Veldt collector on
a schedule, verifies each envelope against the pinned trust anchor,
and persists ACCEPTED recommendations to `kya_inbound_recommendations`
with status='pending'. An operator approves (or rejects) via the same
admin queue that surfaces in-tenant suggestions.

Apply paths:
  • Default (`auto_apply_allowlist=None`)
        all recommendations land as 'pending' regardless of scope.
        Operator approves explicitly through the admin UI / API.
  • Allowlist (`auto_apply_allowlist=[(scope, key), ...]`)
        recommendations matching the allowlist are auto-applied via
        `set_override()` immediately after verify+persist. Everything
        else lands as 'pending'.

Apply ALWAYS routes through `tenant_weights.set_override()`, so:
  • The only-tighten constraint still gates the final value — a
    recommendation cannot loosen the platform default.
  • The change is audited in `kya_weight_changes` with the source
    annotated.

Security contract:
  • Recommendations are verified against pinned public keys (see
    `_inbound_signing.trusted_keys()`).
  • Expired recommendations are rejected at persist time.
  • The fetch is pull-only (no inbound webhook into customer infra).
  • Verification failure NEVER falls back to "apply anyway."
  • Local DB writes are NOT affected by collector availability — the
    fetch loop is a daemon worker; the rest of KYA keeps recording.
"""

from __future__ import annotations

import atexit
import logging
import threading
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update

from ._inbound_signing import (
    SignatureVerificationError,
    require_trusted_keys,
    trusted_keys,
    verify_envelope,
)
from ._legacy_tables import (
    create_legacy_tables,
)
from ._legacy_tables import (
    kya_inbound_recommendations as _T,
)

logger = logging.getLogger(__name__)

# ── Counters ────────────────────────────────────────────────────────


_COUNTERS: dict[str, Any] = {}


def _ensure_counters() -> None:
    if _COUNTERS:
        return
    try:
        from prometheus_client import REGISTRY, Counter, Gauge

        def _g(ctor, name, *args, **kwargs):
            try:
                return ctor(name, *args, **kwargs)
            except ValueError:
                return REGISTRY._names_to_collectors.get(name)

        _COUNTERS["fetched"] = _g(
            Counter, "veldt_kya_inbound_fetched",
            "Recommendations fetched from the collector by outcome.", ["outcome"],
        )
        _COUNTERS["rejected"] = _g(
            Counter, "veldt_kya_inbound_rejected",
            "Recommendations rejected before persisting by reason.", ["reason"],
        )
        _COUNTERS["applied"] = _g(
            Counter, "veldt_kya_inbound_applied",
            "Recommendations applied to set_override by mode.", ["mode"],
        )
        _COUNTERS["last_fetch_at"] = _g(
            Gauge, "veldt_kya_inbound_last_fetch_unixtime",
            "Last successful fetch time (unix seconds).",
        )
    except ImportError:
        pass


def _inc(name: str, **labels) -> None:
    c = _COUNTERS.get(name)
    if c is None:
        return
    try:
        (c.labels(**labels) if labels else c).inc()
    except Exception:
        pass


def _gauge(name: str, value: float) -> None:
    g = _COUNTERS.get(name)
    if g is None:
        return
    try:
        g.set(value)
    except Exception:
        pass


# ── Table bootstrap + low-level helpers ────────────────────────────


def ensure_inbound_table(db) -> None:
    create_legacy_tables(db, [_T])
    db.commit()


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


# Scope/key allowlist — what a recommendation is *permitted* to touch.
# Same set as `dualwrite.ALLOWED_TABLES` is to outbound dual-write:
# explicit so a typo doesn't silently affect production.
KNOWN_SCOPES: frozenset[str] = frozenset({
    "class_weights",
    "capability_weights",
    "source_weights",
    "deployment_weights",
})


def _persist_one(db, envelope: dict, rec: dict) -> tuple[bool, str]:
    """Insert one recommendation row. Returns (persisted, reason).

    Idempotent via UNIQUE(external_id) — re-fetching the same set is a
    no-op. The verify step at the caller already guarantees the envelope
    is signed by a trusted anchor.

    Uses SQLAlchemy Core so schema_translate_map applies on non-PG
    dialects and dialect-specific JSON/JSONB types resolve correctly.
    """
    scope = rec.get("scope")
    key = rec.get("key")
    if scope not in KNOWN_SCOPES:
        return False, f"unknown_scope:{scope}"
    if not isinstance(key, str) or not key:
        return False, "missing_key"
    if not isinstance(rec.get("recommended_value"), (int, float)):
        return False, "missing_recommended_value"

    issued_at = _parse_iso(envelope.get("issued_at"))
    expires_at = _parse_iso(envelope.get("expires_at"))
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        return False, "expired_at_fetch"

    external_id = str(rec.get("id"))
    if not external_id or external_id == "None":
        return False, "missing_external_id"

    # Tenant scope: only from the recommendation, never the envelope's
    # deployment_id (which is a salted host hash, not a tenant UUID).
    tenant_id = rec.get("tenant_id")

    values = {
        "external_id": external_id,
        "signing_key_id": envelope.get("signing_key_id"),
        "tenant_id": tenant_id,
        "scope": scope,
        "key": key,
        "current_value_at_issue": rec.get("current_value_at_issue"),
        "recommended_value": int(rec["recommended_value"]),
        "rationale": rec.get("rationale"),
        "evidence_summary": rec.get("evidence_summary") or {},
        "issued_at": issued_at,
        "expires_at": expires_at,
        "status": "pending",
    }

    try:
        # Existence check first — portable across all backends. Avoids
        # dialect-specific UPSERT syntax (ON CONFLICT / ON DUPLICATE KEY).
        # UNIQUE(external_id) at the DB level is the source of truth;
        # this check is just for the "already there" return reason.
        exists = db.execute(
            select(_T.c.id).where(_T.c.external_id == external_id)
        ).scalar()
        if exists is not None:
            return True, "ok"
        db.execute(_T.insert().values(**values))
        db.commit()
        return True, "ok"
    except Exception as exc:
        db.rollback()
        # Race: another worker inserted between our check and our insert.
        # The UNIQUE constraint catches it; treat as success.
        try:
            exists = db.execute(
                select(_T.c.id).where(_T.c.external_id == external_id)
            ).scalar()
            if exists is not None:
                return True, "ok"
        except Exception:
            pass
        return False, f"db_error:{type(exc).__name__}"


def _auto_apply_if_allowed(db, rec_external_id: str, scope: str, key: str,
                           recommended_value: int, allowlist: Iterable[tuple] | None) -> bool:
    """Apply a fresh recommendation immediately if (scope, key) is in the
    customer-configured auto-apply allowlist. Returns True if applied."""
    if not allowlist:
        return False
    pairs = {tuple(p) for p in allowlist}
    if (scope, key) not in pairs:
        return False
    try:
        from .tenant_weights import set_override

        # Apply at platform-default level. Tenants can still tighten
        # further; only-tighten enforcement happens inside set_override.
        set_override(
            db,
            scope=scope,
            key=key,
            value=recommended_value,
            tenant_id=None,
            changed_by=None,
            reason=f"auto-applied via inbound recommendation {rec_external_id}",
        )
        # WHERE status='pending' so a re-fetch can't roll back an
        # operator-applied row to 'auto_applied'.
        db.execute(
            update(_T)
            .where(_T.c.external_id == rec_external_id)
            .where(_T.c.status == "pending")
            .values(
                status="auto_applied",
                decided_at=func.now(),
                decision_notes="auto-applied per customer allowlist",
            )
        )
        db.commit()
        _inc("applied", mode="auto")
        return True
    except Exception as exc:
        logger.warning("[KYA-INBOUND] auto-apply failed for %s: %s", rec_external_id, exc)
        db.rollback()
        return False


# ── Fetch + persist ────────────────────────────────────────────────


def fetch_now(db, *, collector_url: str, request_timeout_s: float = 15.0,
              auto_apply_allowlist: Iterable[tuple] | None = None,
              since: datetime | None = None) -> dict:
    """Pull the latest envelope from the collector, verify signature,
    persist all OK recommendations. Returns a summary dict.

    Pure foreground call — usable in tests and ops scripts. The schedule
    loop installed by `enable_inbound()` wraps this.

    Raises :class:`RuntimeError` immediately if no trust anchors are
    configured, so a direct ``fetch_now()`` call never silently no-ops
    or wastes an HTTP request against the collector.
    """
    require_trusted_keys()
    _ensure_counters()
    ensure_inbound_table(db)

    try:
        import requests  # type: ignore
    except ImportError as exc:
        raise RuntimeError("kya inbound needs `requests` — install kya[webhooks]") from exc

    params: dict[str, str] = {}
    if since is not None:
        params["since"] = since.isoformat()

    try:
        resp = requests.get(
            collector_url,
            params=params or None,
            headers={"User-Agent": "veldt-kya-inbound/0.1", "Accept": "application/json"},
            timeout=request_timeout_s,
        )
    except Exception as exc:
        _inc("fetched", outcome="network_error")
        logger.warning("[KYA-INBOUND] fetch network error: %s", exc)
        return {"ok": False, "reason": "network_error", "detail": str(exc)}

    if resp.status_code == 204 or not resp.content:
        _inc("fetched", outcome="empty")
        _gauge("last_fetch_at", time.time())
        return {"ok": True, "persisted": 0, "rejected": 0, "auto_applied": 0}
    if resp.status_code >= 400:
        _inc("fetched", outcome=f"http_{resp.status_code // 100}xx")
        return {"ok": False, "reason": f"http_{resp.status_code}",
                "detail": (resp.text or "")[:200]}

    try:
        envelope = resp.json()
    except Exception as exc:
        _inc("fetched", outcome="not_json")
        return {"ok": False, "reason": "not_json", "detail": str(exc)}

    try:
        verify_envelope(envelope)
    except SignatureVerificationError as exc:
        _inc("fetched", outcome="signature_invalid")
        _inc("rejected", reason="signature_invalid")
        logger.warning("[KYA-INBOUND] signature verification FAILED: %s", exc)
        return {"ok": False, "reason": "signature_invalid", "detail": str(exc)}

    recs = envelope.get("recommendations") or []
    if not isinstance(recs, list):
        _inc("rejected", reason="recs_not_list")
        return {"ok": False, "reason": "recs_not_list"}

    persisted = 0
    rejected: list[tuple[str, str]] = []
    auto_applied = 0

    for rec in recs:
        if not isinstance(rec, dict):
            rejected.append(("<non-dict>", "not_dict"))
            _inc("rejected", reason="not_dict")
            continue
        ok, reason = _persist_one(db, envelope, rec)
        if not ok:
            rejected.append((str(rec.get("id", "<no-id>")), reason))
            _inc("rejected", reason=reason.split(":")[0])
            continue
        persisted += 1
        if _auto_apply_if_allowed(
            db,
            rec_external_id=str(rec["id"]),
            scope=rec["scope"],
            key=rec["key"],
            recommended_value=int(rec["recommended_value"]),
            allowlist=auto_apply_allowlist,
        ):
            auto_applied += 1

    _inc("fetched", outcome="ok")
    _gauge("last_fetch_at", time.time())
    return {
        "ok": True,
        "persisted": persisted,
        "rejected": len(rejected),
        "rejections": rejected,
        "auto_applied": auto_applied,
        "envelope": {
            "signing_key_id": envelope.get("signing_key_id"),
            "issued_at": envelope.get("issued_at"),
            "expires_at": envelope.get("expires_at"),
        },
    }


# ── Operator queue API ────────────────────────────────────────────


def list_recommendations(db, *, status: str | None = None,
                         tenant_id: str | None = None,
                         limit: int = 100) -> list[dict]:
    ensure_inbound_table(db)
    stmt = select(_T)
    if status:
        stmt = stmt.where(_T.c.status == status)
    if tenant_id is not None:
        stmt = stmt.where(_T.c.tenant_id == tenant_id)
    stmt = stmt.order_by(_T.c.fetched_at.desc()).limit(int(limit))
    rows = db.execute(stmt).mappings().all()
    return [dict(r) for r in rows]


def _decide(db, rec_id: int, *, new_status: str,
            decided_by: str | None, notes: str | None) -> dict:
    ensure_inbound_table(db)
    row = db.execute(
        select(_T.c.id, _T.c.external_id, _T.c.tenant_id, _T.c.scope,
               _T.c.key, _T.c.recommended_value, _T.c.status)
        .where(_T.c.id == rec_id)
    ).first()
    if not row:
        raise ValueError(f"recommendation id={rec_id} not found")
    if row.status != "pending":
        raise ValueError(
            f"recommendation id={rec_id} is not pending (status={row.status})"
        )
    db.execute(
        update(_T)
        .where(_T.c.id == rec_id)
        .where(_T.c.status == "pending")  # protect against races
        .values(
            status=new_status,
            decided_at=func.now(),
            decided_by=decided_by,
            decision_notes=notes,
        )
    )
    db.commit()
    return {
        "id": int(row.id),
        "external_id": row.external_id,
        "tenant_id": row.tenant_id,
        "scope": row.scope,
        "key": row.key,
        "recommended_value": int(row.recommended_value),
        "status": new_status,
    }


def approve_recommendation(db, rec_id: int, *, approved_by: str | None = None,
                           notes: str | None = None) -> dict:
    """Mark as approved AND apply via set_override. Mirrors
    `kya.approve_suggestion` semantics so reviewers use one mental model."""
    decision = _decide(db, rec_id, new_status="approved", decided_by=approved_by, notes=notes)
    try:
        from .tenant_weights import set_override

        set_override(
            db,
            scope=decision["scope"],
            key=decision["key"],
            value=decision["recommended_value"],
            tenant_id=decision["tenant_id"],
            changed_by=approved_by,
            reason=f"approved inbound recommendation id={rec_id}",
        )
        db.execute(
            update(_T)
            .where(_T.c.id == rec_id)
            .values(status="applied")
        )
        db.commit()
        decision["status"] = "applied"
        _inc("applied", mode="operator")
    except Exception as exc:
        logger.warning("[KYA-INBOUND] approve OK but apply failed for id=%s: %s", rec_id, exc)
        decision["apply_error"] = str(exc)
    return decision


def reject_recommendation(db, rec_id: int, *, rejected_by: str | None = None,
                          notes: str | None = None) -> dict:
    return _decide(db, rec_id, new_status="rejected", decided_by=rejected_by, notes=notes)


# ── Daemon worker ─────────────────────────────────────────────────


class _InboundWorker:
    def __init__(self, db_factory, cfg: dict) -> None:
        self._db_factory = db_factory
        self._cfg = cfg
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="kya-inbound", daemon=True)
        self._thread.start()
        self._last_fetch_summary: dict | None = None
        # Capture a stable reference; atexit.unregister can't match a
        # freshly-bound method (Python quirk). See PYPI item 8 fix.
        self._atexit_handle = self.shutdown
        atexit.register(self._atexit_handle)

    def _run(self) -> None:
        interval = max(60.0, float(self._cfg["interval_s"]))
        # Stagger first fetch so a fleet of SDKs doesn't stampede on the hour.
        if self._stop.wait(min(30.0, interval)):
            return
        while not self._stop.is_set():
            try:
                db = self._db_factory()
                try:
                    self._last_fetch_summary = fetch_now(
                        db,
                        collector_url=self._cfg["collector_url"],
                        request_timeout_s=self._cfg["request_timeout_s"],
                        auto_apply_allowlist=self._cfg.get("auto_apply_allowlist"),
                    )
                finally:
                    try:
                        db.close()
                    except Exception:
                        pass
            except Exception as exc:
                logger.warning("[KYA-INBOUND] worker iter failed: %s", exc)
            if self._stop.wait(interval):
                return

    def shutdown(self) -> None:
        self._stop.set()
        # Join so callers don't pile up stale workers on repeated
        # enable_inbound() cycles. Bounded; daemon=True covers process exit.
        try:
            if self._thread.is_alive() and threading.current_thread() is not self._thread:
                self._thread.join(timeout=2.0)
        except Exception:
            pass
        # Unregister the atexit handler — otherwise repeated
        # enable_inbound()/disable_inbound() cycles accumulate one
        # atexit handler per cycle for the process lifetime (PYPI
        # SHOULD-DO item 8: silent leak in long-running hosts).
        try:
            atexit.unregister(self._atexit_handle)
        except Exception:
            pass


_ACTIVE: _InboundWorker | None = None
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_CFG: dict[str, Any] = {}


def enable_inbound(
    db_factory,
    *,
    collector_url: str,
    interval_s: float = 86400.0,           # daily by default
    request_timeout_s: float = 15.0,
    auto_apply_allowlist: list[tuple[str, str]] | None = None,
) -> dict:
    """Start polling the collector.

    `db_factory()` must return a Session-like object the worker can use
    for one fetch cycle (closed after each iteration). Typically:

        from db.database import SessionLocal
        kya.enable_inbound(SessionLocal, collector_url="...")

    Args:
      interval_s: poll cadence. Default daily. Clamped to >= 60s.
      auto_apply_allowlist: list of (scope, key) tuples that may auto-
        apply without operator review. Default None = all pending.
    """
    global _ACTIVE, _ACTIVE_CFG
    if not collector_url:
        raise ValueError("collector_url is required")
    # Hard-refuse if no trust anchors — never silently no-op the inbound path.
    require_trusted_keys()
    with _ACTIVE_LOCK:
        if _ACTIVE is not None:
            _ACTIVE.shutdown()
        _ACTIVE_CFG = {
            "collector_url": collector_url,
            "interval_s": interval_s,
            "request_timeout_s": request_timeout_s,
            "auto_apply_allowlist": auto_apply_allowlist,
        }
        _ACTIVE = _InboundWorker(db_factory, _ACTIVE_CFG)
    logger.info(
        "[KYA-INBOUND] enabled · url=%s · interval=%ss · auto_apply=%s",
        collector_url, interval_s, bool(auto_apply_allowlist),
    )
    return inbound_status()


def disable_inbound() -> None:
    global _ACTIVE
    with _ACTIVE_LOCK:
        if _ACTIVE is not None:
            _ACTIVE.shutdown()
            _ACTIVE = None
    logger.info("[KYA-INBOUND] disabled")


def inbound_status() -> dict:
    with _ACTIVE_LOCK:
        if _ACTIVE is None:
            return {"enabled": False, "trust_anchors": sorted(trusted_keys().keys())}
        return {
            "enabled": True,
            "collector_url": _ACTIVE_CFG.get("collector_url"),
            "interval_s": _ACTIVE_CFG.get("interval_s"),
            "auto_apply_allowlist": _ACTIVE_CFG.get("auto_apply_allowlist"),
            "trust_anchors": sorted(trusted_keys().keys()),
            "last_fetch": _ACTIVE._last_fetch_summary,
        }
