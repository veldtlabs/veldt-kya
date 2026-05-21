"""
KYA Evidence — append-only forensic payload capture.

What it stores
--------------
The actual content that proves an agent was rogue (or compliant):
    - Prompts the agent received
    - Responses the agent produced
    - Tool calls (with arguments — the SQL it tried to run, the email
      it tried to send)
    - Delegation messages between agents
    - Human-in-the-loop / human-on-the-loop decisions
    - System messages

KYA's scoring tables (kya_invocations, kya_principal_trust) hold the
COUNTS — this table holds the PROOF.

Tamper-evidence — HMAC chain
----------------------------
Each row carries `payload_hash`, `prev_hash`, `signed_hash`:

    payload_hash = SHA-256( canonicalize(payload) )
    prev_hash    = signed_hash of the previous row in the same chain
                   (per-(tenant, invocation) chain) — first row uses "" empty
    signed_hash  = HMAC-SHA256(signing_key, prev_hash || payload_hash)

Verifying the chain:
    walk rows in order; for each, recompute signed_hash; compare to
    stored signed_hash. Mismatch = tampered row.

A DBA with raw write access cannot forge a row without the signing key.
Altering any row breaks the chain at that point AND every row after.

Signing key
-----------
`KYA_EVIDENCE_SIGNING_KEY` env var holds a base64-encoded 32-byte secret.
For dev, a development key is auto-generated and a warning logged.
Production should mount a real key (KMS / sealed-secret / vault).

Key rotation: the `signing_key_id` column records which key signed each
row, but `verify_chain()` only uses the current signing key today. Rows
signed with a previous key will fail verification after rotation —
mitigate by re-signing on rotation or by maintaining a parallel key
registry (out of v1 scope).

Pruning + chain breaks
----------------------
`prune_expired_evidence()` is the only legitimate delete path. After
pruning, `verify_chain()` will report a "prev_hash break" at the first
surviving row whose chain predecessor was removed. That break IS correct
— the deletion was approved by retention policy. Treat the break as a
clean cut, not a tamper. Future rows in the chain still verify among
themselves.

v1 limitations (roadmap items)
------------------------------
- Merkle / third-party anchor: payloads are signed only by the local
  HMAC. For external verifiability, batch a daily root hash to a notary
  (Sigstore, RFC 3161 TSA, Solana) — out of v1 scope.
- Payload privacy: rows are stored plaintext. For PII at rest, layer
  column-level encryption (PG `pgcrypto`, MySQL `AES_ENCRYPT`) at the
  app boundary, or pre-redact via the `redacted` + `redaction_reason`
  fields before calling record_evidence().
- Concurrency: two `record_evidence` calls for the same
  (tenant, invocation) that race can read the same `prev_hash` and
  produce a chain fork. Mitigate with serializable isolation, an
  application-level mutex per invocation, or by sequencing writes
  through a single ingestion process.

Public API
----------
    init_evidence_table(db)
    record_evidence(db, tenant_id, invocation_id, evidence_kind, payload,
                    role=None, source=None, occurred_at=None,
                    data_classes=None, correlation_id=None,
                    parent_invocation_id=None, span_id=None,
                    retention_days=None) -> int
    list_evidence(db, tenant_id, invocation_id=None, correlation_id=None,
                  limit=100) -> list[dict]
    get_evidence(db, evidence_id) -> dict | None
    verify_chain(db, tenant_id, invocation_id) -> dict
    prune_expired_evidence(db, tenant_id=None) -> int

Portability
-----------
ORM-modeled. Works on PostgreSQL, SQLite, DuckDB, MySQL. Integer PK uses
the same Sequence + variant pattern as kya_invocations.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from sqlalchemy import (
        JSON,
        BigInteger,
        Boolean,
        DateTime,
        Index,
        Integer,
        Sequence,
        String,
        func,
        select,
        text,
    )
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    _HAS_SQLALCHEMY = True
except ImportError:  # pragma: no cover
    _HAS_SQLALCHEMY = False


logger = logging.getLogger(__name__)


_PG_SCHEMA = os.getenv("KYA_VERSIONS_SCHEMA", "prov_schema") or None

# Valid evidence kinds — closed set so callers don't invent shapes.
VALID_EVIDENCE_KINDS = {
    "prompt",  # what the agent received
    "response",  # what the agent produced
    "tool_call",  # tool invocation (name + args)
    "tool_result",  # tool's output
    "delegation_message",  # agent-to-agent message
    "hil_decision",  # human approval/rejection
    "system_message",  # framework/system context
}

# Retention defaults per regime (days). Used when caller doesn't supply
# `retention_days` and `data_classes` triggers a regulated regime.
_REGIME_RETENTION_DAYS = {
    "gdpr": 2190,  # 6 years (GDPR Art. 30 ROPA retention)
    "nydfs_500": 1825,  # 5 years
    "hipaa": 2190,  # 6 years
    "sox": 2555,  # 7 years
    "pci_dss": 365,  # 1 year (audit logs minimum)
    "eu_ai_act": 2555,  # 7 years (Art. 12 logs retention for high-risk)
}

# Data-class → applicable regimes mapping. Drives default retention when
# the caller passes data_classes but not retention_days.
_DATA_CLASS_REGIMES = {
    "pii": ["gdpr"],
    "phi": ["hipaa"],
    "pci": ["pci_dss"],
    "financial": ["sox", "nydfs_500"],
    "regulated": ["gdpr", "nydfs_500", "hipaa"],
    "secret": ["gdpr"],  # treat unknown-sensitive as GDPR-equivalent
    "confidential": ["gdpr"],
}


def _require_sqlalchemy() -> None:
    if not _HAS_SQLALCHEMY:
        raise RuntimeError(
            "kya.evidence requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


# ── Signing key management ──────────────────────────────────────────


_DEV_KEY_WARNING_LOGGED = False


def _get_signing_key() -> tuple[bytes, str]:
    """Return (key_bytes, key_id). Resolution order:

    1. **Pluggable provider** — when `KYA_EVIDENCE_KEY_PROVIDER` is set to
       an import path (e.g., `kya.providers.aws_kms:get_key`), import and
       call it: `provider() -> (bytes, str)`. Lets production deployments
       drop in AWS KMS / GCP Cloud KMS / HashiCorp Vault without touching
       this module's code.
    2. **Env-var key** — `KYA_EVIDENCE_SIGNING_KEY` as base64 (≥16 bytes).
       Convenient for k8s sealed-secret / docker secrets mounts.
    3. **Dev fallback** — process-local random key. Logged warning so
       prod misconfig is obvious.

    Key rotation: each row stores `signing_key_id` so the provider can
    return a different key per call and `verify_chain()` knows which key
    to use for which row — though verify still uses the CURRENT key in
    v1 (rotation support is v2.3).
    """
    global _DEV_KEY_WARNING_LOGGED

    # Path 1 — pluggable provider
    provider_path = os.getenv("KYA_EVIDENCE_KEY_PROVIDER")
    if provider_path:
        try:
            module_name, _, fn_name = provider_path.partition(":")
            if not fn_name:
                raise ValueError(
                    f"KYA_EVIDENCE_KEY_PROVIDER must be 'module:function', got '{provider_path}'"
                )
            import importlib

            mod = importlib.import_module(module_name)
            fn = getattr(mod, fn_name)
            key, key_id = fn()
            if not isinstance(key, bytes) or len(key) < 16:
                raise ValueError("provider returned invalid key (must be ≥16 bytes)")
            return key, str(key_id)
        except Exception as exc:
            logger.warning(
                "[KYA-EVIDENCE] KMS provider %r failed: %s — falling back to env",
                provider_path,
                exc,
            )

    # Path 2 — env-mounted key
    env_val = os.getenv("KYA_EVIDENCE_SIGNING_KEY")
    if env_val:
        try:
            key = base64.b64decode(env_val)
            if len(key) < 16:
                raise ValueError("key too short")
            key_id = os.getenv("KYA_EVIDENCE_SIGNING_KEY_ID", "env-v1")
            return key, key_id
        except Exception as exc:
            logger.warning("[KYA-EVIDENCE] invalid signing key in env: %s", exc)

    # Path 3 — dev fallback (process-local random key)
    if not hasattr(_get_signing_key, "_dev_key"):
        _get_signing_key._dev_key = secrets.token_bytes(32)
    if not _DEV_KEY_WARNING_LOGGED:
        logger.warning(
            "[KYA-EVIDENCE] no KYA_EVIDENCE_KEY_PROVIDER or KYA_EVIDENCE_SIGNING_KEY "
            "set — using process-local dev key. Chain will NOT survive restart. "
            "Mount a real key (KMS provider or env secret) in prod."
        )
        _DEV_KEY_WARNING_LOGGED = True
    return _get_signing_key._dev_key, "dev-local"


# ── Canonicalization + hashing ──────────────────────────────────────


def _canonical_default(o: Any) -> Any:
    """JSON-encoder fallback for non-JSON-serializable values. Wraps with
    a type marker so a `datetime` object and the string of its isoformat
    don't collide on hash (which the prior `default=str` allowed).
    """
    # Common timestamp + uuid cases get explicit type prefixes
    type_name = type(o).__name__
    if hasattr(o, "isoformat"):
        return {"__t__": type_name, "v": o.isoformat()}
    if isinstance(o, (bytes, bytearray)):
        return {"__t__": "bytes", "v": o.hex()}
    if isinstance(o, set):
        return {"__t__": "set", "v": sorted(o, key=repr)}
    # Last resort — repr so the marker still differs from a plain string
    return {"__t__": type_name, "v": repr(o)}


def _canonicalize(payload: Any) -> bytes:
    """Deterministic JSON serialization for hashing.
    sort_keys + separators so identical payloads always hash identically
    regardless of dict ordering or whitespace.

    Non-JSON-serializable values get wrapped via `_canonical_default`
    with a type marker — a datetime object and the string of its
    isoformat now hash DIFFERENTLY (would have collided with the prior
    `default=str` shortcut).
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=_canonical_default,
    ).encode("utf-8")


def _payload_hash(payload: Any) -> str:
    return hashlib.sha256(_canonicalize(payload)).hexdigest()


def _hmac_sign(key: bytes, prev_hash: str, payload_hash: str) -> str:
    msg = f"{prev_hash}|{payload_hash}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# ── ORM model ───────────────────────────────────────────────────────


if _HAS_SQLALCHEMY:
    _JsonType = JSON().with_variant(JSONB(), "postgresql")

    class _Base(DeclarativeBase):
        pass

    _EVIDENCE_SEQ = Sequence("kya_evidence_id_seq")

    class _EvidenceRow(_Base):
        __tablename__ = "kya_evidence"

        # Portable autoincrement — same pattern proven in kya_invocations
        id: Mapped[int] = mapped_column(
            BigInteger().with_variant(Integer(), "sqlite"),
            _EVIDENCE_SEQ,
            primary_key=True,
            autoincrement=True,
        )

        tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
        invocation_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
        correlation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
        parent_invocation_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
        span_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

        # Event taxonomy
        evidence_kind: Mapped[str] = mapped_column(String(40), nullable=False)
        role: Mapped[str | None] = mapped_column(String(20), nullable=True)

        # Payload + integrity
        payload: Mapped[dict] = mapped_column(_JsonType, nullable=False)
        payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
        payload_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

        # Cryptographic chain
        prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
        signed_hash: Mapped[str] = mapped_column(String(64), nullable=False)
        signing_key_id: Mapped[str] = mapped_column(String(40), nullable=False)

        # Event-time vs ingest-time
        occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
        ingested_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        )
        source: Mapped[str | None] = mapped_column(String(40), nullable=True)

        # Compliance + retention
        data_classes: Mapped[list | None] = mapped_column(_JsonType, nullable=True)
        redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
        redaction_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
        retention_until: Mapped[datetime | None] = mapped_column(
            DateTime(timezone=True), nullable=True
        )

        __table_args__ = (
            Index("idx_kya_evidence_tenant_inv", "tenant_id", "invocation_id"),
            Index("idx_kya_evidence_correlation", "correlation_id"),
            Index("idx_kya_evidence_occurred", "occurred_at"),
            Index("idx_kya_evidence_retention", "retention_until"),
        )


def _bind_schema(bind) -> None:
    table = _EvidenceRow.__table__
    target = _PG_SCHEMA if bind.dialect.name == "postgresql" else None
    if table.schema != target:
        table.schema = target


def init_evidence_table(db) -> None:
    """Create kya_evidence + indexes if absent. Idempotent + dialect-aware."""
    _require_sqlalchemy()
    conn = db.connection()
    _bind_schema(conn.engine)
    _Base.metadata.create_all(bind=conn, tables=[_EvidenceRow.__table__])


# ── Write ───────────────────────────────────────────────────────────


def record_evidence(
    db,
    tenant_id: str,
    invocation_id: int,
    evidence_kind: str,
    payload: dict,
    role: str | None = None,
    source: str | None = None,
    occurred_at: datetime | None = None,
    data_classes: list[str] | None = None,
    correlation_id: str | None = None,
    parent_invocation_id: int | None = None,
    span_id: str | None = None,
    retention_days: int | None = None,
) -> int:
    """Record one evidence row. Returns the row's id.

    The row joins the per-(tenant, invocation) HMAC chain — its prev_hash
    is the previous row's signed_hash, ensuring tamper-evidence.

    Args:
        evidence_kind: One of VALID_EVIDENCE_KINDS. Unknown values default
            to 'system_message' with a debug log.
        payload: The actual content — dict that JSON-serializes. For
            prompts/responses: {"content": "..."}. For tool calls:
            {"tool_name": "...", "args": {...}}. Free-form; the
            payload_hash makes the exact bytes auditable.
        retention_days: Override the regime-derived default. If None and
            data_classes intersect with a regulated regime, the
            longest applicable retention window applies.
    """
    if evidence_kind not in VALID_EVIDENCE_KINDS:
        logger.debug("[KYA-EVIDENCE] unknown kind=%s -> 'system_message'", evidence_kind)
        evidence_kind = "system_message"

    _require_sqlalchemy()
    init_evidence_table(db)

    if occurred_at is None:
        occurred_at = datetime.now(timezone.utc)

    # Compute integrity fields
    payload_bytes = _canonicalize(payload)
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    payload_size_bytes = len(payload_bytes)

    # CONCURRENCY: the HMAC chain is intrinsically serial — each row
    # signs prev_hash || payload_hash. Concurrent writers to the SAME
    # invocation_id would all read the same tail and fork the chain.
    # We serialize the read-tail/sign/write triple using:
    #   PostgreSQL: pg_advisory_xact_lock keyed by (tenant, invocation).
    #               Works even when the chain is empty (nothing to FOR UPDATE).
    #   MySQL:      SELECT FOR UPDATE on the existing tail row. Won't
    #               serialize the very first writers to an empty chain
    #               but every subsequent writer is serialized.
    #   SQLite:     uses BEGIN IMMEDIATE / SERIALIZABLE isolation in
    #               practice; documented contract is one-writer-per-
    #               invocation.
    #   DuckDB:     same caveat as SQLite.
    try:
        dialect = db.bind.dialect.name
    except Exception:
        dialect = ""
    if dialect == "postgresql":
        try:
            lock_key_str = f"{tenant_id}:{invocation_id}"
            db.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
                {"k": lock_key_str},
            )
        except Exception:
            pass

    prev_stmt = (
        select(_EvidenceRow.signed_hash)
        .where(_EvidenceRow.tenant_id == tenant_id)
        .where(_EvidenceRow.invocation_id == invocation_id)
        .order_by(_EvidenceRow.id.desc())
        .limit(1)
    )
    if dialect == "mysql":
        try:
            prev_stmt = prev_stmt.with_for_update()
        except Exception:
            pass
    prev_hash = db.execute(prev_stmt).scalar() or ""

    key, key_id = _get_signing_key()
    signed_hash = _hmac_sign(key, prev_hash, payload_hash)

    # Retention computation
    retention_until: datetime | None = None
    if retention_days is not None:
        retention_until = datetime.now(timezone.utc) + timedelta(days=retention_days)
    elif data_classes:
        # Map each data class through _DATA_CLASS_REGIMES → regimes →
        # retention days. Pick the longest applicable retention so the
        # strictest regulator's window wins.
        applicable_days: list[int] = []
        for cls in data_classes:
            cls_lc = (cls or "").lower()
            for regime in _DATA_CLASS_REGIMES.get(cls_lc, []):
                if regime in _REGIME_RETENTION_DAYS:
                    applicable_days.append(_REGIME_RETENTION_DAYS[regime])
        if applicable_days:
            retention_until = datetime.now(timezone.utc) + timedelta(days=max(applicable_days))

    row = _EvidenceRow(
        tenant_id=tenant_id,
        invocation_id=invocation_id,
        correlation_id=correlation_id,
        parent_invocation_id=parent_invocation_id,
        span_id=span_id,
        evidence_kind=evidence_kind,
        role=role,
        payload=payload,
        payload_hash=payload_hash,
        payload_size_bytes=payload_size_bytes,
        prev_hash=prev_hash or None,
        signed_hash=signed_hash,
        signing_key_id=key_id,
        occurred_at=occurred_at,
        source=source,
        data_classes=list(data_classes) if data_classes else None,
        retention_until=retention_until,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    logger.info(
        "[KYA-EVIDENCE] tenant=%s inv=%d kind=%s size=%dB id=%d",
        tenant_id,
        invocation_id,
        evidence_kind,
        payload_size_bytes,
        int(row.id),
    )
    try:
        from . import _emit, telemetry
        telemetry.record_event("record_evidence", kind=evidence_kind)
        if _emit.is_enabled():
            _emit.emit(
                "kya_evidence",
                _emit.safe_row({
                    "id": int(row.id),
                    "tenant_id": tenant_id,
                    "invocation_id": invocation_id,
                    "correlation_id": correlation_id,
                    "parent_invocation_id": parent_invocation_id,
                    "span_id": span_id,
                    "evidence_kind": evidence_kind,
                    "role": role,
                    "payload": payload,
                    "payload_hash": payload_hash,
                    "payload_size_bytes": payload_size_bytes,
                    "prev_hash": prev_hash or None,
                    "signed_hash": signed_hash,
                    "signing_key_id": key_id,
                    "source": source,
                    "data_classes": data_classes,
                    "occurred_at": occurred_at,
                    "retention_until": retention_until,
                }),
            )
    except Exception:
        pass
    return int(row.id)


# ── Read ────────────────────────────────────────────────────────────


def _row_to_dict(row: "_EvidenceRow") -> dict[str, Any]:
    return {
        "id": int(row.id),
        "tenant_id": row.tenant_id,
        "invocation_id": int(row.invocation_id),
        "correlation_id": row.correlation_id,
        "parent_invocation_id": (
            int(row.parent_invocation_id) if row.parent_invocation_id is not None else None
        ),
        "span_id": row.span_id,
        "evidence_kind": row.evidence_kind,
        "role": row.role,
        "payload": row.payload
        if isinstance(row.payload, (dict, list))
        else json.loads(row.payload),
        "payload_hash": row.payload_hash,
        "payload_size_bytes": row.payload_size_bytes,
        "prev_hash": row.prev_hash,
        "signed_hash": row.signed_hash,
        "signing_key_id": row.signing_key_id,
        "occurred_at": _to_iso(row.occurred_at),
        "ingested_at": _to_iso(row.ingested_at),
        "source": row.source,
        "data_classes": row.data_classes,
        "redacted": bool(row.redacted),
        "redaction_reason": row.redaction_reason,
        "retention_until": _to_iso(row.retention_until),
        "ingest_lag_ms": _lag_ms(row.occurred_at, row.ingested_at),
    }


def list_evidence(
    db,
    tenant_id: str,
    invocation_id: int | None = None,
    correlation_id: str | None = None,
    evidence_kind: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return evidence rows ordered by `id` ascending (chain order).

    NOTE on `limit` + chain verification: when `limit` truncates a chain,
    the result is a partial slice. Do NOT pass partial results to
    `verify_chain()` — call verify_chain directly against the
    (tenant_id, invocation_id) pair so it walks the full chain
    server-side without limit-induced gaps.
    """
    _require_sqlalchemy()
    init_evidence_table(db)

    stmt = select(_EvidenceRow).where(_EvidenceRow.tenant_id == tenant_id)
    if invocation_id is not None:
        stmt = stmt.where(_EvidenceRow.invocation_id == invocation_id)
    if correlation_id:
        stmt = stmt.where(_EvidenceRow.correlation_id == correlation_id)
    if evidence_kind:
        stmt = stmt.where(_EvidenceRow.evidence_kind == evidence_kind)
    stmt = stmt.order_by(_EvidenceRow.id.asc()).limit(limit)

    return [_row_to_dict(row) for row in db.execute(stmt).scalars().all()]


def get_evidence(db, tenant_id: str, evidence_id: int) -> dict | None:
    """Fetch one evidence row by id. Tenant-scoped — passing a tenant_id
    that doesn't own the row returns None (no cross-tenant read).
    """
    _require_sqlalchemy()
    init_evidence_table(db)
    stmt = (
        select(_EvidenceRow)
        .where(_EvidenceRow.tenant_id == tenant_id)
        .where(_EvidenceRow.id == evidence_id)
    )
    row = db.execute(stmt).scalar_one_or_none()
    return _row_to_dict(row) if row else None


# ── Tamper-evidence verification ────────────────────────────────────


def verify_chain(db, tenant_id: str, invocation_id: int) -> dict:
    """Walk the (tenant, invocation) chain and recompute every signed_hash.

    Returns:
        {
            "valid": bool,            # True iff every row's hash recomputes
            "broken_at": id | None,   # the first row where chain breaks
            "checked": int,           # rows verified
            "reason": str | None,     # human-readable explanation
        }
    """
    _require_sqlalchemy()
    init_evidence_table(db)

    stmt = (
        select(_EvidenceRow)
        .where(_EvidenceRow.tenant_id == tenant_id)
        .where(_EvidenceRow.invocation_id == invocation_id)
        .order_by(_EvidenceRow.id.asc())
    )
    rows = db.execute(stmt).scalars().all()

    if not rows:
        return {"valid": True, "broken_at": None, "checked": 0, "reason": "empty chain"}

    key, _ = _get_signing_key()
    expected_prev = ""
    for row in rows:
        # Re-derive payload_hash from the stored payload — if a DBA edited
        # the payload, the recomputed hash won't match what's stored.
        recomputed_payload_hash = hashlib.sha256(_canonicalize(row.payload)).hexdigest()
        if recomputed_payload_hash != row.payload_hash:
            return {
                "valid": False,
                "broken_at": int(row.id),
                "checked": int(row.id),
                "reason": "payload_hash mismatch — payload was modified",
            }

        # Verify chain link
        if (row.prev_hash or "") != expected_prev:
            return {
                "valid": False,
                "broken_at": int(row.id),
                "checked": int(row.id),
                "reason": "prev_hash break — earlier row was inserted, deleted, or modified",
            }

        recomputed_signed = _hmac_sign(key, expected_prev, row.payload_hash)
        if recomputed_signed != row.signed_hash:
            return {
                "valid": False,
                "broken_at": int(row.id),
                "checked": int(row.id),
                "reason": "signed_hash mismatch — row was forged or signing key changed",
            }

        expected_prev = row.signed_hash

    return {
        "valid": True,
        "broken_at": None,
        "checked": len(rows),
        "reason": None,
    }


# ── Retention sweep ─────────────────────────────────────────────────


def prune_expired_evidence(db, tenant_id: str | None = None) -> int:
    """Delete evidence rows whose retention_until is in the past.

    Returns the number of rows deleted. Safe to call on a cron.

    NOTE: this is the ONE place we mutate the evidence table. By design,
    retention is the only legitimate delete-path. The chain breaks at the
    pruned row — that's correct behavior (pruned data was approved to
    leave audit scope). The next surviving row records `prev_hash =
    signed_hash of the last pruned row` from the DB before the delete,
    so any FUTURE writes still chain correctly.
    """
    _require_sqlalchemy()
    init_evidence_table(db)
    now = datetime.now(timezone.utc)

    stmt = select(_EvidenceRow).where(_EvidenceRow.retention_until < now)
    if tenant_id:
        stmt = stmt.where(_EvidenceRow.tenant_id == tenant_id)

    rows = db.execute(stmt).scalars().all()
    count = 0
    for row in rows:
        db.delete(row)
        count += 1
    db.commit()
    if count:
        logger.info("[KYA-EVIDENCE] pruned %d expired rows", count)
    return count


# ── Helpers ─────────────────────────────────────────────────────────


def _to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _lag_ms(occurred_at: datetime | None, ingested_at: datetime | None) -> int | None:
    if occurred_at is None or ingested_at is None:
        return None
    occ = occurred_at if occurred_at.tzinfo else occurred_at.replace(tzinfo=timezone.utc)
    ing = ingested_at if ingested_at.tzinfo else ingested_at.replace(tzinfo=timezone.utc)
    return int((ing - occ).total_seconds() * 1000)
