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

Operational notes
-----------------
- Third-party-attestable notarization (Sigstore, RFC 3161 TSA) can be
  layered on top of the HMAC chain by batching a daily root hash to
  the notary of your choice.
- Payload privacy: rows are stored plaintext. For PII at rest, layer
  column-level encryption (PG ``pgcrypto``, MySQL ``AES_ENCRYPT``) at
  the app boundary, or pre-redact via the ``redacted`` +
  ``redaction_reason`` fields before calling record_evidence().
- Concurrency: record_evidence acquires a per-(tenant, invocation)
  lock (PG advisory lock, MySQL ``SELECT FOR UPDATE``, in-process
  mutex for SQLite/DuckDB) so concurrent writers serialize on the
  chain head.

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
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from .canonicals import CANONICAL_EVIDENCE_KINDS as _CANONICAL_EVIDENCE_KINDS
from .canonicals import EVIDENCE_KIND_CHAIN_GENESIS

# ---------------------------------------------------------------------------
# Redaction target surface (record_evidence pre-persist redaction)
# ---------------------------------------------------------------------------
# Payload keys that receive redaction pre-persist. Add sparingly — every
# added key increases audit-trail redaction latency. Kept as a
# module-level constant (no hardcoded literals sprinkled through the
# redaction block) so operators can widen via ``KYA_EVIDENCE_REDACTION_KEYS``
# (CSV) without a code change.
#
# Guardrail: for each target key, redaction fires ONLY when the payload
# value is a dict OR a string. Non-string leaf types (numbers, booleans,
# arrays) pass through unchanged — those don't hold secrets under normal
# payload shapes and touching them would just burn CPU on every write.
_REDACTION_TARGET_KEYS: tuple[str, ...] = (
    "tool_arguments",
    "arguments",  # canonical alias
    "prompt",
    "response",
    "http_body",
    "tool_input",
    "tool_output",
    "input",
    "output",
)

# Nested key paths (dot-separated) that also receive redaction. Same
# dict-or-string guardrail applies at the leaf.
_REDACTION_TARGET_NESTED_PATHS: tuple[str, ...] = (
    "tool_call.arguments",
    "tool_call.input",
    "tool_call.output",
)


def _resolve_redaction_target_keys() -> tuple[str, ...]:
    """Return the effective top-level key allowlist.

    Base allowlist = ``_REDACTION_TARGET_KEYS``. Operators can widen
    (never narrow) via the ``KYA_EVIDENCE_REDACTION_KEYS`` env var, which
    is a comma-separated list of extra keys to include. Whitespace and
    empty entries are ignored. Duplicates are collapsed.
    """
    extra = os.environ.get("KYA_EVIDENCE_REDACTION_KEYS", "")
    if not extra:
        return _REDACTION_TARGET_KEYS
    extras = tuple(k.strip() for k in extra.split(",") if k.strip())
    # preserve base order first, then any new extras (dedup preserving order)
    seen = set(_REDACTION_TARGET_KEYS)
    merged = list(_REDACTION_TARGET_KEYS)
    for k in extras:
        if k not in seen:
            merged.append(k)
            seen.add(k)
    return tuple(merged)

# Per-(tenant, invocation) in-process serialization lock for SQLite +
# DuckDB. PG uses pg_advisory_xact_lock, MySQL uses SELECT FOR UPDATE,
# both of which work cross-process. SQLite and DuckDB have no
# row-level lock primitive, so an in-process lock at least guarantees
# in-process multi-writer safety (the common case under
# gunicorn-style worker pools + ThreadPoolExecutor).
_INPROC_CHAIN_LOCKS: dict[str, threading.Lock] = {}
_INPROC_CHAIN_LOCKS_GUARD = threading.Lock()


def _get_chain_lock(tenant_id: str, invocation_id: int) -> threading.Lock:
    key = f"{tenant_id}:{invocation_id}"
    with _INPROC_CHAIN_LOCKS_GUARD:
        lock = _INPROC_CHAIN_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _INPROC_CHAIN_LOCKS[key] = lock
    return lock

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


_PG_SCHEMA = os.getenv("KYA_VERSIONS_SCHEMA") or None

# Valid evidence kinds — mutable set (initialized from
# ``CANONICAL_EVIDENCE_KINDS``) so downstream plugins can ``.add()``
# domain-specific kinds at import time.
VALID_EVIDENCE_KINDS: set[str] = set(_CANONICAL_EVIDENCE_KINDS)

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

    # Path 3 — dev fallback (process-local random key).
    #
    # key_id is derived from a fingerprint of the key bytes
    # (``dev-local-<sha256-prefix>``) so DIFFERENT worker processes get
    # DIFFERENT key_ids even though both fall through to this path.
    # The handoff-VC (and any other) verify path's key-rotation guard
    # then correctly detects the mismatch and returns UNVERIFIABLE with
    # a clear "signed under key_id=X but current is Y" reason —
    # replacing the misleading TAMPERED signal that dogfood-2 observed
    # when verify requests round-robined across uvicorn workers that
    # each held a distinct per-process ``_dev_key``.
    #
    # The value STAYS stable within a single process (fingerprint of
    # the cached key bytes), so single-worker dev / test flows verify
    # exactly as before. Downstream callers that used to compare
    # ``key_id == "dev-local"`` now use ``key_id.startswith("dev-local")``.
    if not hasattr(_get_signing_key, "_dev_key"):
        _get_signing_key._dev_key = secrets.token_bytes(32)
    if not _DEV_KEY_WARNING_LOGGED:
        logger.warning(
            "[KYA-EVIDENCE] no KYA_EVIDENCE_KEY_PROVIDER or KYA_EVIDENCE_SIGNING_KEY "
            "set — using process-local dev key. Chain will NOT survive restart "
            "AND cross-worker verifies WILL flip to UNVERIFIABLE (different "
            "workers = different fingerprints). Mount a real key (KMS provider "
            "or env secret) in prod."
        )
        _DEV_KEY_WARNING_LOGGED = True
    _fp = hashlib.sha256(_get_signing_key._dev_key).hexdigest()[:8]
    return _get_signing_key._dev_key, f"dev-local-{_fp}"


# ── Canonicalization + hashing ──────────────────────────────────────


def _canonical_default(o: Any) -> Any:
    """JSON-encoder fallback for non-JSON-serializable values. Wraps with
    a type marker so a `datetime` object and the string of its isoformat
    don't collide on hash (which the prior `default=str` allowed).

    Normative wire-level `__t__` values per docs/specs/kyp/v0.1:
    `datetime`, `date`, `time`, `UUID`, `bytes`, `set`. The `v` encoding
    for each is the language-agnostic form (canonical hyphenated UUID,
    not `repr()`; hex for bytes; sorted list for sets).
    """
    import uuid as _uuid

    type_name = type(o).__name__
    if isinstance(o, _uuid.UUID):
        # Canonical hyphenated lowercase form — portable across
        # languages. NOT repr() (which is Python-specific).
        return {"__t__": "UUID", "v": str(o)}
    if hasattr(o, "isoformat"):
        return {"__t__": type_name, "v": o.isoformat()}
    if isinstance(o, (bytes, bytearray)):
        return {"__t__": "bytes", "v": o.hex()}
    if isinstance(o, set):
        return {"__t__": "set", "v": sorted(o, key=repr)}
    # Last resort — repr so the marker still differs from a plain
    # string. Out-of-spec for v0.1; flag in a future revision.
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


def _counter_signature(
    key: bytes, tenant_id: str, invocation_id: int, count: int,
) -> str:
    """HMAC signature over the (tenant, invocation, count) tuple.

    The signature binds the row-count anchor to the signing key so an
    attacker with UPDATE on ``kya_invocations`` who deletes evidence
    rows AND rewrites ``evidence_row_count`` to match still cannot
    forge a signature without the key. Uses the same
    ``_canonicalize`` + ``_hmac_sign`` primitives that the per-row
    HMAC chain uses so the crypto surface stays uniform.
    """
    payload = {
        "tenant_id": tenant_id,
        "invocation_id": int(invocation_id),
        "evidence_row_count": int(count),
    }
    canonical_hash = hashlib.sha256(_canonicalize(payload)).hexdigest()
    return _hmac_sign(key, "", canonical_hash)


def _bump_counter_and_resign(
    db, tenant_id: str, invocation_id: int, key: bytes,
) -> None:
    """Increment ``evidence_row_count`` and refresh the counter signature.

    Must be called from within a SAVEPOINT — a legacy schema missing
    ``evidence_row_count_signature`` will raise on the UPDATE, and the
    caller relies on SAVEPOINT rollback to preserve fail-soft
    semantics for the row insert.

    Two statements inside the same SAVEPOINT — portable across every
    supported dialect (postgres RETURNING would work on PG only,
    forcing per-dialect branches for no correctness gain):
    1. INCREMENT the counter.
    2. SELECT the new counter value and UPDATE the signature.
    Genesis and caller rows share this path, so signing key
    resolution stays consistent for both.
    """
    db.execute(text(
        "UPDATE kya_invocations "
        "SET evidence_row_count = COALESCE(evidence_row_count, 0) + 1 "
        "WHERE tenant_id = :t AND id = :i"
    ), {"t": tenant_id, "i": invocation_id})
    new_count = db.execute(text(
        "SELECT evidence_row_count FROM kya_invocations "
        "WHERE tenant_id = :t AND id = :i"
    ), {"t": tenant_id, "i": invocation_id}).scalar()
    if new_count is None:
        # No matching parent invocation row (evidence-only ingest
        # paths, or legacy schema without evidence_row_count). Nothing
        # to sign; the row-count-only anchor semantics catch these.
        return
    signature = _counter_signature(
        key, tenant_id, int(invocation_id), int(new_count),
    )
    db.execute(text(
        "UPDATE kya_invocations "
        "SET evidence_row_count_signature = :s "
        "WHERE tenant_id = :t AND id = :i"
    ), {"s": signature, "t": tenant_id, "i": invocation_id})


# ── ORM model ───────────────────────────────────────────────────────


if _HAS_SQLALCHEMY:
    _JsonType = JSON().with_variant(JSONB(), "postgresql")

    # MySQL's DATETIME defaults to 0 fractional-seconds precision, which
    # collapses sub-second event ordering — the evidence chain relies on
    # deterministic time-ordering, and the replay evidence-slice bound
    # ``occurred_at <= :ts`` fails when the write time and query time
    # collide on the same second. DATETIME(6) fixes this at the column
    # level. Imported here so the ORM column definition below can request
    # it via with_variant().
    try:
        from sqlalchemy.dialects.mysql import DATETIME as _MYSQLDateTime
        _MYSQL_DATETIME_MICROSEC = _MYSQLDateTime(fsp=6, timezone=True)
    except Exception:
        # Fall back to plain DateTime — precision loss, but at least
        # nothing breaks at import if a future SQLAlchemy renames things.
        _MYSQL_DATETIME_MICROSEC = DateTime(timezone=True)

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

        # Evaluator attribution for VERDICT-PRODUCING evidence rows.
        # Populated from ``Verdict.rich["evaluator_name"]``
        # by the gateway/ingest evidence writers so audit queries can
        # answer "which evaluator produced this verdict" without walking
        # back through the payload. Nullable — non-verdict evidence kinds
        # (system_message, prompt/response, runtime_*, delegation) leave
        # this ``None``. Column length matches the ``VerdictResult.
        # evaluator_name`` bounded string.
        evaluator_name: Mapped[str | None] = mapped_column(
            String(64), nullable=True,
        )

        # Payload + integrity
        payload: Mapped[dict] = mapped_column(_JsonType, nullable=False)
        payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
        payload_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

        # Cryptographic chain
        prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
        signed_hash: Mapped[str] = mapped_column(String(64), nullable=False)
        signing_key_id: Mapped[str] = mapped_column(String(40), nullable=False)

        # Event-time vs ingest-time — DATETIME(6) on MySQL to preserve
        # microsecond precision. SQLAlchemy's default DateTime(timezone=True)
        # maps to plain DATETIME (0 µs precision) on MySQL, which causes
        # sub-second boundary rows in the evidence chain to collide on the
        # same second. Replay's evidence-slice query then can't
        # distinguish "row written 5 µs ago" from "row written 1s ago",
        # inflating the slice count on MySQL. Fix: request 6-digit
        # fractional-second precision explicitly, which MySQL 5.6+
        # honors and other dialects ignore.
        occurred_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True).with_variant(
                _MYSQL_DATETIME_MICROSEC, "mysql",
            ),
            nullable=False,
        )
        ingested_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True).with_variant(
                _MYSQL_DATETIME_MICROSEC, "mysql",
            ),
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
            # Audit queries filter by evaluator to
            # answer "which evaluator produced this verdict slice".
            # Sparse index — most rows leave evaluator_name NULL.
            Index("idx_kya_evidence_evaluator", "evaluator_name"),
        )


def _bind_schema(bind) -> None:
    table = _EvidenceRow.__table__
    target = _PG_SCHEMA if bind.dialect.name == "postgresql" else None
    if table.schema != target:
        table.schema = target


def init_evidence_table(db) -> None:
    """Create kya_evidence + indexes if absent. Idempotent + dialect-aware.

    Additionally ensures the ``evaluator_name`` column exists on
    pre-existing dev DBs whose original ``CREATE TABLE`` ran before
    the column was added. ``create_all`` is idempotent for TABLES but does NOT
    add COLUMNS to existing tables. Rather than force a schema migration
    (pre-customer stage — no live data to migrate), we probe the live
    schema and issue a single additive ``ALTER TABLE`` when the column
    is missing. Nullable + no default so the ALTER is safe on any dialect.
    """
    _require_sqlalchemy()
    conn = db.connection()
    _bind_schema(conn.engine)
    _Base.metadata.create_all(bind=conn, tables=[_EvidenceRow.__table__])
    # Dev-DB ALTER probe for the evaluator_name column. Wrapped outer try/except
    # because test-only session stubs (see test_gateway_server._Session)
    # don't implement the full SQLAlchemy Connection interface required
    # by sqlalchemy.inspect(); any AttributeError from the probe on a
    # test stub is expected — the WARN inside logs it but must not
    # break init_evidence_table (which is called from live request
    # paths, not just fresh-DB setup).
    try:
        _ensure_evaluator_name_column(conn)
    except AttributeError as exc:
        logger.debug(
            "[KYA-EVIDENCE] evaluator_name column probe skipped on "
            "test/stub connection: %s", exc,
        )


# One-shot per-engine probe cache for the evaluator_name column ALTER.
# init_evidence_table
# is idempotent + hot; without caching we'd probe information_schema on
# every write. Keyed by the SQLAlchemy engine URL (immutable within a
# process) so the probe fires at most once per (URL, dialect) tuple.
_EVALUATOR_COLUMN_PROBED: set[str] = set()


def _ensure_evaluator_name_column(conn) -> None:
    """Best-effort ``ALTER TABLE`` to add ``evaluator_name`` on older
    schemas. Silent no-op when the column is already present. Logs at
    WARN when the probe or ALTER raises so ops sees the signal.
    """
    try:
        url_key = str(conn.engine.url)
    except Exception:
        url_key = ""
    if url_key and url_key in _EVALUATOR_COLUMN_PROBED:
        return
    try:
        dialect = conn.dialect.name
        table_name = _EvidenceRow.__tablename__
        # SQLAlchemy inspect gives us a portable column list.
        from sqlalchemy import inspect as _inspect
        inspector = _inspect(conn)
        existing_cols = {c["name"] for c in inspector.get_columns(table_name)}
        if "evaluator_name" not in existing_cols:
            # Additive + nullable — safe on every supported dialect.
            # Bounded VARCHAR mirrors the ORM column definition; SQLite
            # treats VARCHAR(n) as TEXT so the length is a no-op there.
            conn.execute(text(
                f"ALTER TABLE {table_name} "
                "ADD COLUMN evaluator_name VARCHAR(64) NULL"
            ))
            logger.warning(
                "[KYA-EVIDENCE] added evaluator_name column to %s on "
                "dialect=%s (dev-DB backfill). Pre-existing rows leave "
                "the value NULL — expected during dev-DB upgrade.",
                table_name, dialect,
            )
    except Exception as exc:
        # Never fail a write path because a probe failed. Loud WARN so
        # ops sees the gap; subsequent writes will attempt to insert
        # None into a missing column and SQLAlchemy will raise there
        # (surfacing the deployment misconfig at the right site).
        logger.warning(
            "[KYA-EVIDENCE] evaluator_name column probe failed: %s "
            "— audit-slice queries filtering by evaluator_name may "
            "return incomplete data until the schema is upgraded.", exc,
        )
    finally:
        if url_key:
            _EVALUATOR_COLUMN_PROBED.add(url_key)


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
    evaluator_name: str | None = None,
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
        evaluator_name: the name of the ``kya.PolicyEvaluator`` whose
            ``VerdictResult`` produced this row. Verdict-producing
            callers pull this from ``Verdict.rich["evaluator_name"]``
            (populated by the attribution helpers in
            ``kya_gateway/policy_pipeline.py``).
            Non-verdict evidence kinds (system_message, prompt/response,
            runtime_*, delegation) leave this ``None`` — the row simply
            won't participate in evaluator-slice audit queries.
    """
    if evidence_kind not in VALID_EVIDENCE_KINDS:
        logger.debug("[KYA-EVIDENCE] unknown kind=%s -> 'system_message'", evidence_kind)
        evidence_kind = "system_message"

    # SECRET-LEAK REDACTION (2026-08-20) — apply the installed
    # ``RedactionHook`` inside ``record_evidence`` itself so every
    # caller (gateway, Pro plugins, third-party integrations) gets
    # redaction for free. Before this, only the gateway's
    # ``_record_verdict_evidence`` called the hook; every other
    # caller silently persisted raw secrets. Bug-prone-by-convention.
    #
    # Scoped redaction — rewrite an explicit allowlist of well-known
    # secret-bearing payload keys (``_REDACTION_TARGET_KEYS``) plus a
    # short list of nested paths (``_REDACTION_TARGET_NESTED_PATHS``).
    # Rewriting arbitrary payload fields would alter the signed
    # evidence chain in unexpected ways for callers that put non-secret
    # dicts under other keys. The allowlist can be widened without a
    # code change via ``KYA_EVIDENCE_REDACTION_KEYS`` (CSV) for
    # customers with custom payload shapes.
    #
    # Design guardrail: for each target, redact ONLY if the value is a
    # dict OR a string. Non-string leaf types (numbers, booleans,
    # arrays) pass through unchanged.
    #
    # Fail-soft — a raise from the hook (e.g. Presidio model glitch)
    # MUST NOT drop the evidence write. Emit WARN + fall through to
    # the raw payload so the audit chain is never silently blank.
    if isinstance(payload, dict):
        try:
            _top_keys = _resolve_redaction_target_keys()
            _nested_paths = _REDACTION_TARGET_NESTED_PATHS
            # Cheap pre-check: skip the whole block (no hook import, no
            # dict copy) when nothing on the payload is in-scope.
            _has_top = any(k in payload for k in _top_keys)
            _has_nested = False
            if not _has_top:
                for _path in _nested_paths:
                    _head = _path.split(".", 1)[0]
                    if isinstance(payload.get(_head), dict):
                        _has_nested = True
                        break
            if _has_top or _has_nested:
                from ._redaction_hooks import get_redaction_hook

                _hook = get_redaction_hook()
                _new_payload = dict(payload)

                # Top-level allowlist
                for _k in _top_keys:
                    if _k not in _new_payload:
                        continue
                    _v = _new_payload[_k]
                    if isinstance(_v, dict):
                        _new_payload[_k] = _hook.redact_attrs(_v)
                    elif isinstance(_v, str):
                        # Wrap the bare string in a single-key attrs bag
                        # so the hook contract (dict-in / dict-out)
                        # applies uniformly; unwrap after.
                        _redacted = _hook.redact_attrs({_k: _v})
                        _new_payload[_k] = _redacted.get(_k, _v)
                    # else: number/bool/list/None — pass through per guardrail

                # Nested dot-paths (e.g. tool_call.arguments)
                #
                # IMPORTANT — walk ``_new_payload`` (NOT ``payload``) so
                # redactions performed by earlier paths in this loop are
                # preserved. Re-walking ``payload`` and re-``dict(_src_child)``
                # would overwrite prior copies with a fresh copy of the
                # original, discarding earlier redactions when multiple
                # nested paths share a parent (e.g. tool_call.arguments +
                # tool_call.input both share the ``tool_call`` parent).
                #
                # To keep the caller's payload immutable, we copy-on-write
                # any parent dict the first time we descend into it
                # (detected by identity check against the source dict).
                for _path in _nested_paths:
                    _parts = _path.split(".")
                    _cursor_new = _new_payload
                    _cursor_src = payload
                    _ok = True
                    for _part in _parts[:-1]:
                        _src_child = _cursor_src.get(_part) if isinstance(_cursor_src, dict) else None
                        if not isinstance(_src_child, dict):
                            _ok = False
                            break
                        _cur_child = _cursor_new.get(_part) if isinstance(_cursor_new, dict) else None
                        # Copy-on-write when the child in _new_payload
                        # is still the source dict (identity match) or
                        # missing/wrong type. Otherwise, keep the prior
                        # copy so earlier redactions on the same parent
                        # survive this iteration.
                        if _cur_child is _src_child or not isinstance(_cur_child, dict):
                            _cur_child = dict(_src_child)
                            _cursor_new[_part] = _cur_child
                        _cursor_new = _cur_child
                        _cursor_src = _src_child
                    if not _ok:
                        continue
                    _leaf = _parts[-1]
                    if _leaf not in _cursor_new:
                        continue
                    _lv = _cursor_new[_leaf]
                    if isinstance(_lv, dict):
                        _cursor_new[_leaf] = _hook.redact_attrs(_lv)
                    elif isinstance(_lv, str):
                        _redacted = _hook.redact_attrs({_leaf: _lv})
                        _cursor_new[_leaf] = _redacted.get(_leaf, _lv)
                    # else: pass through per guardrail

                payload = _new_payload
        except Exception as _hook_exc:
            logger.warning(
                "[KYA-EVIDENCE] redaction hook raised: %s "
                "— proceeding with unredacted payload",
                _hook_exc,
            )

    # Payload size cap + rate limit. Both off-by-default;
    # only fire when operators have set the corresponding env vars.
    # Cap check is HARD (raises PayloadTooLargeError) because writing
    # an oversize row corrupts dashboards downstream. Rate limit is
    # soft (blocks up to 5s) for batch ergonomics — switch to hard
    # at the HTTP layer if you want 429s. Both modules emit
    # security events to kya_principal_trust + Valkey when violations
    # fire — log-only when DB session not threaded through.
    try:
        from .payload_caps import check_payload_size
        check_payload_size(
            payload, primitive="evidence",
            tenant_id=tenant_id, db=db,
            # record_evidence doesn't have direct principal info;
            # the invocation_id maps to one but we'd need a lookup.
            # Log-only attribution is acceptable for v1.
        )
    except Exception:
        # PayloadTooLargeError + TypeError propagate; other failures
        # in the size-check path are caller bugs we want to surface.
        raise
    try:
        from .rate_limit import maybe_rate_limit
        maybe_rate_limit(
            tenant_id, "record_evidence", db=db)
    except Exception as exc:
        # Fail-soft contract — rate-limit module surfaces its own
        # errors only in "hard" mode; here we use soft default so
        # an exception means something unexpected. Log + proceed.
        logger.debug("[KYA-EVIDENCE] rate-limit check raised: %s", exc)

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
    _inproc_lock: threading.Lock | None = None
    if dialect in ("sqlite", "duckdb"):
        # SQLite/DuckDB lack a row-level lock primitive. PG's advisory
        # lock and MySQL's SELECT FOR UPDATE handle cross-process
        # serialization; for SQLite/DuckDB we serialize in-process via
        # a per-(tenant, invocation) Python lock. This catches the
        # common deployment shape (multi-threaded worker pool in one
        # process). Cross-process multi-writer on SQLite/DuckDB
        # remains the documented "single-writer-per-invocation
        # contract" — true row-level locks would require a sidecar
        # advisory-lock service or a swap to PG/MySQL.
        _inproc_lock = _get_chain_lock(tenant_id, invocation_id)
        _inproc_lock.acquire()

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

    # Auto-insert the genesis anchor row on first write to any
    # (tenant, invocation) chain. The genesis row lets verify_chain
    # detect head-truncation: an attacker who deletes rows starting
    # from position 0 leaves a chain whose first surviving row is no
    # longer a genesis, which verify_chain flags. Skipped when the
    # caller is explicitly writing a genesis row itself (e.g. tests
    # or an ingest path that constructs its own anchor).
    if prev_hash == "" and evidence_kind != EVIDENCE_KIND_CHAIN_GENESIS:
        genesis_payload = {
            "tenant_id": tenant_id,
            "invocation_id": invocation_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "chain_version": 1,
        }
        genesis_payload_bytes = _canonicalize(genesis_payload)
        genesis_payload_hash = hashlib.sha256(genesis_payload_bytes).hexdigest()
        genesis_signed = _hmac_sign(key, "", genesis_payload_hash)
        genesis_row = _EvidenceRow(
            tenant_id=tenant_id,
            invocation_id=invocation_id,
            correlation_id=correlation_id,
            parent_invocation_id=parent_invocation_id,
            span_id=span_id,
            evidence_kind=EVIDENCE_KIND_CHAIN_GENESIS,
            role=None,
            payload=genesis_payload,
            payload_hash=genesis_payload_hash,
            payload_size_bytes=len(genesis_payload_bytes),
            prev_hash=None,
            signed_hash=genesis_signed,
            signing_key_id=key_id,
            occurred_at=datetime.now(timezone.utc),
            source=None,
            data_classes=None,
            retention_until=None,
            evaluator_name=None,
        )
        db.add(genesis_row)
        # Best-effort counter bump for the genesis row. The UPDATE lives
        # inside a SAVEPOINT so a missing kya_invocations table or a
        # legacy schema without evidence_row_count rolls back only the
        # counter bump, not the row insert. Missing parent invocation
        # row is expected in some ingest paths — degrades to legacy
        # verify semantics via the NULL counter path.
        #
        # Also refreshes the counter-forgery signature over the new
        # counter value in the SAME SAVEPOINT so an attacker cannot
        # observe an intermediate rows-without-signature (or
        # counter-without-matching-signature) state.
        try:
            with db.begin_nested():
                _bump_counter_and_resign(
                    db, tenant_id, invocation_id, key,
                )
        except Exception as exc:
            logger.debug("[KYA-EVIDENCE] genesis counter bump skipped: %s", exc)
        # Single commit publishes the genesis row AND the counter bump
        # atomically — a concurrent verify_chain reader can never see
        # rows-without-counter (false-positive tamper).
        db.commit()
        db.refresh(genesis_row)
        # The caller's row now chains off the just-inserted genesis.
        prev_hash = genesis_signed

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
        # Evaluator attribution for VERDICT-PRODUCING rows.
        # ``None`` for non-verdict evidence kinds (fine — the
        # column is nullable + the audit-slice query filters
        # ``WHERE evaluator_name IS NOT NULL``).
        evaluator_name=evaluator_name,
    )
    try:
        db.add(row)
        # Counter bump lives inside a SAVEPOINT so it can fail-soft
        # (missing table, legacy schema, missing parent row) without
        # rolling back the row insert. The single outer commit
        # publishes row + counter + signature atomically — a concurrent
        # verify_chain reader never sees a rows-without-counter (or
        # counter-without-matching-signature) false-positive.
        try:
            with db.begin_nested():
                _bump_counter_and_resign(
                    db, tenant_id, invocation_id, key,
                )
        except Exception as exc:
            logger.debug("[KYA-EVIDENCE] counter bump skipped: %s", exc)
        db.commit()
        db.refresh(row)
    finally:
        if _inproc_lock is not None:
            _inproc_lock.release()

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
                    "evaluator_name": evaluator_name,
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
        # Evaluator attribution surfaced on read.
        # ``None`` for rows written before the evaluator_name column
        # existed AND for non-verdict evidence kinds.
        "evaluator_name": row.evaluator_name,
    }


def list_evidence(
    db,
    tenant_id: str,
    invocation_id: int | None = None,
    correlation_id: str | None = None,
    evidence_kind: str | None = None,
    since_ts: datetime | None = None,
    until_ts: datetime | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return evidence rows ordered by `id` ascending (chain order).

    NOTE on `limit` + chain verification: when `limit` truncates a chain,
    the result is a partial slice. Do NOT pass partial results to
    `verify_chain()` — call verify_chain directly against the
    (tenant_id, invocation_id) pair so it walks the full chain
    server-side without limit-induced gaps.

    NOTE on time window: ``since_ts <= occurred_at < until_ts``
    (half-open). When supplied, rows outside the window are
    excluded server-side. The chain itself is still ordered by
    ``id ASC`` so callers receive the chain in canonical order
    within the window. ``verify_chain()`` always walks the FULL
    chain regardless of window.
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
    if since_ts is not None:
        stmt = stmt.where(_EvidenceRow.occurred_at >= since_ts)
    if until_ts is not None:
        stmt = stmt.where(_EvidenceRow.occurred_at < until_ts)
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

    Three independent tamper anchors guard the chain:

    1. **Row-count anchor** — ``kya_invocations.evidence_row_count`` is
       incremented on every successful ``record_evidence`` call.
       verify_chain compares that counter against the number of rows
       actually present. A mismatch means rows were deleted from the
       tail (or the entire chain wiped) even though the surviving rows
       still HMAC-verify against each other.
    2. **Counter-signature anchor** —
       ``kya_invocations.evidence_row_count_signature`` is an HMAC over
       the current row-count value. Blocks counter forgery: an
       attacker with UPDATE on ``kya_invocations`` who deletes evidence
       rows AND rewrites ``evidence_row_count`` to match cannot also
       forge a signature without the signing key. Checked BEFORE the
       row-count comparison so counter forgery gets the specific reason
       string.
    3. **Genesis anchor** — ``record_evidence`` auto-inserts a
       ``chain_genesis`` row on first write. verify_chain requires it
       to still be at position 0. An attacker who deletes rows starting
       from the head (including the genesis) leaves a chain whose
       first surviving row is no longer ``chain_genesis``.

    Legacy chains (rows written before any anchor existed) leave
    ``evidence_row_count`` NULL and have no genesis row. Pre-signature
    chains (counter set but signature NULL) also fall back to the
    row-count-only semantics as a migration bridge — retroactively
    signing them would require the signing key to have been consistent
    between the original counter bump and now, which is not guaranteed.

    Returns:
        {
            "valid": bool,            # True iff every row's hash recomputes
            "broken_at": id | None,   # the first row where chain breaks
            "checked": int,           # rows verified
            "reason": str | None,     # human-readable explanation
            "expected_count": int | None,  # value from evidence_row_count
                                           # (None for legacy chains)
            "expected_count_signature_verified": bool | None,
                # True iff a signature was present AND verified.
                # False iff a signature was expected but missing (NULL
                # column = tampering post-migration) OR present and
                # invalid (counter was rewritten). None only when the
                # row has no count anchor at all (evidence-only ingest
                # path or fresh row that never went through the bump).
        }
    """
    _require_sqlalchemy()
    init_evidence_table(db)

    # Load the row-count anchor + its signature. Missing invocation
    # row OR NULL columns both resolve to ``expected_count = None`` /
    # ``expected_count_signature = None`` (legacy or pre-signature
    # chain — fall back to hash-walk-only or row-count-only semantics
    # respectively).
    expected_count: int | None = None
    expected_count_signature: str | None = None
    try:
        anchor_row = db.execute(
            text(
                "SELECT evidence_row_count, evidence_row_count_signature "
                "FROM kya_invocations "
                "WHERE tenant_id = :t AND id = :i"
            ),
            {"t": tenant_id, "i": invocation_id},
        ).first()
        if anchor_row is not None:
            if anchor_row[0] is not None:
                expected_count = int(anchor_row[0])
            if anchor_row[1] is not None:
                expected_count_signature = str(anchor_row[1])
    except Exception as exc:
        # Column missing on a very old schema, or invocations table
        # absent (evidence-only fixtures). Silent fall-through to
        # legacy semantics. Retry with the older single-column SELECT
        # so upgraded-mid-flight databases (row_count column added,
        # signature column not yet ALTERed) still surface the row-count
        # anchor rather than falling all the way back to hash-walk.
        logger.debug(
            "[KYA-EVIDENCE] full anchor SELECT unavailable, retrying "
            "row-count-only: %s", exc,
        )
        try:
            anchor = db.execute(
                text(
                    "SELECT evidence_row_count FROM kya_invocations "
                    "WHERE tenant_id = :t AND id = :i"
                ),
                {"t": tenant_id, "i": invocation_id},
            ).scalar()
            if anchor is not None:
                expected_count = int(anchor)
        except Exception as exc2:
            logger.debug(
                "[KYA-EVIDENCE] row-count anchor unavailable: %s", exc2,
            )

    # Counter-signature verification MUST run BEFORE the row-count
    # comparison so counter-forgery attempts get attributed with the
    # specific reason string rather than the generic count-mismatch
    # message. Fail-closed on NULL signature when a count is present —
    # the reconciler backfills all pre-existing 0.5.2 rows at boot, so
    # post-migration any NULL signature on a row with a non-NULL count
    # is unambiguous tampering (attacker nulled the column). Rows with
    # a NULL count (never anchored, or evidence-only ingest paths)
    # continue to fall through to the pre-anchor hash-walk semantics.
    expected_count_signature_verified: bool | None = None
    if expected_count is not None:
        if expected_count_signature is None:
            return {
                "valid": False,
                "broken_at": None,
                "checked": 0,
                "reason": (
                    "evidence_row_count signature missing — counter "
                    "column was nulled or backfill incomplete"
                ),
                "expected_count": expected_count,
                "expected_count_signature_verified": False,
            }
        _key_for_sig, _ = _get_signing_key()
        recomputed = _counter_signature(
            _key_for_sig, tenant_id, invocation_id, expected_count,
        )
        if not hmac.compare_digest(recomputed, expected_count_signature):
            return {
                "valid": False,
                "broken_at": None,
                "checked": 0,
                "reason": (
                    "evidence_row_count signature invalid — "
                    "counter was rewritten"
                ),
                "expected_count": expected_count,
                "expected_count_signature_verified": False,
            }
        expected_count_signature_verified = True

    stmt = (
        select(_EvidenceRow)
        .where(_EvidenceRow.tenant_id == tenant_id)
        .where(_EvidenceRow.invocation_id == invocation_id)
        .order_by(_EvidenceRow.id.asc())
    )
    rows = db.execute(stmt).scalars().all()

    if not rows:
        if expected_count is None or expected_count == 0:
            # Truly empty (never written) OR legacy chain that was
            # legitimately pruned to zero. Cannot distinguish from
            # a wipe without the anchor — preserve legacy semantics.
            return {
                "valid": True,
                "broken_at": None,
                "checked": 0,
                "reason": "empty chain",
                "expected_count": expected_count,
                "expected_count_signature_verified": (
                    expected_count_signature_verified
                ),
            }
        return {
            "valid": False,
            "broken_at": None,
            "checked": 0,
            "reason": (
                f"row count mismatch: expected {expected_count}, "
                f"found 0 — full chain wipe detected"
            ),
            "expected_count": expected_count,
            "expected_count_signature_verified": (
                expected_count_signature_verified
            ),
        }

    # Row-count check — only meaningful for post-anchor chains.
    if expected_count is not None and len(rows) != expected_count:
        return {
            "valid": False,
            "broken_at": None,
            "checked": len(rows),
            "reason": (
                f"row count mismatch: expected {expected_count}, "
                f"found {len(rows)} — evidence rows deleted"
            ),
            "expected_count": expected_count,
            "expected_count_signature_verified": (
                expected_count_signature_verified
            ),
        }

    # Genesis check — only meaningful for post-anchor chains
    # (legacy chains never had a genesis row).
    if (
        expected_count is not None
        and rows[0].evidence_kind != EVIDENCE_KIND_CHAIN_GENESIS
    ):
        return {
            "valid": False,
            "broken_at": int(rows[0].id),
            "checked": 0,
            "reason": "chain missing genesis anchor — head row was deleted",
            "expected_count": expected_count,
            "expected_count_signature_verified": (
                expected_count_signature_verified
            ),
        }

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
                "expected_count": expected_count,
                "expected_count_signature_verified": (
                    expected_count_signature_verified
                ),
            }

        # Verify chain link
        if (row.prev_hash or "") != expected_prev:
            return {
                "valid": False,
                "broken_at": int(row.id),
                "checked": int(row.id),
                "reason": "prev_hash break — earlier row was inserted, deleted, or modified",
                "expected_count": expected_count,
                "expected_count_signature_verified": (
                    expected_count_signature_verified
                ),
            }

        recomputed_signed = _hmac_sign(key, expected_prev, row.payload_hash)
        if recomputed_signed != row.signed_hash:
            return {
                "valid": False,
                "broken_at": int(row.id),
                "checked": int(row.id),
                "reason": "signed_hash mismatch — row was forged or signing key changed",
                "expected_count": expected_count,
                "expected_count_signature_verified": (
                    expected_count_signature_verified
                ),
            }

        expected_prev = row.signed_hash

    return {
        "valid": True,
        "broken_at": None,
        "checked": len(rows),
        "reason": None,
        "expected_count": expected_count,
        "expected_count_signature_verified": (
            expected_count_signature_verified
        ),
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
