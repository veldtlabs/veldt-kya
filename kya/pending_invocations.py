"""kya_pending_invocations — persistence for the HITL resume loop (#101).

The KYA gateway emits HTTP 428 when a policy verdict is
``flag_for_review`` (paper Figure 4 canonical vocab — see
``kya.policy_verdicts.GatewayFlagForReviewHandler`` and the emission
point in ``kya_gateway.server``). Legacy configs using ``require_human``
still route through the alias handler; both flow through this module
identically. Before this module, the 428 response was the end of the
road: the caller received the error, the request body was thrown
away, and any human "approve" click in the dashboard had nowhere to
route.

This module fills that gap. On 428, the gateway writes a row here with
the raw request body + headers + the exact policy config hash active
at emission time. When an approver decides, Pro's dashboard-api reads
this row and replays the paused request through the same ingest path
as a fresh invocation — closing the loop.

Why the gateway (OSS) owns this table
-------------------------------------
The gateway is the only component holding the raw request bytes at the
moment of 428. Pro's dashboard-api ingests TELEMETRY post-hoc; it never
sees the invocation payload. Putting the table in OSS + calling
``create_pending()`` from ``kya_gateway.server`` means the pending row
exists before the 428 response ships. Pro reads the row (same
Postgres, different schema neighbor) via SQLAlchemy in the resume
router — no cross-service handoff needed.

Replay policy versioning (M5)
-----------------------------
``policy_config_hash`` stores a stable hash of the policy config active
at emission. The resume endpoint MUST replay the ORIGINAL policy — a
config change between pause and approve should not retroactively
invalidate the approver's decision. If the current policy would deny
what the approver approved, that's an audit finding for the operator
to reconcile, not a runtime error.

At-rest encryption (M7)
-----------------------
Request bodies routinely contain PII (agent tool inputs, user prompts,
credentials). 24h retention of raw bytes is a Day-1 SOC2 problem.
``request_body_ciphertext`` stores AES-256-GCM-encrypted bytes keyed
by a per-tenant DEK. The DEK envelope lives in Pro
(``kya_pro.dashboard_api._hitl_encryption``) so OSS-only deploys that
lack KMS still function: ``create_pending()`` accepts pre-encrypted
bytes, so OSS just writes what it's given.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from sqlalchemy import text as _sql
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)


# ── Status enum ──────────────────────────────────────────────────────


PendingStatus = Literal["pending", "approved", "denied", "expired", "resumed"]


VALID_STATUSES: frozenset[str] = frozenset({
    "pending", "approved", "denied", "expired", "resumed",
})


DEFAULT_TTL_HOURS = 24
"""Wall-clock TTL for a pending row. Approvers get 24h; after that the
row auto-expires (sweeper flips status to 'expired'). Reasonable
trade-off between "human might be off-shift" and "leaked PII in the
body should not sit around forever."
"""


# ── Views ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PendingInvocation:
    """Read-side view of a kya_pending_invocations row.

    Ciphertext is opaque bytes — decryption happens in Pro's resume
    router (which has access to the DEK). This view carries only what
    OSS callers legitimately need: identity + status + metadata.
    """
    id: str
    tenant_id: str
    agent_key: str
    principal_kind: str
    principal_id: str
    action: str
    original_invocation_id: Optional[int]
    request_body_ciphertext: bytes
    request_headers: dict[str, str]
    policy_config_hash: str
    status: PendingStatus
    submitted_at: datetime
    expires_at: datetime
    decided_at: Optional[datetime]
    decided_by: Optional[str]
    resume_result_evidence_id: Optional[int]


# ── Table creation ──────────────────────────────────────────────────


_ENSURED_ENGINES: set[int] = set()


def ensure_table(engine) -> None:
    """CREATE TABLE IF NOT EXISTS kya_pending_invocations.

    Idempotent + portable across postgres / sqlite / mysql / duckdb.
    Called once per process at gateway boot (see
    ``kya_gateway.server._boot_gateway``). Tracks engines it has
    already-ensured so repeat calls on the hot path are free.
    """
    key = id(engine)
    if key in _ENSURED_ENGINES:
        return
    dialect = engine.dialect.name
    # BLOB is universal enough — postgres BYTEA, mysql BLOB, sqlite BLOB,
    # duckdb BLOB. TIMESTAMP WITH TIME ZONE works on postgres + duckdb;
    # sqlite/mysql accept the same DDL and treat it as their TIMESTAMP.
    body_type = "BYTEA" if dialect == "postgresql" else "BLOB"
    json_type = "JSONB" if dialect == "postgresql" else "TEXT"
    ts_type = "TIMESTAMP WITH TIME ZONE"
    with engine.begin() as conn:
        conn.execute(_sql(f"""
            CREATE TABLE IF NOT EXISTS kya_pending_invocations (
                id VARCHAR(36) PRIMARY KEY,
                tenant_id VARCHAR(36) NOT NULL,
                agent_key VARCHAR(512) NOT NULL,
                principal_kind VARCHAR(20) NOT NULL,
                principal_id VARCHAR(200) NOT NULL,
                action VARCHAR(200) NOT NULL,
                original_invocation_id BIGINT,
                request_body_ciphertext {body_type} NOT NULL,
                request_headers {json_type} NOT NULL,
                policy_config_hash VARCHAR(64) NOT NULL,
                status VARCHAR(16) NOT NULL,
                submitted_at {ts_type} NOT NULL,
                expires_at {ts_type} NOT NULL,
                decided_at {ts_type},
                decided_by VARCHAR(36),
                resume_result_evidence_id BIGINT
            )
        """))
        # Index for the sweeper's expired-row scan + approver-queue
        # list ordered by expires_at ASC (most-urgent first).
        conn.execute(_sql("""
            CREATE INDEX IF NOT EXISTS ix_kya_pending_invocations_status_expires
            ON kya_pending_invocations (status, expires_at)
        """))
        # Per-tenant queries are the common approver-UI shape.
        conn.execute(_sql("""
            CREATE INDEX IF NOT EXISTS ix_kya_pending_invocations_tenant_status
            ON kya_pending_invocations (tenant_id, status)
        """))
    _ENSURED_ENGINES.add(key)


# ── Policy config hashing ───────────────────────────────────────────


def hash_policy_config(config: Any) -> str:
    """Deterministic hash of a policy config object.

    Used to pin the policy version at emission time (M5 replay
    versioning). SHA-256 over a canonical JSON serialization — same
    config yields same hash regardless of dict key order.

    Accepts any JSON-serializable object. Non-serializable inputs
    fall back to ``repr()`` which is not stable across processes but
    is stable enough for a single-worker replay window; ops sees a
    WARNING when this path fires.
    """
    try:
        canonical = json.dumps(config, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        logger.warning(
            "[pending_invocations] policy config not JSON-serializable — "
            "falling back to repr(); replay pinning is process-local only"
        )
        canonical = repr(config)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Writer ───────────────────────────────────────────────────────────


def create_pending(
    engine,
    *,
    tenant_id: str,
    agent_key: str,
    principal_kind: str,
    principal_id: str,
    action: str,
    original_invocation_id: Optional[int],
    request_body_ciphertext: bytes,
    request_headers: dict[str, str],
    policy_config_hash: str,
    now: Optional[datetime] = None,
    ttl: Optional[timedelta] = None,
) -> str:
    """Write a pending row + return its uuid (stamp on the 428 response).

    The gateway calls this immediately before returning the 428
    response so the ``X-Kya-Pending-Id`` header the caller receives
    is guaranteed to resolve on the approver side. On DB write
    failure, ``IntegrityError`` propagates — the gateway MUST NOT
    return a 428 without a stampable pending id.

    Idempotency is not enforced at this layer: each 428 gets its own
    row. If the caller retries the same paused request, a new pending
    row is written; the approval queue shows both. That's correct —
    the approver sees the retries and can decide whether to
    approve-all or approve-one.

    ``request_body_ciphertext`` is opaque bytes at this layer. In
    Pro deployments the gateway calls the Pro-side encryption helper
    before invoking this function; in OSS-only deploys the operator
    is responsible for encrypting before calling (or accepts that
    bodies land plaintext, which is documented as an ops decision).
    """
    ts = now or datetime.now(timezone.utc)
    expiry = ts + (ttl or timedelta(hours=DEFAULT_TTL_HOURS))
    pending_id = str(uuid.uuid4())
    # Compact headers JSON so we don't waste bytes; sort keys so equal
    # headers hash-compare as equal in tests.
    headers_json = json.dumps(request_headers, sort_keys=True, separators=(",", ":"))
    try:
        with engine.begin() as conn:
            conn.execute(_sql("""
                INSERT INTO kya_pending_invocations
                    (id, tenant_id, agent_key, principal_kind, principal_id,
                     action, original_invocation_id, request_body_ciphertext,
                     request_headers, policy_config_hash, status,
                     submitted_at, expires_at)
                VALUES
                    (:id, :tid, :ak, :pk, :pid, :act, :oi, :body,
                     :hdrs, :hash, 'pending', :sub, :exp)
            """), {
                "id": pending_id,
                "tid": tenant_id,
                "ak": agent_key,
                "pk": principal_kind,
                "pid": principal_id,
                "act": action,
                "oi": original_invocation_id,
                "body": request_body_ciphertext,
                "hdrs": headers_json,
                "hash": policy_config_hash,
                "sub": ts,
                "exp": expiry,
            })
    except IntegrityError:
        # UUID collision is essentially impossible (2^122) but the retry
        # is cheap — try once with a fresh id and bail if that also fails.
        pending_id = str(uuid.uuid4())
        with engine.begin() as conn:
            conn.execute(_sql("""
                INSERT INTO kya_pending_invocations
                    (id, tenant_id, agent_key, principal_kind, principal_id,
                     action, original_invocation_id, request_body_ciphertext,
                     request_headers, policy_config_hash, status,
                     submitted_at, expires_at)
                VALUES
                    (:id, :tid, :ak, :pk, :pid, :act, :oi, :body,
                     :hdrs, :hash, 'pending', :sub, :exp)
            """), {
                "id": pending_id,
                "tid": tenant_id,
                "ak": agent_key,
                "pk": principal_kind,
                "pid": principal_id,
                "act": action,
                "oi": original_invocation_id,
                "body": request_body_ciphertext,
                "hdrs": headers_json,
                "hash": policy_config_hash,
                "sub": ts,
                "exp": expiry,
            })
    return pending_id


# ── Decide (approve / deny) ──────────────────────────────────────────


def _supports_returning(dialect_name: str) -> bool:
    """Which SQL dialects support ``UPDATE ... RETURNING`` syntax.

    Postgres (all supported versions), SQLite 3.35+, DuckDB — yes.
    MySQL — no until 8.0.35+, and even then not with UPDATE.

    We check via the dialect NAME rather than server_version_info so
    the test fixture can override dialect explicitly. When RETURNING
    is unavailable we fall back to a SELECT-after-UPDATE gate that
    keeps race semantics correct at the cost of a second round-trip.
    """
    return dialect_name in ("postgresql", "sqlite", "duckdb")


def decide(
    engine,
    *,
    pending_id: str,
    decision: Literal["approved", "denied"],
    decided_by: str,
    now: Optional[datetime] = None,
    tenant_id: Optional[str] = None,
) -> bool:
    """Flip a pending row's status. Returns True iff we won the race.

    M8 fix — uses ``WHERE status='pending'`` in the UPDATE so
    simultaneous approvers race safely on the row-level lock and
    exactly one caller finds the row in the target state afterward.

    Rejects decisions on expired rows (belt-and-braces alongside the
    sweeper) so a decision that "wins" the race but arrives after
    expiry doesn't retroactively revive a stale approval.

    Portability note: DuckDB reports ``rowcount == -1`` for UPDATE
    (driver limitation), so a rowcount-based winner check misfires
    there. We use ``RETURNING id`` where supported and fall back to a
    SELECT-after-UPDATE gate for MySQL where RETURNING isn't in the
    UPDATE grammar. Both paths preserve the race semantics.

    ``tenant_id`` is optional; when passed, the UPDATE also requires
    ``AND tenant_id = :tid``. That gives cross-tenant callers a clean
    "row not found" (returns False) without a separate SELECT round
    trip, eliminating any TOCTOU window between an existence check
    and the write. Recommended for batch code paths where the caller
    already knows the tenant.
    """
    if decision not in ("approved", "denied"):
        raise ValueError(f"decision must be 'approved' or 'denied', got {decision!r}")
    ts = now or datetime.now(timezone.utc)
    tenant_clause = " AND tenant_id = :tid" if tenant_id is not None else ""
    params: dict[str, Any] = {
        "id": pending_id, "dec": decision, "ts": ts, "by": decided_by,
    }
    if tenant_id is not None:
        params["tid"] = tenant_id
    with engine.begin() as conn:
        if _supports_returning(engine.dialect.name):
            result = conn.execute(_sql(f"""
                UPDATE kya_pending_invocations
                SET status = :dec, decided_at = :ts, decided_by = :by
                WHERE id = :id AND status = 'pending'
                  AND expires_at > :ts{tenant_clause}
                RETURNING id
            """), params)
            return result.fetchone() is not None
        # MySQL path — do the UPDATE, then SELECT to see if we won.
        conn.execute(_sql(f"""
            UPDATE kya_pending_invocations
            SET status = :dec, decided_at = :ts, decided_by = :by
            WHERE id = :id AND status = 'pending'
              AND expires_at > :ts{tenant_clause}
        """), params)
        confirm = conn.execute(_sql("""
            SELECT 1 FROM kya_pending_invocations
            WHERE id = :id AND status = :dec AND decided_by = :by
        """), {"id": pending_id, "dec": decision, "by": decided_by}).fetchone()
        return confirm is not None


# ── Read ─────────────────────────────────────────────────────────────


def _coerce_datetime(value: Any) -> Optional[datetime]:
    """Coerce a datetime column back to a tz-aware ``datetime``.

    Portability quirk: SQLite (default adapter) round-trips
    timestamps as ISO-8601 strings; DuckDB may return them in the
    session's local timezone; Postgres/MySQL return proper
    ``datetime`` instances. Normalize all three to tz-aware UTC so
    callers can do arithmetic without dispatching on the dialect.
    """
    if value is None:
        return None
    if isinstance(value, str):
        # SQLite's default text adapter — try ISO parse.
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        dt = value
    if dt.tzinfo is None:
        # Naive datetime — treat as UTC (that's what we always write).
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        # Aware but perhaps in local time (DuckDB) — normalize to UTC.
        dt = dt.astimezone(timezone.utc)
    return dt


def _row_to_view(row) -> PendingInvocation:
    """Materialize a row proxy into an immutable view.

    Header JSON is loaded once here so callers don't repeat the parse.
    Datetime columns are dialect-normalized via ``_coerce_datetime``.
    """
    (
        pid, tid, ak, pk, pri, action_str, oi, body, hdrs_json,
        pol_hash, status, sub, exp, dec_at, dec_by, res_ev_id,
    ) = row
    # Postgres JSONB returns a dict/list already; SQLite/DuckDB/MySQL
    # stored it as TEXT and return a JSON string. Handle both.
    if isinstance(hdrs_json, (dict, list)):
        headers = hdrs_json
    else:
        try:
            headers = json.loads(hdrs_json) if hdrs_json else {}
        except (TypeError, ValueError):
            headers = {}
    return PendingInvocation(
        id=str(pid),
        tenant_id=str(tid),
        agent_key=str(ak),
        principal_kind=str(pk),
        principal_id=str(pri),
        action=str(action_str),
        original_invocation_id=int(oi) if oi is not None else None,
        request_body_ciphertext=bytes(body) if body else b"",
        request_headers=headers,
        policy_config_hash=str(pol_hash),
        status=status,  # type: ignore[arg-type]
        submitted_at=_coerce_datetime(sub),
        expires_at=_coerce_datetime(exp),
        decided_at=_coerce_datetime(dec_at),
        decided_by=str(dec_by) if dec_by else None,
        resume_result_evidence_id=int(res_ev_id) if res_ev_id is not None else None,
    )


def get_by_id(engine, pending_id: str) -> Optional[PendingInvocation]:
    """Fetch one pending row by id. Returns None if not found."""
    with engine.connect() as conn:
        result = conn.execute(_sql("""
            SELECT id, tenant_id, agent_key, principal_kind, principal_id,
                   action, original_invocation_id, request_body_ciphertext,
                   request_headers, policy_config_hash, status,
                   submitted_at, expires_at, decided_at, decided_by,
                   resume_result_evidence_id
            FROM kya_pending_invocations
            WHERE id = :id
        """), {"id": pending_id}).fetchone()
    if result is None:
        return None
    return _row_to_view(result)


def find_ready_to_resume(
    engine, pending_id: str, *, now: Optional[datetime] = None,
) -> Optional[PendingInvocation]:
    """Return a row iff it is approved AND not expired AND not already resumed.

    The resume endpoint MUST call this instead of ``get_by_id`` — it
    guarantees the ready-to-run gate in one query so a concurrent
    resume attempt can't get past the same gate. Returns None on any
    other status (denied / expired / resumed / pending) so the
    endpoint can produce a specific error message.
    """
    ts = now or datetime.now(timezone.utc)
    with engine.connect() as conn:
        result = conn.execute(_sql("""
            SELECT id, tenant_id, agent_key, principal_kind, principal_id,
                   action, original_invocation_id, request_body_ciphertext,
                   request_headers, policy_config_hash, status,
                   submitted_at, expires_at, decided_at, decided_by,
                   resume_result_evidence_id
            FROM kya_pending_invocations
            WHERE id = :id
              AND status = 'approved'
              AND expires_at > :ts
              AND resume_result_evidence_id IS NULL
        """), {"id": pending_id, "ts": ts}).fetchone()
    if result is None:
        return None
    return _row_to_view(result)


def list_by_tenant(
    engine,
    *,
    tenant_id: str,
    status: Optional[PendingStatus] = None,
    limit: int = 100,
) -> list[PendingInvocation]:
    """Approver-UI list, most-urgent (earliest expiry) first.

    ``limit`` is capped at 500 so a runaway backlog can't blow the
    JSON payload — the admin UI surfaces "N of M shown" when hit.
    """
    capped = max(1, min(int(limit), 500))
    with engine.connect() as conn:
        if status is None:
            result = conn.execute(_sql("""
                SELECT id, tenant_id, agent_key, principal_kind, principal_id,
                       action, original_invocation_id, request_body_ciphertext,
                       request_headers, policy_config_hash, status,
                       submitted_at, expires_at, decided_at, decided_by,
                       resume_result_evidence_id
                FROM kya_pending_invocations
                WHERE tenant_id = :tid
                ORDER BY expires_at ASC
                LIMIT :lim
            """), {"tid": tenant_id, "lim": capped}).fetchall()
        else:
            result = conn.execute(_sql("""
                SELECT id, tenant_id, agent_key, principal_kind, principal_id,
                       action, original_invocation_id, request_body_ciphertext,
                       request_headers, policy_config_hash, status,
                       submitted_at, expires_at, decided_at, decided_by,
                       resume_result_evidence_id
                FROM kya_pending_invocations
                WHERE tenant_id = :tid AND status = :st
                ORDER BY expires_at ASC
                LIMIT :lim
            """), {"tid": tenant_id, "st": status, "lim": capped}).fetchall()
    return [_row_to_view(r) for r in result]


# ── Resume completion + expiry sweep ────────────────────────────────


def mark_resumed(
    engine,
    *,
    pending_id: str,
    resume_result_evidence_id: int,
) -> bool:
    """Close the loop: link the resume-result evidence row + flip status.

    C4 fix — the evidence row for the resume result MUST reference the
    original invocation's evidence chain via ``parent_invocation_id``.
    That linkage is written by the Pro-side caller in the evidence
    write; this function only records the id so audit can walk from
    the pending row to the resume evidence.

    Returns True iff the row was approved + not already resumed
    (concurrent resume attempts race safely on this).
    """
    with engine.begin() as conn:
        if _supports_returning(engine.dialect.name):
            result = conn.execute(_sql("""
                UPDATE kya_pending_invocations
                SET status = 'resumed',
                    resume_result_evidence_id = :ev
                WHERE id = :id
                  AND status = 'approved'
                  AND resume_result_evidence_id IS NULL
                RETURNING id
            """), {"id": pending_id, "ev": resume_result_evidence_id})
            return result.fetchone() is not None
        conn.execute(_sql("""
            UPDATE kya_pending_invocations
            SET status = 'resumed',
                resume_result_evidence_id = :ev
            WHERE id = :id
              AND status = 'approved'
              AND resume_result_evidence_id IS NULL
        """), {"id": pending_id, "ev": resume_result_evidence_id})
        confirm = conn.execute(_sql("""
            SELECT 1 FROM kya_pending_invocations
            WHERE id = :id AND status = 'resumed'
              AND resume_result_evidence_id = :ev
        """), {"id": pending_id, "ev": resume_result_evidence_id}).fetchone()
        return confirm is not None


def sweep_expired(
    engine, *, now: Optional[datetime] = None, batch_size: int = 500,
) -> int:
    """Flip status='pending' AND expires_at<=now → status='expired'.

    Idempotent — a row already in 'expired' won't match. Batch limit
    exists so a runaway backlog doesn't lock the table indefinitely
    on a single cron tick (cron re-runs pick up remaining rows).
    Returns the number of rows swept for the caller's log.
    """
    ts = now or datetime.now(timezone.utc)
    bounded = max(1, min(int(batch_size), 5000))
    # LIMIT-in-UPDATE is nonstandard across dialects — SELECT ids first,
    # then UPDATE by id-set. Two round-trips instead of one, but portable.
    with engine.begin() as conn:
        ids = [r[0] for r in conn.execute(_sql("""
            SELECT id FROM kya_pending_invocations
            WHERE status = 'pending' AND expires_at <= :ts
            LIMIT :lim
        """), {"ts": ts, "lim": bounded}).fetchall()]
        if not ids:
            return 0
        # Chunk in case of a huge id list; parameter limits vary.
        # Same DuckDB rowcount=-1 quirk as decide/mark_resumed: use
        # RETURNING where supported, fall back to COUNT-after-UPDATE.
        swept = 0
        uses_returning = _supports_returning(engine.dialect.name)
        for i in range(0, len(ids), 200):
            chunk = ids[i:i + 200]
            placeholders = ",".join(f":i{j}" for j in range(len(chunk)))
            params: dict[str, Any] = {f"i{j}": chunk[j] for j in range(len(chunk))}
            if uses_returning:
                result = conn.execute(_sql(f"""
                    UPDATE kya_pending_invocations
                    SET status = 'expired'
                    WHERE id IN ({placeholders}) AND status = 'pending'
                    RETURNING id
                """), params)
                swept += len(result.fetchall())
            else:
                conn.execute(_sql(f"""
                    UPDATE kya_pending_invocations
                    SET status = 'expired'
                    WHERE id IN ({placeholders}) AND status = 'pending'
                """), params)
                count = conn.execute(_sql(f"""
                    SELECT COUNT(*) FROM kya_pending_invocations
                    WHERE id IN ({placeholders}) AND status = 'expired'
                """), params).fetchone()
                swept += int(count[0] if count else 0)
    if swept:
        logger.info("[pending_invocations] swept %d expired row(s)", swept)
    return swept


__all__ = [
    "PendingStatus",
    "VALID_STATUSES",
    "DEFAULT_TTL_HOURS",
    "PendingInvocation",
    "ensure_table",
    "hash_policy_config",
    "create_pending",
    "decide",
    "get_by_id",
    "find_ready_to_resume",
    "list_by_tenant",
    "mark_resumed",
    "sweep_expired",
]
