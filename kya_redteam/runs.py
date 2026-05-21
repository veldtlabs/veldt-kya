"""kya_redteam_runs — execution tracking, cancellation, heartbeats.

A run row is created the moment a campaign is fired (sync or async).
It holds the lifecycle state of one execution: status, progress
counters, cancellation flag, heartbeat. Long-running multi-turn
campaigns can be:
  - polled       via GET /redteam/runs/{run_id}
  - cancelled    via POST /redteam/runs/{run_id}/cancel
  - audited      via the run row's attestation_id (Ed25519 chain)
  - reconciled   when vd-app restarts (heartbeat-timeout sweeps the
                 'running' rows that no longer have a live worker)

Cancellation flow
-----------------
1. POST /cancel sets `cancel_requested = true` on the DB row AND
   writes a Valkey key `kya:redteam:cancel:{run_id}` with TTL 1h.
2. The orchestrator polls Valkey at the start of each loop iteration
   via `is_cancel_requested(run_id)` (cheap — Valkey GET).
3. On cancel, the orchestrator stops dispatching new prompts and
   calls `finalize_run(status='cancelled')`. In-flight prompts are
   allowed to complete so partial findings persist.

Heartbeat
---------
Orchestrator calls `heartbeat(db, run_id)` at most once per K seconds
(K = `_HEARTBEAT_MIN_INTERVAL_S`). A reconciliation helper marks runs
with `status='running'` and `last_heartbeat_at` older than `_STALE_S`
as failed — survives a vd-app crash mid-campaign.

Storage notes
-------------
- `run_id` is the public identifier (UUID). The serial `id` exists
  only for compact indexing.
- `severity_buckets` is JSONB with the four buckets so the dashboard
  doesn't have to GROUP BY over findings to show severity counts.
- `posted_event_ids` is JSONB array — every /events/rogue row created
  during this run, for the regulator-pack drill-back.
"""
from __future__ import annotations

import json as _json
import logging
import os
import time
import uuid
from typing import Any, Optional

try:
    from sqlalchemy import text
except ImportError:
    def text(s):  # type: ignore
        raise RuntimeError("kya_redteam.runs requires SQLAlchemy")

from kya._migrations import apply_migrations

logger = logging.getLogger(__name__)


VALID_STATUSES = (
    "queued", "running", "completed", "failed", "cancelled", "denied_by_tier",
)

_HEARTBEAT_MIN_INTERVAL_S = 5
_STALE_S = 300  # 5 minutes — heartbeats older than this mean the worker is dead


# ── DDL ─────────────────────────────────────────────────────────────

_RUNS_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_redteam_runs (
    id                      SERIAL PRIMARY KEY,
    tenant_id               UUID NOT NULL,
    run_id                  UUID NOT NULL UNIQUE,
    campaign_id             INT,
    agent_key               VARCHAR(50) NOT NULL,
    orchestrator            TEXT NOT NULL,
    target_id               INT,
    target_endpoint_redacted TEXT,
    status                  TEXT NOT NULL DEFAULT 'queued',
    cancel_requested        BOOLEAN NOT NULL DEFAULT false,
    cancel_requested_by     UUID,
    cancel_requested_at     TIMESTAMPTZ,
    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at             TIMESTAMPTZ,
    last_heartbeat_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    prompts_sent            INT NOT NULL DEFAULT 0,
    findings_count          INT NOT NULL DEFAULT 0,
    severity_buckets        JSONB NOT NULL DEFAULT '{}'::jsonb,
    attacker_tokens_estimated INT NOT NULL DEFAULT 0,
    target_errors           INT NOT NULL DEFAULT 0,
    posted_event_ids        JSONB NOT NULL DEFAULT '[]'::jsonb,
    auto_incidents_created  INT NOT NULL DEFAULT 0,
    error_message           TEXT,
    initiated_by            UUID,
    attestation_id          INT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

_RUNS_IDX = """
CREATE INDEX IF NOT EXISTS idx_kya_redteam_runs_tenant_agent
    ON prov_schema.kya_redteam_runs (tenant_id, agent_key);
CREATE INDEX IF NOT EXISTS idx_kya_redteam_runs_campaign
    ON prov_schema.kya_redteam_runs (tenant_id, campaign_id);
CREATE INDEX IF NOT EXISTS idx_kya_redteam_runs_status
    ON prov_schema.kya_redteam_runs (tenant_id, status);
"""

_MIGRATIONS: list = []

_ENSURED = False


def ensure_table(db) -> None:
    """Idempotent — runs once per process. Dialect-aware via _legacy_tables.

    On PG, the advisory lock prevents the two-uvicorn-worker DDL race;
    on non-PG dialects the lock no-ops and create_all is naturally idempotent.
    """
    global _ENSURED
    if _ENSURED:
        return
    try:
        bind = db.connection()
        # PG-only advisory lock — skip on other dialects
        if bind.dialect.name == "postgresql":
            lock_row = db.execute(
                text("SELECT pg_try_advisory_xact_lock(hashtext('kya_redteam_runs_ddl'))")
            ).fetchone()
            if not lock_row or not lock_row[0]:
                db.commit()
                return

        from kya._legacy_tables import create_legacy_tables, kya_redteam_runs

        create_legacy_tables(db, [kya_redteam_runs])
        apply_migrations(db, "kya_redteam_runs", _MIGRATIONS)
        db.commit()
        _ENSURED = True
    except Exception as exc:
        logger.warning("[REDTEAM-RUNS] ensure_table failed: %s", exc)
        db.rollback()


# ── URL redaction for the run-row breadcrumb ────────────────────────

def _redact_endpoint(url: Optional[str]) -> str:
    """Strip user-info + query string from a URL for storage. The full
    URL stays in the (encrypted) target row; this is just a label so a
    regulator can tell which endpoint was hit without seeing tokens."""
    if not url:
        return ""
    try:
        # Naive split, no urllib dependency on the hot path
        scheme_sep = url.find("://")
        if scheme_sep < 0:
            return url[:200]
        scheme = url[:scheme_sep]
        rest = url[scheme_sep + 3:]
        # Strip user-info before @
        at = rest.find("@")
        if at >= 0:
            rest = rest[at + 1:]
        # Trim query/fragment
        for sep in ("?", "#"):
            i = rest.find(sep)
            if i >= 0:
                rest = rest[:i]
        return f"{scheme}://{rest}"[:200]
    except Exception:
        return (url or "")[:200]


# ── Create + finalize ───────────────────────────────────────────────

def create_run(
    db, *,
    tenant_id: str,
    campaign_id: Optional[int],
    agent_key: str,
    orchestrator: str,
    target_id: Optional[int] = None,
    target_endpoint: Optional[str] = None,
    initiated_by: Optional[str] = None,
    status: str = "queued",
) -> str:
    """Create a run row, return the public run_id (UUID)."""
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status}")
    ensure_table(db)
    run_id = str(uuid.uuid4())
    db.execute(
        text(
            "INSERT INTO prov_schema.kya_redteam_runs "
            "  (tenant_id, run_id, campaign_id, agent_key, orchestrator, "
            "   target_id, target_endpoint_redacted, status, initiated_by, "
            "   started_at, last_heartbeat_at) "
            "VALUES ((:tid)::uuid, (:rid)::uuid, :cid, :ak, :ork, "
            "        :tgt, :ter, :st, "
            "        CASE WHEN :uid = '' THEN NULL ELSE (:uid)::uuid END, "
            "        now(), now())"
        ),
        {
            "tid": tenant_id, "rid": run_id, "cid": campaign_id,
            "ak": agent_key, "ork": orchestrator,
            "tgt": target_id,
            "ter": _redact_endpoint(target_endpoint),
            "st": status,
            "uid": initiated_by or "",
        },
    )
    db.commit()
    return run_id


def set_running(db, run_id: str) -> None:
    """Transition queued->running. Idempotent."""
    db.execute(
        text(
            "UPDATE prov_schema.kya_redteam_runs "
            "SET status = 'running', last_heartbeat_at = now() "
            "WHERE run_id = (:rid)::uuid AND status IN ('queued','running')"
        ),
        {"rid": run_id},
    )
    db.commit()


# ── Per-prompt updates (called from the orchestrator hot loop) ──────

class HeartbeatState:
    """Lightweight per-run state held by the orchestrator. Avoids hitting
    the DB on every prompt — we only flush heartbeat at most once per
    `_HEARTBEAT_MIN_INTERVAL_S` and progress at the end of every prompt.
    """
    __slots__ = ("run_id", "last_hb_at", "_session_for_cancel_check")
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.last_hb_at = 0.0
        self._session_for_cancel_check = 0.0


def heartbeat(db, state: HeartbeatState) -> None:
    """Update last_heartbeat_at if enough time has passed since the last
    DB write. Cheap on hot path — most calls are no-ops."""
    now = time.monotonic()
    if (now - state.last_hb_at) < _HEARTBEAT_MIN_INTERVAL_S:
        return
    state.last_hb_at = now
    try:
        db.execute(
            text(
                "UPDATE prov_schema.kya_redteam_runs "
                "SET last_heartbeat_at = now() "
                "WHERE run_id = (:rid)::uuid"
            ),
            {"rid": state.run_id},
        )
        db.commit()
    except Exception as exc:
        logger.debug("[REDTEAM-RUNS] heartbeat failed: %s", exc)
        db.rollback()


def update_run_progress(
    db, run_id: str,
    *,
    prompts_sent: Optional[int] = None,
    findings_count: Optional[int] = None,
    severity_buckets: Optional[dict] = None,
    attacker_tokens: Optional[int] = None,
    target_errors: Optional[int] = None,
    posted_event_id: Optional[int] = None,
    auto_incidents_created: Optional[int] = None,
) -> None:
    """Patch-update progress fields. None = leave unchanged.

    For `posted_event_id`, append to the JSONB array rather than
    replacing the column.
    """
    set_clauses = ["last_heartbeat_at = now()"]
    params: dict[str, Any] = {"rid": run_id}
    if prompts_sent is not None:
        set_clauses.append("prompts_sent = :ps")
        params["ps"] = prompts_sent
    if findings_count is not None:
        set_clauses.append("findings_count = :fc")
        params["fc"] = findings_count
    if severity_buckets is not None:
        set_clauses.append("severity_buckets = CAST(:sb AS JSONB)")
        params["sb"] = _json.dumps(severity_buckets)
    if attacker_tokens is not None:
        set_clauses.append("attacker_tokens_estimated = :at")
        params["at"] = attacker_tokens
    if target_errors is not None:
        set_clauses.append("target_errors = :te")
        params["te"] = target_errors
    if auto_incidents_created is not None:
        set_clauses.append("auto_incidents_created = :aic")
        params["aic"] = auto_incidents_created
    if posted_event_id is not None:
        set_clauses.append(
            "posted_event_ids = "
            "  COALESCE(posted_event_ids, '[]'::jsonb) || CAST(:pe AS JSONB)"
        )
        params["pe"] = _json.dumps([posted_event_id])
    if len(set_clauses) == 1:
        return  # only the heartbeat clause; nothing to update
    try:
        db.execute(
            text(
                "UPDATE prov_schema.kya_redteam_runs "
                f"SET {', '.join(set_clauses)} "
                "WHERE run_id = (:rid)::uuid"
            ),
            params,
        )
        db.commit()
    except Exception as exc:
        logger.warning("[REDTEAM-RUNS] update_run_progress failed: %s", exc)
        db.rollback()


# ── Cancellation (Valkey-backed flag) ───────────────────────────────

_CANCEL_TTL_S = 3600   # 1 hour — long enough for any reasonable campaign


def _cancel_key(run_id: str) -> str:
    return f"kya:redteam:cancel:{run_id}"


def _get_valkey():
    """Best-effort Valkey accessor. Falls back to None when redis client
    isn't importable (e.g. in unit tests outside the container)."""
    try:
        from db.redis import get_redis  # type: ignore
        return get_redis()
    except Exception:
        return None


def request_cancel(db, run_id: str, *, by_user_id: Optional[str]) -> bool:
    """Request cancellation. Writes to DB AND Valkey. Returns True if a
    row matched and was flagged. Idempotent — re-requesting a cancel
    just refreshes the Valkey TTL.
    """
    ensure_table(db)
    result = db.execute(
        text(
            "UPDATE prov_schema.kya_redteam_runs "
            "SET cancel_requested = true, "
            "    cancel_requested_by = "
            "      CASE WHEN :uid = '' THEN NULL ELSE (:uid)::uuid END, "
            "    cancel_requested_at = now() "
            "WHERE run_id = (:rid)::uuid "
            "  AND status IN ('queued','running')"
        ),
        {"rid": run_id, "uid": by_user_id or ""},
    )
    db.commit()
    if (result.rowcount or 0) == 0:
        return False
    rds = _get_valkey()
    if rds is not None:
        try:
            rds.set(_cancel_key(run_id), "1", ex=_CANCEL_TTL_S)
        except Exception as exc:
            logger.debug("[REDTEAM-RUNS] valkey cancel write failed: %s", exc)
    return True


def is_cancel_requested(run_id: str) -> bool:
    """Cheap check on the orchestrator hot path. Valkey first (single
    GET, microseconds); DB only if Valkey unavailable."""
    rds = _get_valkey()
    if rds is not None:
        try:
            if rds.get(_cancel_key(run_id)):
                return True
            return False
        except Exception as exc:
            logger.debug("[REDTEAM-RUNS] valkey cancel read failed: %s", exc)
    # Valkey unavailable -- fall through to DB. Don't open a new
    # session here; callers that need this should pass one in via
    # is_cancel_requested_db().
    return False


def is_cancel_requested_db(db, run_id: str) -> bool:
    """DB-backed cancel check — fallback when Valkey is missing."""
    row = db.execute(
        text(
            "SELECT cancel_requested FROM prov_schema.kya_redteam_runs "
            "WHERE run_id = (:rid)::uuid"
        ),
        {"rid": run_id},
    ).fetchone()
    return bool(row and row[0])


# ── Finalize (with optional Ed25519 attestation) ────────────────────

def finalize_run(
    db, run_id: str,
    *,
    status: str,
    error_message: Optional[str] = None,
    tenant_id: Optional[str] = None,
    sign_attestation: bool = True,
) -> dict:
    """Set status + finished_at, optionally create an Ed25519
    attestation row referencing this run. Attestation lets a regulator
    verify the run summary wasn't tampered with after the fact.
    """
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status}")
    ensure_table(db)
    db.execute(
        text(
            "UPDATE prov_schema.kya_redteam_runs "
            "SET status = :st, finished_at = now(), "
            "    error_message = :err "
            "WHERE run_id = (:rid)::uuid"
        ),
        {"rid": run_id, "st": status, "err": error_message},
    )
    db.commit()

    if sign_attestation and tenant_id and status in ("completed", "cancelled"):
        try:
            row = get_run(db, tenant_id, run_id)
            if row:
                _sign_run_attestation(db, tenant_id, row)
        except Exception as exc:
            logger.warning("[REDTEAM-RUNS] attestation failed: %s", exc)
    return get_run(db, tenant_id, run_id) if tenant_id else {"run_id": run_id, "status": status}


def _sign_run_attestation(db, tenant_id: str, run: dict) -> Optional[int]:
    """Best-effort Ed25519 signing of the run summary."""
    try:
        from decisions.attestation.service import create_attestation  # type: ignore
    except Exception:
        return None
    try:
        att = create_attestation(
            db, tenant_id=tenant_id,
            entity_type="kya_redteam_run",
            entity_id=run["run_id"],
            attester_id=str(run.get("initiated_by") or ""),
            action="completed",
            content_fields={
                "run_id": run["run_id"],
                "agent_key": run["agent_key"],
                "orchestrator": run["orchestrator"],
                "status": run["status"],
                "prompts_sent": run["prompts_sent"],
                "findings_count": run["findings_count"],
                "severity_buckets": run["severity_buckets"],
                "posted_event_ids": run["posted_event_ids"],
            },
            metadata={"source": "kya_redteam_run_finalize"},
        )
        db.execute(
            text(
                "UPDATE prov_schema.kya_redteam_runs "
                "SET attestation_id = :aid "
                "WHERE run_id = (:rid)::uuid"
            ),
            {"aid": att.id, "rid": run["run_id"]},
        )
        db.commit()
        return att.id
    except Exception as exc:
        logger.warning("[REDTEAM-RUNS] sign attestation failed: %s", exc)
        db.rollback()
        return None


# ── Read ────────────────────────────────────────────────────────────

_SELECT_COLS = (
    "id, tenant_id, run_id, campaign_id, agent_key, orchestrator, "
    "target_id, target_endpoint_redacted, status, cancel_requested, "
    "cancel_requested_by, cancel_requested_at, started_at, finished_at, "
    "last_heartbeat_at, prompts_sent, findings_count, severity_buckets, "
    "attacker_tokens_estimated, target_errors, posted_event_ids, "
    "auto_incidents_created, error_message, initiated_by, attestation_id, "
    "created_at"
)


def _row_to_run(r) -> dict:
    return {
        "id": r[0],
        "tenant_id": str(r[1]),
        "run_id": str(r[2]),
        "campaign_id": r[3],
        "agent_key": r[4],
        "orchestrator": r[5],
        "target_id": r[6],
        "target_endpoint_redacted": r[7],
        "status": r[8],
        "cancel_requested": r[9],
        "cancel_requested_by": str(r[10]) if r[10] else None,
        "cancel_requested_at": r[11],
        "started_at": r[12],
        "finished_at": r[13],
        "last_heartbeat_at": r[14],
        "prompts_sent": r[15],
        "findings_count": r[16],
        "severity_buckets": r[17] or {},
        "attacker_tokens_estimated": r[18],
        "target_errors": r[19],
        "posted_event_ids": r[20] or [],
        "auto_incidents_created": r[21],
        "error_message": r[22],
        "initiated_by": str(r[23]) if r[23] else None,
        "attestation_id": r[24],
        "created_at": r[25],
    }


def get_run(db, tenant_id: str, run_id: str) -> Optional[dict]:
    ensure_table(db)
    row = db.execute(
        text(
            f"SELECT {_SELECT_COLS} "
            "FROM prov_schema.kya_redteam_runs "
            "WHERE tenant_id = (:tid)::uuid AND run_id = (:rid)::uuid"
        ),
        {"tid": tenant_id, "rid": run_id},
    ).fetchone()
    return _row_to_run(row) if row else None


def list_runs(
    db, tenant_id: str,
    *,
    agent_key: Optional[str] = None,
    campaign_id: Optional[int] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    ensure_table(db)
    clauses = ["tenant_id = (:tid)::uuid"]
    params: dict[str, Any] = {"tid": tenant_id, "lim": min(max(limit, 1), 500)}
    if agent_key:
        clauses.append("agent_key = :ak")
        params["ak"] = agent_key
    if campaign_id is not None:
        clauses.append("campaign_id = :cid")
        params["cid"] = campaign_id
    if status:
        clauses.append("status = :st")
        params["st"] = status
    rows = db.execute(
        text(
            f"SELECT {_SELECT_COLS} "
            "FROM prov_schema.kya_redteam_runs "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY id DESC LIMIT :lim"
        ),
        params,
    ).fetchall()
    return [_row_to_run(r) for r in rows]


# ── Reconciliation (heartbeat sweep on startup or periodically) ─────

def reconcile_stale_runs(db) -> dict:
    """Mark 'running' rows with stale heartbeats as 'failed'. Returns a
    summary dict (`{"swept": N, "run_ids": [...]}`). Safe to call from
    a worker startup hook OR a periodic task.

    Why this matters: a vd-app crash mid-campaign leaves a 'running'
    row that no live worker is updating. Without reconciliation,
    operators would see ghost campaigns "in progress" indefinitely and
    a regulator pulling an evidence pack would think the run is still
    going. The heartbeat + sweep pattern bounds this to `_STALE_S`.

    Concurrency note: vd-app runs two uvicorn workers. A naïve sweep
    on each worker startup would race and double-count. We guard with
    a Postgres advisory lock — only the first worker to acquire it
    actually runs the sweep; the rest no-op. The lock is released on
    function exit (transaction commit), so the next periodic call can
    re-acquire freely.
    """
    ensure_table(db)
    # pg_try_advisory_xact_lock — non-blocking, scope-tied to the
    # surrounding transaction. Hash a fixed string so all workers
    # contend for the same lock key.
    lock_row = db.execute(
        text("SELECT pg_try_advisory_xact_lock(hashtext('kya_redteam_reconcile'))")
    ).fetchone()
    if not lock_row or not lock_row[0]:
        logger.debug("[REDTEAM-RUNS] reconcile skipped — another worker holds the lock")
        db.commit()
        return {"swept": 0, "run_ids": [], "lock_held_elsewhere": True}
    result = db.execute(
        text(
            "UPDATE prov_schema.kya_redteam_runs "
            "SET status = 'failed', "
            "    finished_at = now(), "
            "    error_message = COALESCE(error_message, '') || "
            "                    'heartbeat_timeout_sweep' "
            "WHERE status = 'running' "
            f"  AND last_heartbeat_at < now() - INTERVAL '{_STALE_S} seconds' "
            "RETURNING run_id"
        )
    )
    swept = [str(r[0]) for r in result.fetchall()]
    db.commit()
    if swept:
        logger.warning("[REDTEAM-RUNS] reconciled %d stale run(s): %s",
                       len(swept), swept[:5])
        try:
            from kya.fleet_metrics import inc_heartbeat_sweep
            inc_heartbeat_sweep(outcome="reconciled")
            for _ in swept[1:]:
                inc_heartbeat_sweep(outcome="reconciled")
        except Exception:
            pass
    return {"swept": len(swept), "run_ids": swept}


# ── Async runner — ThreadPoolExecutor singleton ─────────────────────

_POOL = None


def _get_pool():
    global _POOL
    if _POOL is None:
        from concurrent.futures import ThreadPoolExecutor
        max_workers = int(os.environ.get("KYA_REDTEAM_MAX_CONCURRENT_RUNS", "3"))
        _POOL = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="kya-redteam",
        )
        logger.info("[REDTEAM-RUNS] thread pool initialized max_workers=%d", max_workers)
    return _POOL


def submit_async_run(
    runner_callable,
    *args,
    **kwargs,
):
    """Submit a runner function to the pool. Returns the Future.

    The caller is responsible for creating its own DB session inside
    `runner_callable` — sessions are not thread-safe, so passing one
    in from the request handler would race with the response cycle.
    """
    pool = _get_pool()
    return pool.submit(runner_callable, *args, **kwargs)
