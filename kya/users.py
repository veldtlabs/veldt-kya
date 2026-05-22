"""
KYU — Know Your User.

Per-USER trust score and rogue-signal tracking. Sits next to KYA's
agent-centric scoring: the same `data_leak` event bumps BOTH the
agent's rogue counter AND the user's user-trust score downward. A
user with 5 cross-tenant attempts across 3 different agents is the
actual threat actor, not the agents they're driving.

Why this matters
----------------
KYA scores agents — but a clean agent in a malicious user's hands is
still a problem. SaaS fraud teams already work this way: an account
that triggers 10 fraud signals across products is a different problem
from a single product being broken. KYU surfaces that signal.

Trust score
-----------
Starts at 50. Bounded 0-100.
  + Decays positive on clean invocations (small per-call increment)
  - Decays negative on rogue signals attributed to the user:
      rbac_refusal:        -2
      out_of_scope_tool:   -3
      governance_block:    -2
      cross_tenant_attempt: -15
      data_leak:           -10
  + Time decay: 7 days without any signal restores 1 point/day
    toward the starting value of 50 (configurable)

Storage
-------
prov_schema.kya_user_trust — current state per (tenant_id, user_id):
  trust_score (int 0-100)
  signal_counts (jsonb) — all-time per-signal counters
  last_signal_at, last_clean_at — for time-decay
  updated_at

Also: per-user Valkey windowed counters mirror the agent pattern at
`kya:user:{tenant_id}:{user_id}:{signal_kind}:{window}` so the same
1m-7d sliding windows are available.

Public API
----------
    ensure_user_trust_table(db)
    record_user_signal(db, tenant_id, user_id, signal_kind)
    record_user_clean(db, tenant_id, user_id)   # bumps trust upward
    get_user_trust(db, tenant_id, user_id) -> UserTrust
    list_user_trust(db, tenant_id, limit=100) -> list[dict]
    bucket_for_trust(score: int) -> str   # "trusted" / "neutral" / "risky" / "blocked"
"""

import logging
from dataclasses import dataclass, field

# Lazy SQLAlchemy import — keep KYA SDK-friendly.
try:
    from sqlalchemy import text as _sa_text

    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False

    def _sa_text(s):
        raise RuntimeError(
            "kya.users requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


text = _sa_text

logger = logging.getLogger(__name__)

# ── Trust score config ───────────────────────────────────────────────────

STARTING_TRUST = 50
MIN_TRUST = 0
MAX_TRUST = 100

# How much each signal moves the score (negative = trust loss).
SIGNAL_DELTAS = {
    "rbac_refusal": -2,
    "oos_tool": -3,
    "governance_block": -2,
    "cross_tenant": -15,
    "data_leak": -10,
    "injection_attempt": -5,
    # Behavioral policy violation — jailbreak, harmful output, refusal failure.
    # Severity-between data_leak (-10) and oos_tool (-3); these are real but
    # not always the worst kind of signal.
    "policy_violation": -7,
    # Synthetic "clean run" — small upward bump for cooperative usage
    "clean_invocation": +1,
}


# Trust buckets — for UI badges and policy decisions
def bucket_for_trust(score: int) -> str:
    if score >= 75:
        return "trusted"
    if score >= 40:
        return "neutral"
    if score >= 15:
        return "risky"
    return "blocked"


# ── Data class ───────────────────────────────────────────────────────────


@dataclass
class UserTrust:
    user_id: str
    tenant_id: str
    trust_score: int = STARTING_TRUST
    bucket: str = "neutral"
    signal_counts: dict = field(default_factory=dict)
    last_signal_at: str | None = None
    last_clean_at: str | None = None
    updated_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "trust_score": self.trust_score,
            "bucket": self.bucket,
            "signal_counts": self.signal_counts,
            "last_signal_at": self.last_signal_at,
            "last_clean_at": self.last_clean_at,
            "updated_at": self.updated_at,
        }


# ── DDL ──────────────────────────────────────────────────────────────────

_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_user_trust (
    id              SERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    user_id         UUID NOT NULL,
    trust_score     INTEGER NOT NULL DEFAULT 50,
    signal_counts   JSONB   NOT NULL DEFAULT '{}'::jsonb,
    last_signal_at  TIMESTAMPTZ,
    last_clean_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id)
);
"""

_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS idx_kya_user_trust_tenant_score
    ON prov_schema.kya_user_trust (tenant_id, trust_score);
"""


def ensure_user_trust_table(db) -> None:
    """Idempotent — dialect-aware via _legacy_tables.create_legacy_tables."""
    from ._legacy_tables import create_legacy_tables, kya_user_trust

    create_legacy_tables(db, [kya_user_trust])
    db.commit()


# ── Read ─────────────────────────────────────────────────────────────────


def get_user_trust(db, tenant_id: str, user_id: str) -> UserTrust:
    """Read a single user's trust row. Returns a fresh-default UserTrust
    when the user has never had a signal recorded (no row yet)."""
    ensure_user_trust_table(db)
    row = db.execute(
        text("""
            SELECT trust_score, signal_counts, last_signal_at, last_clean_at, updated_at
            FROM prov_schema.kya_user_trust
            WHERE tenant_id = :tid AND user_id = :uid
        """),
        {"tid": tenant_id, "uid": user_id},
    ).fetchone()
    if not row:
        return UserTrust(
            user_id=user_id,
            tenant_id=tenant_id,
            trust_score=STARTING_TRUST,
            bucket=bucket_for_trust(STARTING_TRUST),
        )
    sc = row[1] if isinstance(row[1], dict) else {}
    score = int(row[0])
    return UserTrust(
        user_id=user_id,
        tenant_id=tenant_id,
        trust_score=score,
        bucket=bucket_for_trust(score),
        signal_counts=sc,
        last_signal_at=row[2].isoformat() if row[2] else None,
        last_clean_at=row[3].isoformat() if row[3] else None,
        updated_at=row[4].isoformat() if row[4] else None,
    )


def list_user_trust(db, tenant_id: str, limit: int = 100) -> list[dict]:
    """Tenant-scoped list of users sorted by lowest trust first
    (most-risky surfaced at the top — that's what governance teams want)."""
    ensure_user_trust_table(db)
    rows = db.execute(
        text("""
            SELECT user_id, trust_score, signal_counts,
                   last_signal_at, last_clean_at, updated_at
            FROM prov_schema.kya_user_trust
            WHERE tenant_id = :tid
            ORDER BY trust_score ASC, updated_at DESC
            LIMIT :lim
        """),
        {"tid": tenant_id, "lim": limit},
    ).fetchall()
    out = []
    for r in rows:
        sc = r[2] if isinstance(r[2], dict) else {}
        score = int(r[1])
        out.append(
            {
                "user_id": str(r[0]),
                "trust_score": score,
                "bucket": bucket_for_trust(score),
                "signal_counts": sc,
                "last_signal_at": r[3].isoformat() if r[3] else None,
                "last_clean_at": r[4].isoformat() if r[4] else None,
                "updated_at": r[5].isoformat() if r[5] else None,
            }
        )
    return out


# ── Write ────────────────────────────────────────────────────────────────


def _apply_delta(current: int, delta: int) -> int:
    return max(MIN_TRUST, min(MAX_TRUST, current + delta))


def _upsert_with_delta(
    db, tenant_id: str, user_id: str, signal_kind: str, delta: int, is_signal: bool
) -> int:
    """Upsert: increment signal counter + apply delta to trust score.

    Cross-backend strategy:
        PG       — keeps the single-statement jsonb UPSERT (atomic,
                   no read-modify-write window).
        non-PG   — SELECT current state → mutate in Python → portable
                   upsert via _dialect_helpers. A small lost-update
                   window is possible under concurrent writers on
                   non-PG; document as a non-PG limitation.

    Returns the new trust score.
    """
    from datetime import datetime, timezone
    from ._dialect_helpers import dialect_of, portable_upsert
    from ._legacy_tables import kya_user_trust

    ensure_user_trust_table(db)
    ts_col = "last_signal_at" if is_signal else "last_clean_at"
    dialect = dialect_of(db)

    if dialect == "postgresql":
        result = db.execute(
            text(f"""
                INSERT INTO prov_schema.kya_user_trust
                    (id, tenant_id, user_id, trust_score, signal_counts,
                     {ts_col}, updated_at)
                VALUES (
                    nextval('kya_user_trust_id_seq'),
                    :tid, :uid,
                    GREATEST({MIN_TRUST}, LEAST({MAX_TRUST}, {STARTING_TRUST} + :delta)),
                    jsonb_build_object(:kind, 1),
                    now(), now()
                )
                ON CONFLICT (tenant_id, user_id) DO UPDATE
                SET trust_score = GREATEST({MIN_TRUST}, LEAST({MAX_TRUST},
                                           prov_schema.kya_user_trust.trust_score + :delta)),
                    signal_counts =
                        jsonb_set(
                            COALESCE(prov_schema.kya_user_trust.signal_counts, '{{}}'::jsonb),
                            ARRAY[:kind],
                            to_jsonb(COALESCE(
                                (prov_schema.kya_user_trust.signal_counts->>:kind)::int, 0
                            ) + 1)
                        ),
                    {ts_col} = now(),
                    updated_at = now()
                RETURNING trust_score
            """),
            {"tid": tenant_id, "uid": user_id, "kind": signal_kind, "delta": delta},
        ).fetchone()
        db.commit()
        return int(result[0]) if result else STARTING_TRUST

    # Non-PG: read-modify-write.
    schema = kya_user_trust.schema
    table_ref = f"{schema}.kya_user_trust" if schema else "kya_user_trust"
    row = db.execute(
        text(
            f"SELECT trust_score, signal_counts FROM {table_ref} "
            f"WHERE tenant_id = :tid AND user_id = :uid"
        ),
        {"tid": tenant_id, "uid": user_id},
    ).fetchone()

    if row is None:
        new_score = _apply_delta(STARTING_TRUST, delta)
        counts = {signal_kind: 1}
    else:
        existing = row[1]
        if isinstance(existing, str):
            import json as _json
            try:
                existing = _json.loads(existing)
            except Exception:
                existing = {}
        elif existing is None:
            existing = {}
        counts = dict(existing)
        counts[signal_kind] = int(counts.get(signal_kind, 0)) + 1
        new_score = _apply_delta(int(row[0]), delta)

    now_utc = datetime.now(timezone.utc)
    values = {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "trust_score": new_score,
        "signal_counts": counts,
        ts_col: now_utc,
        "updated_at": now_utc,
    }
    portable_upsert(
        db,
        kya_user_trust,
        values,
        conflict_cols=("tenant_id", "user_id"),
        update_cols=("trust_score", "signal_counts", ts_col, "updated_at"),
    )
    db.commit()
    return new_score


def record_user_signal(
    db,
    tenant_id: str,
    user_id: str,
    signal_kind: str,
) -> int:
    """Record a rogue signal attributed to a user. Decrements trust by the
    signal-kind weight, increments the per-signal counter, mirrors to a
    Valkey windowed counter for real-time burst detection. Returns the
    new trust score.

    `signal_kind` should be one of SIGNAL_DELTAS keys; unknown kinds default
    to a -2 conservative penalty.
    """
    delta = SIGNAL_DELTAS.get(signal_kind, -2)
    new_score = _upsert_with_delta(db, tenant_id, user_id, signal_kind, delta, is_signal=True)
    # Mirror to Valkey windowed counters for live dashboards (1m, 5m, 15m, 1h, 24h, 7d)
    try:
        from .realtime import WINDOWS, _get_redis

        r = _get_redis()
        if r is not None:
            pipe = r.pipeline()
            for window, (_w, ttl_sec) in WINDOWS.items():
                k = f"kya:user:{tenant_id}:{user_id}:{signal_kind}:{window}"
                pipe.incr(k)
                pipe.expire(k, ttl_sec)
            pipe.execute()
    except Exception as exc:
        logger.debug("[KYU] Valkey mirror failed: %s", exc)
    logger.info(
        "[KYU] tenant=%s user=%s signal=%s trust=%d",
        tenant_id,
        user_id,
        signal_kind,
        new_score,
    )
    return new_score


def record_user_clean(db, tenant_id: str, user_id: str) -> int:
    """Tick the trust score upward for a cooperative invocation. Used by
    the agent dispatch path on successful, signal-free completions. Bounded
    by MAX_TRUST so a long-running user can recover from past dings.
    """
    delta = SIGNAL_DELTAS["clean_invocation"]
    return _upsert_with_delta(db, tenant_id, user_id, "clean_invocation", delta, is_signal=False)
