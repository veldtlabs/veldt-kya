"""
KYP — Know Your Principal.

Generalization of KYU (per-user trust) to track any principal that can
drive an agent action — humans, other agents, or service accounts.

Principal taxonomy
------------------
    user             — a human user (UUID id, stored as string)
    agent            — another agent (agent_key id)
    service_account  — automated service / cron / pipeline

Same trust mechanics across all three:
  - Start at STARTING_TRUST (50)
  - Signal events decrement; clean events increment
  - Bounded 0-100
  - Bucket: trusted (>=75) / neutral (>=40) / risky (>=15) / blocked

Backend portability
-------------------
ORM-modeled — works on PostgreSQL, SQLite, DuckDB, MySQL. Trust upserts
use a portable read-modify-write pattern (Python-side merge of
`signal_counts` and `attributes`) instead of PG-specific `ON CONFLICT
... jsonb_set(...)` so the SDK runs on any SQLAlchemy backend.

Storage
-------
kya_principal_trust:
    tenant_id, principal_kind, principal_id  — composite primary key
    trust_score, signal_counts (JSON), actor_human_id, attributes (JSON)
    last_signal_at,  -- event-time of the most-recent signal
    last_clean_at,   -- event-time of the most-recent clean event
    created_at,      -- ingest time of the FIRST record for this principal
    updated_at       -- ingest time of the last upsert

Public API
----------
    ensure_principal_table(db)
    record_principal_signal(db, tenant_id, principal_kind, principal_id, signal_kind,
                            actor_human_id=None, attributes=None,
                            occurred_at=None) -> int
    record_principal_clean(db, tenant_id, principal_kind, principal_id) -> int
    get_principal_trust(db, ...) -> PrincipalTrust
    list_principals(db, tenant_id, kind=None, limit=100) -> list[dict]
    seed_trust_gauge_from_db(db, tenant_id=None, limit=5000) -> int
    recompute_fleet_metrics(db) -> dict
    get_principal_window_counts(...) -> dict      (Valkey, no DB)
    detect_principal_burst_anomalies(...) -> list (Valkey, no DB)
"""

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

try:
    from sqlalchemy import (
        JSON,
        DateTime,
        Integer,
        String,
        Text,
        func,
        select,
    )
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    _HAS_SQLALCHEMY = True
except ImportError:  # pragma: no cover
    _HAS_SQLALCHEMY = False


logger = logging.getLogger(__name__)


from .users import MAX_TRUST, MIN_TRUST, SIGNAL_DELTAS, STARTING_TRUST, bucket_for_trust

#: Canonical principal kinds. Additive over time — never remove or
#: rename a value, because existing rows depend on the literal string.
#:
#: KYA models *governed autonomy*: any actor that can take an
#: autonomous action is a principal, and the same evidence /
#: attribution / trust model applies regardless of what kind of
#: thing the actor is. The vocabulary is flat and granular because a
#: drone's lineage can include an AI agent, so the two must be
#: distinguishable.
#:
#: Existing kinds (since v0.1.0):
#:     ``user``             — human operators
#:     ``agent``            — software AI agents (LLM-driven or rule-driven)
#:     ``service_account``  — non-human service identity (k8s SA, machine credential)
#:
#: Autonomy kinds (added v0.1.8):
#:     ``drone``             — UAS (ArduPilot, PX4, ...)
#:     ``robot``             — physical robotic systems (industrial arms, AGVs)
#:     ``vehicle``           — ground / surface / sub-surface autonomous vehicles
#:     ``plc``               — programmable logic controllers (industrial automation)
#:     ``controller``        — mission / fleet orchestrators that aren't AI agents
#:     ``sensor``            — IoT sensors emitting trust-relevant signals
#:     ``actuator``          — end effectors (servos, grippers, valves)
#:     ``lakehouse_job``     — autonomous data pipelines / scheduled jobs
#:     ``machine_identity``  — generic machine identity catch-all
#:     ``autonomous_system`` — *composed* principal representing a whole
#:                             mission / fleet / cell whose members are
#:                             themselves principals. Example: ``mission_alpha``
#:                             whose ``attributes.lineage`` lists the human
#:                             operator, the controller, the planner agent,
#:                             and each drone. Use this kind when you want
#:                             to score / sign at the system level alongside
#:                             per-member rows.
#:
#: The ``attributes`` JSON column on ``kya_principal_trust`` carries
#: kind-specific metadata + the authority chain. Convention:
#:
#:     attributes = {
#:         "asset_type": "drone",                  # human-readable kind
#:         "protocol":   "mavlink",                # transport / dialect
#:         "platform":   "ardupilot",              # vendor / firmware
#:         "lineage": [                            # delegation chain, root first
#:             {"kind": "user",        "id": "op_jane"},
#:             {"kind": "controller",  "id": "mission_alpha"},
#:             {"kind": "agent",       "id": "planner_v2"}
#:         ],
#:         # ... any protocol-specific fields (sysid/compid, node_id, ...)
#:     }
#:
#: Recording lineage is OPTIONAL — leaving it out keeps the row as a
#: top-level principal. When present it lets the bridge propagate
#: trust deltas up the chain and lets evidence packs cover an entire
#: authority graph in one signed deliverable.
#:
#: Composite actions / interactions
#: --------------------------------
#: An action authorized by a user *through* an agent *on* a drone is
#: NOT modeled as a single "composite principal" — that would lose
#: attributability. Instead, every action has:
#:
#:     * one **primary principal**  — the immediate actor whose
#:       trust score moves, e.g. ``drone:uav_002``
#:     * a **lineage** carried in ``attributes.lineage`` — every
#:       upstream party with shared accountability
#:     * an optional **actor_human_id** column — the ultimate human
#:       on the hook (set when known; helps regulators read the
#:       trust ledger in plain language)
#:
#: Peer-to-peer messages between principals (agent-to-agent talk)
#: write two evidence rows joined by a shared ``correlation_id``; no
#: synthetic "interaction principal" is created. This keeps the
#: ledger interpretable: every row names exactly one accountable
#: actor, and joint accountability is reconstructed by walking
#: lineage + correlation_id rather than hidden inside an opaque
#: composite key.
#:
#: Identifier scopes (top-down)
#: ----------------------------
#: Every action in KYA is reachable through a stack of identifiers,
#: each answering a different question:
#:
#:     ``tenant_id``                  -- whose data is this?
#:     ``principal_kind`` + ``principal_id``
#:                                    -- who/what acted? (the actor)
#:     autonomous_system principal    -- what composed system does
#:                                       this actor structurally belong to?
#:                                       (resolved via ``kya.principal_edges``
#:                                       ``walk_ancestors``)
#:     ``correlation_id``             -- which specific operation /
#:                                       session / mission run was this?
#:                                       (lives on kya_invocations +
#:                                       kya_evidence; ties actions across
#:                                       principals)
#:     ``invocation_id``              -- which call?
#:     ``evidence_id``                -- which signed row?
#:
#: For a drone shared across two missions, ``walk_ancestors`` finds
#: both ``autonomous_system`` umbrellas; ``correlation_id`` on the
#: invocation row picks the specific mission run the action belonged
#: to. No new "operation_id" / "session_id" column is needed —
#: ``correlation_id`` already covers cross-principal session
#: grouping.
PRINCIPAL_KINDS: tuple[str, ...] = (
    # Existing
    "user",
    "agent",
    "service_account",
    # Autonomy (v0.1.8)
    "drone",
    "robot",
    "vehicle",
    "plc",
    "controller",
    "sensor",
    "actuator",
    "lakehouse_job",
    "machine_identity",
    "autonomous_system",
)

# ── Runtime extensibility ───────────────────────────────────────────
#
# Vendors / integrators can register new principal kinds without
# modifying KYA source. Two paths:
#
#   1) Env var (declarative, no code):
#        KYA_PRINCIPAL_KINDS_EXTRA=swarm,satellite,iot_gateway
#
#   2) Programmatic at startup (for SDK users):
#        from kya.principals import register_principal_kind
#        register_principal_kind("swarm")
#
# Both feed the same in-process registry. Validation reads the
# registry rather than the static ``PRINCIPAL_KINDS`` tuple, so an
# unknown kind passed to ``record_principal_signal`` is only
# rejected if it isn't in the *registered* set.
#
# Naming rules (enforced by ``register_principal_kind``):
#   * lowercase ASCII letters, digits, underscores
#   * length 1..20 (matches the VARCHAR(20) column width)
#   * cannot start with a digit
#
# These rules keep the wire format predictable for downstream
# consumers (dashboards, exports, attack-chain rules).

_KIND_REGEX = re.compile(r"^[a-z][a-z0-9_]{0,19}$")


def _initial_registered_kinds() -> set[str]:
    extras: set[str] = set()
    raw = os.environ.get("KYA_PRINCIPAL_KINDS_EXTRA", "").strip()
    if raw:
        for k in raw.split(","):
            k = k.strip()
            if k and _KIND_REGEX.match(k):
                extras.add(k)
            elif k:
                logger.warning(
                    "[KYP-KINDS] ignoring malformed extra kind %r from "
                    "KYA_PRINCIPAL_KINDS_EXTRA — must match %s",
                    k, _KIND_REGEX.pattern,
                )
    return set(PRINCIPAL_KINDS) | extras


_REGISTERED_PRINCIPAL_KINDS: set[str] = _initial_registered_kinds()


def register_principal_kind(kind: str) -> None:
    """Register an additional principal kind for the lifetime of
    this process.

    Idempotent. Raises ``ValueError`` if the kind violates the
    naming rules (lowercase ASCII / digits / underscore, length
    1..20, no leading digit).

    Use this at SDK startup to add domain-specific principal kinds
    that your fleet emits but that aren't in the default vocabulary
    yet. For deploy-time declaration without code changes, prefer
    the ``KYA_PRINCIPAL_KINDS_EXTRA`` env var.
    """
    if not isinstance(kind, str) or not _KIND_REGEX.match(kind):
        raise ValueError(
            f"invalid principal_kind {kind!r}; must match "
            f"{_KIND_REGEX.pattern} (lowercase ASCII letters, digits, "
            f"underscore; 1-20 chars; no leading digit)")
    _REGISTERED_PRINCIPAL_KINDS.add(kind)


def is_valid_principal_kind(kind: str) -> bool:
    """True if ``kind`` is known to the registry — either in the
    default ``PRINCIPAL_KINDS`` tuple or added via
    :func:`register_principal_kind` or the
    ``KYA_PRINCIPAL_KINDS_EXTRA`` env var."""
    return kind in _REGISTERED_PRINCIPAL_KINDS


def registered_principal_kinds() -> tuple[str, ...]:
    """Snapshot of every kind currently accepted by the registry.
    Useful for tests / introspection / building dashboards that
    enumerate the full vocabulary."""
    return tuple(sorted(_REGISTERED_PRINCIPAL_KINDS))

# Schema qualifier — PG only. Defaults to None (= dialect's default
# namespace) as of v0.1.6; set KYA_VERSIONS_SCHEMA in the environment
# to pin tables to a named schema.
_PG_SCHEMA = os.getenv("KYA_VERSIONS_SCHEMA") or None


def _require_sqlalchemy() -> None:
    if not _HAS_SQLALCHEMY:
        raise RuntimeError(
            "kya.principals requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


# ── Prometheus gauges (separate from DB — no portability concern) ───
_TRUST_GAUGE = None


def _ensure_trust_gauge():
    global _TRUST_GAUGE
    if _TRUST_GAUGE is not None:
        return
    try:
        from prometheus_client import Gauge

        kwargs = dict(
            name="veldt_kya_principal_trust_score",
            documentation=(
                "Current trust score per principal (0-100). Single rollup "
                "of all signal deltas — risk + rogue + governance flow here."
            ),
            labelnames=["tenant_id", "principal_kind", "principal_id"],
        )
        for mode in ("mostrecent", "max"):
            try:
                _TRUST_GAUGE = Gauge(**kwargs, multiprocess_mode=mode)
                break
            except (TypeError, ValueError) as exc:
                if "multiprocess_mode" in str(exc):
                    continue
                if "Duplicated" in str(exc) or "already" in str(exc).lower():
                    from prometheus_client import REGISTRY

                    _TRUST_GAUGE = REGISTRY._names_to_collectors.get(
                        "veldt_kya_principal_trust_score"
                    )
                    break
                continue
        if _TRUST_GAUGE is None:
            try:
                _TRUST_GAUGE = Gauge(**kwargs)
            except ValueError:
                from prometheus_client import REGISTRY

                _TRUST_GAUGE = REGISTRY._names_to_collectors.get("veldt_kya_principal_trust_score")
    except ImportError:
        pass


_FLEET_MEAN_GAUGE = None
_FLEET_COUNT_GAUGE = None
_FLEET_BELOW_GAUGE = None
_FLEET_THRESHOLD = 50


def _ensure_fleet_gauges():
    global _FLEET_MEAN_GAUGE, _FLEET_COUNT_GAUGE, _FLEET_BELOW_GAUGE
    if _FLEET_MEAN_GAUGE is not None:
        return
    try:
        from prometheus_client import Gauge
    except ImportError:
        return

    def _make(name, doc, labels):
        kw = dict(name=name, documentation=doc, labelnames=labels)
        for mode in ("mostrecent", "max"):
            try:
                return Gauge(**kw, multiprocess_mode=mode)
            except (TypeError, ValueError) as exc:
                if "multiprocess_mode" in str(exc):
                    continue
                if "Duplicated" in str(exc) or "already" in str(exc).lower():
                    from prometheus_client import REGISTRY

                    return REGISTRY._names_to_collectors.get(name)
        try:
            return Gauge(**kw)
        except ValueError:
            from prometheus_client import REGISTRY

            return REGISTRY._names_to_collectors.get(name)

    _FLEET_MEAN_GAUGE = _make(
        "veldt_kya_fleet_trust_mean",
        "Fleet-wide mean principal trust score per tenant (0-100).",
        ["tenant_id", "principal_kind"],
    )
    _FLEET_COUNT_GAUGE = _make(
        "veldt_kya_fleet_principal_count",
        "Number of principals fed into the fleet trust mean.",
        ["tenant_id", "principal_kind"],
    )
    _FLEET_BELOW_GAUGE = _make(
        "veldt_kya_fleet_agents_below_threshold",
        f"Number of principals with trust below {_FLEET_THRESHOLD} per tenant.",
        ["tenant_id", "principal_kind"],
    )


def _set_trust_gauge(tenant_id: str, principal_kind: str, principal_id: str, score: int) -> None:
    _ensure_trust_gauge()
    if _TRUST_GAUGE is None:
        return
    try:
        _TRUST_GAUGE.labels(
            tenant_id=tenant_id or "unknown",
            principal_kind=principal_kind or "unknown",
            principal_id=principal_id or "unknown",
        ).set(int(score))
    except Exception as exc:
        logger.debug("[KYP] trust gauge set failed: %s", exc)


# ── ORM model ───────────────────────────────────────────────────────
if _HAS_SQLALCHEMY:
    # JSONB on PG (indexable + queryable), plain JSON on other dialects.
    _JsonType = JSON().with_variant(JSONB(), "postgresql")

    class _Base(DeclarativeBase):
        pass

    class _PrincipalRow(_Base):
        __tablename__ = "kya_principal_trust"

        # Composite natural primary key — the identity of a principal
        # IS (tenant, kind, id). No surrogate `id` column needed; Veldt's
        # existing PG table has one but create_all is idempotent so the
        # legacy column survives untouched.
        tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
        principal_kind: Mapped[str] = mapped_column(String(20), primary_key=True)
        principal_id: Mapped[str] = mapped_column(String(200), primary_key=True)

        trust_score: Mapped[int] = mapped_column(Integer, nullable=False, default=STARTING_TRUST)
        signal_counts: Mapped[dict] = mapped_column(_JsonType, nullable=False, default=dict)
        actor_human_id: Mapped[str | None] = mapped_column(Text, nullable=True)
        attributes: Mapped[dict] = mapped_column(_JsonType, nullable=False, default=dict)

        # Phase 4b — IdP binding fields. Optional structured pointers
        # from KYA's internal principal_id to the upstream Identity
        # Provider's view of the same principal. Lets dashboards link
        # a KYA trust score back to the Okta/Auth0/Keycloak/SPIFFE
        # user record without parsing the `attributes` JSON blob.
        # All NULL by default; populated by bind_principal_to_idp()
        # or directly by record_principal_signal(idp_subject=...).
        idp_subject: Mapped[str | None] = mapped_column(
            String(255), nullable=True
        )
        idp_issuer: Mapped[str | None] = mapped_column(
            String(255), nullable=True
        )
        idp_kind: Mapped[str | None] = mapped_column(
            String(50), nullable=True
        )
        federated_id: Mapped[str | None] = mapped_column(
            String(500), nullable=True
        )

        # Event-time of the most-recent signal / clean event.
        last_signal_at: Mapped[datetime | None] = mapped_column(
            DateTime(timezone=True), nullable=True
        )
        last_clean_at: Mapped[datetime | None] = mapped_column(
            DateTime(timezone=True), nullable=True
        )

        # Ingest-time bookkeeping.
        created_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        )
        updated_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        )

        __table_args__ = (
            # Phase 4d fix: the trust_score index and the
            # idp_subject index are INTENTIONALLY OMITTED from
            # __table_args__. DuckDB rejects UPDATE on any indexed
            # column, which would break the ON CONFLICT DO UPDATE
            # path that record_principal_signal uses. The indexes
            # get added back conditionally for non-DuckDB dialects
            # via ALTER TABLE in _apply_idp_binding_migrations()
            # below. Without the index, DuckDB does a full-scan
            # lookup; acceptable at typical KYA scale (thousands
            # of principals per tenant).
        )


def _bind_schema(bind) -> None:
    table = _PrincipalRow.__table__
    target = _PG_SCHEMA if bind.dialect.name == "postgresql" else None
    if table.schema != target:
        table.schema = target


def ensure_principal_table(db) -> None:
    """Create kya_principal_trust + index if absent. Idempotent.

    Schema selection is dialect-aware. Uses the session's own connection
    so DDL participates in the same transaction (DuckDB compat).

    Also applies additive migrations (Phase 4b — IdP binding columns)
    so deployments upgrading from older KYA pick up the new columns
    without dropping the table.
    """
    _require_sqlalchemy()
    conn = db.connection()
    _bind_schema(conn.engine)
    _Base.metadata.create_all(bind=conn, tables=[_PrincipalRow.__table__])
    _apply_idp_binding_migrations(db)


def _apply_idp_binding_migrations(db) -> None:
    """Phase 4b additive ALTER for existing deployments. Idempotent
    via IF NOT EXISTS guards. SQLite >= 3.35 supports ADD COLUMN IF
    NOT EXISTS natively; older versions raise UndefinedColumn which
    apply_migrations swallows + logs."""
    from ._migrations import apply_migrations
    dialect = db.get_bind().dialect.name
    # PG uses the schema configured via KYA_VERSIONS_SCHEMA env
    # (default: dialect's default schema; override via KYA_VERSIONS_SCHEMA
    # env var). Other backends use the default namespace.
    # Hardcoding a schema name here would mismatch any deployment that
    # set KYA_VERSIONS_SCHEMA="" or to a custom name.
    qual = (f"{_PG_SCHEMA}."
            if dialect == "postgresql" and _PG_SCHEMA
            else "")
    table = f"{qual}kya_principal_trust"
    migrations = [
        f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
        f"idp_subject VARCHAR(255);",
        f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
        f"idp_issuer VARCHAR(255);",
        f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
        f"idp_kind VARCHAR(50);",
        f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
        f"federated_id VARCHAR(500);",
    ]
    # Dialect-specific index — DuckDB rejects ON CONFLICT DO UPDATE
    # on any indexed column, so we skip the index there and accept
    # full-scan lookups (DuckDB is typically used analytical / smaller
    # working sets). PG / MySQL / SQLite get the indexed-lookup path.
    if dialect != "duckdb":
        migrations.extend([
            # Tenant trust-distribution queries (rank principals
            # by score). Phase 4d: lives here (conditional ALTER)
            # instead of __table_args__ so DuckDB skips it.
            f"CREATE INDEX IF NOT EXISTS "
            f"idx_kya_principal_trust_tenant_kind_score "
            f"ON {table} (tenant_id, principal_kind, trust_score);",
            # Phase 4b lookup-by-IdP-subject.
            f"CREATE INDEX IF NOT EXISTS "
            f"idx_kya_principal_trust_tenant_idp_subject "
            f"ON {table} (tenant_id, idp_subject);",
        ])
    apply_migrations(db, "kya_principal_trust", migrations)


# ── Dataclass (consumer-facing) ─────────────────────────────────────


@dataclass
class PrincipalTrust:
    tenant_id: str
    principal_kind: str
    principal_id: str
    trust_score: int = STARTING_TRUST
    bucket: str = "neutral"
    signal_counts: dict = field(default_factory=dict)
    actor_human_id: str | None = None
    attributes: dict = field(default_factory=dict)
    last_signal_at: str | None = None
    last_clean_at: str | None = None
    updated_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "principal_kind": self.principal_kind,
            "principal_id": self.principal_id,
            "trust_score": self.trust_score,
            "bucket": self.bucket,
            "signal_counts": self.signal_counts,
            "actor_human_id": self.actor_human_id,
            "attributes": self.attributes,
            "last_signal_at": self.last_signal_at,
            "last_clean_at": self.last_clean_at,
            "updated_at": self.updated_at,
        }


# ── Read ────────────────────────────────────────────────────────────


def get_principal_trust(
    db,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
) -> PrincipalTrust:
    """Fetch one principal's trust row. Returns starting defaults when no
    row exists (i.e., no signals or clean events recorded yet)."""
    _require_sqlalchemy()
    ensure_principal_table(db)

    stmt = (
        select(_PrincipalRow)
        .where(_PrincipalRow.tenant_id == tenant_id)
        .where(_PrincipalRow.principal_kind == principal_kind)
        .where(_PrincipalRow.principal_id == principal_id)
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        return PrincipalTrust(
            tenant_id=tenant_id,
            principal_kind=principal_kind,
            principal_id=principal_id,
            trust_score=STARTING_TRUST,
            bucket=bucket_for_trust(STARTING_TRUST),
        )

    return PrincipalTrust(
        tenant_id=tenant_id,
        principal_kind=principal_kind,
        principal_id=principal_id,
        trust_score=int(row.trust_score),
        bucket=bucket_for_trust(int(row.trust_score)),
        signal_counts=dict(row.signal_counts or {}),
        actor_human_id=row.actor_human_id,
        attributes=dict(row.attributes or {}),
        last_signal_at=_to_iso(row.last_signal_at),
        last_clean_at=_to_iso(row.last_clean_at),
        updated_at=_to_iso(row.updated_at),
    )


def list_principals(
    db,
    tenant_id: str,
    kind: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Tenant-scoped. Sorted by lowest trust first (riskiest at top)."""
    _require_sqlalchemy()
    ensure_principal_table(db)

    stmt = select(_PrincipalRow).where(_PrincipalRow.tenant_id == tenant_id)
    if kind:
        stmt = stmt.where(_PrincipalRow.principal_kind == kind)
    stmt = stmt.order_by(
        _PrincipalRow.trust_score.asc(),
        _PrincipalRow.updated_at.desc(),
    ).limit(limit)

    out = []
    for row in db.execute(stmt).scalars().all():
        score = int(row.trust_score)
        out.append(
            {
                "principal_kind": row.principal_kind,
                "principal_id": row.principal_id,
                "trust_score": score,
                "bucket": bucket_for_trust(score),
                "signal_counts": dict(row.signal_counts or {}),
                "actor_human_id": row.actor_human_id,
                "attributes": dict(row.attributes or {}),
                "last_signal_at": _to_iso(row.last_signal_at),
                "last_clean_at": _to_iso(row.last_clean_at),
                "updated_at": _to_iso(row.updated_at),
            }
        )
    return out


# ── Write ───────────────────────────────────────────────────────────


def record_principal_signal(
    db,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    signal_kind: str,
    actor_human_id: str | None = None,
    attributes: dict | None = None,
    occurred_at: datetime | None = None,
) -> int:
    """Record a rogue signal attributed to a principal. Returns the new
    trust score. Mirrors to Valkey windowed counters.

    `occurred_at` — event-time of the signal. Defaults to record-time.
    Supply when replaying signals from a log to keep `last_signal_at`
    semantically correct.

    Portable upsert: SELECT-then-INSERT-or-UPDATE in Python. The
    JSONB-merge atomic ON-CONFLICT pattern (PG-only) is replaced by an
    in-Python dict merge so the same code runs on PG/SQLite/DuckDB/MySQL.
    Trade-off: under high contention two concurrent signals can race on
    `signal_counts`; mitigated by application-level retry if needed.
    """
    if not is_valid_principal_kind(principal_kind):
        logger.debug(
            "[KYP] unregistered principal_kind=%s -- defaulting to 'user'. "
            "Register via KYA_PRINCIPAL_KINDS_EXTRA or "
            "register_principal_kind() to keep the original kind.",
            principal_kind)
        principal_kind = "user"
    if occurred_at is None:
        occurred_at = datetime.now(timezone.utc)

    _require_sqlalchemy()
    ensure_principal_table(db)

    delta = SIGNAL_DELTAS.get(signal_kind, -2)

    # SELECT-then-INSERT/UPDATE has a race: under concurrent mirror
    # writes (e.g. many record_oos_tool_attempt calls via the
    # actor_agent_key path), multiple sessions can both SELECT None and
    # both attempt to INSERT, causing an IntegrityError on the composite
    # PK. We retry with exponential backoff so high-throughput fleets
    # don't silently lose signal counts. 10 retries with jitter handle
    # the worst contention observed in the load test (20 workers × 50
    # ops on the same principal — 99% land).
    import random as _random
    import time as _time

    from sqlalchemy.exc import IntegrityError, OperationalError

    # SQLite/DuckDB: serialize in-process per (tenant, kind, id) to
    # close the lost-update window on the SELECT-merge-UPDATE path.
    # PG/MySQL use SELECT FOR UPDATE below; SQLite/DuckDB lack row
    # locks, so without this lock concurrent mirror writes from
    # different sessions can both read the same row, merge their
    # local increment, then both write — losing one of the increments.
    _inproc_lock = None
    try:
        if db.bind.dialect.name in ("sqlite", "duckdb"):
            from .evidence import _get_chain_lock as _gl
            _inproc_lock = _gl(tenant_id, f"principal:{principal_kind}:{principal_id}")
            _inproc_lock.acquire()
    except Exception:
        _inproc_lock = None

    last_exc: Exception | None = None
    for attempt in range(30):
        stmt = (
            select(_PrincipalRow)
            .where(_PrincipalRow.tenant_id == tenant_id)
            .where(_PrincipalRow.principal_kind == principal_kind)
            .where(_PrincipalRow.principal_id == principal_id)
        )
        # SELECT FOR UPDATE on PG/MySQL serializes the read-modify-write
        # against concurrent writers. Without this, two workers can both
        # SELECT the same row, both merge their increment locally, then
        # both UPDATE — and the second write silently overwrites the
        # first (lost-update anomaly).
        try:
            if db.bind.dialect.name in ("postgresql", "mysql"):
                stmt = stmt.with_for_update()
        except Exception:
            pass
        try:
            row = db.execute(stmt).scalar_one_or_none()
        except Exception:
            db.rollback()
            raise

        if row is None:
            new_score = max(MIN_TRUST, min(MAX_TRUST, STARTING_TRUST + delta))
            row = _PrincipalRow(
                tenant_id=tenant_id,
                principal_kind=principal_kind,
                principal_id=principal_id,
                trust_score=new_score,
                signal_counts={signal_kind: 1},
                actor_human_id=actor_human_id,
                attributes=dict(attributes or {}),
                last_signal_at=occurred_at,
            )
            db.add(row)
        else:
            new_score = max(MIN_TRUST, min(MAX_TRUST, int(row.trust_score) + delta))
            merged_counts = dict(row.signal_counts or {})
            merged_counts[signal_kind] = merged_counts.get(signal_kind, 0) + 1
            merged_attrs = {**(dict(row.attributes or {})), **(attributes or {})}

            row.trust_score = new_score
            row.signal_counts = merged_counts
            if actor_human_id:
                row.actor_human_id = actor_human_id
            row.attributes = merged_attrs
            row.last_signal_at = occurred_at
            row.updated_at = func.now()

        try:
            db.commit()
            break
        except (IntegrityError, OperationalError) as exc:
            last_exc = exc
            db.rollback()
            if attempt == 9:
                if _inproc_lock is not None:
                    _inproc_lock.release()
                raise
            # Sleep with exponential backoff + jitter so retries don't
            # synchronize across workers and re-collide on the same tick.
            _time.sleep(0.001 * (2 ** attempt) + _random.uniform(0, 0.002))
            continue

    if _inproc_lock is not None:
        _inproc_lock.release()

    _set_trust_gauge(tenant_id, principal_kind, principal_id, new_score)

    # Valkey windowed mirror — same pattern as users.py
    try:
        from .realtime import WINDOWS, _get_redis

        r = _get_redis()
        if r is not None:
            pipe = r.pipeline()
            for window, (_w, ttl_sec) in WINDOWS.items():
                k = f"kya:principal:{tenant_id}:{principal_kind}:{principal_id}:{signal_kind}:{window}"
                pipe.incr(k)
                pipe.expire(k, ttl_sec)
            pipe.execute()
    except Exception as exc:
        logger.debug("[KYP] Valkey mirror failed: %s", exc)

    logger.info(
        "[KYP] tenant=%s %s::%s signal=%s trust=%d",
        tenant_id,
        principal_kind,
        principal_id,
        signal_kind,
        new_score,
    )
    try:
        from . import _emit, telemetry
        telemetry.record_event("record_principal_signal", kind=signal_kind)
        if _emit.is_enabled():
            _emit.emit(
                "kya_principal_trust",
                _emit.safe_row({
                    "tenant_id": tenant_id,
                    "principal_kind": principal_kind,
                    "principal_id": principal_id,
                    "signal_kind": signal_kind,
                    "trust_score": new_score,
                    "actor_human_id": actor_human_id,
                    "attributes": attributes,
                    "occurred_at": occurred_at,
                }),
            )
    except Exception:
        pass
    return new_score


def record_principal_clean(
    db,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    occurred_at: datetime | None = None,
) -> int:
    """Tick principal trust upward for a cooperative invocation.

    Mirrors the same upsert + Valkey + gauge plumbing as
    `record_principal_signal` so behavior stays symmetric.
    """
    if not is_valid_principal_kind(principal_kind):
        principal_kind = "user"
    if occurred_at is None:
        occurred_at = datetime.now(timezone.utc)

    _require_sqlalchemy()
    ensure_principal_table(db)
    delta = SIGNAL_DELTAS.get("clean_invocation", +1)

    stmt = (
        select(_PrincipalRow)
        .where(_PrincipalRow.tenant_id == tenant_id)
        .where(_PrincipalRow.principal_kind == principal_kind)
        .where(_PrincipalRow.principal_id == principal_id)
    )
    row = db.execute(stmt).scalar_one_or_none()

    if row is None:
        new_score = max(MIN_TRUST, min(MAX_TRUST, STARTING_TRUST + delta))
        row = _PrincipalRow(
            tenant_id=tenant_id,
            principal_kind=principal_kind,
            principal_id=principal_id,
            trust_score=new_score,
            signal_counts={"clean_invocation": 1},
            last_clean_at=occurred_at,
        )
        db.add(row)
    else:
        new_score = max(MIN_TRUST, min(MAX_TRUST, int(row.trust_score) + delta))
        merged_counts = dict(row.signal_counts or {})
        merged_counts["clean_invocation"] = merged_counts.get("clean_invocation", 0) + 1
        row.trust_score = new_score
        row.signal_counts = merged_counts
        row.last_clean_at = occurred_at
        row.updated_at = func.now()

    db.commit()
    _set_trust_gauge(tenant_id, principal_kind, principal_id, new_score)

    # Mirror to Valkey windowed counters — parity with record_principal_signal
    try:
        from .realtime import WINDOWS, _get_redis

        r = _get_redis()
        if r is not None:
            pipe = r.pipeline()
            for window, (_w, ttl_sec) in WINDOWS.items():
                k = (
                    f"kya:principal:{tenant_id}:{principal_kind}:"
                    f"{principal_id}:clean_invocation:{window}"
                )
                pipe.incr(k)
                pipe.expire(k, ttl_sec)
            pipe.execute()
    except Exception as exc:
        logger.debug("[KYP] Valkey mirror failed: %s", exc)

    try:
        from . import _emit, telemetry
        telemetry.record_event("record_principal_signal", kind="clean_invocation")
        if _emit.is_enabled():
            _emit.emit(
                "kya_principal_trust",
                _emit.safe_row({
                    "tenant_id": tenant_id,
                    "principal_kind": principal_kind,
                    "principal_id": principal_id,
                    "signal_kind": "clean_invocation",
                    "trust_score": new_score,
                    "occurred_at": occurred_at,
                }),
            )
    except Exception:
        pass
    return new_score


# ── Fleet rollups (portable Python aggregation) ─────────────────────


def recompute_fleet_metrics(db) -> dict:
    """Recompute the three fleet-rollup gauges from current DB state.
    Portable Python aggregation (was PG-only `COUNT(*) FILTER (WHERE)`).
    Returns a summary dict.

    Idempotent + cheap — safe to call on a periodic timer.
    """
    _require_sqlalchemy()
    _ensure_fleet_gauges()
    if _FLEET_MEAN_GAUGE is None:
        return {"tenants": 0, "rows_aggregated": 0, "ok": False}
    try:
        ensure_principal_table(db)
        stmt = select(
            _PrincipalRow.tenant_id,
            _PrincipalRow.principal_kind,
            _PrincipalRow.trust_score,
        )
        rows = db.execute(stmt).all()
        # Aggregate in Python — (tenant_id, kind) → (sum, count, below)
        buckets: dict[tuple[str, str], list[int]] = {}
        for tid, kind, score in rows:
            key = (str(tid), str(kind))
            agg = buckets.setdefault(key, [0, 0, 0])
            agg[0] += int(score or 0)  # sum
            agg[1] += 1  # count
            if int(score or 0) < _FLEET_THRESHOLD:
                agg[2] += 1  # below threshold

        for (tid, kind), (total, count, below) in buckets.items():
            try:
                labels = {"tenant_id": tid, "principal_kind": kind}
                mean = round(total / count, 2) if count else 0.0
                _FLEET_MEAN_GAUGE.labels(**labels).set(mean)
                _FLEET_COUNT_GAUGE.labels(**labels).set(count)
                _FLEET_BELOW_GAUGE.labels(**labels).set(below)
            except Exception:
                continue
        return {
            "tenants": len({k[0] for k in buckets}),
            "rows_aggregated": sum(v[1] for v in buckets.values()),
            "ok": True,
        }
    except Exception as exc:
        logger.warning("[KYP] recompute_fleet_metrics failed: %s", exc)
        return {"tenants": 0, "rows_aggregated": 0, "ok": False, "error": str(exc)}


def seed_trust_gauge_from_db(db, tenant_id: str | None = None, limit: int = 5000) -> int:
    """Bootstrap the trust gauge from durable DB rows so Grafana can
    chart trust BEFORE the next signal fires. Portable across backends.
    """
    _require_sqlalchemy()
    _ensure_trust_gauge()
    if _TRUST_GAUGE is None:
        return 0
    try:
        ensure_principal_table(db)
        stmt = select(
            _PrincipalRow.tenant_id,
            _PrincipalRow.principal_kind,
            _PrincipalRow.principal_id,
            _PrincipalRow.trust_score,
        )
        if tenant_id:
            stmt = stmt.where(_PrincipalRow.tenant_id == tenant_id)
        stmt = stmt.order_by(_PrincipalRow.updated_at.desc()).limit(limit)
        rows = db.execute(stmt).all()
        count = 0
        for tid, kind, pid, score in rows:
            try:
                _TRUST_GAUGE.labels(
                    tenant_id=str(tid),
                    principal_kind=str(kind),
                    principal_id=str(pid),
                ).set(int(score or 0))
                count += 1
            except Exception:
                continue
        logger.info("[KYP] seeded trust gauge with %d principals", count)
        return count
    except Exception as exc:
        logger.warning("[KYP] seed_trust_gauge_from_db failed: %s", exc)
        return 0


# ── Time-windowed signal counts (Valkey — no DB) ────────────────────


_BURST_SIGNAL_KINDS = (
    "rbac_refusal",
    "oos_tool",
    "governance_block",
    "cross_tenant",
    "data_leak",
    "injection_attempt",
)


def get_principal_window_counts(
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    signals: list[str] | None = None,
) -> dict:
    """Return per-window signal counts for one principal.

    Fail-soft. Empty dict when Valkey isn't reachable.
    """
    from .realtime import WINDOWS, _get_redis

    sigs = signals or list(_BURST_SIGNAL_KINDS)
    out = {w: {s: 0 for s in sigs} for w in WINDOWS}
    r = _get_redis()
    if r is None:
        return out
    try:
        pipe = r.pipeline()
        keys: list[tuple[str, str]] = []
        for window in WINDOWS:
            for sig in sigs:
                k = f"kya:principal:{tenant_id}:{principal_kind}:{principal_id}:{sig}:{window}"
                pipe.get(k)
                keys.append((window, sig))
        results = pipe.execute()
        for (window, sig), val in zip(keys, results):
            out[window][sig] = int(val) if val else 0
    except Exception as exc:
        logger.debug("[KYP] get_principal_window_counts failed: %s", exc)
    return out


_PRINCIPAL_BURST_THRESHOLDS = {
    "oos_tool": {"1m": 3, "5m": 5, "15m": 8, "1h": 12, "24h": 40},
    "rbac_refusal": {"1m": 3, "5m": 5, "15m": 8, "1h": 12, "24h": 40},
    "governance_block": {"1m": 5, "5m": 8, "15m": 15, "1h": 25, "24h": 100},
}
_PRINCIPAL_CRITICAL_ALWAYS = {"cross_tenant", "data_leak", "injection_attempt"}
_WINDOW_ORDER = ("1m", "5m", "15m", "1h", "24h")


def detect_principal_burst_anomalies(
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
) -> list[dict]:
    """Return burst anomalies for one principal."""
    counts = get_principal_window_counts(tenant_id, principal_kind, principal_id)
    anomalies: list[dict] = []

    for sig in _PRINCIPAL_CRITICAL_ALWAYS:
        for window in _WINDOW_ORDER[:3]:
            n = counts.get(window, {}).get(sig, 0)
            if n > 0:
                anomalies.append(
                    {
                        "severity": "critical",
                        "code": f"principal_burst_{sig}_{window}",
                        "message": (
                            f"{principal_kind}={principal_id} triggered {n} "
                            f"{sig} event(s) in the last {window}."
                        ),
                        "detail": {"window": window, "count": n, "signal": sig},
                    }
                )
                break

    for sig, thresholds in _PRINCIPAL_BURST_THRESHOLDS.items():
        fired_window: tuple[str, int, int] | None = None
        for window in _WINDOW_ORDER:
            threshold = thresholds.get(window)
            if threshold is None:
                continue
            n = counts.get(window, {}).get(sig, 0)
            if n >= threshold:
                fired_window = (window, n, threshold)
                break
        if fired_window:
            window, n, threshold = fired_window
            anomalies.append(
                {
                    "severity": "warning",
                    "code": f"principal_burst_{sig}_{window}",
                    "message": (
                        f"{principal_kind}={principal_id} has {n} {sig} "
                        f"signals in the last {window} (>= {threshold})."
                    ),
                    "detail": {
                        "window": window,
                        "count": n,
                        "signal": sig,
                        "threshold": threshold,
                    },
                }
            )

    return anomalies


# ── Helpers ─────────────────────────────────────────────────────────


def _to_iso(dt: Any) -> str | None:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    if hasattr(dt, "tzinfo"):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    return str(dt)
