"""Many-to-many principal relationships.

The :mod:`kya.principals` module gives every actor a row in
``kya_principal_trust`` plus an ``attributes.lineage`` JSON convention
that captures a single delegation chain. That convention covers
tree-shaped authority (one parent per child) and is enough for the
common cases — a drone delegating to its mission controller, an agent
serving exactly one user.

The real world sometimes needs a graph:

* A drone leased between two missions belongs to two parents.
* A robot arm participates in multiple factory cells.
* A service account is shared across several controllers.

This module provides the ``kya_principal_edges`` table to express
many-to-many parent-child relationships between principals, plus a
minimal CRUD + walk API. It coexists with ``attributes.lineage``:

* ``attributes.lineage`` -- denormalised single-chain hint, fast to
  read off a row, populated when the relationship is unambiguous.
* ``kya_principal_edges`` -- source of truth when a principal has
  multiple parents OR when downstream code needs to enumerate
  children / walk descendants programmatically.

Edge kinds
----------
A free vocabulary keyed by ``edge_kind``. Defaults to ``delegation``;
common values:

* ``delegation``   -- parent delegated authority to child (matches lineage).
* ``membership``   -- child is a member of parent (drone in a fleet).
* ``control``      -- parent controls child (PLC operates an actuator).
* ``supervision``  -- parent supervises child (human oversees agent).
* ``composition``  -- child is a component of parent (sensor part of robot).

Vocabularies are intentionally NOT enforced -- vendors register their
own edge kinds without coordinating with KYA. Naming rule (enforced):
lowercase ASCII letters / digits / underscore, length 1..50.

Time-bounded edges
------------------
``expires_at`` is nullable. When set, ``list_children`` /
``list_parents`` filter out edges whose expiry is in the past. This
covers leased / time-shared assets (e.g., "drone D is under controller
A for the next 6 hours") without writing a separate retention job.

Scope: open SDK (v0.1.8)
------------------------
The minimal API ships in v0.1.8. Graph walks (descendants /
ancestors, trust propagation) are intentionally bounded by
``max_depth`` and run in Python -- recursive CTEs land in v0.1.9 when
we have a customer with > 10k edges. Until then, a Python BFS over a
few hundred edges per tenant is cheaper to ship and read than a CTE.
"""
from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

try:
    from sqlalchemy import (
        JSON,
        BigInteger,
        DateTime,
        Index,
        String,
        UniqueConstraint,
        func,
        select,
    )
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    _HAS_SQLALCHEMY = True
except ImportError:  # pragma: no cover
    _HAS_SQLALCHEMY = False

logger = logging.getLogger(__name__)

# Naming rule for edge_kind, matching the principal-kind discipline:
# lowercase ASCII / digits / underscore, length 1..50. Longer than
# principal_kind because edge taxonomies tend to be more verbose
# (e.g., "temporary_delegation").
_EDGE_KIND_REGEX = re.compile(r"^[a-z][a-z0-9_]{0,49}$")

# Default edge kind for one-arg callers — matches ``attributes.lineage``
# semantics, so populating both stays consistent.
DEFAULT_EDGE_KIND = "delegation"

# Schema qualifier -- PG only. Same convention as kya.principals.
_PG_SCHEMA = os.getenv("KYA_VERSIONS_SCHEMA") or None


def _require_sqlalchemy() -> None:
    if not _HAS_SQLALCHEMY:
        raise RuntimeError(
            "kya.principal_edges requires SQLAlchemy. Install with: "
            "pip install 'veldt-kya[persistence]' or 'pip install sqlalchemy'."
        )


# ── ORM ────────────────────────────────────────────────────────────


if _HAS_SQLALCHEMY:

    class _Base(DeclarativeBase):
        pass


    class _PrincipalEdgeRow(_Base):
        """Many-to-many parent -> child relationships between
        principals. Composite uniqueness on
        ``(tenant, parent_kind, parent_id, child_kind, child_id,
        edge_kind)`` so re-inserting an existing edge is idempotent.
        """

        __tablename__ = "kya_principal_edges"
        if _PG_SCHEMA:
            __table_args__ = (
                UniqueConstraint(
                    "tenant_id",
                    "parent_kind", "parent_id",
                    "child_kind", "child_id",
                    "edge_kind",
                    name="uq_kya_principal_edges",
                ),
                Index(
                    "ix_kya_principal_edges_parent",
                    "tenant_id", "parent_kind", "parent_id",
                ),
                Index(
                    "ix_kya_principal_edges_child",
                    "tenant_id", "child_kind", "child_id",
                ),
                {"schema": _PG_SCHEMA},
            )
        else:
            __table_args__ = (
                UniqueConstraint(
                    "tenant_id",
                    "parent_kind", "parent_id",
                    "child_kind", "child_id",
                    "edge_kind",
                    name="uq_kya_principal_edges",
                ),
                Index(
                    "ix_kya_principal_edges_parent",
                    "tenant_id", "parent_kind", "parent_id",
                ),
                Index(
                    "ix_kya_principal_edges_child",
                    "tenant_id", "child_kind", "child_id",
                ),
            )

        id: Mapped[int] = mapped_column(
            BigInteger().with_variant(
                __import__("sqlalchemy").Integer(), "sqlite"),
            primary_key=True, autoincrement=True,
        )
        tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)

        parent_kind: Mapped[str] = mapped_column(String(20), nullable=False)
        parent_id: Mapped[str] = mapped_column(String(200), nullable=False)

        child_kind: Mapped[str] = mapped_column(String(20), nullable=False)
        child_id: Mapped[str] = mapped_column(String(200), nullable=False)

        edge_kind: Mapped[str] = mapped_column(
            String(50), nullable=False, default=DEFAULT_EDGE_KIND,
        )

        attributes: Mapped[dict] = mapped_column(
            JSON, nullable=False, default=dict,
        )

        created_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True),
            nullable=False, server_default=func.now(),
        )
        # NULL = no expiry; otherwise the row is filtered out of
        # walks once ``now() > expires_at``.
        expires_at: Mapped[datetime | None] = mapped_column(
            DateTime(timezone=True), nullable=True,
        )


def ensure_principal_edges_table(db: Any) -> None:
    """Create ``kya_principal_edges`` if it isn't present yet.

    Idempotent. Cheap to call repeatedly (existence check by the
    ORM ``create_all``).
    """
    _require_sqlalchemy()
    _Base.metadata.create_all(
        db.bind, tables=[_PrincipalEdgeRow.__table__],
    )


# ── Public dataclass ──────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PrincipalEdge:
    """One directed edge between principals.

    Endpoints are ``(kind, id)`` pairs that MUST already exist as
    principals (or will exist by the time the bridge dispatches —
    KYA does not enforce referential integrity on principal_edges
    because principals are write-once on first signal).
    """

    tenant_id: str
    parent_kind: str
    parent_id: str
    child_kind: str
    child_id: str
    edge_kind: str = DEFAULT_EDGE_KIND
    attributes: dict = None  # type: ignore[assignment]
    created_at: datetime | None = None
    expires_at: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "parent_kind": self.parent_kind,
            "parent_id": self.parent_id,
            "child_kind": self.child_kind,
            "child_id": self.child_id,
            "edge_kind": self.edge_kind,
            "attributes": dict(self.attributes or {}),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


# ── CRUD ──────────────────────────────────────────────────────────


def _validate_edge_kind(edge_kind: str) -> None:
    if not isinstance(edge_kind, str) or not _EDGE_KIND_REGEX.match(edge_kind):
        raise ValueError(
            f"invalid edge_kind {edge_kind!r}; must match "
            f"{_EDGE_KIND_REGEX.pattern}")


def _row_to_edge(row: Any) -> PrincipalEdge:
    return PrincipalEdge(
        tenant_id=row.tenant_id,
        parent_kind=row.parent_kind, parent_id=row.parent_id,
        child_kind=row.child_kind, child_id=row.child_id,
        edge_kind=row.edge_kind,
        attributes=dict(row.attributes or {}),
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


def add_principal_edge(
    db: Any,
    *,
    tenant_id: str,
    parent_kind: str,
    parent_id: str,
    child_kind: str,
    child_id: str,
    edge_kind: str = DEFAULT_EDGE_KIND,
    attributes: dict | None = None,
    expires_at: datetime | None = None,
) -> PrincipalEdge:
    """Insert an edge (idempotent on the composite uniqueness).

    Same-shape re-insert merges ``attributes`` and refreshes
    ``expires_at`` instead of raising. Returns the resulting
    :class:`PrincipalEdge`.
    """
    _require_sqlalchemy()
    _validate_edge_kind(edge_kind)
    ensure_principal_edges_table(db)

    stmt = (
        select(_PrincipalEdgeRow)
        .where(_PrincipalEdgeRow.tenant_id == tenant_id)
        .where(_PrincipalEdgeRow.parent_kind == parent_kind)
        .where(_PrincipalEdgeRow.parent_id == parent_id)
        .where(_PrincipalEdgeRow.child_kind == child_kind)
        .where(_PrincipalEdgeRow.child_id == child_id)
        .where(_PrincipalEdgeRow.edge_kind == edge_kind)
    )
    row = db.execute(stmt).scalar_one_or_none()

    if row is None:
        row = _PrincipalEdgeRow(
            tenant_id=tenant_id,
            parent_kind=parent_kind, parent_id=parent_id,
            child_kind=child_kind, child_id=child_id,
            edge_kind=edge_kind,
            attributes=dict(attributes or {}),
            expires_at=expires_at,
        )
        db.add(row)
    else:
        # Idempotent re-add: merge attributes, refresh expiry.
        merged = {**(dict(row.attributes or {})), **(attributes or {})}
        row.attributes = merged
        row.expires_at = expires_at
    db.commit()
    return _row_to_edge(row)


def remove_principal_edge(
    db: Any,
    *,
    tenant_id: str,
    parent_kind: str,
    parent_id: str,
    child_kind: str,
    child_id: str,
    edge_kind: str = DEFAULT_EDGE_KIND,
) -> bool:
    """Delete one edge. Returns True if a row was removed."""
    _require_sqlalchemy()
    ensure_principal_edges_table(db)
    stmt = (
        select(_PrincipalEdgeRow)
        .where(_PrincipalEdgeRow.tenant_id == tenant_id)
        .where(_PrincipalEdgeRow.parent_kind == parent_kind)
        .where(_PrincipalEdgeRow.parent_id == parent_id)
        .where(_PrincipalEdgeRow.child_kind == child_kind)
        .where(_PrincipalEdgeRow.child_id == child_id)
        .where(_PrincipalEdgeRow.edge_kind == edge_kind)
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


# ── Walks ─────────────────────────────────────────────────────────


def _active_now(row: Any, now: datetime) -> bool:
    """An edge is active when it has no expiry, or its expiry is in
    the future. SQLite drops timezone information on round-trip, so
    we coerce expires_at to UTC-aware before comparing — otherwise
    the comparison raises ``TypeError`` on naive-vs-aware datetimes.
    """
    if row.expires_at is None:
        return True
    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > now


def list_children(
    db: Any,
    *,
    tenant_id: str,
    parent_kind: str,
    parent_id: str,
    edge_kind: str | None = None,
    include_expired: bool = False,
) -> list[PrincipalEdge]:
    """Direct children of ``(parent_kind, parent_id)``."""
    _require_sqlalchemy()
    ensure_principal_edges_table(db)
    stmt = (
        select(_PrincipalEdgeRow)
        .where(_PrincipalEdgeRow.tenant_id == tenant_id)
        .where(_PrincipalEdgeRow.parent_kind == parent_kind)
        .where(_PrincipalEdgeRow.parent_id == parent_id)
    )
    if edge_kind is not None:
        stmt = stmt.where(_PrincipalEdgeRow.edge_kind == edge_kind)
    rows = db.execute(stmt).scalars().all()
    now = datetime.now(timezone.utc)
    if not include_expired:
        rows = [r for r in rows if _active_now(r, now)]
    return [_row_to_edge(r) for r in rows]


def list_parents(
    db: Any,
    *,
    tenant_id: str,
    child_kind: str,
    child_id: str,
    edge_kind: str | None = None,
    include_expired: bool = False,
) -> list[PrincipalEdge]:
    """Direct parents of ``(child_kind, child_id)``. A principal with
    multiple parents (shared drone / robot) returns multiple edges."""
    _require_sqlalchemy()
    ensure_principal_edges_table(db)
    stmt = (
        select(_PrincipalEdgeRow)
        .where(_PrincipalEdgeRow.tenant_id == tenant_id)
        .where(_PrincipalEdgeRow.child_kind == child_kind)
        .where(_PrincipalEdgeRow.child_id == child_id)
    )
    if edge_kind is not None:
        stmt = stmt.where(_PrincipalEdgeRow.edge_kind == edge_kind)
    rows = db.execute(stmt).scalars().all()
    now = datetime.now(timezone.utc)
    if not include_expired:
        rows = [r for r in rows if _active_now(r, now)]
    return [_row_to_edge(r) for r in rows]


def walk_descendants(
    db: Any,
    *,
    tenant_id: str,
    root_kind: str,
    root_id: str,
    edge_kind: str | None = None,
    max_depth: int = 10,
    include_expired: bool = False,
) -> list[tuple[int, PrincipalEdge]]:
    """BFS walk over descendants up to ``max_depth`` hops.

    Returns ``[(depth, edge), ...]`` where depth==1 means a direct
    child of the root, 2 is a grandchild, etc.

    Cycle guard: visited ``(kind, id)`` pairs are tracked and not
    re-expanded. This is the v0.1.8 fallback before a recursive CTE
    lands. Suitable for fleets up to a few thousand principals.
    """
    _require_sqlalchemy()
    ensure_principal_edges_table(db)
    if max_depth < 1:
        return []

    visited: set[tuple[str, str]] = {(root_kind, root_id)}
    out: list[tuple[int, PrincipalEdge]] = []
    frontier: list[tuple[int, str, str]] = [(0, root_kind, root_id)]

    while frontier:
        next_frontier: list[tuple[int, str, str]] = []
        for depth, k, i in frontier:
            if depth >= max_depth:
                continue
            for child in list_children(
                db,
                tenant_id=tenant_id,
                parent_kind=k, parent_id=i,
                edge_kind=edge_kind,
                include_expired=include_expired,
            ):
                pair = (child.child_kind, child.child_id)
                if pair in visited:
                    continue
                visited.add(pair)
                out.append((depth + 1, child))
                next_frontier.append((depth + 1, *pair))
        frontier = next_frontier
    return out


def walk_ancestors(
    db: Any,
    *,
    tenant_id: str,
    leaf_kind: str,
    leaf_id: str,
    edge_kind: str | None = None,
    max_depth: int = 10,
    include_expired: bool = False,
) -> list[tuple[int, PrincipalEdge]]:
    """BFS walk over ancestors -- the dual of :func:`walk_descendants`."""
    _require_sqlalchemy()
    ensure_principal_edges_table(db)
    if max_depth < 1:
        return []

    visited: set[tuple[str, str]] = {(leaf_kind, leaf_id)}
    out: list[tuple[int, PrincipalEdge]] = []
    frontier: list[tuple[int, str, str]] = [(0, leaf_kind, leaf_id)]

    while frontier:
        next_frontier: list[tuple[int, str, str]] = []
        for depth, k, i in frontier:
            if depth >= max_depth:
                continue
            for parent in list_parents(
                db,
                tenant_id=tenant_id,
                child_kind=k, child_id=i,
                edge_kind=edge_kind,
                include_expired=include_expired,
            ):
                pair = (parent.parent_kind, parent.parent_id)
                if pair in visited:
                    continue
                visited.add(pair)
                out.append((depth + 1, parent))
                next_frontier.append((depth + 1, *pair))
        frontier = next_frontier
    return out


__all__ = [
    "DEFAULT_EDGE_KIND",
    "PrincipalEdge",
    "ensure_principal_edges_table",
    "add_principal_edge",
    "remove_principal_edge",
    "list_children",
    "list_parents",
    "walk_descendants",
    "walk_ancestors",
]
