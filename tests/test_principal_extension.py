"""Tests for the v0.1.8 principal-vocabulary extension + edges DAG.

Covers:
* New principal_kind values (drone, robot, ..., autonomous_system).
* Runtime registry: env var + register_principal_kind() + naming rules.
* principal_metadata.lineage convention round-trips through
  record_principal_signal.
* kya_principal_edges CRUD (idempotent re-add, removal).
* Many-to-many DAG: a child can have multiple parents.
* walk_descendants / walk_ancestors traversal with cycle guard.
* Time-bounded edges filter out expired entries.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest


def _fresh_db():
    """Each test gets an isolated SQLite database."""
    os.environ.pop("KYA_VERSIONS_SCHEMA", None)
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    path = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
    eng = create_engine(f"sqlite:///{path}")
    db = Session(eng)
    import kya
    kya.init_storage(db)
    db.commit()
    return db


# ── Vocabulary extension ──────────────────────────────────────────


class TestPrincipalKindVocabulary:
    def test_existing_kinds_preserved(self):
        from kya.principals import PRINCIPAL_KINDS
        for k in ("user", "agent", "service_account"):
            assert k in PRINCIPAL_KINDS, f"v0.1.8 must keep {k!r} (backwards-compat)"

    def test_autonomy_kinds_added(self):
        from kya.principals import PRINCIPAL_KINDS
        for k in ("drone", "robot", "vehicle", "plc", "controller",
                  "sensor", "actuator", "lakehouse_job",
                  "machine_identity", "autonomous_system"):
            assert k in PRINCIPAL_KINDS

    def test_drone_principal_signal_round_trip(self):
        from kya.principals import (
            get_principal_trust,
            record_principal_signal,
        )
        db = _fresh_db()
        record_principal_signal(
            db, tenant_id="acme",
            principal_kind="drone", principal_id="uav_001",
            signal_kind="trust_clean",
            attributes={
                "asset_type": "drone",
                "protocol": "mavlink",
                "platform": "ardupilot",
                "lineage": [
                    {"kind": "user", "id": "op_jane"},
                    {"kind": "agent", "id": "planner_v2"},
                ],
            },
        )
        row = get_principal_trust(db, "acme", "drone", "uav_001")
        assert row.attributes["asset_type"] == "drone"
        assert row.attributes["lineage"][0] == {"kind": "user", "id": "op_jane"}


# ── Runtime registry ──────────────────────────────────────────────


class TestRuntimeRegistry:
    def test_default_kinds_registered(self):
        from kya.principals import (
            PRINCIPAL_KINDS,
            is_valid_principal_kind,
            registered_principal_kinds,
        )
        for k in PRINCIPAL_KINDS:
            assert is_valid_principal_kind(k)
        assert set(registered_principal_kinds()) >= set(PRINCIPAL_KINDS)

    def test_register_new_kind(self):
        from kya.principals import (
            is_valid_principal_kind,
            register_principal_kind,
        )
        register_principal_kind("test_swarm_kind")
        assert is_valid_principal_kind("test_swarm_kind")

    def test_register_is_idempotent(self):
        from kya.principals import register_principal_kind
        register_principal_kind("test_idempotent_kind")
        register_principal_kind("test_idempotent_kind")  # no raise

    @pytest.mark.parametrize("bad", [
        "UPPER",          # uppercase
        "1leading_digit",  # leading digit
        "has-dash",        # dash not allowed
        "has.dot",         # dot not allowed
        "",                # empty
        "way_too_long_kind_name_extra",  # > 20 chars
    ])
    def test_register_rejects_malformed(self, bad):
        from kya.principals import register_principal_kind
        with pytest.raises(ValueError):
            register_principal_kind(bad)

    def test_unregistered_kind_falls_back_to_user(self, caplog):
        from kya.principals import (
            get_principal_trust,
            record_principal_signal,
        )
        db = _fresh_db()
        record_principal_signal(
            db, tenant_id="acme",
            principal_kind="totally_unregistered_kind_xyz",
            principal_id="p1",
            signal_kind="trust_clean",
        )
        # Falls back to 'user'
        row = get_principal_trust(db, "acme", "user", "p1")
        assert row.trust_score > 0


# ── Edges DAG ─────────────────────────────────────────────────────


class TestPrincipalEdges:
    def test_add_and_list_children(self):
        from kya.principal_edges import (
            add_principal_edge,
            list_children,
        )
        db = _fresh_db()
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1",
            child_kind="agent", child_id="a1",
        )
        children = list_children(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1",
        )
        assert len(children) == 1
        assert children[0].child_id == "a1"

    def test_idempotent_re_add(self):
        from kya.principal_edges import (
            add_principal_edge,
            list_children,
        )
        db = _fresh_db()
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1",
            child_kind="agent", child_id="a1",
        )
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1",
            child_kind="agent", child_id="a1",
            attributes={"note": "second add"},
        )
        children = list_children(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1",
        )
        assert len(children) == 1
        assert children[0].attributes["note"] == "second add"

    def test_many_to_many_multiple_parents(self):
        from kya.principal_edges import (
            add_principal_edge,
            list_parents,
        )
        db = _fresh_db()
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="mission_alpha",
            child_kind="drone", child_id="uav_001",
        )
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="mission_beta",
            child_kind="drone", child_id="uav_001",
        )
        parents = list_parents(
            db, tenant_id="t",
            child_kind="drone", child_id="uav_001",
        )
        assert len(parents) == 2
        assert {p.parent_id for p in parents} == {"mission_alpha", "mission_beta"}

    def test_walk_descendants_depth_bounded(self):
        from kya.principal_edges import (
            add_principal_edge,
            walk_descendants,
        )
        db = _fresh_db()
        # user -> controller -> agent -> drone -> actuator
        chain = [
            ("user", "u1", "controller", "c1"),
            ("controller", "c1", "agent", "a1"),
            ("agent", "a1", "drone", "d1"),
            ("drone", "d1", "actuator", "act1"),
        ]
        for pk, pi, ck, ci in chain:
            add_principal_edge(db, tenant_id="t",
                               parent_kind=pk, parent_id=pi,
                               child_kind=ck, child_id=ci)
        # Depth 2 -> only first two hops
        walk = walk_descendants(
            db, tenant_id="t",
            root_kind="user", root_id="u1", max_depth=2)
        assert len(walk) == 2
        assert walk[-1][1].child_kind == "agent"
        # Full depth -> all 4 hops
        walk_full = walk_descendants(
            db, tenant_id="t",
            root_kind="user", root_id="u1", max_depth=10)
        assert len(walk_full) == 4

    def test_walk_ancestors_dual(self):
        from kya.principal_edges import (
            add_principal_edge,
            walk_ancestors,
        )
        db = _fresh_db()
        add_principal_edge(db, tenant_id="t",
                           parent_kind="user", parent_id="u1",
                           child_kind="controller", child_id="c1")
        add_principal_edge(db, tenant_id="t",
                           parent_kind="controller", parent_id="c1",
                           child_kind="drone", child_id="d1")
        ancestors = walk_ancestors(
            db, tenant_id="t",
            leaf_kind="drone", leaf_id="d1", max_depth=10)
        assert len(ancestors) == 2
        assert ancestors[-1][1].parent_kind == "user"

    def test_cycle_guard(self):
        from kya.principal_edges import (
            add_principal_edge,
            walk_descendants,
        )
        db = _fresh_db()
        # Create a cycle: A -> B -> A. This shouldn't happen in
        # practice but the walker must not infinite-loop.
        add_principal_edge(db, tenant_id="t",
                           parent_kind="agent", parent_id="A",
                           child_kind="agent", child_id="B")
        add_principal_edge(db, tenant_id="t",
                           parent_kind="agent", parent_id="B",
                           child_kind="agent", child_id="A")
        walk = walk_descendants(
            db, tenant_id="t",
            root_kind="agent", root_id="A", max_depth=20)
        # A->B is visited once; B->A loops back and is filtered.
        assert len(walk) == 1
        assert walk[0][1].child_id == "B"

    def test_remove_edge(self):
        from kya.principal_edges import (
            add_principal_edge,
            list_children,
            remove_principal_edge,
        )
        db = _fresh_db()
        add_principal_edge(db, tenant_id="t",
                           parent_kind="user", parent_id="u1",
                           child_kind="agent", child_id="a1")
        removed = remove_principal_edge(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1",
            child_kind="agent", child_id="a1")
        assert removed is True
        assert list_children(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1") == []
        # Removing again returns False
        assert remove_principal_edge(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1",
            child_kind="agent", child_id="a1") is False

    def test_expired_edges_filtered_by_default(self):
        from kya.principal_edges import (
            add_principal_edge,
            list_children,
        )
        db = _fresh_db()
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="c1",
            child_kind="drone", child_id="d1",
            expires_at=past,
        )
        # Default: expired edges hidden
        assert list_children(
            db, tenant_id="t",
            parent_kind="controller", parent_id="c1") == []
        # Opt-in to see them
        assert len(list_children(
            db, tenant_id="t",
            parent_kind="controller", parent_id="c1",
            include_expired=True)) == 1

    def test_invalid_edge_kind_rejected(self):
        from kya.principal_edges import add_principal_edge
        db = _fresh_db()
        with pytest.raises(ValueError):
            add_principal_edge(
                db, tenant_id="t",
                parent_kind="user", parent_id="u1",
                child_kind="agent", child_id="a1",
                edge_kind="HAS-DASH-AND-CAPS",
            )
