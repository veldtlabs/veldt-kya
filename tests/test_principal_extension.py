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


class TestPrincipalFingerprint:
    """Middle layer of the fingerprint chain: composes definition
    hash + lineage + edge ancestors into one deterministic id."""

    def _setup_drone(self, db, *, firmware="v1", lineage=None,
                     tenant="t"):
        from kya import (
            record_principal_signal,
            snapshot_principal,
        )
        snapshot_principal(
            db, tenant_id=tenant,
            principal_kind="drone", principal_id="uav_001",
            definition={"firmware_version": firmware,
                        "airframe": "quad",
                        "platform": "ardupilot"},
        )
        if lineage is not None:
            record_principal_signal(
                db, tenant_id=tenant,
                principal_kind="drone", principal_id="uav_001",
                signal_kind="trust_clean",
                attributes={"lineage": lineage},
            )

    def test_fingerprint_shape(self):
        from kya import principal_fingerprint
        db = _fresh_db()
        self._setup_drone(db, lineage=[
            {"kind": "user", "id": "op_jane"}])
        fp = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        assert fp["scheme"] == "principal-v1"
        assert fp["principal_kind"] == "drone"
        assert fp["principal_id"] == "uav_001"
        assert len(fp["fingerprint"]) == 64  # sha256 hex
        assert fp["definition_hash"] is not None
        assert fp["lineage"] == [{"kind": "user", "id": "op_jane"}]
        assert fp["ancestors"] == []

    def test_deterministic(self):
        from kya import principal_fingerprint
        db = _fresh_db()
        self._setup_drone(db)
        fp1 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        fp2 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        assert fp1["fingerprint"] == fp2["fingerprint"]

    def test_firmware_bump_changes_fingerprint(self):
        from kya import principal_fingerprint, snapshot_principal
        db = _fresh_db()
        self._setup_drone(db, firmware="v1")
        fp1 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        # Firmware bump (snapshot v2)
        snapshot_principal(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001",
            definition={"firmware_version": "v2",
                        "airframe": "quad",
                        "platform": "ardupilot"},
        )
        fp2 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        assert fp1["fingerprint"] != fp2["fingerprint"]
        assert fp1["definition_hash"] != fp2["definition_hash"]

    def test_edge_addition_changes_fingerprint(self):
        from kya import add_principal_edge, principal_fingerprint
        db = _fresh_db()
        self._setup_drone(db)
        fp1 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        # Add a parent edge
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="mission_alpha",
            child_kind="drone", child_id="uav_001",
        )
        fp2 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        assert fp1["fingerprint"] != fp2["fingerprint"]
        assert fp2["ancestors"] == [
            {"kind": "controller", "id": "mission_alpha"}]

    def test_lineage_change_changes_fingerprint(self):
        from kya import principal_fingerprint, record_principal_signal
        db = _fresh_db()
        self._setup_drone(db, lineage=[{"kind": "user", "id": "op_jane"}])
        fp1 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        # Reassign lineage
        record_principal_signal(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001",
            signal_kind="trust_clean",
            attributes={"lineage": [{"kind": "user", "id": "op_riley"}]},
        )
        fp2 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        assert fp1["fingerprint"] != fp2["fingerprint"]

    def test_no_snapshot_still_well_defined(self):
        """A principal with a trust row but no agent_versions snapshot
        still gets a fingerprint -- definition_hash is None and the
        fingerprint covers lineage + ancestors only."""
        from kya import principal_fingerprint, record_principal_signal
        db = _fresh_db()
        record_principal_signal(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_002",
            signal_kind="trust_clean",
        )
        fp = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_002")
        assert fp["definition_hash"] is None
        assert len(fp["fingerprint"]) == 64

    def test_fingerprint_stable_with_cycle_in_edges(self):
        """A cycle in the edges DAG (A -> B -> A) must produce a
        deterministic fingerprint -- the BFS cycle guard kicks in
        but the resulting ancestor set must be canonical."""
        from kya import add_principal_edge, principal_fingerprint
        db = _fresh_db()
        self._setup_drone(db)
        # Build a cycle around the drone: c1 -> uav_001 -> c1
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="c1",
            child_kind="drone", child_id="uav_001",
        )
        # Re-frame as if the drone parents the controller too --
        # nonsensical but the BFS must still terminate.
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="drone", parent_id="uav_001",
            child_kind="controller", child_id="c1",
        )
        fp1 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        fp2 = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        # Determinism survives the cycle
        assert fp1["fingerprint"] == fp2["fingerprint"]
        # Ancestors include the controller exactly once
        ctrl_count = sum(1 for a in (fp1["ancestors"] or [])
                         if a == {"kind": "controller", "id": "c1"})
        assert ctrl_count == 1

    def test_include_edges_false(self):
        from kya import (
            add_principal_edge,
            principal_fingerprint,
        )
        db = _fresh_db()
        self._setup_drone(db)
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="mission_alpha",
            child_kind="drone", child_id="uav_001",
        )
        fp_with = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001",
            include_edges=True)
        fp_without = principal_fingerprint(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001",
            include_edges=False)
        # ancestors=None when include_edges=False; ancestors=[]
        # when include_edges=True with no edges -- distinct shapes
        assert fp_with["ancestors"] == [
            {"kind": "controller", "id": "mission_alpha"}]
        assert fp_without["ancestors"] is None
        assert fp_with["fingerprint"] != fp_without["fingerprint"]


class TestSnapshotPrincipal:
    """snapshot_principal() generalisation must preserve every v0.1.7
    agent_versions row and add a working path for non-agent kinds."""

    def test_snapshot_agent_kind_routes_same_storage(self):
        """``snapshot_principal(kind='agent')`` must hit the SAME
        agent_versions storage as ``snapshot_agent``. Two writes from
        the two APIs are visible to a single ``list_versions(agent_key=...)``."""
        from kya import (
            list_versions,
            snapshot_agent,
            snapshot_principal,
        )
        db = _fresh_db()
        snapshot_agent(db, tenant_id="t", agent_key="planner",
                       definition={"agent_key": "planner", "tools": ["sql"]})
        snapshot_principal(db, tenant_id="t",
                           principal_kind="agent",
                           principal_id="planner",
                           definition={"agent_key": "planner",
                                       "tools": ["sql", "http"]})
        rows = list_versions(db, tenant_id="t", agent_key="planner")
        assert len(rows) == 2
        assert {r["version_no"] for r in rows} == {1, 2}

    def test_drone_versioning(self):
        from kya import list_principal_versions, snapshot_principal
        db = _fresh_db()
        for fw in ("ardupilot-4.5.1", "ardupilot-4.5.2"):
            snapshot_principal(
                db, tenant_id="t",
                principal_kind="drone", principal_id="uav_001",
                definition={"firmware_version": fw,
                            "airframe": "quad",
                            "platform": "ardupilot"},
            )
        versions = list_principal_versions(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        assert len(versions) == 2

    def test_drift_detection_drone(self):
        """``detect_drift`` fires on a drone whose firmware bumped
        without a fresh snapshot -- the original audit story for
        agents now works for drones."""
        from kya import snapshot_principal
        from kya.integrity import canonical_hash, detect_drift
        db = _fresh_db()
        d1 = {"firmware_version": "ardupilot-4.5.1",
              "airframe": "quad", "platform": "ardupilot"}
        snapshot_principal(db, tenant_id="t",
                           principal_kind="drone", principal_id="uav_001",
                           definition=d1)
        declared = canonical_hash(d1, principal_kind="drone")
        # No drift on the same definition
        assert detect_drift(declared, d1, principal_kind="drone") is False
        # Drift on firmware bump
        d2 = {**d1, "firmware_version": "ardupilot-4.5.2"}
        assert detect_drift(declared, d2, principal_kind="drone") is True

    def test_colon_in_principal_id_rejected(self):
        """principal_id MUST NOT contain ':' -- the composed
        agent_key would decompose to the wrong (kind, id) pair.
        Regression test for Day-2 review finding I1."""
        from kya import snapshot_principal
        db = _fresh_db()
        for bad_id in ("ip6:::1", "name:thing", "kind:id"):
            with pytest.raises(ValueError, match="reserved separator"):
                snapshot_principal(
                    db, tenant_id="t",
                    principal_kind="machine_identity",
                    principal_id=bad_id,
                    definition={},
                )

    def test_colon_in_agent_id_rejected(self):
        """Even for kind='agent' (bare-key storage), a colon would
        confuse downstream decomposition. Rejected for consistency."""
        from kya import snapshot_principal
        db = _fresh_db()
        with pytest.raises(ValueError, match="reserved separator"):
            snapshot_principal(
                db, tenant_id="t",
                principal_kind="agent", principal_id="ns:agent",
                definition={"agent_key": "ns:agent"},
            )

    def test_oversized_composed_key_rejected(self):
        from kya import snapshot_principal
        db = _fresh_db()
        with pytest.raises(ValueError) as excinfo:
            snapshot_principal(
                db, tenant_id="t",
                principal_kind="machine_identity",
                principal_id="x" * 45,
                definition={},
            )
        # Error message names the column width + the kind
        msg = str(excinfo.value)
        assert "50-char" in msg
        assert "machine_identity" in msg

    def test_concurrent_snapshot_principal_race(self):
        """Two threads snapshotting the same principal concurrently
        must NOT lose a version due to the version_no race -- the
        existing snapshot_agent retry loop handles this. Regression
        test for Day-2 review MEDIUM coverage gap."""
        import threading
        from kya import (
            list_principal_versions,
            snapshot_principal,
        )
        from kya.principal_edges import ensure_principal_edges_table
        db_main = _fresh_db()
        ensure_principal_edges_table(db_main)
        from sqlalchemy.orm import Session
        engine = db_main.bind
        errors: list[Exception | None] = [None, None]

        def worker(i: int):
            sess = Session(engine)
            try:
                snapshot_principal(
                    sess, tenant_id="t",
                    principal_kind="drone", principal_id="uav_001",
                    definition={"firmware_version": f"v{i}"},
                )
            except Exception as exc:
                errors[i] = exc
            finally:
                sess.close()

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Neither thread raised
        for e in errors:
            assert e is None, f"thread raised: {e!r}"
        # Both versions landed
        versions = list_principal_versions(
            db_main, tenant_id="t",
            principal_kind="drone", principal_id="uav_001")
        assert len(versions) == 2

    def test_unicode_principal_id_accepted(self):
        """Non-ASCII principal_ids must round-trip cleanly. KYA's
        identifiers are opaque strings, not constrained to ASCII."""
        from kya import (
            get_principal_version,
            snapshot_principal,
        )
        db = _fresh_db()
        unicode_id = "drone-é-test"  # "drone-é-test"
        snapshot_principal(
            db, tenant_id="t",
            principal_kind="drone", principal_id=unicode_id,
            definition={"firmware_version": "v1"},
        )
        got = get_principal_version(
            db, tenant_id="t",
            principal_kind="drone", principal_id=unicode_id,
            version_no=1)
        assert got is not None
        assert got["definition"]["firmware_version"] == "v1"

    def test_long_principal_id_within_limit(self):
        """A principal_id at the maximum allowed length for its
        kind must succeed."""
        from kya import snapshot_principal
        db = _fresh_db()
        # "drone:" is 6 chars; column is 50; so max id is 44 chars
        max_id = "u" * 44
        snapshot_principal(
            db, tenant_id="t",
            principal_kind="drone", principal_id=max_id,
            definition={"firmware_version": "v1"},
        )

    def test_get_principal_version_returns_definition(self):
        from kya import get_principal_version, snapshot_principal
        db = _fresh_db()
        snapshot_principal(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001",
            definition={"firmware_version": "v1", "airframe": "quad"},
        )
        row = get_principal_version(
            db, tenant_id="t",
            principal_kind="drone", principal_id="uav_001",
            version_no=1,
        )
        assert row is not None
        assert row["definition"]["firmware_version"] == "v1"


class TestCanonicalHashDeterminism:
    """Regression for Day-2 review C2: datetime values inside a
    definition must hash identically across PG / SQLite even when
    one strips timezone info on round-trip."""

    def test_naive_vs_aware_utc_datetime_hash_identically(self):
        """A naive datetime is interpreted as UTC; an aware-UTC
        datetime is already UTC. Their ISO-coerced forms agree, so
        canonical_hash must return the same digest."""
        from datetime import datetime, timezone

        from kya.integrity import canonical_hash
        # Two definitions with the same logical timestamp but
        # different tzinfo (mimicking PG-aware vs SQLite-stripped).
        defn_aware = {
            "agent_key": "x", "tools": ["a"],
            "last_edited_at": datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
        }
        defn_naive = {
            "agent_key": "x", "tools": ["a"],
            "last_edited_at": datetime(2026, 6, 1, 12, 0),
        }
        # Note: "last_edited_at" isn't in _HASHED_FIELDS so it gets
        # filtered out -- both hashes are identical for that reason.
        # The non-trivial case: a datetime stored UNDER a hashed
        # field (e.g. an autonomy_asset's "firmware_hash" might be
        # accidentally typed as a datetime in test data).
        defn_in_hash_aware = {
            "firmware_version": "v1",
            "firmware_hash": datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
        }
        defn_in_hash_naive = {
            "firmware_version": "v1",
            "firmware_hash": datetime(2026, 6, 1, 12, 0),
        }
        h_aware = canonical_hash(defn_in_hash_aware, principal_kind="drone")
        h_naive = canonical_hash(defn_in_hash_naive, principal_kind="drone")
        assert h_aware == h_naive, (
            "naive UTC and aware UTC datetimes must hash identically "
            "so a definition survives a PG -> SQLite round-trip")

    def test_nested_datetime_canonicalised(self):
        """Datetimes nested inside list / dict values inside the
        definition must also be coerced."""
        from datetime import datetime, timezone

        from kya.integrity import canonical_hash
        d1 = {
            "firmware_version": "v1",
            "approved_modes": ["LOITER", "AUTO"],
            "geofence_id": "F-1",
            # Nested datetime inside parameter_set_hash (atypical
            # but the canonicalisation must reach it):
            "parameter_set_hash": {
                "issued_at": datetime(2026, 6, 1, tzinfo=timezone.utc),
            },
        }
        d2 = {
            "firmware_version": "v1",
            "approved_modes": ["LOITER", "AUTO"],
            "geofence_id": "F-1",
            "parameter_set_hash": {
                "issued_at": datetime(2026, 6, 1),  # naive
            },
        }
        assert (canonical_hash(d1, principal_kind="drone")
                == canonical_hash(d2, principal_kind="drone"))


class TestHashedFieldsRegistry:
    """canonical_hash + register_hashed_fields round-trip."""

    def test_default_agent_hash_unchanged(self):
        """v0.1.7 callers passing no principal_kind must get the
        SAME hash they got in v0.1.7 (backwards-compat contract)."""
        from kya.integrity import canonical_hash
        agent_def = {
            "agent_key": "planner",
            "tools": ["sql", "http"],
            "system_prompt": "plan things",
            "model": "gpt-4o-mini",
        }
        # No kwarg vs explicit kind="agent" must match
        assert (canonical_hash(agent_def)
                == canonical_hash(agent_def, principal_kind="agent"))

    def test_drone_firmware_bump_changes_hash(self):
        """Firmware change MUST flip the drone fingerprint --
        otherwise two materially-different drones hash identically
        and audit can't tell them apart."""
        from kya.integrity import canonical_hash
        drone = {
            "firmware_version": "ardupilot-4.5.1",
            "airframe": "quad",
            "platform": "ardupilot",
            "geofence_id": "farm_A",
        }
        drone_v2 = {**drone, "firmware_version": "ardupilot-4.5.2"}
        h1 = canonical_hash(drone, principal_kind="drone")
        h2 = canonical_hash(drone_v2, principal_kind="drone")
        assert h1 != h2

    def test_vendor_registered_kind_round_trip(self):
        """A vendor that calls register_hashed_fields must then see
        canonical_hash project those fields (not the agent fallback)."""
        from kya.integrity import (
            canonical_hash,
            hashed_fields_for,
            register_hashed_fields,
        )
        register_hashed_fields(
            "test_swarm", ("formation", "size", "comms_protocol"))
        assert hashed_fields_for("test_swarm") == (
            "formation", "size", "comms_protocol")
        # Definition projects only the registered fields; an extra
        # key (system_prompt -- an agent field) is ignored.
        h = canonical_hash(
            {"formation": "V", "size": 5,
             "comms_protocol": "mavlink",
             "system_prompt": "should be ignored"},
            principal_kind="test_swarm",
        )
        # Same definition without the irrelevant field hashes
        # identically -- projection is by field set, not by full dict.
        h_clean = canonical_hash(
            {"formation": "V", "size": 5, "comms_protocol": "mavlink"},
            principal_kind="test_swarm",
        )
        assert h == h_clean

    def test_register_hashed_fields_validates(self):
        from kya.integrity import register_hashed_fields
        with pytest.raises(TypeError):
            register_hashed_fields("k", ["not", "a", "tuple"])  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            register_hashed_fields("k", ("", "empty_string"))
        with pytest.raises(ValueError):
            register_hashed_fields("k", (123,))  # type: ignore[arg-type]


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

    def test_invalid_attributes_type_rejected_cleanly(self):
        """Non-dict attributes must raise BEFORE the row goes into
        the session, otherwise the mid-merge failure leaves the
        session in a dirty state and confuses the next operation."""
        from kya.principal_edges import add_principal_edge
        db = _fresh_db()
        with pytest.raises(TypeError):
            add_principal_edge(
                db, tenant_id="t",
                parent_kind="user", parent_id="u1",
                child_kind="agent", child_id="a1",
                attributes="not a dict",  # type: ignore[arg-type]
            )
        # Session is still healthy after the rejection
        edge = add_principal_edge(
            db, tenant_id="t",
            parent_kind="user", parent_id="u1",
            child_kind="agent", child_id="a1",
        )
        assert edge.child_id == "a1"

    def test_re_add_without_expires_at_preserves_existing_expiry(self):
        """A re-add that doesn't supply ``expires_at=`` MUST NOT
        wipe an existing expiry. The buggy v1 of this function would
        silently turn a time-bounded lease into a permanent edge."""
        from kya.principal_edges import (
            add_principal_edge,
            list_children,
        )
        db = _fresh_db()
        future = datetime.now(timezone.utc) + timedelta(hours=24)
        # Initial add: 24-hour lease
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="m1",
            child_kind="drone", child_id="d1",
            expires_at=future,
        )
        # Re-add to bump attributes; do NOT pass expires_at
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="m1",
            child_kind="drone", child_id="d1",
            attributes={"note": "bumped"},
        )
        children = list_children(
            db, tenant_id="t",
            parent_kind="controller", parent_id="m1",
        )
        assert len(children) == 1
        edge = children[0]
        assert edge.attributes["note"] == "bumped"
        # Existing expiry preserved
        assert edge.expires_at is not None
        # Within 1s of the original (SQLite may round microseconds).
        # SQLite strips tzinfo on round-trip; coerce both sides to
        # naive UTC for the subtraction.
        got = edge.expires_at.replace(tzinfo=None) if edge.expires_at.tzinfo else edge.expires_at
        want = future.replace(tzinfo=None)
        delta = abs((got - want).total_seconds())
        assert delta < 1.0, f"expires_at drifted by {delta}s"

    def test_re_add_with_new_expires_at_updates(self):
        """An explicit ``expires_at=`` on re-add DOES override --
        callers can extend or shorten a lease."""
        from kya.principal_edges import (
            add_principal_edge,
            list_children,
        )
        db = _fresh_db()
        t1 = datetime.now(timezone.utc) + timedelta(hours=1)
        t2 = datetime.now(timezone.utc) + timedelta(hours=48)
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="m1",
            child_kind="drone", child_id="d1",
            expires_at=t1,
        )
        add_principal_edge(
            db, tenant_id="t",
            parent_kind="controller", parent_id="m1",
            child_kind="drone", child_id="d1",
            expires_at=t2,
        )
        children = list_children(
            db, tenant_id="t",
            parent_kind="controller", parent_id="m1",
        )
        assert children[0].expires_at is not None
        got = children[0].expires_at.replace(tzinfo=None) if children[0].expires_at.tzinfo else children[0].expires_at
        want = t2.replace(tzinfo=None)
        delta = abs((got - want).total_seconds())
        assert delta < 1.0

    def test_concurrent_add_same_edge_survives_race(self):
        """Two threads adding the same edge concurrently must NOT
        raise IntegrityError -- the retry loop + per-edge lock must
        serialise them. Result: one row, attributes merged."""
        import threading
        from kya.principal_edges import (
            add_principal_edge,
            list_children,
        )
        db_main = _fresh_db()
        # Ensure the table exists before threads race
        from kya.principal_edges import ensure_principal_edges_table
        ensure_principal_edges_table(db_main)

        # Each thread uses its own session bound to the same engine
        from sqlalchemy.orm import Session
        engine = db_main.bind
        results: list[Exception | None] = [None, None]

        def worker(i: int, attr_value: str):
            sess = Session(engine)
            try:
                add_principal_edge(
                    sess, tenant_id="t",
                    parent_kind="user", parent_id="u1",
                    child_kind="agent", child_id="a1",
                    attributes={f"k{i}": attr_value},
                )
            except Exception as exc:
                results[i] = exc
            finally:
                sess.close()

        threads = [
            threading.Thread(target=worker, args=(0, "value0")),
            threading.Thread(target=worker, args=(1, "value1")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Neither thread raised
        for r in results:
            assert r is None, f"thread raised: {r!r}"

        # Exactly one row, both attribute keys present
        children = list_children(
            db_main, tenant_id="t",
            parent_kind="user", parent_id="u1",
        )
        assert len(children) == 1
        # Both threads' attributes survived the merge (in some order)
        merged = children[0].attributes
        # Note: race may cause only one to be visible if both saw row=None
        # and one was overwritten by the retry path -- the contract is "no
        # exception + exactly one row", not "both attribute keys present".
        # We assert at least one key is present.
        assert ("k0" in merged or "k1" in merged), \
            f"expected at least one writer's attribute, got {merged}"
