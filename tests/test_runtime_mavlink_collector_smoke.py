"""Smoke test for the MAVLink collector example.

Verifies the wire-up in ``examples/runtime_mavlink_collector.py``
without spinning SITL or pymavlink. Catches regressions in:

* MavlinkCollector class instantiation
* install_principal_resolver -> ExplicitBindingCache + MavlinkSysidResolver
  chain construction
* ingest_frame happy path (known principal -> invocation created
  + cached)
* ingest_frame unbound path (unknown sysid -> bridge surfaces
  unbound without inventing a tenant)
* Cache scoping (two collectors in the same process don't collide)
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_EXAMPLE = Path(__file__).parent.parent / "examples" / "runtime_mavlink_collector.py"


def _import_example():
    """Import the example as a regular module so its top-level
    state (logger, FLEET_MANIFEST, MavlinkCollector class) is
    available to the tests."""
    spec = importlib.util.spec_from_file_location(
        "_collector_example", _EXAMPLE,
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_collector_example"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestCollectorSmokeRun:
    def test_smoke_function_outcomes(self):
        """The _smoke_test entrypoint exercises both the bound
        (uav_001) and the unbound (unknown sysid=99) paths and
        returns an outcomes dict. Both assertions must hold."""
        mod = _import_example()
        outcomes = mod._smoke_test()
        assert outcomes["known_principal_anchored"] is True, (
            "uav_001 (sysid=1, compid=1) is in FLEET_MANIFEST but "
            "did NOT get cached -- the happy path is broken")
        assert outcomes["unknown_principal_unbound"] is True, (
            "an unknown sysid landed in the invocation cache -- "
            "an unbound principal must NOT be assigned a fabricated "
            "anchor")


class TestCollectorInstanceIsolation:
    """Two collectors in one process must not share the per-vehicle
    invocation cache -- a regression here would make multi-mission
    deployments silently cross-anchor."""

    def test_two_collectors_have_independent_caches(self):
        import os
        import tempfile

        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        os.environ.pop("KYA_VERSIONS_SCHEMA", None)
        eng = create_engine(
            f"sqlite:///{tempfile.NamedTemporaryFile(suffix='.db', delete=False).name}")
        db = Session(eng)
        import kya
        kya.init_storage(db)
        db.commit()

        mod = _import_example()

        manifest_a = {(1, 1): ("acme", "drone:uav_alpha")}
        manifest_b = {(1, 1): ("globex", "drone:uav_beta")}

        collector_a = mod.MavlinkCollector(fleet_manifest=manifest_a)
        collector_b = mod.MavlinkCollector(fleet_manifest=manifest_b)

        # Each collector has its own cache + manifest -- mutating
        # one doesn't affect the other.
        collector_a._invocation_cache[(1, 1)] = 42
        assert (1, 1) not in collector_b._invocation_cache, (
            "collector B's cache was mutated by collector A -- "
            "they share state and should NOT")

        collector_b._invocation_cache[(1, 1)] = 99
        assert collector_a._invocation_cache[(1, 1)] == 42
        assert collector_b._invocation_cache[(1, 1)] == 99

    def test_multi_vehicle_distinct_anchors(self):
        """A single collector handling multiple vehicles in one
        session creates a distinct invocation per (sysid, compid)
        -- not one shared anchor. Otherwise evidence from drone A
        and drone B would chain under the same invocation_id,
        collapsing two principals into one audit thread."""
        import os
        import tempfile

        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        os.environ.pop("KYA_VERSIONS_SCHEMA", None)
        eng = create_engine(
            f"sqlite:///{tempfile.NamedTemporaryFile(suffix='.db', delete=False).name}")
        db = Session(eng)
        import kya
        kya.init_storage(db)
        db.commit()

        mod = _import_example()
        collector = mod.MavlinkCollector()
        collector.install_principal_resolver()

        try:
            # Send commands from three different drones via ONE
            # collector (the realistic multi-vehicle case).
            for sysid in (1, 2, 3):
                collector.ingest_frame(db, {
                    "mavpackettype": "COMMAND_LONG",
                    "sysid": sysid, "compid": 1,
                    "command": 400, "param1": 1.0,
                })

            # Each known vehicle got its own cached anchor;
            # no two vehicles share an invocation_id.
            cache = collector._invocation_cache
            assert (1, 1) in cache
            assert (2, 1) in cache
            assert (3, 1) in cache
            # All three anchors must be distinct
            ids = {cache[(1, 1)], cache[(2, 1)], cache[(3, 1)]}
            assert len(ids) == 3, (
                f"multi-vehicle cache collapsed to {len(ids)} "
                f"anchor(s); each drone must get its own. cache={cache}")
        finally:
            from kya.runtime import reset_principal_resolver_to_default
            reset_principal_resolver_to_default()

    def test_concurrent_collectors_isolated(self):
        """Two collectors running concurrently against the SAME db
        don't trample each other's caches. Mirrors the realistic
        case of mission_alpha and mission_beta running in one
        process."""
        import os
        import tempfile
        import threading

        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        os.environ.pop("KYA_VERSIONS_SCHEMA", None)
        eng = create_engine(
            f"sqlite:///{tempfile.NamedTemporaryFile(suffix='.db', delete=False).name}")
        db_main = Session(eng)
        import kya
        kya.init_storage(db_main)
        db_main.commit()

        mod = _import_example()
        # Two collectors with DIFFERENT manifests for the same
        # sysid -- mission_alpha thinks (1, 1) is uav_alpha,
        # mission_beta thinks it's uav_beta. Real-world: rare
        # misconfig, but the test asserts independence.
        collector_a = mod.MavlinkCollector(
            fleet_manifest={(1, 1): ("acme", "drone:uav_alpha")})
        collector_b = mod.MavlinkCollector(
            fleet_manifest={(1, 1): ("acme", "drone:uav_beta")})

        errors: list[Exception | None] = [None, None]

        def worker(i: int, collector):
            try:
                sess = Session(eng)
                collector.ingest_frame(sess, {
                    "mavpackettype": "COMMAND_LONG",
                    "sysid": 1, "compid": 1,
                    "command": 400, "param1": 1.0,
                })
                sess.close()
            except Exception as exc:
                errors[i] = exc

        threads = [
            threading.Thread(target=worker, args=(0, collector_a)),
            threading.Thread(target=worker, args=(1, collector_b)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for e in errors:
            assert e is None, f"collector raised: {e!r}"
        # Each collector cached its OWN view of (1, 1) -- different
        # principals because different manifests
        assert collector_a._invocation_cache[(1, 1)] != \
               collector_b._invocation_cache[(1, 1)]

    def test_unknown_principal_does_not_get_acme_fallback(self):
        """An unknown sysid must NOT silently inherit the default
        manifest's tenant. The bridge surfaces it as unbound."""
        import os
        import tempfile

        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session

        os.environ.pop("KYA_VERSIONS_SCHEMA", None)
        eng = create_engine(
            f"sqlite:///{tempfile.NamedTemporaryFile(suffix='.db', delete=False).name}")
        db = Session(eng)
        import kya
        kya.init_storage(db)
        db.commit()

        mod = _import_example()
        collector = mod.MavlinkCollector()
        collector.install_principal_resolver()

        try:
            # sysid=99 is NOT in FLEET_MANIFEST
            collector.ingest_frame(db, {
                "mavpackettype": "COMMAND_LONG",
                "sysid": 99, "compid": 1,
                "command": 400, "param1": 1.0,
            })
            # The unknown principal is NOT cached against any
            # tenant -- there's no invocation to anchor it to.
            assert (99, 1) not in collector._invocation_cache
        finally:
            from kya.runtime import reset_principal_resolver_to_default
            reset_principal_resolver_to_default()
