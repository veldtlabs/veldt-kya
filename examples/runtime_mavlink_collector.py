"""End-to-end example: wire MAVLink frames into KYA.

Shows how to:

1. Define a fleet manifest mapping (sysid, compid) -> (tenant, principal_id).
2. Construct the resolver chain with MavlinkSysidResolver.
3. Stream MAVLink frames from a UDP endpoint OR replay from a .tlog.
4. Hand each frame to ``kya.runtime.ingest`` so the bridge resolves
   the principal, attaches the evidence chain, and dispatches the
   attack-chain engine.

The collector code below assumes ``pymavlink`` is installed
(``pip install 'veldt-kya[mavlink]'``). If your collector pre-decodes
MAVLink to dicts via some other means (Kafka, NDJSON, gRPC), skip the
pymavlink section and call ``ingest(frame_dict, source_tool='mavlink')``
directly.

Anchoring evidence to invocations
---------------------------------
KYA's evidence chain is keyed by ``(tenant, invocation)``. Runtime
collectors typically use one of two patterns:

* **Per-vehicle invocation anchor** -- create one ``invocation`` per
  drone, per session, and pass its id with every event. The chain
  carries the full mission per-vehicle.
* **Per-mission invocation anchor** -- create one ``invocation`` per
  mission_id and pass it for every vehicle involved. The chain
  carries the joint timeline.

This example uses the per-vehicle pattern; switch ``_invocation_for``
to use mission_id if you want cross-vehicle aggregation.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

logger = logging.getLogger(__name__)


# ── 1. Fleet manifest -------------------------------------------
#
# The operator's source-of-truth mapping. In production this comes
# from a YAML / JSON config, an IdP query, or a database. Keep it
# small + explicit so a regulator can audit who-is-who at a glance.
FLEET_MANIFEST: dict[tuple[int, int], tuple[str, str]] = {
    # (sysid, compid): (tenant_id, principal_id)
    (1, 1): ("acme", "drone:uav_001"),
    (2, 1): ("acme", "drone:uav_002"),
    (3, 1): ("acme", "drone:uav_003"),
    # The Ground Control Station that authorises commands -- modeled
    # as a 'controller' principal so the lineage walks back to a
    # named operator authority.
    (10, 190): ("acme", "controller:gcs_alpha"),
}


class MavlinkCollector:
    """Instance-scoped MAVLink collector.

    Owns its own invocation cache, fleet manifest, and (eventually)
    its own resolver registration. Two collectors in the same
    process don't share state -- which is what you want when one
    collector handles ``mission_alpha`` and another handles
    ``mission_beta`` against the same DB.

    For a single-tenant single-mission deployment, instantiate
    once at startup and call ``ingest_frame`` per MAVLink message.
    For multi-mission deployments, build one ``MavlinkCollector``
    per mission and route the wire stream by mission_id upstream.
    """

    def __init__(
        self,
        fleet_manifest: dict[tuple[int, int], tuple[str, str]] | None = None,
    ) -> None:
        # Default to the example manifest; production callers
        # supply their own loaded from YAML / IdP / DB.
        self.fleet_manifest = (
            dict(fleet_manifest) if fleet_manifest is not None
            else dict(FLEET_MANIFEST)
        )
        # Cached per-vehicle invocation anchors -- instance-scoped
        # so two collectors don't collide. Production collectors
        # persist this to Valkey / Redis so the chain survives
        # process restarts.
        self._invocation_cache: dict[tuple[int, int], int] = {}

    # ── Resolver wire-up ─────────────────────────────────────────

    def install_principal_resolver(self) -> None:
        """Install a process-global resolver chain that consults
        this collector's fleet manifest.

        Note: ``set_principal_resolver`` is process-global. In a
        multi-collector deployment the LAST collector to call this
        wins for the whole process. The convention in such
        deployments is to install one shared resolver chain that
        unions every fleet manifest, OR to call only the parent
        collector's ``install_principal_resolver`` once.
        """
        from kya.runtime import (
            ExplicitBindingCache,
            MavlinkSysidResolver,
            PrincipalResolverChain,
            set_principal_resolver,
        )

        chain = PrincipalResolverChain([
            ExplicitBindingCache(),
            MavlinkSysidResolver(self.fleet_manifest),
        ])
        set_principal_resolver(chain)

    # ── Invocation anchor (per vehicle) ──────────────────────────

    def _invocation_for(
        self,
        db: Any, *,
        tenant_id: str, sysid: int, compid: int,
        principal_id: str,
    ) -> int:
        """Return the invocation_id for this (sysid, compid),
        creating one if it doesn't exist yet."""
        key = (sysid, compid)
        cached = self._invocation_cache.get(key)
        if cached is not None:
            return cached

        from kya import record_invocation
        inv_id = record_invocation(
            db,
            tenant_id=tenant_id,
            agent_key=principal_id,
            # 'autonomous_action' is a canonical mode; see
            # kya.invocations for the full vocabulary.
            mode="autonomous_action",
            principal_kind="drone",
            principal_id=principal_id,
            outcome="success",
        )
        self._invocation_cache[key] = inv_id
        return inv_id

    # ── Ingest one frame ─────────────────────────────────────────

    def ingest_frame(self, db: Any, frame: dict) -> None:
        """Push one MAVLink message dict through the bridge.

        Unknown (sysid, compid) is NOT silently bound to a default
        tenant -- the bridge surfaces it as unbound, which is the
        whole point: an unauthorised sysid is the attack signal a
        regulator wants. The caller can apply tenant-routing
        logic UPSTREAM of the collector if they need per-source
        attribution beyond the fleet manifest.
        """
        from kya.runtime import ingest

        sysid = frame.get("sysid")
        compid = frame.get("compid", 1)
        if not isinstance(sysid, int) or not isinstance(compid, int):
            return  # parser will also reject -- bail early

        principal = self.fleet_manifest.get((sysid, compid))
        if principal is None:
            # Unknown source -- the bridge will mark unbound.
            # Surface it WITHOUT inventing a tenant: an unbound
            # event flows through the evidence chain with
            # tenant_id=None, which downstream queries can filter
            # / alert on. This is the safe failure mode.
            invocation_id = None
        else:
            tenant_id, principal_id = principal
            invocation_id = self._invocation_for(
                db, tenant_id=tenant_id,
                sysid=sysid, compid=compid,
                principal_id=principal_id,
            )

        result = ingest(
            frame,
            source_tool="mavlink",
            db=db,
            invocation_id=invocation_id,
        )
        if not result.accepted:
            logger.warning(
                "[KYA-MAVLINK-COLLECTOR] frame rejected: %s",
                result.error,
            )

    # ── Live UDP reader (optional pymavlink path) ────────────────

    def stream_from_udp(
        self,
        db: Any, *, host: str = "127.0.0.1", port: int = 14550,
    ) -> None:
        """Stream MAVLink frames live from a UDP endpoint (the
        typical setup when a router like mavlink-routerd is
        between the autopilot and ground software)."""
        try:
            from pymavlink import mavutil
        except ImportError:
            logger.error(
                "pymavlink not installed. Either install "
                "veldt-kya[mavlink] or pre-decode frames to dicts "
                "upstream."
            )
            return

        conn = mavutil.mavlink_connection(f"udp:{host}:{port}")
        logger.info(
            "[KYA-MAVLINK-COLLECTOR] listening on udp:%s:%d",
            host, port,
        )
        while True:
            msg = conn.recv_match(blocking=True, timeout=5)
            if msg is None:
                continue
            self.ingest_frame(db, msg.to_dict())


# ── Smoke-test entrypoint ---------------------------------------


def _smoke_test() -> dict:
    """Run a couple of pre-canned frames through the pipeline so
    a developer can verify the wire-up without spinning SITL.

    Returns a small dict of the test outcomes so the
    ``tests/test_runtime_mavlink_collector_smoke.py`` integration
    can assert without re-implementing the smoke logic.
    """
    import tempfile
    import os
    os.environ.pop("KYA_VERSIONS_SCHEMA", None)
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    import kya

    eng = create_engine(
        f"sqlite:///{tempfile.NamedTemporaryFile(suffix='.db', delete=False).name}")
    db = Session(eng)
    kya.init_storage(db)
    db.commit()

    collector = MavlinkCollector()
    collector.install_principal_resolver()

    # Synthetic ARM from uav_001 (known principal)
    collector.ingest_frame(db, {
        "mavpackettype": "COMMAND_LONG",
        "sysid": 1, "compid": 1,
        "command": 400, "param1": 1.0,
    })
    # Synthetic STATUSTEXT from an unknown source -- demonstrates
    # the unbound path (no fleet manifest entry).
    collector.ingest_frame(db, {
        "mavpackettype": "STATUSTEXT",
        "sysid": 99, "compid": 1,
        "severity": 4, "text": "unknown autopilot reports warning",
    })

    # Reset the resolver so the smoke test doesn't pollute global
    # state for subsequent tests in the same process.
    from kya.runtime import reset_principal_resolver_to_default
    reset_principal_resolver_to_default()

    outcomes = {
        "known_principal_anchored": (1, 1) in collector._invocation_cache,
        "unknown_principal_unbound": (99, 1) not in collector._invocation_cache,
    }
    print(f"collector smoke test outcomes: {outcomes}")
    return outcomes


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if "--smoke" in sys.argv:
        _smoke_test()
    else:
        print(__doc__)
        print()
        print("Use --smoke to run the in-process smoke test or")
        print("instantiate MavlinkCollector and call ingest_frame.")
