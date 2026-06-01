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


# ── 2. Wire the resolver chain -----------------------------------


def install_principal_resolver() -> None:
    from kya.runtime import (
        ExplicitBindingCache,
        MavlinkSysidResolver,
        PrincipalResolverChain,
        set_principal_resolver,
    )

    # ExplicitBindingCache covers any test/agent-spawn bindings;
    # MavlinkSysidResolver maps the (sysid, compid) hint emitted
    # by the parser to a principal via the manifest above. Order
    # matters: explicit beats manifest beats none.
    chain = PrincipalResolverChain([
        ExplicitBindingCache(),
        MavlinkSysidResolver(FLEET_MANIFEST),
    ])
    set_principal_resolver(chain)


# ── 3. Per-vehicle invocation anchor ----------------------------
#
# Cached so the same drone uses the same anchor across an entire
# session. A real collector persists this to Valkey / Redis so the
# chain survives restarts.
_invocation_cache: dict[tuple[int, int], int] = {}


def _invocation_for(
    db: Any, *, tenant_id: str, sysid: int, compid: int,
    principal_id: str,
) -> int:
    """Return the invocation_id for this (sysid, compid) pair,
    creating one if it doesn't exist yet."""
    key = (sysid, compid)
    cached = _invocation_cache.get(key)
    if cached is not None:
        return cached

    from kya import record_invocation
    inv_id = record_invocation(
        db,
        tenant_id=tenant_id,
        agent_key=principal_id,
        # 'autonomous_action' is a canonical mode; see kya.invocations
        # for the full vocabulary.
        mode="autonomous_action",
        # The collector doesn't have a per-frame prompt; we anchor
        # the session with a synthetic record.
        request="MAVLink session anchor",
        principal_kind="drone",
        principal_id=principal_id,
        outcome="ok",
    )
    _invocation_cache[key] = inv_id
    return inv_id


# ── 4. Ingest a frame -------------------------------------------


def ingest_mavlink_frame(db: Any, frame: dict) -> None:
    """Push one MAVLink message dict through the bridge."""
    from kya.runtime import ingest

    sysid = frame.get("sysid")
    compid = frame.get("compid", 1)
    if not isinstance(sysid, int) or not isinstance(compid, int):
        return  # parser will also reject -- bail early

    # Anchor to an invocation per vehicle. The fleet manifest tells
    # us which principal owns this (sysid, compid).
    principal = FLEET_MANIFEST.get((sysid, compid))
    if principal is None:
        # Unknown source -- the bridge will mark unbound. Still
        # surface it: an unauthorised sysid is the attack signal.
        invocation_id = None
        tenant_id = "acme"  # fallback for cross-tenant unbound
    else:
        tenant_id, principal_id = principal
        invocation_id = _invocation_for(
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
            result.error)


# ── 5. Live UDP reader (optional pymavlink path) ----------------


def stream_from_udp(
    db: Any, *, host: str = "127.0.0.1", port: int = 14550,
) -> None:
    """Stream MAVLink frames live from a UDP endpoint (the typical
    setup when a router like mavlink-routerd is between the
    autopilot and ground software)."""
    try:
        from pymavlink import mavutil
    except ImportError:
        logger.error(
            "pymavlink not installed. Either install "
            "veldt-kya[mavlink] or pre-decode frames to dicts upstream.")
        return

    conn = mavutil.mavlink_connection(f"udp:{host}:{port}")
    logger.info("[KYA-MAVLINK-COLLECTOR] listening on udp:%s:%d",
                host, port)
    while True:
        msg = conn.recv_match(blocking=True, timeout=5)
        if msg is None:
            continue
        ingest_mavlink_frame(db, msg.to_dict())


# ── Smoke-test entrypoint ---------------------------------------


def _smoke_test() -> None:
    """Run a couple of pre-canned frames through the pipeline so
    a developer can verify the wire-up without spinning SITL."""
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

    install_principal_resolver()

    # Synthetic ARM from uav_001
    ingest_mavlink_frame(db, {
        "mavpackettype": "COMMAND_LONG",
        "sysid": 1, "compid": 1,
        "command": 400, "param1": 1.0,
    })
    # Synthetic STATUSTEXT from an unknown source -- demonstrates
    # the unbound path (no fleet manifest entry).
    ingest_mavlink_frame(db, {
        "mavpackettype": "STATUSTEXT",
        "sysid": 99, "compid": 1,
        "severity": 4, "text": "unknown autopilot reports warning",
    })

    print("collector smoke test OK -- check the evidence chain in the DB")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if "--smoke" in sys.argv:
        _smoke_test()
    else:
        print(__doc__)
        print()
        print("Use --smoke to run the in-process smoke test or call")
        print("stream_from_udp(db) from your own collector.")
