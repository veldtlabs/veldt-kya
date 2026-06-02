"""KYA partner demo -- MAVLink / drone autonomy governance (v0.1.8)

Shows off the v0.1.8 surface end-to-end on a single SQLite tempdb:

  * 14 principal_kinds: 'drone', 'controller', 'autonomous_system'
    used here (rest of the vocabulary: agent, service_account, robot,
    vehicle, plc, scada, sensor, actuator, lakehouse_job,
    machine_identity, user).
  * Many-to-many principal edges (``kya_principal_edges``):
    edges carry an edge_kind (operates / member_of / supervises /
    delegates_to). Walks are cycle-safe and queryable.
  * Hierarchical fingerprint chain:
    definition_hash  ->  principal_fingerprint
    (kya_pro layers fleet_fingerprint + pack_fingerprint on top --
     this demo stays in open-SDK territory.)
  * MAVLink parser (kya.runtime.parsers.mavlink) canonicalises
    six message families into AutonomyEvent records.
  * Tamper-evident HMAC evidence chain across the 3 demo phases.

Three-phase narrative:
  Phase A. Agent-approved mission start
              GCS Alpha (controller) issues SET_MODE / arm / takeoff
              to drone uav_001. Each command attributed to BOTH the
              GCS operator and the receiving autopilot.
  Phase B. Human override mid-flight
              GCS issues COMMAND_LONG flight_termination (critical).
              Parser surfaces severity=critical; audit row carries
              full operator attribution -- "who pressed kill" is a
              single SELECT.
  Phase C. Unauthorized command source
              Unknown sysid=99 emits COMMAND_LONG arm. Fleet manifest
              has no mapping -> bridge records the event UNBOUND
              (no tenant). Safe failure mode; surfaces in audit
              queries as the regulator signal.

Zero-setup: SQLite tempdb. No Docker, no pymavlink, no SITL, no
Postgres. Run with ``python examples/partner_demo_mavlink.py``.
"""
from __future__ import annotations

import os
import platform
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Suppress the "no signing key set" warning by providing a stable
# demo key. The chain still HMAC-signs; the warning is just kya's
# nudge for production deployments to mount a real KMS provider.
# Key must be base64(32 bytes); this is "kya-demo-key" padded with
# zeros + base64-encoded so the chain has a stable key across runs.
import base64 as _b64
os.environ.setdefault(
    "KYA_EVIDENCE_SIGNING_KEY",
    _b64.b64encode(b"partner-demo-mavlink-key-32bytes").decode(),
)

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import kya
from kya import principal_fingerprint, snapshot_principal
from kya.principal_edges import (
    add_principal_edge,
    list_children,
    walk_descendants,
)
from kya.runtime import (
    ExplicitBindingCache,
    MavlinkSysidResolver,
    PrincipalResolverChain,
    record_runtime_event,
    set_principal_resolver,
)
from kya.runtime.parsers import mavlink

# ── Style helpers ──────────────────────────────────────────────


HR = "=" * 72
THIN = "-" * 72


def banner(title: str) -> None:
    print()
    print(HR)
    print(f"  {title}")
    print(HR)


def phase(n: int, title: str) -> None:
    print()
    print(f"[{n}] {title}")


def sub(line: str) -> None:
    print(f"     {line}")


# ── Fleet topology ─────────────────────────────────────────────
#
# Principals (kya_principals):
#   autonomous_system: fleet:alpha       (the operator-defined fleet)
#   controller       : controller:gcs_alpha
#   drone            : drone:uav_001, drone:uav_002, drone:uav_003
#
# Edges (kya_principal_edges):
#   controller --operates--> autonomous_system
#   autonomous_system --member_of--> drone × 3
#       (member_of points parent=system, child=drone -- the system
#        "has" each drone as a member)
#
# Wire mapping (kya.runtime.MavlinkSysidResolver):
#   sysid:compid -> (tenant, principal_id)

TENANT = "acme_aero"

FLEET = "fleet_alpha"
GCS = "gcs_alpha"
UAV1, UAV2, UAV3 = "uav_001", "uav_002", "uav_003"

WIRE_MAP: dict[tuple[int, int], tuple[str, str]] = {
    # (sysid, compid) : (tenant_id, principal_id)
    (1, 1): (TENANT, UAV1),
    (2, 1): (TENANT, UAV2),
    (3, 1): (TENANT, UAV3),
    (10, 190): (TENANT, GCS),
}


# ── MAVLink frame builders ─────────────────────────────────────
#
# Real collectors would get these from pymavlink.to_dict() over UDP.
# We synthesise them so the demo doesn't need pymavlink / SITL.

MAV_CMD_NAV_TAKEOFF = 22
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_FLIGHT_TERMINATION = 185
MAV_PARAM_TYPE_REAL32 = 9
MAV_MODE_FLAG_CUSTOM_MODE_ENABLED = 1


def set_mode_frame(*, src, target_sysid, custom_mode=4):
    return {
        "mavpackettype": "SET_MODE",
        "sysid": src[0], "compid": src[1],
        "target_system": target_sysid,
        "base_mode": MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        "custom_mode": custom_mode,
    }


def command_long_frame(*, src, target_sysid, target_compid, command, **params):
    p = {f"param{i}": 0.0 for i in range(1, 8)}
    p.update(params)
    return {
        "mavpackettype": "COMMAND_LONG",
        "sysid": src[0], "compid": src[1],
        "target_system": target_sysid,
        "target_component": target_compid,
        "command": command,
        "confirmation": 0,
        **p,
    }


def param_set_frame(*, src, target_sysid, target_compid,
                    param_id, param_value):
    return {
        "mavpackettype": "PARAM_SET",
        "sysid": src[0], "compid": src[1],
        "target_system": target_sysid,
        "target_component": target_compid,
        "param_id": param_id,
        "param_value": param_value,
        "param_type": MAV_PARAM_TYPE_REAL32,
    }


def statustext_frame(*, src, severity: int, text: str):
    """Drone-side STATUSTEXT. Source is the drone (autopilot), not
    the operator. Shows per-vehicle attribution alongside operator
    attribution in the same evidence flow."""
    return {
        "mavpackettype": "STATUSTEXT",
        "sysid": src[0], "compid": src[1],
        "severity": severity,
        "text": text,
    }


# ── Per-frame ingestion ────────────────────────────────────────
#
# The runtime bridge chains evidence under (tenant, invocation), so
# we need an invocation anchor per vehicle. Cache one per
# (sysid, compid) -- this is exactly the
# ``examples/runtime_mavlink_collector.py`` pattern, inlined so the
# demo is self-contained.
_invocation_cache: dict[tuple[int, int], int] = {}


def invocation_for(db: Session, *, tenant_id: str, sysid: int,
                   compid: int, principal_id: str,
                   principal_kind: str) -> int:
    key = (sysid, compid)
    if key in _invocation_cache:
        return _invocation_cache[key]
    inv = kya.record_invocation(
        db,
        tenant_id=tenant_id,
        agent_key=principal_id,
        mode="autonomous_action",
        principal_kind=principal_kind,
        principal_id=principal_id,
        outcome="success",
    )
    _invocation_cache[key] = inv
    return inv


def ingest_and_describe(db: Session, frame: dict) -> dict | None:
    ev = mavlink.parse(frame)
    if ev is None:
        return None

    # Look up the principal binding ourselves so we can build
    # the invocation anchor BEFORE the bridge runs.
    sysid = frame.get("sysid")
    compid = frame.get("compid", 1)
    binding = WIRE_MAP.get((sysid, compid))
    if binding is None:
        # Unknown source -- bridge will record unbound, no invocation
        invocation_id = None
        kind = "unknown"
    else:
        tenant_id, pid = binding
        kind = ("controller" if pid == GCS else
                "autonomous_system" if pid == FLEET else
                "drone")
        invocation_id = invocation_for(
            db, tenant_id=tenant_id,
            sysid=sysid, compid=compid,
            principal_id=pid,
            principal_kind=kind,
        )

    result = record_runtime_event(
        ev, db=db, invocation_id=invocation_id,
    )
    return {
        "action": ev.action,
        "severity": getattr(ev, "severity", None),
        "principal": result.principal_id,
        "principal_kind": kind if binding else None,
        "tenant": result.tenant_id,
        "binding_method": result.principal_binding_method,
        "accepted": result.accepted,
        "evidence_id": result.evidence_id,
        "invocation_id": invocation_id,
        "src_sysid": sysid,
        "src_compid": compid,
    }


# ── Main flow ──────────────────────────────────────────────────


def main() -> int:
    started_at = datetime.now(timezone.utc).isoformat()

    # ── Banner ──
    banner("KYA PARTNER DEMO -- MAVLink / drone autonomy governance")
    print(f"# captured at  : {started_at}")
    print(f"# host         : {platform.node()} ({platform.system()})")
    print(f"# python       : {platform.python_version()}")
    print(f"# veldt-kya    : {kya.__version__}")
    print( "# topology     : 1 fleet (autonomous_system) +"
           " 1 controller + 3 drones")
    print( "# zero-setup   : SQLite tempdb, no Docker, no pymavlink, no SITL")
    print( "# live data    : run is NOT artificially deterministic --")
    print( "                evidence_ids and HMAC bytes differ per run.")

    # ── Bootstrap ──
    phase(0, "bootstrap: SQLite tempdb + kya tables + resolver chain")
    fd, dbpath = tempfile.mkstemp(suffix=".sqlite",
                                   prefix="kya_drone_demo_")
    os.close(fd)
    engine = create_engine(f"sqlite:///{dbpath}")
    db = Session(engine)
    kya.init_storage(db)
    db.commit()
    set_principal_resolver(PrincipalResolverChain([
        ExplicitBindingCache(),
        MavlinkSysidResolver(WIRE_MAP),
    ]))
    sub(f"sqlite db: {dbpath}")
    sub(f"wire map entries: {len(WIRE_MAP)}")

    # ── Register principals with explicit kinds ──
    phase(1, "Register principals (14-kind vocabulary; "
             "using 3 kinds here)")
    principal_defs = [
        ("autonomous_system", FLEET,
         {"role": "fleet_aggregator", "site": "wodonga_test_range"}),
        ("controller", GCS,
         {"role": "ground_station",
          "operator": "j.kim@acme.aero",
          "site": "wodonga_test_range"}),
        ("drone", UAV1,
         {"airframe": "quadcopter",
          "serial": "AC-X4-001",
          "firmware": "ArduCopter 4.5.7"}),
        ("drone", UAV2,
         {"airframe": "quadcopter",
          "serial": "AC-X4-002",
          "firmware": "ArduCopter 4.5.7"}),
        ("drone", UAV3,
         {"airframe": "hexacopter",
          "serial": "AC-H6-003",
          "firmware": "ArduCopter 4.5.7"}),
    ]
    snapshots: dict[str, int] = {}
    for kind, pid, defin in principal_defs:
        v = snapshot_principal(
            db, tenant_id=TENANT,
            principal_kind=kind, principal_id=pid,
            definition=defin,
        )
        snapshots[pid] = v
        sub(f"snapshot_principal  kind={kind:<19s} "
            f"id={pid:<24s} version={v}")
    db.commit()

    # ── Wire many-to-many edges ──
    phase(2, "Wire many-to-many edges (kya_principal_edges)")
    edges = [
        # The fleet "has" each drone as a member.
        ("autonomous_system", FLEET, "drone", UAV1, "member_of"),
        ("autonomous_system", FLEET, "drone", UAV2, "member_of"),
        ("autonomous_system", FLEET, "drone", UAV3, "member_of"),
        # The controller "operates" the fleet (the regulatory authority
        # walks operator -> fleet -> drone for incident attribution).
        ("controller", GCS, "autonomous_system", FLEET, "operates"),
    ]
    for pk, pid, ck, cid, ek in edges:
        add_principal_edge(
            db, tenant_id=TENANT,
            parent_kind=pk, parent_id=pid,
            child_kind=ck, child_id=cid,
            edge_kind=ek,
            attributes={"declared_at": started_at},
        )
        sub(f"{pid:<24s} --{ek:^10s}--> {cid}")
    db.commit()

    # ── Show topology via edge walk ──
    phase(3, "Topology walk (walk_descendants from controller)")
    # Walk from controller -> fleet -> drones to demonstrate that the
    # operator authority is reachable to every drone via edges.
    sub(f"  {GCS}  (controller)")
    indent = {0: "    |-- "}
    for depth, edge in walk_descendants(
        db, tenant_id=TENANT,
        root_kind="controller", root_id=GCS,
        max_depth=3,
    ):
        prefix = "    " + "    " * depth + "|-- "
        sub(f"{prefix}{edge.child_id}  "
            f"({edge.child_kind}, via {edge.edge_kind})")

    # ── Hierarchical fingerprint chain ──
    phase(4, "Principal fingerprint chain "
             "(definition_hash -> principal_fingerprint)")
    sub(f"{'principal':<14s} {'kind':<19s} "
        f"{'def_hash':<19s} fingerprint (scheme={'principal-v1'})")
    sub(THIN)
    for kind, pid, _ in principal_defs:
        fp = principal_fingerprint(
            db, tenant_id=TENANT,
            principal_kind=kind, principal_id=pid,
        )
        dh = fp.get("definition_hash") or "(none)"
        sub(f"{pid:<14s} {kind:<19s} "
            f"{dh[:16]:<19s} {fp['fingerprint'][:16]}...")

    # ── Phase A: agent-approved start ──
    phase(5, "Phase A -- agent-approved mission start "
             "(GCS Alpha -> uav_001)")
    gcs_wire = (10, 190)
    uav1_wire = (1, 1)
    phase_a_frames = [
        # Operator -> drone commands (sysid 10:190 -> 1:1)
        ("SET_MODE GUIDED  (op -> drone)",
         set_mode_frame(src=gcs_wire, target_sysid=uav1_wire[0])),
        ("PARAM_SET FENCE_ENABLE=1  (op -> drone)",
         param_set_frame(
             src=gcs_wire, target_sysid=uav1_wire[0],
             target_compid=uav1_wire[1],
             param_id="FENCE_ENABLE", param_value=1.0,
         )),
        ("COMMAND_LONG ARM  (op -> drone)",
         command_long_frame(
             src=gcs_wire, target_sysid=uav1_wire[0],
             target_compid=uav1_wire[1],
             command=MAV_CMD_COMPONENT_ARM_DISARM, param1=1.0,
         )),
        # Drone-side telemetry coming back (sysid 1:1, autopilot)
        ("STATUSTEXT 'EKF3 IMU0 in-flight'  (drone)",
         statustext_frame(
             src=uav1_wire, severity=6,
             text="EKF3 IMU0 in-flight learning enabled",
         )),
        ("COMMAND_LONG TAKEOFF 20m  (op -> drone)",
         command_long_frame(
             src=gcs_wire, target_sysid=uav1_wire[0],
             target_compid=uav1_wire[1],
             command=MAV_CMD_NAV_TAKEOFF, param7=20.0,
         )),
    ]
    all_records: list[dict] = []
    for label, frame in phase_a_frames:
        d = ingest_and_describe(db, frame)
        if d is None:
            sub(f"{label:32s}  parser=SKIP")
            continue
        all_records.append(d)
        kind = d['principal_kind'] or '?'
        sub(
            f"{label:32s}  -> action={d['action']:<18s} "
            f"src=({d['src_sysid']},{d['src_compid']}) "
            f"principal={d['principal']} [{kind}]"
        )
    db.commit()

    # ── Phase B: human override ──
    phase(6, "Phase B -- human override mid-flight "
             "(operator kill-switch)")
    kill = command_long_frame(
        src=gcs_wire, target_sysid=uav1_wire[0],
        target_compid=uav1_wire[1],
        command=MAV_CMD_FLIGHT_TERMINATION, param1=1.0,
    )
    d = ingest_and_describe(db, kill)
    db.commit()
    if d is not None:
        all_records.append(d)
        sub(f"COMMAND_LONG FLIGHT_TERMINATION  -> "
            f"action={d['action']}  severity={d['severity']}")
        sub(f"operator attribution             -> "
            f"{d['principal']} [{d['principal_kind']}]")
        sub(f"audit row                        -> "
            f"evidence_id={str(d['evidence_id'])[:12]}...  "
            f"accepted={d['accepted']}")

    # ── Phase C: unauthorized source ──
    phase(7, "Phase C -- unauthorized command source "
             "(rogue sysid=99 emits ARM)")
    rogue_wire = (99, 1)
    rogue_arm = command_long_frame(
        src=rogue_wire, target_sysid=uav1_wire[0],
        target_compid=uav1_wire[1],
        command=MAV_CMD_COMPONENT_ARM_DISARM, param1=1.0,
    )
    d = ingest_and_describe(db, rogue_arm)
    db.commit()
    if d is not None:
        all_records.append(d)
        sub(f"rogue COMMAND_LONG ARM            -> "
            f"action={d['action']}")
        sub(f"fleet manifest lookup             -> "
            f"sysid=99 UNKNOWN (not in wire map)")
        sub(f"principal binding                 -> "
            f"principal={d['principal'] or '<unbound>'} "
            f"tenant={d['tenant'] or '<unbound>'}")
        sub(f"audit row                         -> "
            f"evidence_id={str(d['evidence_id'])[:12]}...  "
            f"accepted={d['accepted']}  "
            f"(safe failure mode: unbound row)")

    # ── DAG view ──
    phase(8, "Evidence DAG: per-principal invocation chain")
    by_principal: dict[str | None, list[dict]] = {}
    for r in all_records:
        by_principal.setdefault(r["principal"], []).append(r)
    for pid, rows in sorted(by_principal.items(),
                            key=lambda kv: (kv[0] or "")):
        kind = rows[0]['principal_kind'] or '?'
        invs = sorted({
            r["invocation_id"] for r in rows
            if r["invocation_id"] is not None
        })
        sub(f"{pid or '<unbound>':<30s} [{kind}]")
        sub(f"  invocations: {invs or '(none -- unbound)'}")
        sub(f"  evidence rows: {len(rows)} "
            f"(actions: "
            f"{', '.join(r['action'] for r in rows)})")

    # ── HMAC chain integrity ──
    phase(9, "HMAC evidence chain integrity (per invocation)")
    valid = 0
    broken = 0
    for inv in sorted(set(_invocation_cache.values())):
        ok = kya.verify_chain(db, tenant_id=TENANT, invocation_id=inv)
        ok_bool = bool(ok if isinstance(ok, bool) else ok.get("valid", False))
        if ok_bool:
            valid += 1
            sub(f"invocation {inv}: VALID  ({ok})")
        else:
            broken += 1
            sub(f"invocation {inv}: BROKEN ({ok})")
    chain_report = {"valid_chains": valid, "broken_chains": broken}

    # ── Final summary ──
    banner("FINAL CAPTURE SUMMARY")
    print(f"tenant                 : {TENANT}")
    print(f"started_at             : {started_at}")
    print(f"principals registered  : "
          f"{len(principal_defs)} "
          f"(1 autonomous_system, 1 controller, 3 drones)")
    print(f"edges declared         : "
          f"{len(edges)} "
          f"(3 member_of + 1 operates)")
    bound = [r for r in all_records if r["tenant"]]
    unbound = [r for r in all_records if not r["tenant"]]
    print(f"phase A (approved)     : "
          f"{len(bound) - 1} approved frames "
          f"(4 op + 1 drone telemetry)")
    print(f"phase B (override)     : "
          f"1 critical flight_termination (operator-attributed)")
    print(f"phase C (rogue)        : "
          f"{len(unbound)} unauthorized arm (UNBOUND, audit signal)")
    print(f"evidence rows total    : {len(all_records)}")
    print(f"HMAC chains            : "
          f"valid={chain_report.get('valid_chains', 0)} "
          f"broken={chain_report.get('broken_chains', 0)}")
    print()
    print("ALL PHASES COMPLETED")

    # ── Key proofs ──
    banner("KEY PROOFS (for compliance / regulator review)")
    print("1. Typed attribution        every event carries"
          " principal_kind +")
    print("                            principal_id. A regulator can"
          " query")
    print("                            'which drone' vs 'which operator'")
    print("                            without joining ad-hoc strings.")
    print("2. Graph attribution        kya_principal_edges declares the")
    print("                            controller -> fleet -> drone chain;")
    print("                            walk_descendants enumerates 'which")
    print("                            drones did this operator authorise")
    print("                            for' in one query.")
    print("3. Fingerprinted identity   principal_fingerprint hashes the")
    print("                            (kind, id, definition, edges)")
    print("                            tuple. A drone with a different")
    print("                            firmware produces a different")
    print("                            fingerprint -> audit can detect")
    print("                            silently-replaced units.")
    print("4. Tamper-evident           every evidence row HMAC-chained;")
    print("                            verify_chain reports valid/broken.")
    print("5. Safe failure mode        unknown sysid -> unbound row, NOT")
    print("                            silent drop. Audit queries can")
    print("                            select where tenant_id IS NULL to")
    print("                            find rogue command sources.")
    print("6. Operator override audit  critical flight_termination preserved")
    print("                            with full GCS attribution. 'Who")
    print("                            pressed kill' is a single SELECT.")

    # ── Glossary ──
    banner("GLOSSARY")
    print("principal_kind   one of 14 typed labels for an actor: drone,")
    print("                 controller, autonomous_system, agent,")
    print("                 service_account, robot, vehicle, plc, scada,")
    print("                 sensor, actuator, lakehouse_job,")
    print("                 machine_identity, user.")
    print("principal_edge   parent -> child relationship in")
    print("                 kya_principal_edges. Carries an edge_kind")
    print("                 (operates, member_of, supervises,")
    print("                 delegates_to, ...). Walks are cycle-safe.")
    print("sysid : compid   MAVLink wire addressing. sysid identifies the")
    print("                 node; compid the component (autopilot,")
    print("                 gimbal, GCS UI, ...). The fleet manifest")
    print("                 maps (sysid, compid) -> typed principal.")
    print("fingerprint      stable hash of (kind, id, definition,")
    print("                 edges-out). Changes when any of those")
    print("                 change -> silently-replaced units detected.")
    print("HMAC chain       each evidence row's hash includes the prior")
    print("                 row's hash + a tenant-keyed HMAC signature.")
    print("                 Tamper anywhere -> verify_chain reports")
    print("                 a broken chain.")
    print("unbound          an event whose source did not match the")
    print("                 fleet manifest. Recorded WITHOUT a tenant")
    print("                 so audit queries surface it. The safe")
    print("                 failure mode for rogue sources.")

    db.close()
    print()
    print(f"# capture db: {dbpath}")
    print( "# rerun: python examples/partner_demo_mavlink.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
