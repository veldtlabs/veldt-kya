#!/usr/bin/env python3
"""Live MAVLink capture via ArduPilot SITL for the kya parser tests.

Designed to run on:
  * GitHub Actions ubuntu-latest (Docker available)
  * Bare-metal Linux developer workstations
  * macOS dev machines (Docker Desktop)

The script spins ArduPilot SITL in Docker, waits for the autopilot
to boot, runs a scripted mission (ARM -> mode change -> waypoint
upload -> takeoff -> RTL), and captures every MAVLink frame the
autopilot emits + every command the script issues. Output is a
JSON file of dicts shaped like pymavlink's ``message.to_dict()`` --
exactly what ``kya.runtime.parsers.mavlink.parse`` consumes.

Exits non-zero if:
  * docker not installed OR daemon not running
  * pymavlink is not installed (collector dep missing)
  * SITL fails to boot within the timeout
  * Capture produced zero governance-relevant frames

so the calling CI workflow fails loudly rather than silently.

Environment:
  OUT                  output JSON file path (default /tmp/mavlink-sitl.json)
  TIMEOUT              SITL boot timeout in seconds (default 120)
  MISSION              capture duration in seconds (default 30)
  MAVLINK_PORT         host TCP port to map to the container's
                       arducopter console port (default 14550).
                       NOTE: TCP, not UDP -- the rework to
                       --no-mavproxy means we read arducopter's
                       direct TCP console at container port 5760.
                       Override (1-65535) to run multiple SITL
                       instances in parallel.
  SITL_IMAGE           override the container image (default is a
                       pinned ArduPilot SITL build; see
                       _SITL_IMAGE_DEFAULT).
  KYA_SITL_CONTAINER   override the container name. Default is
                       PID-tagged ("kya-mavlink-sitl-<pid>") so
                       two parallel local invocations don't race
                       each other's cleanup. Set this only when
                       a deployment / CI step needs a fixed name.
  GCS_SYSID            sysid the script emits as the ground-station
                       (default 255 -- mavproxy convention).
  GCS_COMPID           compid the script emits as the ground-station
                       (default 1).

Usage:
  python3 scripts/mavlink_sitl_live_capture.py
  OUT=/tmp/my.json TIMEOUT=180 python3 scripts/mavlink_sitl_live_capture.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Local import -- shared helpers between the two SITL scripts.
sys.path.insert(0, str(Path(__file__).parent))
from _sitl_common import (  # noqa: E402
    capture,
    cleanup_container,
    cleanup_stale_kya_containers,
    die,
    drain,
    env_int,
    env_port,
    preflight,
    run,
    verify_container_running,
    verify_host_port_free,
    wait_for_heartbeat,
    wait_for_port_serving,
    write_ndjson,
)

# ── Configuration ────────────────────────────────────────────────


OUT = Path(os.environ.get("OUT", "/tmp/mavlink-sitl.json"))
BOOT_TIMEOUT = env_int("TIMEOUT", 120)
CAPTURE_SECONDS = env_int("MISSION", 30)
MAVLINK_PORT = env_port("MAVLINK_PORT", 14550)

# ArduPilot SITL container.
#
# Image choice rationale: ardupilot/* official images on Docker Hub
# (ardupilot/ardupilot-dev-base, *-clang, *-chibios, etc.) are
# CI-for-BUILDING images -- they ship the toolchain to compile
# ArduPilot from source but do NOT contain a pre-built sim_vehicle.py
# runnable. ArduPilot's official project doesn't publish a turn-key
# SITL runtime image.
#
# The community-maintained ``radarku/ardupilot-sitl`` (highest-
# starred SITL runtime as of mid-2026) ships pre-built ArduCopter
# binaries + sim_vehicle.py at /ardupilot/Tools/autotest/sim_vehicle.py.
# Verified to boot ArduCopter v4.x against this script's command-line.
#
# Pinned by SHA digest, NOT ``:latest``. Reasons:
#   1. ``:latest`` is mutable -- the 3rd-party publisher can push
#      a breaking or compromised image and our CI silently picks
#      it up. Pinning makes the supply-chain footprint
#      bit-for-bit reproducible.
#   2. radarku is a community publisher (6 stars). We cannot
#      revoke their image, but we CAN refuse to trust new
#      revisions until we've re-verified locally.
#
# Bumping the pin: pull the new tag locally, run
# ``python scripts/mavlink_sitl_live_capture.py`` end-to-end,
# confirm the 4 live integration tests pass, then update the
# digest below AND in .github/workflows/mavlink-sitl-live.yml.
# A workflow step asserts the two literals match -- if you bump
# one without the other, CI will fail loudly.
#
# Override via SITL_IMAGE env var for vendored / mirrored images
# (e.g. ghcr.io/veldtlabs/...) in a customer deployment.
_SITL_IMAGE_DEFAULT = (
    "radarku/ardupilot-sitl@sha256:"
    "2364ae14e190e4cdd5d0839b3a55e6b5c6a980d9ff0000b1be7b8baae6fd50f1"
)
SITL_IMAGE = os.environ.get("SITL_IMAGE", _SITL_IMAGE_DEFAULT)

# Full path to sim_vehicle.py inside the image -- not on PATH by
# default in radarku/ardupilot-sitl, but at this canonical location.
_SIM_VEHICLE_PATH = "/ardupilot/Tools/autotest/sim_vehicle.py"

# Container name. PID-tagged by default so two local invocations
# don't race each other's cleanup_container() and one doesn't
# silently kill the other's container. Stable prefix preserves
# the "docker ps | grep mavlink-sitl" + "docker logs" debugging
# story.
#
# Set ``KYA_SITL_CONTAINER`` to override -- useful for a CI step
# that wants a fixed name across re-runs, or a deployment that
# wants a stable name for an external sidecar.
_CONTAINER_PREFIX = "kya-mavlink-sitl"
CONTAINER_NAME = os.environ.get(
    "KYA_SITL_CONTAINER",
    f"{_CONTAINER_PREFIX}-{os.getpid()}",
)

# Loopback only -- SITL TCP must not be reachable from outside the
# host. A laptop on a coffee-shop network would otherwise expose
# the autopilot to the LAN.
MAVLINK_HOST = "127.0.0.1"

# Inside-container port that arducopter listens on. Without
# mavproxy, arducopter SITL emits MAVLink on this TCP port (the
# canonical "console" port). Earlier we tried mapping UDP 14550,
# but ``--out udp:...`` is a mavproxy flag and silently does
# nothing when ``--no-mavproxy`` is set -- nothing was forwarded
# from 5760 -> 14550, so the host saw no traffic and the parser
# hung waiting for HEARTBEAT.
_SITL_INNER_PORT = 5760


# ── SITL launch ──────────────────────────────────────────────────


def launch_sitl() -> None:
    """Start ArduPilot SITL in a Docker container and bind its
    MAVLink TCP port to the host loopback only.

    Stages:
      1. (C) Sweep any abandoned ``kya-mavlink-sitl-*`` containers
         older than 60 min (Ctrl-C / CI-cancel leakage).
      2. Remove any container with OUR exact name -- a no-op on a
         fresh runner but defends against re-runs with
         ``KYA_SITL_CONTAINER`` set to the same value.
      3. (A) Verify host port is free BEFORE docker run, so a
         silent capture from someone else's MAVLink stream is
         impossible.
      4. ``docker run -d``.
      5. (B) Inspect the container -- if it crashed on entrypoint,
         catch it now (sub-second) rather than burning 180s on
         wait_for_port_serving.
    """
    # (C) Stale-sweep first. Won't touch a parallel run's
    # container -- those are <1 hour old.
    cleanup_stale_kya_containers(prefix=_CONTAINER_PREFIX)

    # Our exact name -- belt-and-braces.
    cleanup_container(CONTAINER_NAME)

    # (A) Port pre-check. Fail fast with a useful message if
    # something is already on the host port. TCP because the
    # live SITL path uses --no-mavproxy and reads arducopter's
    # TCP console directly (see _SITL_INNER_PORT docs).
    verify_host_port_free(MAVLINK_HOST, MAVLINK_PORT, protocol="tcp")

    # SITL command line:
    #   --model quad      quadcopter dynamics
    #   --speedup 5       run 5x real-time for faster CI
    #   --no-mavproxy     don't fork MAVProxy; we read MAVLink
    #                     directly via pymavlink against the
    #                     arducopter TCP console (port 5760).
    cmd = [
        "docker", "run", "-d", "--name", CONTAINER_NAME,
        # Hardening posture for an SDK marketed on principal-bound
        # evidence: drop ALL caps + forbid privilege escalation.
        # arducopter is a userland binary -- it has no legitimate
        # need for any Linux capability. The TCP port it binds
        # (5760) is unprivileged. Dropping caps is free.
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges:true",
        "-p", f"{MAVLINK_HOST}:{MAVLINK_PORT}:{_SITL_INNER_PORT}/tcp",
        SITL_IMAGE,
        # Full path -- sim_vehicle.py isn't on PATH in this image.
        _SIM_VEHICLE_PATH,
        "-v", "ArduCopter",
        "--model", "quad",
        "--speedup", "5",
        "--no-mavproxy",
    ]
    result = run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        die(f"docker run failed: {result.stderr}")

    # (B) Container running + state check. A 1-second guard
    # against "docker run accepted, container crashed on entry
    # to sim_vehicle.py" -- which would otherwise present as a
    # 180s wait_for_port_serving timeout.
    verify_container_running(CONTAINER_NAME)


# ── Scripted mission ─────────────────────────────────────────────


def run_scripted_mission(conn) -> tuple[list[dict], list[dict]]:
    """Issue a minimal flight cycle so the autopilot emits every
    governance-relevant message family the parser handles:

        1. SET_MODE (-> mode_transition)
        2. PARAM_SET (-> parameter_change)
        3. MISSION_ITEM_INT upload (-> mission_waypoint)
        4. COMMAND_LONG arm (-> arm)
        5. COMMAND_LONG takeoff (-> takeoff)
        6. STATUSTEXT will fire naturally during the cycle (-> status)

    Returns a 2-tuple:
      * operator_frames: list of dicts for the commands the
        script JUST emitted (pymavlink to_dict() shape).
      * inbound_during_mission: list of dicts for the autopilot's
        return traffic captured INLINE between sends. Drains
        the TCP buffer during the ~2.5s mission window so the
        COMMAND_ACK / SET_MODE_ACK / mode-change STATUSTEXT
        bursts aren't lost to buffer overrun before the
        post-mission ``capture()`` window starts (the H1 fix
        from the SITL CI review).

    Why we synthesize operator frames rather than read back from
    the wire: in normal MAVLink, commands flow from operator ->
    autopilot and the autopilot ACKs them; the autopilot does
    NOT echo the original command back. A real KYA deployment
    hooks into a MAVLink router (mavproxy aircraft hook, GCS
    sidecar) that tees both directions. This script is its own
    operator -- so we record what we emit, then merge with what
    the autopilot returns.

    The inter-command sleeps are now ``drain`` calls instead of
    bare ``time.sleep`` so the inter-command intervals double as
    capture windows. A cold CI runner still needs ~0.5s for
    SET_MODE to ACK before the next frame fires; that time is
    now spent reading the socket instead of idle-blocking.
    """
    from pymavlink import mavutil  # noqa: PLC0415

    sysid = conn.target_system or 1
    compid = conn.target_component or 1
    # The operator-side sysid we emit under. pymavlink defaults
    # to 255 for ground-station traffic, but allow override via
    # GCS_SYSID env (a multi-operator test setup would use this).
    gcs_sysid = env_int("GCS_SYSID", 255)
    gcs_compid = env_int("GCS_COMPID", 1)

    emitted: list[dict] = []
    inbound: list[dict] = []

    def _record(d: dict) -> None:
        d.setdefault("sysid", gcs_sysid)
        d.setdefault("compid", gcs_compid)
        d["_handled"] = True
        d["_ts"] = time.time()
        emitted.append(d)

    def _pause(seconds: float) -> None:
        """Replace bare time.sleep with an inline drain so the
        TCP buffer can't overrun. Same wall-clock duration as
        the old sleep, but now feeding ``inbound``."""
        inbound.extend(drain(conn, seconds))

    # 1. SET_MODE -> GUIDED (custom_mode=4 for ArduCopter)
    print("set_mode GUIDED ...")
    conn.mav.set_mode_send(
        sysid,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        4,  # GUIDED
    )
    _record({
        "mavpackettype": "SET_MODE",
        "target_system": sysid,
        "base_mode": mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        "custom_mode": 4,
    })
    _pause(0.5)

    # 2. PARAM_SET FENCE_ENABLE=1
    print("param_set FENCE_ENABLE=1 ...")
    conn.mav.param_set_send(
        sysid, compid,
        b"FENCE_ENABLE",
        1.0,
        mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
    )
    _record({
        "mavpackettype": "PARAM_SET",
        "target_system": sysid,
        "target_component": compid,
        "param_id": "FENCE_ENABLE",
        "param_value": 1.0,
        "param_type": mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
    })
    _pause(0.5)

    # 3. Mission upload (one waypoint)
    print("mission upload ...")
    conn.mav.mission_count_send(sysid, compid, 1)
    _pause(0.5)
    conn.mav.mission_item_int_send(
        sysid, compid,
        0,  # seq
        mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
        0, 1,
        0, 0, 0, 0,
        (-353621480), 1491600400, 50.0,  # Canberra-ish + 50m
    )
    _record({
        "mavpackettype": "MISSION_ITEM_INT",
        "target_system": sysid,
        "target_component": compid,
        "seq": 0,
        "frame": mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        "command": mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
        "current": 0,
        "autocontinue": 1,
        "x": -353621480,
        "y": 1491600400,
        "z": 50.0,
    })
    _pause(0.5)

    # 4. COMMAND_LONG arm
    print("command_long arm ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0,
        1, 0, 0, 0, 0, 0, 0,
    )
    _record({
        "mavpackettype": "COMMAND_LONG",
        "target_system": sysid,
        "target_component": compid,
        "command": mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        "confirmation": 0,
        "param1": 1.0, "param2": 0.0, "param3": 0.0, "param4": 0.0,
        "param5": 0.0, "param6": 0.0, "param7": 0.0,
    })
    _pause(1.0)

    # 5. COMMAND_LONG takeoff to 20m
    print("command_long takeoff 20m ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
        0,
        0, 0, 0, 0, 0, 0, 20.0,
    )
    _record({
        "mavpackettype": "COMMAND_LONG",
        "target_system": sysid,
        "target_component": compid,
        "command": mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
        "confirmation": 0,
        "param1": 0.0, "param2": 0.0, "param3": 0.0, "param4": 0.0,
        "param5": 0.0, "param6": 0.0, "param7": 20.0,
    })

    # Final small drain to catch the last ACK after takeoff.
    _pause(0.5)
    return emitted, inbound


# ── Entrypoint ───────────────────────────────────────────────────


def main() -> int:
    preflight(OUT)
    try:
        launch_sitl()
        # Gate: don't connect pymavlink until arducopter is
        # actually serving on the inner port. Without this the
        # connect would EOF immediately on the slow CI runner
        # and waste the entire heartbeat timeout window.
        wait_for_port_serving(
            host=MAVLINK_HOST, port=MAVLINK_PORT,
            timeout=BOOT_TIMEOUT,
            container_name=CONTAINER_NAME,
        )
        conn = wait_for_heartbeat(
            host=MAVLINK_HOST, port=MAVLINK_PORT,
            timeout=BOOT_TIMEOUT,
            container_name=CONTAINER_NAME,
            transport="tcp",
        )
        operator_frames, inbound_during = run_scripted_mission(conn)
        inbound_after = capture(conn, CAPTURE_SECONDS)
    finally:
        cleanup_container(CONTAINER_NAME)

    # Stitch operator emissions + inbound traffic captured DURING
    # the mission (inline drain between sends) + inbound capture
    # AFTER the mission. The mission-window drain is the H1 fix:
    # without it the COMMAND_ACK / SET_MODE_ACK / mode-change
    # STATUSTEXT bursts that come back during the ~2.5s of mission
    # sends would sit in pymavlink's TCP recv buffer until the
    # post-mission ``capture()`` finally reads them -- on slow
    # CI runners that buffer overruns and loses frames.
    inbound_frames = inbound_during + inbound_after
    frames = operator_frames + inbound_frames

    handled_count = sum(1 for f in frames if f.get("_handled"))
    print(
        f"captured {len(frames)} total frames; "
        f"{handled_count} are governance-relevant "
        f"({len(operator_frames)} operator + "
        f"{len(inbound_during)} inbound-during + "
        f"{len(inbound_after)} inbound-after)"
    )

    # H1-canary: assert we got non-empty inbound traffic. If the
    # autopilot booted but emitted nothing back -- or the TCP
    # buffer overran without us noticing -- the integration test
    # would otherwise still pass on the synthesised operator
    # frames alone. Fail explicitly so the next CI run surfaces
    # the regression instead of silently shrinking coverage.
    if not inbound_frames:
        die(
            "captured ZERO inbound frames -- the autopilot replied "
            "nothing during/after the mission window. Either SITL "
            "is hung after heartbeat OR the H1 fix regressed and "
            "frames are being dropped. Investigate."
        )

    write_ndjson(frames, OUT)
    print(f"wrote {OUT}")

    if handled_count == 0:
        die(
            "captured zero governance-relevant frames "
            "(no COMMAND_LONG / SET_MODE / PARAM_SET / etc.). "
            "SITL booted but the scripted mission did not exercise "
            "the parser surface -- investigate."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
