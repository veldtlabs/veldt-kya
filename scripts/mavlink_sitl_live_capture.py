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
  OUT           output JSON file path (default /tmp/mavlink-sitl.json)
  TIMEOUT       SITL boot timeout in seconds (default 120)
  MISSION       capture duration in seconds (default 30)
  MAVLINK_PORT  host UDP port to bind (default 14550). Override to
                run multiple SITL instances in parallel.
  SITL_IMAGE    override the container image (default is a pinned
                ArduPilot SITL build; see _SITL_IMAGE_DEFAULT).

Usage:
  python3 scripts/mavlink_sitl_live_capture.py
  OUT=/tmp/my.json TIMEOUT=180 python3 scripts/mavlink_sitl_live_capture.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Local import -- shared helpers between the two SITL scripts.
sys.path.insert(0, str(Path(__file__).parent))
from _sitl_common import (  # noqa: E402
    capture,
    cleanup_container,
    die,
    env_int,
    preflight,
    run,
    wait_for_heartbeat,
    write_ndjson,
)


# ── Configuration ────────────────────────────────────────────────


OUT = Path(os.environ.get("OUT", "/tmp/mavlink-sitl.json"))
BOOT_TIMEOUT = env_int("TIMEOUT", 120)
CAPTURE_SECONDS = env_int("MISSION", 30)
MAVLINK_PORT = env_int("MAVLINK_PORT", 14550)

# ArduPilot SITL container. Pinning to ``:latest`` is intentional
# for development convenience; CI overrides this via SITL_IMAGE to
# point at a SHA-digested mirror so demos reproduce next year. To
# pin locally:
#   SITL_IMAGE=ardupilot/ardupilot-dev-base@sha256:<digest>
_SITL_IMAGE_DEFAULT = "ardupilot/ardupilot-dev-base:latest"
SITL_IMAGE = os.environ.get("SITL_IMAGE", _SITL_IMAGE_DEFAULT)

# Container name -- fixed so cleanup is deterministic.
CONTAINER_NAME = "kya-mavlink-sitl"

# Loopback only -- SITL UDP must not be reachable from outside the
# host. A laptop on a coffee-shop network would otherwise expose
# the autopilot to the LAN.
MAVLINK_HOST = "127.0.0.1"


# ── SITL launch ──────────────────────────────────────────────────


def launch_sitl() -> None:
    """Start ArduPilot SITL in a Docker container and bind its
    MAVLink UDP port to the host loopback only."""
    cleanup_container(CONTAINER_NAME)

    # SITL command line:
    #   --model quad      quadcopter dynamics
    #   --speedup 5       run 5x real-time for faster CI
    #   --no-mavproxy     don't fork MAVProxy; we read MAVLink
    #                     directly via pymavlink
    cmd = [
        "docker", "run", "-d", "--name", CONTAINER_NAME,
        "-p", f"{MAVLINK_HOST}:{MAVLINK_PORT}:14550/udp",
        SITL_IMAGE,
        "sim_vehicle.py",
        "-v", "ArduCopter",
        "--model", "quad",
        "--speedup", "5",
        "--no-mavproxy",
        # SITL emits MAVLink on UDP 14550 inside the container; the
        # -p above maps that to MAVLINK_PORT on the host loopback.
        "--out", "udp:127.0.0.1:14550",
    ]
    result = run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        die(f"docker run failed: {result.stderr}")


# ── Scripted mission ─────────────────────────────────────────────


def run_scripted_mission(conn) -> None:
    """Issue a minimal flight cycle so the autopilot emits every
    governance-relevant message family the parser handles:

        1. SET_MODE (-> mode_transition)
        2. PARAM_SET (-> parameter_change)
        3. MISSION_ITEM_INT upload (-> mission_waypoint)
        4. COMMAND_LONG arm (-> arm)
        5. COMMAND_LONG takeoff (-> takeoff)
        6. STATUSTEXT will fire naturally during the cycle (-> status)

    The inter-command sleeps are conservative: a cold CI runner
    with --speedup 5 needs ~0.5s to ACK SET_MODE before the next
    frame fires. The live integration test catches a silently-
    dropped command via the "required actions" coverage assertion.
    """
    import time as _time  # local; never used at module load
    from pymavlink import mavutil  # noqa: PLC0415

    sysid = conn.target_system or 1
    compid = conn.target_component or 1

    # 1. SET_MODE -> GUIDED (custom_mode=4 for ArduCopter)
    print("set_mode GUIDED ...")
    conn.mav.set_mode_send(
        sysid,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        4,  # GUIDED
    )
    _time.sleep(0.5)

    # 2. PARAM_SET FENCE_ENABLE=1
    print("param_set FENCE_ENABLE=1 ...")
    conn.mav.param_set_send(
        sysid, compid,
        b"FENCE_ENABLE",
        1.0,
        mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
    )
    _time.sleep(0.5)

    # 3. Mission upload (one waypoint)
    print("mission upload ...")
    conn.mav.mission_count_send(sysid, compid, 1)
    _time.sleep(0.5)
    conn.mav.mission_item_int_send(
        sysid, compid,
        0,  # seq
        mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
        0, 1,
        0, 0, 0, 0,
        int(-353621480), int(1491600400), 50.0,  # Canberra-ish + 50m
    )
    _time.sleep(0.5)

    # 4. COMMAND_LONG arm
    print("command_long arm ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0,
        1, 0, 0, 0, 0, 0, 0,
    )
    _time.sleep(1.0)

    # 5. COMMAND_LONG takeoff to 20m
    print("command_long takeoff 20m ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
        0,
        0, 0, 0, 0, 0, 0, 20.0,
    )


# ── Entrypoint ───────────────────────────────────────────────────


def main() -> int:
    preflight(OUT)
    try:
        launch_sitl()
        conn = wait_for_heartbeat(
            host=MAVLINK_HOST, port=MAVLINK_PORT,
            timeout=BOOT_TIMEOUT,
        )
        run_scripted_mission(conn)
        frames = capture(conn, CAPTURE_SECONDS)
    finally:
        cleanup_container(CONTAINER_NAME)

    handled_count = sum(1 for f in frames if f.get("_handled"))
    print(f"captured {len(frames)} total frames; "
          f"{handled_count} are governance-relevant")

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
