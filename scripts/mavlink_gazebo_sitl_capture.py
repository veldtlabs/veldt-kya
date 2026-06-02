#!/usr/bin/env python3
"""ArduPilot SITL + Gazebo: visible-flight capture for partner demos.

Same MAVLink capture as ``mavlink_sitl_live_capture.py``, but with
Gazebo running alongside SITL so a partner audience SEES a drone
flying in a 3D world instead of just reading terminal logs.

Why two scripts?
----------------
The pure-SITL harness ships in ``mavlink_sitl_live_capture.py`` for
CI: lightweight (~500MB container), no display dependency, runs
headless on any GitHub Actions ubuntu-latest runner. It proves the
parser is correct against a real autopilot's MAVLink output.

This script is the **demo upgrade path**: layer Gazebo on top so
the same flight cycle becomes a credible visual demonstration. The
MAVLink output is identical -- Gazebo adds physics + visuals, not
new MAVLink shapes -- so the parser and the bridge see the exact
same frames.

Setup requirements
------------------
* Docker daemon running (script checks via ``docker info``)
* Display server -- one of:
    - Linux host with X11: works out-of-the-box. The script
      auto-opens X11 to local Docker via ``xhost +local:docker``
      AND restores ``xhost -local:docker`` on exit so the host's
      X session isn't left wide open after the demo.
    - macOS / Windows: run via XQuartz / VcXsrv, OR set
      ``KYA_GAZEBO_HEADLESS=1`` to capture without rendering
      (you still get the MAVLink trace; visuals are skipped).
    - WSL2: use WSLg (Windows 11) or VcXsrv on the Windows host.
* GPU optional but recommended -- Gazebo's physics is CPU-friendly
  but the renderer prefers a GPU. Without one, expect ~5fps.

Image choice
------------
We use ``khancyr/ardupilot-gazebo`` -- a community-maintained image
that bundles ArduPilot SITL + Gazebo + the iris quadcopter model
already configured. This avoids the multi-step "build PX4 + add
Gazebo plugins" dance the official ArduPilot docs walk through.

A defence-adjacent deployment should mirror this image to a
project-controlled registry and pin by SHA digest.

Environment
-----------
  OUT                  output JSON path (default /tmp/mavlink-gazebo.json)
  TIMEOUT              SITL boot timeout in seconds (default 180 --
                       Gazebo needs longer than headless SITL)
  MISSION              capture duration in seconds (default 60)
  MAVLINK_PORT         host UDP port (default 14550)
  KYA_GAZEBO_HEADLESS  "1" / "true" / "yes" / "on" -> run Gazebo
                       without rendering (CI / no-display environments)
  GAZEBO_IMAGE         override the container image

Usage
-----
  # Local demo with display:
  python3 scripts/mavlink_gazebo_sitl_capture.py

  # Headless (CI / SSH-only):
  KYA_GAZEBO_HEADLESS=1 python3 scripts/mavlink_gazebo_sitl_capture.py
"""
from __future__ import annotations

import atexit
import os
import subprocess
import sys
from pathlib import Path

# Local import -- shared helpers between the two SITL scripts.
sys.path.insert(0, str(Path(__file__).parent))
from _sitl_common import (  # noqa: E402
    capture,
    cleanup_container,
    cleanup_stale_kya_containers,
    die,
    env_int,
    env_port,
    preflight,
    run,
    verify_container_running,
    verify_host_port_free,
    wait_for_heartbeat,
    write_ndjson,
)

# ── Configuration ────────────────────────────────────────────────


OUT = Path(os.environ.get("OUT", "/tmp/mavlink-gazebo.json"))
BOOT_TIMEOUT = env_int("TIMEOUT", 180)
CAPTURE_SECONDS = env_int("MISSION", 60)
MAVLINK_PORT = env_port("MAVLINK_PORT", 14550)
HEADLESS = os.environ.get("KYA_GAZEBO_HEADLESS", "").strip().lower() in (
    "1", "true", "yes", "on",
)

# ArduPilot + Gazebo image. Community-maintained -- mirror + digest-pin
# for any deployment that needs supply-chain guarantees.
GAZEBO_IMAGE = os.environ.get(
    "GAZEBO_IMAGE",
    "khancyr/ardupilot-gazebo:latest",
)

_CONTAINER_PREFIX = "kya-mavlink-gazebo"
CONTAINER_NAME = os.environ.get(
    "KYA_GAZEBO_CONTAINER",
    f"{_CONTAINER_PREFIX}-{os.getpid()}",
)

# Loopback only -- same rationale as the headless SITL script.
MAVLINK_HOST = "127.0.0.1"


# ── X11 handling ─────────────────────────────────────────────────


_xhost_opened = False


def _allow_x11_to_docker() -> None:
    """Linux only: open X11 to local Docker so Gazebo can render.
    No-op on macOS/Windows (users wire XQuartz / VcXsrv themselves)
    and when running headless. Best-effort -- a failure here only
    means the visuals won't appear; the capture still works.

    Registers an ``atexit`` handler that restores
    ``xhost -local:docker`` so the host's X session isn't left
    wide open after the demo. (Without that restore, ANY local
    Docker container could connect to the X server for the
    remainder of the X session, which is fine for a demo laptop
    but not for a multi-user dev host.)
    """
    global _xhost_opened
    if sys.platform != "linux" or HEADLESS:
        return
    try:
        result = subprocess.run(
            ["xhost", "+local:docker"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            _xhost_opened = True
            atexit.register(_revoke_x11_from_docker)
    except Exception:  # noqa: BLE001
        # xhost not installed or no DISPLAY -- demo runs headless.
        pass


def _revoke_x11_from_docker() -> None:
    """Best-effort xhost restore. Called via atexit so the cleanup
    runs even when the script is interrupted."""
    if not _xhost_opened:
        return
    try:
        subprocess.run(
            ["xhost", "-local:docker"],
            capture_output=True, timeout=5,
        )
    except Exception:  # noqa: BLE001
        pass


# ── Gazebo + SITL launch ─────────────────────────────────────────


def launch_gazebo_sitl() -> None:
    """Start ArduPilot SITL + Gazebo in a single Docker container."""
    # (C) Stale-sweep abandoned gazebo containers (Ctrl-C leakage).
    cleanup_stale_kya_containers(prefix=_CONTAINER_PREFIX)
    cleanup_container(CONTAINER_NAME)
    # (A) Port pre-check. Gazebo path uses MAVProxy-bridged UDP
    # (the bridge image emits MAVLink on UDP 14550 inside the
    # container), so the probe is a UDP-bind check, not TCP.
    verify_host_port_free(MAVLINK_HOST, MAVLINK_PORT, protocol="udp")
    _allow_x11_to_docker()

    docker_args = [
        "docker", "run", "-d", "--name", CONTAINER_NAME,
        # Hardening: same posture as the headless SITL path -- drop
        # ALL caps, forbid privilege escalation. Gazebo + ArduPilot
        # are userland binaries; no legitimate cap need.
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges:true",
        "-p", f"{MAVLINK_HOST}:{MAVLINK_PORT}:14550/udp",
    ]

    # Wire up X11 + GPU only when we want visuals AND we're on Linux.
    if not HEADLESS and sys.platform == "linux":
        display = os.environ.get("DISPLAY", ":0")
        docker_args += [
            "-e", f"DISPLAY={display}",
            "-v", "/tmp/.X11-unix:/tmp/.X11-unix",
        ]
        if Path("/dev/dri").exists():
            docker_args += ["--device", "/dev/dri"]

    docker_args += [GAZEBO_IMAGE]
    if HEADLESS:
        docker_args += ["gazebo", "--verbose", "--no-gui"]

    result = run(docker_args, capture_output=True, text=True)
    if result.returncode != 0:
        die(f"docker run failed: {result.stderr}")

    # (B) Container running check -- catch immediate entrypoint
    # crashes (e.g. image-missing entry script) in <1s rather
    # than waiting BOOT_TIMEOUT for nothing.
    verify_container_running(CONTAINER_NAME)


# ── Demo mission (visible) ────────────────────────────────────────


def run_demo_mission(conn) -> None:
    """A longer, more visible mission than the headless harness's
    scripted cycle. Demonstrates the same parser surface at
    real-time speedup so an audience can follow what's happening.

    Sequence:
        1. SET_MODE GUIDED
        2. PARAM_SET FENCE_ENABLE = 1
        3. Mission upload: 4-waypoint square pattern
        4. ARM
        5. TAKEOFF to 30m
        6. (~25s flight time -- visible in Gazebo)
        7. RTL (visible return-to-launch)
    """
    import time as _time  # local

    from pymavlink import mavutil  # noqa: PLC0415

    sysid = conn.target_system or 1
    compid = conn.target_component or 1

    print("set_mode GUIDED ...")
    conn.mav.set_mode_send(
        sysid,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        4,  # GUIDED
    )
    _time.sleep(1)

    print("param_set FENCE_ENABLE=1 ...")
    conn.mav.param_set_send(
        sysid, compid,
        b"FENCE_ENABLE", 1.0,
        mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
    )
    _time.sleep(1)

    # 4-waypoint square mission for visible motion
    print("mission upload (4 waypoints) ...")
    waypoints = [
        # (lat_int, lon_int, alt_m) -- ArduPilot Iris default
        # origin is roughly Canberra airport for the SITL world.
        ((-353621480),  1491600400,  30.0),
        ((-353620000),  1491600400,  30.0),
        ((-353620000),  1491603000,  30.0),
        ((-353621480),  1491603000,  30.0),
    ]
    conn.mav.mission_count_send(sysid, compid, len(waypoints))
    _time.sleep(0.5)
    for i, (lat, lon, alt) in enumerate(waypoints):
        conn.mav.mission_item_int_send(
            sysid, compid,
            i,
            mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
            mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
            0, 1,
            0, 0, 0, 0,
            lat, lon, alt,
        )
        _time.sleep(0.2)

    print("command_long arm ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0, 1, 0, 0, 0, 0, 0, 0,
    )
    _time.sleep(2)

    print("command_long takeoff 30m ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
        0, 0, 0, 0, 0, 0, 0, 30.0,
    )
    # Let the drone climb + fly the waypoint pattern. Audience
    # sees the visible flight here.
    _time.sleep(25)

    print("command_long RTL ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH,
        0, 0, 0, 0, 0, 0, 0, 0,
    )


# ── Entrypoint ───────────────────────────────────────────────────


def main() -> int:
    preflight(OUT)
    try:
        launch_gazebo_sitl()
        conn = wait_for_heartbeat(
            host=MAVLINK_HOST, port=MAVLINK_PORT,
            timeout=BOOT_TIMEOUT,
            container_name=CONTAINER_NAME,
        )
        run_demo_mission(conn)
        frames = capture(conn, CAPTURE_SECONDS)
    finally:
        cleanup_container(CONTAINER_NAME)

    handled_count = sum(1 for f in frames if f.get("_handled"))
    print(f"captured {len(frames)} total frames; "
          f"{handled_count} are governance-relevant")

    write_ndjson(frames, OUT)
    print(f"wrote {OUT}")
    if not HEADLESS:
        print(
            "Audience tip: Gazebo's render window stayed open the "
            "entire flight. The MAVLink trace KYA captured above "
            "is the same MAVLink messages a production Pixhawk "
            "would emit."
        )

    if handled_count == 0:
        die("captured zero governance-relevant frames")
    return 0


if __name__ == "__main__":
    sys.exit(main())
