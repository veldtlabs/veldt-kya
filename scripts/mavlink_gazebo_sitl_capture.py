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
the same flight cycle becomes a credible visual demonstration for
defense / aerospace / In-Q-Tel audiences who expect to see a drone,
not just read logs. The protocol output is identical -- Gazebo
adds physics + visuals, not new MAVLink shapes -- so the parser
and the bridge see the exact same frames.

Setup requirements
------------------
* Docker (same as SITL-only)
* Display server -- one of:
    - Linux host with X11: works out-of-the-box once you allow
      ``xhost +local:docker`` (script does this for you)
    - macOS / Windows: run via XQuartz / VcXsrv, OR set
      ``KYA_GAZEBO_HEADLESS=1`` to capture without rendering
      (you still get the MAVLink trace; the visuals are skipped)
    - WSL2: use WSLg (Windows 11) or VcXsrv on the Windows host
* GPU optional but recommended -- Gazebo's physics is CPU-friendly
  but the renderer prefers a GPU. Without one, expect ~5fps.

Image choice
------------
We use ``khancyr/ardupilot-gazebo`` -- a community-maintained image
that bundles ArduPilot SITL + Gazebo + the iris quadcopter model
already configured. This avoids the multi-step "build PX4 + add
Gazebo plugins" dance that the official ArduPilot docs walk through.

Environment
-----------
  OUT            output JSON file path (default /tmp/mavlink-gazebo.json)
  TIMEOUT        SITL boot timeout in seconds (default 180 -- Gazebo
                 needs longer than headless SITL)
  MISSION        capture duration in seconds (default 60 -- more time
                 because demos run at real-time speedup, not 5x)
  KYA_GAZEBO_HEADLESS  set to "1" to run Gazebo without rendering
                       (CI / no-display environments)

Usage
-----
  # Local demo with display:
  python3 scripts/mavlink_gazebo_sitl_capture.py

  # Headless (CI / SSH-only):
  KYA_GAZEBO_HEADLESS=1 python3 scripts/mavlink_gazebo_sitl_capture.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ── Configuration ────────────────────────────────────────────────


OUT = Path(os.environ.get("OUT", "/tmp/mavlink-gazebo.json"))
BOOT_TIMEOUT = int(os.environ.get("TIMEOUT", "180"))
CAPTURE_SECONDS = int(os.environ.get("MISSION", "60"))
HEADLESS = os.environ.get("KYA_GAZEBO_HEADLESS", "").strip() in (
    "1", "true", "yes", "on")

# ArduPilot + Gazebo image. Pin to a tag so demos reproduce.
GAZEBO_IMAGE = os.environ.get(
    "GAZEBO_IMAGE",
    "khancyr/ardupilot-gazebo:latest",
)

CONTAINER_NAME = "kya-mavlink-gazebo"

MAVLINK_HOST = "127.0.0.1"
MAVLINK_PORT = 14550


# ── Helpers ──────────────────────────────────────────────────────


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _die(msg: str, exit_code: int = 1) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(exit_code)


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, **kw)


def _cleanup_container() -> None:
    try:
        subprocess.run(
            ["docker", "rm", "-f", CONTAINER_NAME],
            capture_output=True, timeout=15,
        )
    except Exception:  # noqa: BLE001
        pass


def _allow_x11_to_docker() -> None:
    """Linux only: open X11 to local Docker containers so Gazebo
    can render. No-op on macOS/Windows where users wire up XQuartz
    or VcXsrv themselves. Best-effort -- a failure here only means
    the visuals won't appear, the capture still works."""
    if sys.platform != "linux":
        return
    if HEADLESS:
        return
    try:
        subprocess.run(
            ["xhost", "+local:docker"],
            capture_output=True, timeout=5,
        )
    except Exception:  # noqa: BLE001
        # xhost not installed or no DISPLAY -- demo runs headless.
        pass


# ── Preflight ────────────────────────────────────────────────────


def preflight() -> None:
    if not _have("docker"):
        _die("docker not found in PATH")
    try:
        import pymavlink  # noqa: F401
    except ImportError:
        _die(
            "pymavlink not installed. Install with: "
            "pip install 'veldt-kya[mavlink]'"
        )
    if OUT.exists():
        OUT.unlink()
    OUT.parent.mkdir(parents=True, exist_ok=True)


# ── Gazebo + SITL launch ─────────────────────────────────────────


def launch_gazebo_sitl() -> None:
    """Start ArduPilot SITL + Gazebo in a single Docker container."""
    _cleanup_container()
    _allow_x11_to_docker()

    docker_args = [
        "docker", "run", "-d", "--name", CONTAINER_NAME,
        "-p", f"{MAVLINK_PORT}:14550/udp",
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

    docker_args += [
        GAZEBO_IMAGE,
        # The image's default entrypoint launches Gazebo + SITL +
        # MAVProxy. When HEADLESS, pass --no-gui so Gazebo runs
        # without the renderer.
    ]
    if HEADLESS:
        docker_args += ["gazebo", "--verbose", "--no-gui"]

    result = _run(docker_args, capture_output=True, text=True)
    if result.returncode != 0:
        _die(f"docker run failed: {result.stderr}")


def wait_for_heartbeat(timeout: int):  # type: ignore[no-untyped-def]
    """Same logic as the headless SITL harness -- block until the
    autopilot emits its first HEARTBEAT or timeout."""
    from pymavlink import mavutil  # noqa: PLC0415

    conn_str = f"udp:{MAVLINK_HOST}:{MAVLINK_PORT}"
    print(f"connecting to {conn_str} ...")
    conn = mavutil.mavlink_connection(conn_str)

    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = conn.recv_match(type="HEARTBEAT", blocking=True, timeout=5)
        if msg is not None:
            print(f"got heartbeat from sys={msg.get_srcSystem()} "
                  f"comp={msg.get_srcComponent()}")
            return conn
    _die(f"no HEARTBEAT within {timeout}s -- Gazebo/SITL didn't boot. "
         "Likely causes: container needs longer pull (try TIMEOUT=300), "
         "or display server isn't reachable (try KYA_GAZEBO_HEADLESS=1).")


# ── Demo mission (visible) ────────────────────────────────────────


def run_demo_mission(conn) -> None:
    """A longer, more visible mission than the headless harness's
    scripted cycle. Demonstrates the same parser surface but at
    real-time speedup so an audience can follow what's happening.

    Sequence:
        1. SET_MODE GUIDED
        2. PARAM_SET FENCE_ENABLE = 1
        3. Mission upload: 4-waypoint square pattern
        4. ARM
        5. TAKEOFF to 30m
        6. (~30s flight time -- visible in Gazebo)
        7. RTL (visible return-to-launch)
    """
    from pymavlink import mavutil  # noqa: PLC0415

    sysid = conn.target_system or 1
    compid = conn.target_component or 1

    print("set_mode GUIDED ...")
    conn.mav.set_mode_send(
        sysid,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        4,  # GUIDED
    )
    time.sleep(1)

    print("param_set FENCE_ENABLE=1 ...")
    conn.mav.param_set_send(
        sysid, compid,
        b"FENCE_ENABLE", 1.0,
        mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
    )
    time.sleep(1)

    # 4-waypoint square mission for visible motion
    print("mission upload (4 waypoints) ...")
    waypoints = [
        # (lat_int, lon_int, alt_m) -- ArduPilot Iris default origin is
        # roughly Canberra airport for the SITL world.
        (int(-353621480),  int(1491600400),  30.0),
        (int(-353620000),  int(1491600400),  30.0),
        (int(-353620000),  int(1491603000),  30.0),
        (int(-353621480),  int(1491603000),  30.0),
    ]
    conn.mav.mission_count_send(sysid, compid, len(waypoints))
    time.sleep(0.5)
    for i, (lat, lon, alt) in enumerate(waypoints):
        conn.mav.mission_item_int_send(
            sysid, compid,
            i,  # seq
            mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
            mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
            0, 1,
            0, 0, 0, 0,
            lat, lon, alt,
        )
        time.sleep(0.2)

    print("command_long arm ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0, 1, 0, 0, 0, 0, 0, 0,
    )
    time.sleep(2)

    print("command_long takeoff 30m ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
        0, 0, 0, 0, 0, 0, 0, 30.0,
    )
    # Let the drone climb + start flying the waypoint pattern.
    # Audience sees the visible flight here.
    time.sleep(25)

    print("command_long RTL ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_NAV_RETURN_TO_LAUNCH,
        0, 0, 0, 0, 0, 0, 0, 0,
    )


# ── Capture loop ─────────────────────────────────────────────────


def capture(conn, seconds: int) -> list[dict]:
    """Same capture logic as the headless harness. Output dicts are
    identical -- the parser doesn't care whether Gazebo was running."""
    captured: list[dict] = []
    deadline = time.time() + seconds
    handled = {
        "COMMAND_LONG", "COMMAND_INT",
        "MISSION_ITEM", "MISSION_ITEM_INT",
        "SET_MODE", "PARAM_SET", "STATUSTEXT",
        "SERVO_OUTPUT_RAW", "DO_SET_SERVO",
    }
    while time.time() < deadline:
        msg = conn.recv_match(blocking=True, timeout=1)
        if msg is None:
            continue
        d = msg.to_dict()
        d["_handled"] = msg.get_type() in handled
        d["_ts"] = time.time()
        captured.append(d)
    return captured


# ── Entrypoint ───────────────────────────────────────────────────


def main() -> int:
    preflight()
    try:
        launch_gazebo_sitl()
        conn = wait_for_heartbeat(BOOT_TIMEOUT)
        run_demo_mission(conn)
        frames = capture(conn, CAPTURE_SECONDS)
    finally:
        _cleanup_container()

    handled_count = sum(1 for f in frames if f.get("_handled"))
    print(f"captured {len(frames)} total frames; "
          f"{handled_count} are governance-relevant")

    OUT.write_text("\n".join(json.dumps(f) for f in frames))
    print(f"wrote {OUT}")
    if not HEADLESS:
        print(
            "Audience tip: Gazebo's render window stayed open the "
            "entire flight. The MAVLink trace KYA captured above is "
            "the SAME wire format a production deployment would see.")

    if handled_count == 0:
        _die("captured zero governance-relevant frames")
    return 0


if __name__ == "__main__":
    sys.exit(main())
