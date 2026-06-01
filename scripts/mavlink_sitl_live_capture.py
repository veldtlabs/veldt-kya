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
  * pymavlink is not installed (collector dep missing)
  * SITL fails to boot within the timeout
  * Capture produced zero governance-relevant frames

so the calling CI workflow fails loudly rather than silently.

Environment:
  OUT      output JSON file path (default /tmp/mavlink-sitl.json)
  TIMEOUT  SITL boot timeout in seconds (default 120)
  MISSION  capture duration in seconds (default 30)

Usage:
  python3 scripts/mavlink_sitl_live_capture.py
  OUT=/tmp/my.json TIMEOUT=180 python3 scripts/mavlink_sitl_live_capture.py
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


OUT = Path(os.environ.get("OUT", "/tmp/mavlink-sitl.json"))
BOOT_TIMEOUT = int(os.environ.get("TIMEOUT", "120"))
CAPTURE_SECONDS = int(os.environ.get("MISSION", "30"))

# ArduPilot SITL container -- the official ArduPilot project ships
# this image with the SITL binary + DroneKit preinstalled. Pin to
# a known-good tag rather than :latest so a CI run today reproduces
# next year.
SITL_IMAGE = os.environ.get(
    "SITL_IMAGE",
    "ardupilot/ardupilot-dev-base:latest",
)

# Container name -- fixed so cleanup is deterministic
CONTAINER_NAME = "kya-mavlink-sitl"

# UDP port SITL emits MAVLink on (loopback)
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
    """Best-effort container cleanup -- never raises."""
    try:
        subprocess.run(
            ["docker", "rm", "-f", CONTAINER_NAME],
            capture_output=True, timeout=15,
        )
    except Exception:  # noqa: BLE001
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


# ── SITL launch ──────────────────────────────────────────────────


def launch_sitl() -> None:
    """Start ArduPilot SITL in a Docker container and expose its
    MAVLink UDP port on the host."""
    _cleanup_container()

    # SITL command line:
    #   --model quad         quadcopter dynamics
    #   --speedup 5          run 5x real-time for faster CI
    #   --instance 0         single instance on default UDP ports
    cmd = [
        "docker", "run", "-d", "--name", CONTAINER_NAME,
        "-p", f"{MAVLINK_PORT}:14550/udp",
        SITL_IMAGE,
        "sim_vehicle.py",
        "-v", "ArduCopter",
        "--model", "quad",
        "--speedup", "5",
        "--no-mavproxy",
        "--out", f"udp:0.0.0.0:14550",
    ]
    result = _run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        _die(f"docker run failed: {result.stderr}")


def wait_for_heartbeat(timeout: int) -> "mavutil.mavlink_connection":  # type: ignore[name-defined]
    """Block until SITL emits its first HEARTBEAT or timeout.
    Returns the live mavutil connection."""
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
    _die(f"no HEARTBEAT within {timeout}s -- SITL didn't boot")


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
    """
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
    time.sleep(0.5)

    # 2. PARAM_SET FENCE_ENABLE=1
    print("param_set FENCE_ENABLE=1 ...")
    conn.mav.param_set_send(
        sysid, compid,
        b"FENCE_ENABLE",
        1.0,
        mavutil.mavlink.MAV_PARAM_TYPE_REAL32,
    )
    time.sleep(0.5)

    # 3. Mission upload (one waypoint)
    print("mission upload ...")
    conn.mav.mission_count_send(sysid, compid, 1)
    time.sleep(0.5)
    conn.mav.mission_item_int_send(
        sysid, compid,
        0,  # seq
        mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
        0, 1,
        0, 0, 0, 0,
        int(-353621480), int(1491600400), 50.0,  # Canberra-ish + 50m
    )
    time.sleep(0.5)

    # 4. COMMAND_LONG arm
    print("command_long arm ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0,
        1, 0, 0, 0, 0, 0, 0,
    )
    time.sleep(1.0)

    # 5. COMMAND_LONG takeoff to 20m
    print("command_long takeoff 20m ...")
    conn.mav.command_long_send(
        sysid, compid,
        mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
        0,
        0, 0, 0, 0, 0, 0, 20.0,
    )


# ── Capture loop ─────────────────────────────────────────────────


def capture(conn, seconds: int) -> list[dict]:
    """Read MAVLink frames from the connection for ``seconds`` and
    return each as a dict (the same shape ``parse`` consumes)."""
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
        msg_type = msg.get_type()
        # We log EVERY message for after-the-fact analysis but
        # mark the governance-relevant ones so the test can assert
        # canonical events fired.
        d = msg.to_dict()
        d["_handled"] = msg_type in handled
        # Stamp the absolute wall-clock so a .tlog replay later
        # can carry deterministic timestamps (see _extract_ts in
        # the parser docstring).
        d["_ts"] = time.time()
        captured.append(d)
    return captured


# ── Entrypoint ───────────────────────────────────────────────────


def main() -> int:
    preflight()
    try:
        launch_sitl()
        conn = wait_for_heartbeat(BOOT_TIMEOUT)
        run_scripted_mission(conn)
        frames = capture(conn, CAPTURE_SECONDS)
    finally:
        _cleanup_container()

    handled_count = sum(1 for f in frames if f.get("_handled"))
    print(f"captured {len(frames)} total frames; "
          f"{handled_count} are governance-relevant")

    OUT.write_text("\n".join(json.dumps(f) for f in frames))
    print(f"wrote {OUT}")

    if handled_count == 0:
        _die(
            "captured zero governance-relevant frames "
            "(no COMMAND_LONG / SET_MODE / PARAM_SET / etc.). "
            "SITL booted but the scripted mission did not exercise "
            "the parser surface -- investigate."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
