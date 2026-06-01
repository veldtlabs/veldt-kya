"""Shared helpers for the MAVLink SITL capture scripts.

Both ``mavlink_sitl_live_capture.py`` and
``mavlink_gazebo_sitl_capture.py`` use the same preflight,
container-cleanup, heartbeat-wait, and capture-loop logic. The
per-script variations are only:

* Which Docker image to spin
* Which extra docker-run args (X11 mount, GPU device, ports)
* Which mission to script

Keeping the shared logic here keeps each entrypoint script lean
(~70 lines instead of ~300) and means a security or correctness
fix lands once.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


# ── Constants ────────────────────────────────────────────────────


# Set of MAVLink message types the open-SDK parser canonicalises.
# Used to mark "_handled" on each captured frame so downstream
# tests can assert coverage without re-importing the parser.
HANDLED_MESSAGE_TYPES: frozenset[str] = frozenset({
    "COMMAND_LONG", "COMMAND_INT",
    "MISSION_ITEM", "MISSION_ITEM_INT",
    "SET_MODE", "PARAM_SET", "STATUSTEXT",
    "SERVO_OUTPUT_RAW", "DO_SET_SERVO",
})


# ── Process control ──────────────────────────────────────────────


def have(cmd: str) -> bool:
    """True iff ``cmd`` is on PATH."""
    return shutil.which(cmd) is not None


def die(msg: str, exit_code: int = 1) -> None:
    """Print to stderr and exit non-zero so the calling CI step
    fails loudly."""
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(exit_code)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """Print + execute. Argv form -- never invokes a shell, so
    list elements (including env-var-derived image names) cannot
    inject shell metacharacters."""
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, **kw)


def cleanup_container(name: str) -> None:
    """Best-effort ``docker rm -f`` -- never raises so it's safe
    in a finally clause."""
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True, timeout=15,
        )
    except Exception:  # noqa: BLE001
        pass


# ── Preflight ────────────────────────────────────────────────────


def preflight(out_path: Path) -> None:
    """Common preflight: docker on PATH + daemon reachable +
    pymavlink installed + output path writable.

    The ``docker info`` ping catches "docker installed but daemon
    not running" (common on macOS Docker Desktop) with a
    friendlier message than the raw ``docker run`` failure.
    """
    if not have("docker"):
        die("docker not found in PATH")
    info = subprocess.run(
        ["docker", "info"], capture_output=True, timeout=5,
    )
    if info.returncode != 0:
        die(
            "docker daemon not reachable. Start Docker Desktop "
            "(macOS / Windows) or run `sudo systemctl start docker` "
            "(Linux), then retry."
        )
    try:
        import pymavlink  # noqa: F401, PLC0415
    except ImportError:
        die(
            "pymavlink not installed. Install with: "
            "pip install 'veldt-kya[mavlink]'"
        )
    if out_path.exists():
        out_path.unlink()
    out_path.parent.mkdir(parents=True, exist_ok=True)


# ── Heartbeat ────────────────────────────────────────────────────


def wait_for_heartbeat(
    *, host: str, port: int, timeout: int,
):  # type: ignore[no-untyped-def]
    """Block until SITL emits its first HEARTBEAT or ``timeout``
    seconds elapse. Returns the live pymavlink connection.

    Implementation note: the inner ``recv_match(blocking=True,
    timeout=5)`` wakes every 5s, so the actual maximum wait is
    ``timeout + 5s``. The 5s wake-up bound keeps the loop
    responsive to SIGINT during local debugging.
    """
    from pymavlink import mavutil  # noqa: PLC0415

    conn_str = f"udp:{host}:{port}"
    print(f"connecting to {conn_str} ...")
    conn = mavutil.mavlink_connection(conn_str)

    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = conn.recv_match(type="HEARTBEAT", blocking=True, timeout=5)
        if msg is not None:
            print(
                f"got heartbeat from sys={msg.get_srcSystem()} "
                f"comp={msg.get_srcComponent()}"
            )
            return conn
    die(f"no HEARTBEAT within {timeout}s")


# ── Capture loop ─────────────────────────────────────────────────


def capture(conn, seconds: int) -> list[dict]:
    """Read MAVLink frames for ``seconds`` and return each as a
    dict (the shape ``kya.runtime.parsers.mavlink.parse`` consumes).

    Each frame is annotated with:
      ``_handled``  True iff the type is canonicalised by the
                    open-SDK parser (helps downstream tests assert
                    coverage).
      ``_ts``       Wall-clock at capture moment, so a later
                    .tlog replay can carry deterministic
                    timestamps (avoids the time.time() fallback
                    in the parser).
    """
    captured: list[dict] = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        msg = conn.recv_match(blocking=True, timeout=1)
        if msg is None:
            continue
        d = msg.to_dict()
        d["_handled"] = msg.get_type() in HANDLED_MESSAGE_TYPES
        d["_ts"] = time.time()
        captured.append(d)
    return captured


def write_ndjson(frames: list[dict], path: Path) -> None:
    """Write frames as NDJSON to ``path``. One JSON object per
    line, trailing newline (the conventional NDJSON shape)."""
    lines = "\n".join(json.dumps(f) for f in frames)
    path.write_text(lines + "\n" if lines else "")


def env_int(name: str, default: int) -> int:
    """Read an integer env var with a default. Used by the
    capture entrypoints for TIMEOUT / MISSION / MAVLINK_PORT."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        die(f"env var {name}={raw!r} is not an integer")


__all__ = [
    "HANDLED_MESSAGE_TYPES",
    "have",
    "die",
    "run",
    "cleanup_container",
    "preflight",
    "wait_for_heartbeat",
    "capture",
    "write_ndjson",
    "env_int",
]
