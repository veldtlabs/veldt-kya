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
#
# CRITICAL: This is imported from the parser module rather than
# redefined here. Two frozensets that drift apart would silently
# misclassify a captured frame as "_handled": False when the
# parser actually canonicalises it (or vice versa). The import
# ensures one source of truth -- a new message family added to
# the parser flows into capture stats automatically.
from kya.runtime.parsers.mavlink._parser import (  # noqa: E402, PLC0415
    _HANDLED_MESSAGES as HANDLED_MESSAGE_TYPES,
)

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


def dump_container_diagnostics(name: str) -> None:
    """Dump container state + logs to stderr. Called on heartbeat
    timeout so a CI failure tells us WHY SITL didn't boot rather
    than the bare ``no HEARTBEAT within Ns`` line.

    The 4 cheap signals worth emitting:
      * ``docker ps -a`` row -- tells us if the container exited,
        is still Running, or never started (Created).
      * ``docker inspect`` State.* -- the structured truth
        (ExitCode, OOMKilled, Error). docker ps elides this.
      * ``docker logs`` tail (last 200 lines) -- the actual stdout
        from sim_vehicle.py / arducopter. EKF init failures,
        missing-frame parser errors, and license-check refusals
        all surface here.
      * ``docker logs --stderr`` separately, so a stderr-only
        crash (segfault, GLIBC mismatch) isn't drowned out by
        chatty stdout.

    Best-effort throughout -- a diagnostics failure must not mask
    the original error.
    """
    print(
        f"\n── dumping diagnostics for container {name!r} ──",
        file=sys.stderr,
    )
    for label, cmd in [
        ("ps -a", ["docker", "ps", "-a", "--filter", f"name={name}"]),
        ("inspect state",
         ["docker", "inspect", "--format",
          "Status={{.State.Status}} "
          "ExitCode={{.State.ExitCode}} "
          "OOMKilled={{.State.OOMKilled}} "
          "Error={{.State.Error}}",
          name]),
        ("logs (tail 200)", ["docker", "logs", "--tail", "200", name]),
    ]:
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
            )
            print(f"── {label} ──", file=sys.stderr)
            if r.stdout:
                print(r.stdout, file=sys.stderr)
            if r.stderr:
                print(r.stderr, file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"  (diagnostics {label!r} failed: {e})",
                  file=sys.stderr)
    print("── end diagnostics ──\n", file=sys.stderr)


# ── Preflight ────────────────────────────────────────────────────


def preflight(out_path: Path) -> None:
    """Common preflight: docker on PATH + daemon reachable +
    pymavlink installed + output path writable.

    The ``docker info`` ping catches "docker installed but daemon
    not running" (common on macOS Docker Desktop) with a
    friendlier message than the raw ``docker run`` failure.
    Timeout is 30s because Docker Desktop on macOS/Windows
    routinely takes 15-45s to come up after a reboot; a 5s
    timeout would surface a misleading TimeoutExpired traceback
    rather than the actionable error message.
    """
    if not have("docker"):
        die("docker not found in PATH")
    try:
        info = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        die(
            "docker daemon not responding within 30s. If Docker "
            "Desktop is still starting, wait for it to finish and "
            "retry. On Linux, check that the docker service is "
            "running (`systemctl status docker`)."
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
    container_name: str | None = None,
):  # type: ignore[no-untyped-def]
    """Block until SITL emits its first HEARTBEAT or ``timeout``
    seconds elapse. Returns the live pymavlink connection.

    Implementation note: the inner ``recv_match(blocking=True,
    timeout=5)`` wakes every 5s, so the actual maximum wait is
    ``timeout + 5s``. The 5s wake-up bound keeps the loop
    responsive to SIGINT during local debugging.

    On timeout, if ``container_name`` is provided, dumps the
    container's ``docker logs`` + ``docker inspect`` before exit
    so CI can see WHY SITL didn't emit heartbeat -- an opaque
    "no HEARTBEAT in 300s" line is impossible to debug.
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
    if container_name:
        dump_container_diagnostics(container_name)
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
    line, trailing newline (the conventional NDJSON shape).

    Behaviour on ``frames == []``: creates an empty file. The
    live integration test (``tests/test_mavlink_sitl_live.py``)
    skips with a clear message in this case, so a "captured zero
    frames" outcome doesn't masquerade as a missing-capture
    skip downstream. Direct consumers that key off file
    existence should also check size > 0 before assuming
    "capture available".
    """
    lines = "\n".join(json.dumps(f) for f in frames)
    path.write_text(lines + "\n" if lines else "")


def env_int(name: str, default: int) -> int:
    """Read an integer env var with a default. Used by the
    capture entrypoints for TIMEOUT / MISSION / MAVLINK_PORT.

    Rejects non-positive values: ``TIMEOUT=-5`` or ``MISSION=0``
    would cause the heartbeat/capture loops to never enter
    (``time.time() < deadline`` is immediately false), producing
    a confusing "no HEARTBEAT" error rather than the real cause
    (bad env var). Fail fast with a clear message instead.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        val = int(raw)
    except ValueError:
        die(f"env var {name}={raw!r} is not an integer")
    if val < 1:
        die(
            f"env var {name}={val} must be a positive integer "
            f"(1 or greater); negative / zero would cause the "
            f"capture loop to skip without producing a useful "
            f"error message."
        )
    return val


__all__ = [
    "HANDLED_MESSAGE_TYPES",
    "have",
    "die",
    "run",
    "cleanup_container",
    "dump_container_diagnostics",
    "preflight",
    "wait_for_heartbeat",
    "capture",
    "write_ndjson",
    "env_int",
]
