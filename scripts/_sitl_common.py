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
import socket
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


def cleanup_stale_kya_containers(
    *, prefix: str, max_age_minutes: int = 60,
) -> None:
    """Reap leftover containers from prior failed / Ctrl-C'd runs.

    A typical leak chain: developer Ctrl-Cs the script BETWEEN
    ``docker run -d`` and the ``finally: cleanup_container()``
    clause -- or CI's ``cancel-in-progress`` SIGTERMs the job at
    the wrong moment. The container survives and holds the host
    port mapping. Without sweep, the next invocation has to
    either fail to bind or rely on the user remembering to run
    ``docker rm -f`` manually.

    Sweep policy: any container whose name starts with
    ``prefix + "-"`` AND was created more than ``max_age_minutes``
    ago. The age threshold keeps a CURRENTLY-running parallel
    invocation safe (its container is fresh) while reaping the
    leaked ones.

    Prefix anchoring is CRITICAL: ``docker ps --filter name=X``
    is a SUBSTRING match by default, not a prefix match. Without
    post-filtering, a user's adjacent container like
    ``my-kya-mavlink-sitl-debug`` would be silently reaped. We
    use the docker filter only to narrow the listing and
    re-verify the prefix in Python.

    Best-effort; failures are printed but don't abort the caller.
    """
    # Anchor: we only ever sweep names that are EXACTLY
    # "<prefix>-<suffix>" -- ``startswith(anchor)`` requires the
    # trailing hyphen so ``my-kya-mavlink-sitl-debug`` cannot
    # match ``kya-mavlink-sitl``.
    anchor = f"{prefix}-"
    try:
        listing = subprocess.run(
            ["docker", "ps", "-a",
             "--filter", f"name={prefix}",
             "--format", "{{.Names}}\t{{.CreatedAt}}\t{{.ID}}"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as e:  # noqa: BLE001
        print(f"  (stale-sweep listing failed: {e})", file=sys.stderr)
        return

    now = time.time()
    threshold = max_age_minutes * 60
    for line in (listing.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, created_at, cid = parts[0], parts[1], parts[2]
        # H1 review fix: docker ps name filter is substring; re-verify
        # prefix in Python so we don't reap an adjacent container.
        if not name.startswith(anchor):
            continue
        # Parse the docker ps CreatedAt directly. Format:
        # "2026-06-01 23:42:58 +0000 UTC". Strip the trailing
        # " UTC" + parse via strptime so we don't shell back into
        # docker inspect (which was the per-row hot path the
        # reviewer flagged for sweep inefficiency).
        created_ts = _parse_docker_created_at(created_at)
        if created_ts is None:
            continue
        age = now - created_ts
        if age >= threshold:
            print(
                f"  stale-sweep: removing {name!r} "
                f"(age={int(age)}s, cid={cid[:12]})"
            )
            cleanup_container(name)


def _parse_docker_created_at(s: str) -> float | None:
    """Parse ``docker ps`` ``{{.CreatedAt}}`` to a unix timestamp.

    Docker's CreatedAt is essentially:
      "YYYY-MM-DD HH:MM:SS +TZ TZNAME"  (e.g. "+0000 UTC")

    Returns None on any parse failure -- callers should treat
    that as "skip this row" not "abort the sweep".
    """
    import re
    from datetime import datetime
    # Strip trailing tz-name (e.g. " UTC") -- keep the +0000 offset.
    s = re.sub(r"\s+[A-Z]{1,4}$", "", s.strip())
    for fmt in (
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return None


def verify_host_port_free(
    host: str, port: int, *, protocol: str = "tcp",
) -> None:
    """Fail-fast guard against silently capturing from someone
    else's MAVLink stream.

    If something is already listening on ``host:port`` BEFORE we
    launch our container, the docker port bind will fail with an
    opaque ``port is already allocated`` error -- OR, more
    insidiously, the bind might succeed for another reason and
    the capture script would then collect frames from the OTHER
    MAVLink emitter (the dev's mavproxy, a stale autopilot
    container, a forgotten SITL).

    Probe strategy depends on ``protocol``:

      * "tcp" -- open a TCP connection. If the connect succeeds,
        a listener is accepting; die. ConnectionRefused / timeout
        / OSError = nothing there, return.

      * "udp" -- attempt to bind a UDP socket to ``(host, port)``.
        If bind succeeds, nothing is bound there; close and return.
        If bind fails with EADDRINUSE, someone is bound; die.
        UDP is connectionless so "is anyone listening" can't be
        proven by sending alone -- bind-occupancy is the
        reliable proof.

    Uses a 1s timeout for TCP -- a live listener on loopback
    answers in microseconds; if it's slower, something is wrong
    enough that the user should investigate manually anyway.
    """
    if protocol == "tcp":
        try:
            with socket.create_connection((host, port), timeout=1):
                pass
        except (ConnectionRefusedError, socket.timeout, OSError):
            # The expected case: nothing accepts the connection.
            return
        die(
            f"tcp port {host}:{port} is already in use by ANOTHER "
            f"process or container. If this is leftover from a "
            f"previous SITL run, run "
            f"`docker ps -a --filter name=kya-mavlink-` and remove "
            f"with `docker rm -f`. If it's mavproxy / another GCS, "
            f"either stop it or set MAVLINK_PORT to a free port."
        )

    if protocol == "udp":
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            try:
                probe.bind((host, port))
            except OSError as e:
                # EADDRINUSE -- something already bound this port.
                # We do NOT swallow other OSErrors; they'd produce
                # an opaque failure mode users can't action.
                if e.errno in (
                    98,  # Linux: EADDRINUSE
                    48,  # macOS: EADDRINUSE
                    10048,  # Windows: WSAEADDRINUSE
                ):
                    die(
                        f"udp port {host}:{port} is already bound "
                        f"by ANOTHER process. If this is leftover "
                        f"from a previous Gazebo / mavproxy run, "
                        f"find it with `ss -ulnp | grep {port}` "
                        f"(Linux) or `lsof -i :{port}` (macOS/BSD)."
                    )
                # Some other bind failure -- surface it instead of
                # silently passing.
                die(f"udp probe bind failed unexpectedly: {e!r}")
        finally:
            probe.close()
        return

    die(f"verify_host_port_free: unknown protocol={protocol!r}; "
        f"use 'tcp' or 'udp'.")


def verify_container_running(name: str) -> None:
    """Confirm our just-launched container is actually Running and
    has the expected port mapping live.

    Why this exists: ``docker run -d`` returns success the moment
    the container is CREATED, not when it's running. If the
    image's entrypoint segfaults immediately, the container exits
    within milliseconds and the script proceeds blissfully to
    wait_for_port_serving -- which then times out 180s later
    without ever surfacing the "container died on start" cause.

    A docker-inspect check up front catches that crash in under
    a second.
    """
    try:
        r = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.State.Status}}|{{.State.ExitCode}}|"
             "{{.State.Error}}",
             name],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:  # noqa: BLE001
        die(f"failed to inspect container {name!r}: {e}")

    if r.returncode != 0:
        die(
            f"container {name!r} not found "
            f"(docker inspect returned {r.returncode}). "
            f"docker run may have failed silently."
        )

    parts = (r.stdout or "").strip().split("|")
    if len(parts) < 3:
        die(f"unexpected docker inspect output: {r.stdout!r}")
    status, exit_code, err = parts[0], parts[1], parts[2]

    if status != "running":
        # Surface the root cause inline so the user doesn't have
        # to chase docker logs separately.
        dump_container_diagnostics(name)
        die(
            f"container {name!r} is not Running "
            f"(Status={status}, ExitCode={exit_code}, "
            f"Error={err!r}). See diagnostics above."
        )


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

    # H5: probe whether the container is still Running BEFORE we
    # run ``docker exec``. Running ``exec`` against an Exited
    # container produces a noisy "Container is not running" stderr
    # line that drowns out the real failure cause -- the very
    # signal we're collecting these diagnostics to surface.
    is_running = False
    try:
        running_probe = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=10,
        )
        is_running = (running_probe.stdout or "").strip() == "true"
    except Exception:  # noqa: BLE001
        is_running = False

    diagnostics: list[tuple[str, list[str]]] = [
        ("ps -a", ["docker", "ps", "-a", "--filter", f"name={name}"]),
        ("inspect state",
         ["docker", "inspect", "--format",
          "Status={{.State.Status}} "
          "ExitCode={{.State.ExitCode}} "
          "OOMKilled={{.State.OOMKilled}} "
          "Error={{.State.Error}}",
          name]),
        ("logs (tail 200)", ["docker", "logs", "--tail", "200", name]),
    ]
    if is_running:
        # ArduCopter binary logs to /tmp/ArduCopter.log INSIDE the
        # container when no controlling terminal is attached
        # ("RiTW: Window access not found, logging to ..."). That
        # file holds the real boot trace -- EKF/IMU/GPS init,
        # MAVLink listener start, etc. ``docker logs`` would show
        # only sim_vehicle.py's wrapper output, which is useless.
        # Tail the last 100 lines to surface the failure mode
        # without flooding the CI log. Only attempt when the
        # container is actually Running -- ``docker exec`` against
        # an Exited container is just noise.
        diagnostics.append((
            "ArduCopter.log (tail 100)",
            ["docker", "exec", name,
             "sh", "-c", "tail -n 100 /tmp/ArduCopter.log 2>&1 || "
                        "echo '(no /tmp/ArduCopter.log)'"],
        ))
    else:
        print(
            "── ArduCopter.log skipped (container not Running) ──",
            file=sys.stderr,
        )

    for label, cmd in diagnostics:
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


# ── Wait for ArduCopter inner port to actually be serving ───────


def wait_for_port_serving(
    *, host: str, port: int, timeout: int = 180,
    container_name: str | None = None,
) -> None:
    """Block until <host>:<port> serves at least one TCP byte
    (not just accepts the connection).

    Why this exists: ``docker run -d`` returns the moment the
    container is created -- LONG before sim_vehicle.py inside
    has launched arducopter and arducopter has bound its TCP
    console. If pymavlink calls ``mavlink_connection`` in that
    gap, the connection enters one of two failure modes:

      1. Docker's userland proxy accepts the TCP connect
         (because the host port mapping is live) but the
         backend isn't ready -- the proxy immediately closes,
         pymavlink sees EOF, recv_match returns None, and
         the heartbeat loop spins at ~30 000 EOFs/sec for the
         full TIMEOUT window. Wall: 5 min lost, log: 500 MB+
         of "EOF on TCP socket" lines.

      2. The connect itself refuses, but pymavlink retries in
         the same hot loop.

    Both modes manifest as "no HEARTBEAT in <timeout>s" but
    waste the timeout window. The actual hang isn't a kya bug
    or a parser bug -- it's a timing bug in the SITL harness.

    This helper does the right thing: a single short TCP connect
    + recv(1) per attempt. Returns the moment arducopter emits
    its first MAVLink magic byte. Sleeps between attempts so we
    don't pin a core.
    """
    print(f"waiting for tcp:{host}:{port} to serve MAVLink bytes ...")
    deadline = time.time() + timeout
    attempt = 0
    last_err: Exception | None = None
    while time.time() < deadline:
        attempt += 1
        try:
            with socket.create_connection(
                (host, port), timeout=2,
            ) as probe:
                probe.settimeout(2)
                try:
                    data = probe.recv(8)
                except socket.timeout:
                    data = b""
            if data:
                magic = data[0]
                print(
                    f"tcp:{host}:{port} serving "
                    f"(first byte 0x{magic:02x}, "
                    f"attempt {attempt})"
                )
                return
            # Connect succeeded but backend produced no bytes
            # in 2s -- docker proxy accepted while arducopter
            # is still initialising. Keep waiting.
        except OSError as e:
            last_err = e
        time.sleep(2)

    print(
        f"FAIL: tcp:{host}:{port} never served bytes "
        f"within {timeout}s "
        f"(last err: {last_err!r})",
        file=sys.stderr,
    )
    if container_name:
        dump_container_diagnostics(container_name)
    die(f"port {host}:{port} never served bytes within {timeout}s")


# ── Heartbeat ────────────────────────────────────────────────────


def wait_for_heartbeat(
    *, host: str, port: int, timeout: int,
    container_name: str | None = None,
    transport: str = "udp",
):  # type: ignore[no-untyped-def]
    """Block until SITL emits its first HEARTBEAT or ``timeout``
    seconds elapse. Returns the live pymavlink connection.

    ``transport`` is either "udp" (mavproxy-forwarded UDP, e.g.
    Gazebo path) or "tcp" (direct arducopter TCP console, e.g.
    the live SITL path when running with ``--no-mavproxy``).
    Picking the wrong one is a silent timeout -- pymavlink will
    happily open a port that no one writes to and wait forever.

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

    if transport not in {"udp", "tcp"}:
        die(f"unsupported transport={transport!r}; use 'udp' or 'tcp'")
    conn_str = f"{transport}:{host}:{port}"
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
        # pymavlink's to_dict() omits the source sysid/compid -- they
        # live on the parent message object via the get_src* accessors,
        # not in the dialect-generated dict body. Without them the
        # kya parser sees ``sysid: None compid: None`` on every frame
        # and can't derive principal hints (which is what burned us
        # in local SITL probe #2). Use ``setdefault`` so a dialect
        # that DOES include them in the dict still wins.
        d.setdefault("sysid", msg.get_srcSystem())
        d.setdefault("compid", msg.get_srcComponent())
        d["_handled"] = msg.get_type() in HANDLED_MESSAGE_TYPES
        d["_ts"] = time.time()
        captured.append(d)
    return captured


def _json_default(obj):
    """JSON fallback encoder for the bytes-y stuff pymavlink
    emits in ``msg.to_dict()``.

    pymavlink keeps STATUSTEXT.text, PARAM_SET.param_id, and
    MISSION_ITEM string fields as ``bytearray`` (raw on-wire
    bytes). ``json.dumps`` doesn't know how to encode those.
    Decode as UTF-8 with ``replace`` so a malformed/embedded-NUL
    byte sequence becomes a U+FFFD sentinel rather than
    crashing the capture write at the very end of a 30-second
    run -- which is exactly what bit me locally.

    For raw ``bytes`` we do the same. Anything we don't know,
    re-raise so we don't silently drop data.
    """
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", errors="replace")
    raise TypeError(
        f"Object of type {type(obj).__name__} is not JSON serializable"
    )


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
    lines = "\n".join(json.dumps(f, default=_json_default) for f in frames)
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


def env_port(name: str, default: int) -> int:
    """Read a TCP/UDP port from env. Like ``env_int`` but bounds
    the value to a valid port range.

    H3 review finding: without an upper bound, ``MAVLINK_PORT=99999``
    burns ~3 min on a wasted image pull before ``docker run`` rejects
    the bind with an opaque error. The port check catches it in
    microseconds, before any container work starts.

    Port 0 is rejected by ``env_int`` (positive-only). Ports below
    1024 are accepted -- they require root, but that's the caller's
    problem to surface, not ours.
    """
    val = env_int(name, default)
    if val > 65535:
        die(
            f"env var {name}={val} is above the maximum TCP/UDP port "
            f"number (65535). Use 1-65535 inclusive."
        )
    return val


__all__ = [
    "HANDLED_MESSAGE_TYPES",
    "have",
    "die",
    "run",
    "cleanup_container",
    "cleanup_stale_kya_containers",
    "verify_host_port_free",
    "verify_container_running",
    "dump_container_diagnostics",
    "preflight",
    "wait_for_port_serving",
    "wait_for_heartbeat",
    "capture",
    "write_ndjson",
    "env_int",
    "env_port",
]
