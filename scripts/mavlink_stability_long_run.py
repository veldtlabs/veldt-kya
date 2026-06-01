#!/usr/bin/env python3
"""Long-running stability profile for the MAVLink collector.

OFF by default. Triggered manually via the
``mavlink-stability-long-run`` GitHub Actions workflow OR locally
when a stability signal is needed:

    python3 scripts/mavlink_stability_long_run.py
    # default: 1h at 50Hz, fails if RSS grows >100MB or fds >20

    DURATION_SECONDS=300 RATE_HZ=100 \
        python3 scripts/mavlink_stability_long_run.py
    # short profile: 5min at 100Hz

What it exercises
-----------------
A single ``MavlinkCollector`` instance ingests synthetic dict-shape
MAVLink frames at the configured rate. Every 5000 frames the
script samples RSS + open file descriptors and writes a row to
the JSON profile file. At the end it asserts that growth in each
metric stayed within the configured cap.

What it does NOT exercise
-------------------------
* Real ArduPilot SITL (synthetic frames only -- this is about
  the collector's memory behaviour, not the autopilot's)
* Multi-vehicle / multi-tenant (single collector, single
  ``(sysid, compid)``)
* Network I/O (frames are constructed in-process)
* Real signing keys (uses the process-local dev key)

A stability regression here means our collector leaks under
sustained load. A real-network / real-SITL regression is a
different signal and belongs in a different workflow.

Output
------
JSON profile at ``/tmp/stability-<unix_ts>.json``:

    {
      "started_at_unix": 1717249800.0,
      "duration_seconds": 3600,
      "rate_hz": 50,
      "frames_processed": 180000,
      "samples": [
        {"frame_count": 0,    "rss_mb": 45.2, "fds": 12},
        {"frame_count": 5000, "rss_mb": 47.1, "fds": 12},
        ...
      ],
      "verdict": {
        "rss_growth_mb": 3.4,
        "fd_growth": 0,
        "rss_cap_mb": 100,
        "fd_cap": 20,
        "passed": true
      }
    }
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Local import for env_int + die helpers.
sys.path.insert(0, str(Path(__file__).parent))
from _sitl_common import die, env_int  # noqa: E402


DURATION_SECONDS = env_int("DURATION_SECONDS", 3600)
RATE_HZ = env_int("RATE_HZ", 50)
MEMORY_GROWTH_MB_CAP = env_int("MEMORY_GROWTH_MB_CAP", 100)
FD_GROWTH_CAP = env_int("FD_GROWTH_CAP", 20)
SAMPLE_EVERY = env_int("SAMPLE_EVERY_FRAMES", 5000)

OUT = Path(os.environ.get(
    "STABILITY_PROFILE_OUT",
    f"/tmp/stability-{int(time.time())}.json",
))


def _frame(seq: int) -> dict:
    """Synthesise one MAVLink-shape dict. Rotates through the six
    handled families so the collector sees the full canonical
    surface, not just one action verb."""
    families = (
        # COMMAND_LONG arm
        {"mavpackettype": "COMMAND_LONG", "sysid": 1, "compid": 1,
         "command": 400, "param1": 1.0},
        # SET_MODE
        {"mavpackettype": "SET_MODE", "sysid": 1, "compid": 1,
         "base_mode": 1, "custom_mode": 4},
        # PARAM_SET
        {"mavpackettype": "PARAM_SET", "sysid": 1, "compid": 1,
         "param_id": "FENCE_ENABLE", "param_value": 1.0},
        # MISSION_ITEM_INT
        {"mavpackettype": "MISSION_ITEM_INT", "sysid": 1, "compid": 1,
         "seq": seq % 100, "x": 0, "y": 0, "z": 30.0, "frame": 3},
        # STATUSTEXT
        {"mavpackettype": "STATUSTEXT", "sysid": 1, "compid": 1,
         "severity": 6, "text": f"telemetry frame {seq}"},
        # SERVO_OUTPUT_RAW
        {"mavpackettype": "SERVO_OUTPUT_RAW", "sysid": 1, "compid": 1,
         "servo": 9, "pwm": 1500},
    )
    return families[seq % len(families)]


def _sample_process() -> dict:
    """Snapshot RSS + open file descriptors of the current
    process. Returns ``{"rss_mb": float, "fds": int}``."""
    try:
        import psutil
    except ImportError:
        die("psutil not installed. Install with: pip install psutil")
    p = psutil.Process()
    rss_bytes = p.memory_info().rss
    # num_fds is Linux/macOS only; num_handles is Windows. Both
    # measure roughly the same concept (open OS resources).
    fds = (
        p.num_fds() if hasattr(p, "num_fds")
        else p.num_handles() if hasattr(p, "num_handles")
        else 0
    )
    return {"rss_mb": round(rss_bytes / 1024 / 1024, 2), "fds": fds}


def main() -> int:
    # Lazy imports so a syntax error in kya doesn't break
    # script-level env validation.
    import kya
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    # Add examples/ to path so the MavlinkCollector class is
    # importable without packaging it. The collector is currently
    # an example, not part of the published wheel.
    sys.path.insert(0, str(Path(__file__).parent.parent / "examples"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_collector",
        Path(__file__).parent.parent / "examples" / "runtime_mavlink_collector.py",
    )
    collector_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector_mod)

    os.environ.pop("KYA_VERSIONS_SCHEMA", None)
    db_path = tempfile.NamedTemporaryFile(
        suffix=".stability.db", delete=False).name
    eng = create_engine(f"sqlite:///{db_path}")
    db = Session(eng)
    kya.init_storage(db)
    db.commit()

    collector = collector_mod.MavlinkCollector()
    collector.install_principal_resolver()

    print(f"stability profile starting:")
    print(f"  duration:       {DURATION_SECONDS}s")
    print(f"  rate:           {RATE_HZ} Hz")
    print(f"  sample every:   {SAMPLE_EVERY} frames")
    print(f"  rss cap:        {MEMORY_GROWTH_MB_CAP} MB growth")
    print(f"  fd cap:         {FD_GROWTH_CAP} growth")
    print(f"  profile out:    {OUT}")

    started_at = time.time()
    deadline = started_at + DURATION_SECONDS
    period = 1.0 / RATE_HZ

    baseline = _sample_process()
    samples: list[dict] = [{
        "frame_count": 0,
        "elapsed_s": 0.0,
        **baseline,
    }]
    print(f"  baseline rss=  {baseline['rss_mb']} MB  fds={baseline['fds']}")

    seq = 0
    next_tick = started_at
    last_report = started_at
    try:
        while time.time() < deadline:
            collector.ingest_frame(db, _frame(seq))
            seq += 1

            if seq % SAMPLE_EVERY == 0:
                snap = _sample_process()
                samples.append({
                    "frame_count": seq,
                    "elapsed_s": round(time.time() - started_at, 2),
                    **snap,
                })

            if time.time() - last_report > 30:
                elapsed = time.time() - started_at
                snap = _sample_process()
                print(
                    f"  [{elapsed:6.0f}s] seq={seq:>9}  "
                    f"rss={snap['rss_mb']:>6.2f}MB  fds={snap['fds']}  "
                    f"rate={seq/elapsed:.1f}fps"
                )
                last_report = time.time()

            # Rate limiting -- maintain ~RATE_HZ target.
            next_tick += period
            sleep_for = next_tick - time.time()
            if sleep_for > 0:
                time.sleep(sleep_for)
            else:
                # We're falling behind the target rate -- skip
                # the sleep but don't try to "catch up", since
                # bursting would defeat the stability profile.
                next_tick = time.time()
    finally:
        try:
            db.close()
        except Exception:  # noqa: BLE001
            pass

    final = _sample_process()
    samples.append({
        "frame_count": seq,
        "elapsed_s": round(time.time() - started_at, 2),
        **final,
    })

    rss_growth = final["rss_mb"] - baseline["rss_mb"]
    fd_growth = final["fds"] - baseline["fds"]
    passed = (
        rss_growth <= MEMORY_GROWTH_MB_CAP
        and fd_growth <= FD_GROWTH_CAP
    )

    profile = {
        "started_at_unix": started_at,
        "duration_seconds": DURATION_SECONDS,
        "rate_hz": RATE_HZ,
        "sample_every": SAMPLE_EVERY,
        "frames_processed": seq,
        "samples": samples,
        "verdict": {
            "rss_growth_mb": round(rss_growth, 2),
            "fd_growth": fd_growth,
            "rss_cap_mb": MEMORY_GROWTH_MB_CAP,
            "fd_cap": FD_GROWTH_CAP,
            "passed": passed,
        },
    }
    OUT.write_text(json.dumps(profile, indent=2))
    print(f"\nprofile written: {OUT}")
    print(f"verdict: rss_growth={rss_growth:.2f}MB (cap={MEMORY_GROWTH_MB_CAP}), "
          f"fd_growth={fd_growth} (cap={FD_GROWTH_CAP}), "
          f"passed={passed}")

    if not passed:
        die("stability profile FAILED -- see profile JSON for details", 2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
