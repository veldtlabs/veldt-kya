# MAVLink + ArduPilot SITL: two capture paths

KYA's MAVLink parser is exercised against a **real ArduPilot
autopilot binary** via two scripts. Both write the same JSON
output the parser consumes; the difference is whether you also
want to *see* the drone fly.

| Script | Image | Purpose | Display | RAM |
|---|---|---|---|---|
| `mavlink_sitl_live_capture.py` | `ardupilot/ardupilot-dev-base` | CI + technical-DD proof | None (headless) | ~500MB |
| `mavlink_gazebo_sitl_capture.py` | `khancyr/ardupilot-gazebo` | Partner-meeting demo | Gazebo 3D | ~2GB |

## Which one should I run?

- **GitHub Actions / CI**: `mavlink_sitl_live_capture.py`. Headless,
  fast, deterministic. Already wired into
  `.github/workflows/mavlink-sitl-live.yml`.
- **Engineering DD demo** (technical buyer): same SITL-only script.
  A defense engineer who knows MAVLink doesn't need 3D visuals;
  they need protocol fidelity, which SITL provides.
- **Executive / aerospace partner demo**: `mavlink_gazebo_sitl_capture.py`.
  Adds visible flight. The MAVLink trace KYA captures is byte-
  identical to the headless path; Gazebo only adds physics + visuals
  on top of the same firmware binary.
- **No-display environments** (SSH dev box, headless Linux):
  `KYA_GAZEBO_HEADLESS=1 python3 mavlink_gazebo_sitl_capture.py`.
  Runs the demo mission via Gazebo's physics engine but skips
  rendering. Useful for testing demo-flow timing without a screen.

## Both scripts produce identical parser input

The MAVLink wire protocol doesn't change when Gazebo is added.
Gazebo simulates **physics + sensors + visuals**; it doesn't
re-encode MAVLink frames. So:

- Same SET_MODE / PARAM_SET / MISSION_ITEM_INT / COMMAND_LONG
  / STATUSTEXT messages
- Same canonical actions land in `AutonomyEvent`
- Same fleet fingerprint composition
- Same signed regulator pack

This means **passing tests against the headless SITL prove
correctness for the Gazebo demo as well**. The demo is purely a
visual upgrade for human audiences.

## Quick start

```bash
# Headless (CI-style):
python3 scripts/mavlink_sitl_live_capture.py
# -> /tmp/mavlink-sitl.json

# With Gazebo visuals (Linux + X11):
python3 scripts/mavlink_gazebo_sitl_capture.py
# -> /tmp/mavlink-gazebo.json
# (Gazebo window opens; quadcopter takes off, flies a square,
# returns to launch)

# Then run the live integration test against either capture:
MAVLINK_SITL_CAPTURE=/tmp/mavlink-sitl.json \
  pytest tests/test_mavlink_sitl_live.py -v
```

## When Gazebo won't render

- **macOS / Windows host**: install XQuartz (mac) or VcXsrv
  (Windows). Set `DISPLAY` accordingly. Alternatively run with
  `KYA_GAZEBO_HEADLESS=1` and capture without visuals.
- **Pure-SSH server**: `KYA_GAZEBO_HEADLESS=1` is the only option.
  The MAVLink capture works identically.
- **Container fails to pull** (slow network): set
  `TIMEOUT=600` to give the cold-pull more room.

## What this proves to a partner

> "This is the actual ArduPilot firmware running in Docker --
> not a vendor mock. The MAVLink commands KYA sees are the
> same bytes a production Pixhawk would emit. Every action
> (mode change, parameter write, arming, takeoff, payload
> servo command) is canonicalised, signed into an evidence
> chain, and reproducible from the saved capture file
> years later."

The demo cycle takes <90 seconds end-to-end (boot, mission,
RTL) and the resulting signed regulator pack can be opened,
verified, and reproduced bit-identically by any third party.
