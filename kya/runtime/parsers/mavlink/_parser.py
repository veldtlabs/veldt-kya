"""MAVLink message dict -> :class:`AutonomyEvent` translator.

The parser operates on ``dict`` inputs -- the same shape that
``pymavlink.dialects.v20.common.MAVLink_message.to_dict()``
produces. Keeping the input type as plain dict means:

* Tests can construct fixture inputs without a pymavlink dep.
* Collectors that prefer raw struct parsing can convert to dict
  once and feed many parsers.
* The Apache-2.0 kya core stays clean of the LGPL-3.0 pymavlink
  dependency.

Wire-format contract
--------------------
Expected dict keys (case-insensitive on ``mavpackettype``):

    mavpackettype     str  message name, e.g. "COMMAND_LONG"
    sysid             int  source system id, 0..255
    compid            int  source component id, 0..255  (default 1)

    -- message-specific fields per the MAVLink spec:
    command           int  MAV_CMD enum (only for COMMAND_LONG)
    param1..param7    float
    target_system     int  (only for SET_MODE)
    target_component  int
    seq               int  (only for MISSION_ITEM*)
    frame             int
    x, y, z           float (waypoint coordinates)
    param_id          str   (only for PARAM_SET)
    param_value       float
    base_mode         int   (only for SET_MODE)
    custom_mode       int
    text              str   (only for STATUSTEXT)
    severity          int   (MAV_SEVERITY enum)
    servo             int   (DO_SET_SERVO)
    pwm               int

A dict missing required fields is treated as "not my message" and
returns ``None``.
"""
from __future__ import annotations

import time

from ..._canonical import (
    AutonomyEvent,
    PrincipalHint,
    RuntimeSeverity,
    VehicleRef,
    encode_mavlink_sysid,
)

# MAV_CMD enum values we canonicalise. Source:
# https://mavlink.io/en/messages/common.html#mav_commands
# Values that don't appear here fall through to a generic
# "command" action with the numeric enum preserved in raw.
#
# The selection prioritises commands a regulator (or an attacker)
# cares about most: arming, mode changes, flight termination,
# mission flow hijack, payload release. The mapping is additive
# -- adding a new command id is a one-line change.
_COMMAND_LONG_ACTIONS: dict[int, str] = {
    400: "arm",                    # MAV_CMD_COMPONENT_ARM_DISARM (param1=1 arm, 0 disarm)
    22:  "takeoff",                # MAV_CMD_NAV_TAKEOFF
    21:  "land",                   # MAV_CMD_NAV_LAND
    20:  "rtl",                    # MAV_CMD_NAV_RETURN_TO_LAUNCH
    300: "mission_start",          # MAV_CMD_MISSION_START
    176: "mode_transition",        # MAV_CMD_DO_SET_MODE
    179: "set_home",               # MAV_CMD_DO_SET_HOME
    183: "set_servo",              # MAV_CMD_DO_SET_SERVO
    246: "preflight_reboot",       # MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
    # Attacker-favoured / high-risk additions per Day-3 review:
    185: "flight_termination",     # MAV_CMD_DO_FLIGHT_TERMINATION (kill switch)
    177: "mission_jump",           # MAV_CMD_DO_JUMP (mission flow hijack)
    180: "set_parameter",          # MAV_CMD_DO_SET_PARAMETER (alt to PARAM_SET)
    2510: "vtol_takeoff",          # MAV_CMD_NAV_VTOL_TAKEOFF
    2511: "vtol_land",             # MAV_CMD_NAV_VTOL_LAND
    223: "set_yaw_speed",          # MAV_CMD_NAV_SET_YAW_SPEED
}

# Which canonical actions are CRITICAL severity by default --
# rest are HIGH. Flight termination and forced arm are explicitly
# critical so the bridge surfaces them above the noise floor.
_CRITICAL_ACTIONS: frozenset[str] = frozenset({
    "flight_termination",
    "arm_invalid",
})


# MAV_FRAME enum -> documented symbolic name. Source:
# https://mavlink.io/en/messages/common.html#MAV_FRAME
# A numeric frame not in this table falls back to
# ``"MAV_FRAME_UNKNOWN_{n}"`` so a reader can tell symbolic
# from synthetic; the previous ``MAV_FRAME_3`` style was
# misleading (3 == GLOBAL_RELATIVE_ALT, not "frame number 3").
_FRAME_NAMES: dict[int, str] = {
    0:  "MAV_FRAME_GLOBAL",
    1:  "MAV_FRAME_LOCAL_NED",
    2:  "MAV_FRAME_MISSION",
    3:  "MAV_FRAME_GLOBAL_RELATIVE_ALT",
    4:  "MAV_FRAME_LOCAL_ENU",
    5:  "MAV_FRAME_GLOBAL_INT",
    6:  "MAV_FRAME_GLOBAL_RELATIVE_ALT_INT",
    7:  "MAV_FRAME_LOCAL_OFFSET_NED",
    8:  "MAV_FRAME_BODY_NED",
    9:  "MAV_FRAME_BODY_OFFSET_NED",
    10: "MAV_FRAME_GLOBAL_TERRAIN_ALT",
    11: "MAV_FRAME_GLOBAL_TERRAIN_ALT_INT",
    12: "MAV_FRAME_BODY_FRD",
    20: "MAV_FRAME_LOCAL_FRD",
    21: "MAV_FRAME_LOCAL_FLU",
}

# Maximum length of STATUSTEXT.text that the parser copies into
# the event (and the raw evidence). A hostile autopilot or an
# adversarial collector can stuff arbitrary bytes here; without a
# cap, the bridge would HMAC-sign multi-MB strings on every
# evidence row. 1 KiB is well over MAVLink's documented 50-byte
# STATUSTEXT field (v1) or 250 bytes (v2 chunked), so legitimate
# traffic is never truncated.
_STATUSTEXT_MAX_LEN = 1024


# MAV_SEVERITY (STATUSTEXT) -> KYA RuntimeSeverity.
# Source: https://mavlink.io/en/messages/common.html#MAV_SEVERITY
#
# ArduPilot uses NOTICE liberally (mission step completion,
# parameter loaded, sensor armed). Promoting all NOTICE to medium
# would flood the evidence chain on every flight; map to "low"
# instead so a NOTICE-volume firehose stays out of high-priority
# alert buckets while still being chained for after-the-fact audit.
_STATUSTEXT_SEVERITY: dict[int, RuntimeSeverity] = {
    0: "critical",        # EMERGENCY
    1: "critical",        # ALERT
    2: "critical",        # CRITICAL
    3: "high",            # ERROR
    4: "high",            # WARNING
    5: "low",             # NOTICE
    6: "informational",   # INFO
    7: "informational",   # DEBUG
}


# Message types the parser DOES handle. The bridge calls
# ``can_parse`` to decide autodetect; this set is the authoritative
# answer.
_HANDLED_MESSAGES: frozenset[str] = frozenset({
    "COMMAND_LONG",
    "COMMAND_INT",
    "MISSION_ITEM",
    "MISSION_ITEM_INT",
    "SET_MODE",
    "PARAM_SET",
    "STATUSTEXT",
    "SERVO_OUTPUT_RAW",
    "DO_SET_SERVO",
})


def _msg_type(raw: dict) -> str | None:
    """Extract the MAVLink message type, normalised to UPPER_CASE.
    pymavlink uses ``mavpackettype`` consistently; older tools used
    ``type``. Accept either."""
    for key in ("mavpackettype", "type", "MAVPACKETTYPE"):
        val = raw.get(key)
        if isinstance(val, str) and val:
            return val.upper()
    return None


def can_parse(raw: dict) -> bool:
    """Cheap shape check -- return True for any dict carrying a
    recognised MAVLink message type plus a valid sysid. Never raises.

    sysid=0 is reserved by the MAVLink spec for broadcast / "any
    sender" -- not a legitimate source -- so it's rejected here
    rather than allowed to land as a real principal.
    """
    if not isinstance(raw, dict):
        return False
    msg = _msg_type(raw)
    if msg is None or msg not in _HANDLED_MESSAGES:
        return False
    sysid = raw.get("sysid")
    return (
        isinstance(sysid, int)
        and not isinstance(sysid, bool)
        and 1 <= sysid <= 255
    )


def parse(raw: dict) -> AutonomyEvent | None:
    """Translate a MAVLink message dict into a canonical
    :class:`AutonomyEvent`. Returns ``None`` for messages this
    parser doesn't handle. Never raises on malformed input -- the
    bridge contract is fail-soft."""
    if not isinstance(raw, dict):
        return None
    msg = _msg_type(raw)
    if msg is None:
        return None

    sysid = raw.get("sysid")
    compid = raw.get("compid", 1)  # MAVLink default component id
    # sysid=0 is reserved (see can_parse). bool is a subclass of
    # int in Python, so an explicit isinstance(_, bool) reject
    # prevents True/False from sneaking through.
    if not (isinstance(sysid, int) and not isinstance(sysid, bool)
            and 1 <= sysid <= 255
            and isinstance(compid, int) and not isinstance(compid, bool)
            and 0 <= compid <= 255):
        return None

    # Dispatch by message type. Each helper returns
    # (action, severity, message_text) -- the AutonomyEvent
    # composition below is shared so message-type-specific code
    # stays minimal.
    if msg in ("COMMAND_LONG", "COMMAND_INT"):
        triple = _from_command(raw)
    elif msg in ("MISSION_ITEM", "MISSION_ITEM_INT"):
        triple = _from_mission_item(raw)
    elif msg == "SET_MODE":
        triple = _from_set_mode(raw)
    elif msg == "PARAM_SET":
        triple = _from_param_set(raw)
    elif msg == "STATUSTEXT":
        triple = _from_statustext(raw)
    elif msg in ("SERVO_OUTPUT_RAW", "DO_SET_SERVO"):
        triple = _from_servo(raw)
    else:
        return None

    if triple is None:
        return None
    action, severity, message_text = triple

    # Vehicle reference -- everything the message tells us about
    # the source.
    vehicle = VehicleRef(
        sysid=sysid,
        compid=compid,
        frame=_extract_frame(raw),
        mission_id=_extract_str(raw, "mission_id"),
    )

    # Identity hint -- (sysid, compid) encoded for the Pro fleet
    # manifest resolver. Best-effort attribution: the bytes are
    # forgeable on the wire, so the bridge surfaces unbound
    # principals rather than inventing identity.
    hint = PrincipalHint(
        kind="mavlink_sysid",
        value=encode_mavlink_sysid(sysid, compid),
    )

    return AutonomyEvent(
        source_tool="mavlink",
        source_rule_id=f"mavlink/{msg}",
        occurred_at_ts=_extract_ts(raw),
        severity=severity,
        action=action,
        message=message_text,
        vehicle=vehicle,
        geo_lat=_extract_float(raw, "lat", "x"),
        geo_lon=_extract_float(raw, "lon", "y"),
        geo_alt_m=_extract_float(raw, "alt", "z"),
        flight_mode=_extract_str(raw, "custom_mode_str", "base_mode_str"),
        link_quality=_extract_int(raw, "rssi", "link_quality"),
        command_origin_addr=_extract_str(raw, "_origin_addr"),
        principal_hints=(hint,),
        raw=dict(raw),
    )


# ── Per-message-type translators ──────────────────────────────────


def _from_command(raw: dict) -> tuple[str, RuntimeSeverity, str] | None:
    """COMMAND_LONG / COMMAND_INT. The ``command`` field carries the
    MAV_CMD enum.

    Special case for ARM/DISARM: same command_id (400), but
    governance-meaningfully different actions distinguished by
    ``param1``. The MAVLink spec says param1=1.0 means arm,
    param1=0.0 means disarm; any OTHER value (including
    ArduPilot's force-arm magic 21196.0, NaN, negative, etc.) is
    out-of-spec and should NOT silently look like a normal arm.
    Such payloads land as ``action="arm_invalid"`` with critical
    severity -- that's the exact attack signal a regulator wants.
    """
    cmd = raw.get("command")
    # bool is a subclass of int; reject so True/False don't slip in.
    if not isinstance(cmd, int) or isinstance(cmd, bool):
        return None

    severity: RuntimeSeverity = "high"

    if cmd == 400:
        param1 = raw.get("param1")
        # Strict literal match: only floats / ints equal to 0 or 1.
        # bool excluded (subclass of int). NaN never compares equal
        # so always falls through to arm_invalid.
        if (isinstance(param1, (int, float))
                and not isinstance(param1, bool)
                and param1 == 1.0):
            action = "arm"
        elif (isinstance(param1, (int, float))
                and not isinstance(param1, bool)
                and param1 == 0.0):
            action = "disarm"
        else:
            action = "arm_invalid"
    else:
        action = _COMMAND_LONG_ACTIONS.get(cmd, "command")

    # ``flight_termination`` is already in _CRITICAL_ACTIONS (see
    # the frozenset definition above); the redundant elif check
    # I had earlier was unreachable dead code. Single-check is the
    # right shape: any action in the critical set bumps severity,
    # everything else stays at the "high" default set above.
    if action in _CRITICAL_ACTIONS:
        severity = "critical"

    msg_text = f"COMMAND id={cmd} ({action})"
    return action, severity, msg_text


def _from_mission_item(raw: dict) -> tuple[str, RuntimeSeverity, str]:
    seq = raw.get("seq", "?")
    return "mission_waypoint", "medium", f"MISSION_ITEM seq={seq}"


def _from_set_mode(raw: dict) -> tuple[str, RuntimeSeverity, str]:
    base = raw.get("base_mode", "?")
    custom = raw.get("custom_mode", "?")
    return (
        "mode_transition",
        "high",
        f"SET_MODE base={base} custom={custom}",
    )


def _from_param_set(raw: dict) -> tuple[str, RuntimeSeverity, str]:
    pid = raw.get("param_id", "?")
    val = raw.get("param_value", "?")
    return "parameter_change", "high", f"PARAM_SET {pid}={val}"


def _from_statustext(raw: dict) -> tuple[str, RuntimeSeverity, str] | None:
    sev_raw = raw.get("severity")
    if not isinstance(sev_raw, int) or isinstance(sev_raw, bool):
        return None
    severity = _STATUSTEXT_SEVERITY.get(sev_raw, "informational")
    text = _normalise_statustext(raw.get("text"))
    return "status", severity, f"STATUSTEXT: {text}"


def _normalise_statustext(text: object) -> str:
    """Coerce a STATUSTEXT.text value to a bounded, UTF-8-safe
    string. A hostile autopilot or collector could ship multi-MB
    or non-UTF-8 bytes; without bounding, every evidence row would
    HMAC-sign the full payload. The 1 KiB cap is well above
    MAVLink's documented 50-byte (v1) / 250-byte (v2 chunked)
    STATUSTEXT field, so legitimate traffic is never truncated.
    """
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 -- defensive: text must yield a str
            text = ""
    if not isinstance(text, str):
        return ""
    if len(text) > _STATUSTEXT_MAX_LEN:
        return text[:_STATUSTEXT_MAX_LEN]
    return text


def _from_servo(raw: dict) -> tuple[str, RuntimeSeverity, str]:
    # SERVO_OUTPUT_RAW is high-rate telemetry; DO_SET_SERVO is a
    # discrete command. We use the same action verb for both but
    # bump severity for the discrete command path.
    msg_type = _msg_type(raw)
    if msg_type == "DO_SET_SERVO":
        servo = raw.get("servo", "?")
        pwm = raw.get("pwm", "?")
        return (
            "actuator_action",
            "high",
            f"DO_SET_SERVO servo={servo} pwm={pwm}",
        )
    # SERVO_OUTPUT_RAW: telemetry, informational by default.
    return "actuator_action", "informational", "SERVO_OUTPUT_RAW"


# ── Field extractors (best-effort) ───────────────────────────────


def _extract_ts(raw: dict) -> float:
    """Resolve the event timestamp from absolute clock sources only.

    Returns UNIX-epoch seconds. Prefers in order:
      ``_ts`` / ``timestamp``  -- collector-supplied absolute ts
      ``time_unix_usec``       -- MAVLink wall-clock (microseconds)

    The legacy fallback to ``time.time()`` is intentionally NOT
    used: a ``.tlog`` replay would land every event at the same
    ingest moment, collapsing attack-chain windowing. When no
    absolute clock is present, the function falls back to
    ``time.time()`` AND callers are expected to override via the
    collector layer (see ``examples/runtime_mavlink_collector.py``).

    ``time_boot_ms`` is NOT used here -- it's milliseconds since
    autopilot boot, relative to a per-vehicle epoch the parser
    has no way to know. A collector that wants to use it must
    materialise the boot epoch externally and write ``_ts`` into
    the raw dict before calling parse().
    """
    val = raw.get("_ts") or raw.get("timestamp")
    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
        return float(val)
    val = raw.get("time_unix_usec")
    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
        return float(val) / 1_000_000.0
    # Last-resort fallback. The caller / collector should set
    # ``_ts`` to avoid this path under replay.
    return time.time()


def _extract_str(raw: dict, *keys: str) -> str | None:
    """Return the first non-empty string value among ``keys``."""
    for k in keys:
        v = raw.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _extract_int(raw: dict, *keys: str) -> int | None:
    for k in keys:
        v = raw.get(k)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    return None


def _extract_float(raw: dict, *keys: str) -> float | None:
    for k in keys:
        v = raw.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return float(v)
    return None


def _extract_frame(raw: dict) -> str | None:
    """MAVLink ``frame`` is an enum (MAV_FRAME). Pass the symbolic
    name through when the collector already provided one. For
    numeric values we look up the documented symbolic name in
    ``_FRAME_NAMES``; unknown numerics return
    ``"MAV_FRAME_UNKNOWN_{n}"`` so the reader can tell synthetic
    from authoritative names (the previous ``f"MAV_FRAME_{n}"``
    format was misleading -- e.g. ``MAV_FRAME_3`` actually means
    ``MAV_FRAME_GLOBAL_RELATIVE_ALT``).
    """
    fr = raw.get("frame")
    if isinstance(fr, str) and fr:
        return fr
    if isinstance(fr, int) and not isinstance(fr, bool):
        name = _FRAME_NAMES.get(fr)
        if name is not None:
            return name
        return f"MAV_FRAME_UNKNOWN_{fr}"
    return None
