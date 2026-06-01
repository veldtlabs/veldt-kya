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

import logging
from typing import Any

from ..._canonical import (
    AutonomyEvent,
    PrincipalHint,
    RuntimeSeverity,
    VehicleRef,
    encode_mavlink_sysid,
)

logger = logging.getLogger(__name__)


# MAV_CMD enum values we canonicalise. Source:
# https://mavlink.io/en/messages/common.html#mav_commands
# Values that don't appear here fall through to a generic
# "command" action with the numeric enum preserved in raw.
_COMMAND_LONG_ACTIONS: dict[int, str] = {
    400: "arm",                  # MAV_CMD_COMPONENT_ARM_DISARM (param1=1 -> arm)
    22: "takeoff",               # MAV_CMD_NAV_TAKEOFF
    21: "land",                  # MAV_CMD_NAV_LAND
    20: "rtl",                   # MAV_CMD_NAV_RETURN_TO_LAUNCH
    300: "mission_start",        # MAV_CMD_MISSION_START
    176: "mode_transition",      # MAV_CMD_DO_SET_MODE
    179: "set_home",             # MAV_CMD_DO_SET_HOME
    183: "set_servo",            # MAV_CMD_DO_SET_SERVO
    246: "preflight_reboot",     # MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
}


# MAV_SEVERITY (STATUSTEXT) -> KYA RuntimeSeverity.
# Source: https://mavlink.io/en/messages/common.html#MAV_SEVERITY
_STATUSTEXT_SEVERITY: dict[int, RuntimeSeverity] = {
    0: "critical",        # EMERGENCY
    1: "critical",        # ALERT
    2: "critical",        # CRITICAL
    3: "high",            # ERROR
    4: "high",            # WARNING
    5: "medium",          # NOTICE
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
    recognised MAVLink message type plus a sysid. Never raises."""
    if not isinstance(raw, dict):
        return False
    msg = _msg_type(raw)
    if msg is None or msg not in _HANDLED_MESSAGES:
        return False
    sysid = raw.get("sysid")
    return isinstance(sysid, int) and 0 <= sysid <= 255


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
    if not (isinstance(sysid, int) and 0 <= sysid <= 255
            and isinstance(compid, int) and 0 <= compid <= 255):
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
    """COMMAND_LONG / COMMAND_INT. The command_id field carries the
    MAV_CMD enum. Special case for ARM/DISARM (one command_id, two
    actions distinguished by param1=1.0 vs param1=0.0)."""
    cmd = raw.get("command")
    if not isinstance(cmd, int):
        return None

    # ARM/DISARM special case: same command_id, param1=1 means arm,
    # param1=0 means disarm. The distinction matters for the audit
    # trail -- "ARM" and "DISARM" are governance-meaningfully
    # different actions.
    if cmd == 400:
        param1 = raw.get("param1")
        if isinstance(param1, (int, float)) and param1 == 0:
            action = "disarm"
        else:
            action = "arm"
    else:
        action = _COMMAND_LONG_ACTIONS.get(cmd, "command")

    # All commands are high-severity by default in the autonomy
    # world: arming, takeoff, RTL, set_servo are all
    # operator-noticeable actions. The bridge can rewrite via rules.
    severity: RuntimeSeverity = "high"
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
    if not isinstance(sev_raw, int):
        return None
    severity = _STATUSTEXT_SEVERITY.get(sev_raw, "informational")
    text = raw.get("text") or ""
    return "status", severity, f"STATUSTEXT: {text}"


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
    """Use the message timestamp when present; fall back to current
    time. The bridge needs a monotonic-per-source ts for correlation;
    a missing timestamp is unusual but shouldn't drop the event."""
    import time as _time
    for key in ("time_unix_usec", "time_boot_ms", "_ts", "timestamp"):
        val = raw.get(key)
        if isinstance(val, (int, float)) and val > 0:
            # MAVLink uses microseconds since UNIX epoch for
            # time_unix_usec; time_boot_ms is milliseconds since
            # boot -- not absolute. Use absolute when available;
            # otherwise let the bridge synthesise.
            if key == "time_unix_usec":
                return float(val) / 1_000_000.0
            if key == "_ts" or key == "timestamp":
                return float(val)
    return _time.time()


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
    """MAVLink ``frame`` is an enum (MAV_FRAME). We pass the symbolic
    name through when present (modern collectors set it) and the
    numeric value otherwise."""
    fr = raw.get("frame")
    if isinstance(fr, str) and fr:
        return fr
    if isinstance(fr, int):
        return f"MAV_FRAME_{fr}"
    return None
