"""MAVLink -> KYA AutonomyEvent parser.

MAVLink (https://mavlink.io/) is the dominant open protocol for
drones / UAS, used by ArduPilot, PX4, and many ground control
stations. This module translates MAVLink messages -- whether
streamed live from a flight controller or replayed from a ``.tlog``
file -- into KYA's canonical :class:`kya.runtime.AutonomyEvent`.

The collector that feeds this parser is the user's responsibility
(MAVLink router, sidecar reading the autopilot UART, sidekick
reading rosbag, anything that produces a dict-shaped MAVLink
message). Tests at ``tests/test_mavlink_parser.py`` exercise
parsing from in-memory dicts shaped like pymavlink's
``message.to_dict()``.

Six message families are mapped today (the minimum to cover the
governance-relevant commands a regulator cares about):

    COMMAND_LONG (arm/disarm/takeoff/RTL) -> command actions
    MISSION_ITEM / MISSION_ITEM_INT        -> mission_waypoint
    SET_MODE                                 -> mode_transition
    PARAM_SET                                -> parameter_change
    STATUSTEXT                               -> status (severity-mapped)
    SERVO_OUTPUT_RAW / DO_SET_SERVO          -> actuator_action

Adding a message family is one mapping + one test case; the parser
ignores any message it doesn't recognise (returns None from parse).

Optional dependency
-------------------
This parser is fully usable without ``pymavlink`` -- it parses the
dict-shape that pymavlink's ``message.to_dict()`` produces, so a
collector or test that already has dicts works directly. ``pymavlink``
itself is LGPL-3.0; we declare it as an optional extra
(``pip install veldt-kya[mavlink]``) so it's only pulled in when
the collector needs the live UART / UDP / TLog reader. The kya
core wheel stays Apache-2.0 clean.
"""
from __future__ import annotations

from ._parser import can_parse, parse

__all__ = ["can_parse", "parse"]
