"""Unit tests for the MAVLink parser.

Covers:
* Per-message-type canonicalisation (the 6 families the parser handles)
* Identity hint generation -- (sysid, compid) -> mavlink_sysid encoding
* Severity mapping (STATUSTEXT MAV_SEVERITY -> KYA RuntimeSeverity)
* ARM vs DISARM disambiguation (same command_id, different param1)
* Malformed / unhandled messages -> None (fail-soft, never raise)
* Bridge integration -- the parser registers as source_tool="mavlink"
  and a parsed event flows through record_runtime_event as autonomy.

Fixtures are plain dicts shaped like ``pymavlink.message.to_dict()``.
No pymavlink dependency in the test suite.
"""
from __future__ import annotations

import pytest

# ── Helpers ──────────────────────────────────────────────────────


def _arm(sysid=1, compid=1, param1=1.0):
    return {
        "mavpackettype": "COMMAND_LONG",
        "sysid": sysid, "compid": compid,
        "command": 400, "param1": param1,
        "time_unix_usec": 1_717_249_800_000_000,
    }


def _takeoff(sysid=1, compid=1, altitude=20.0):
    return {
        "mavpackettype": "COMMAND_LONG",
        "sysid": sysid, "compid": compid,
        "command": 22, "param7": altitude,
        "time_unix_usec": 1_717_249_800_100_000,
    }


def _waypoint(sysid=1, compid=1, seq=0, lat=47.0, lon=-122.0, alt=50.0):
    return {
        "mavpackettype": "MISSION_ITEM_INT",
        "sysid": sysid, "compid": compid, "seq": seq,
        "x": lat, "y": lon, "z": alt,
        "frame": 3,
    }


def _set_mode(sysid=1, base=1, custom=4):
    return {
        "mavpackettype": "SET_MODE",
        "sysid": sysid, "compid": 1,
        "base_mode": base, "custom_mode": custom,
    }


def _param_set(sysid=1, name="FENCE_ENABLE", value=1.0):
    return {
        "mavpackettype": "PARAM_SET",
        "sysid": sysid, "compid": 1,
        "param_id": name, "param_value": value,
    }


def _statustext(sysid=1, severity=3, text="GPS failure"):
    return {
        "mavpackettype": "STATUSTEXT",
        "sysid": sysid, "compid": 1,
        "severity": severity, "text": text,
    }


def _servo(sysid=1, servo=9, pwm=1500, discrete=False):
    return {
        "mavpackettype": "DO_SET_SERVO" if discrete else "SERVO_OUTPUT_RAW",
        "sysid": sysid, "compid": 1,
        "servo": servo, "pwm": pwm,
    }


# ── can_parse ────────────────────────────────────────────────────


class TestCanParse:
    def test_recognises_handled_messages(self):
        from kya.runtime.parsers import mavlink
        assert mavlink.can_parse(_arm())
        assert mavlink.can_parse(_waypoint())
        assert mavlink.can_parse(_set_mode())
        assert mavlink.can_parse(_param_set())
        assert mavlink.can_parse(_statustext())
        assert mavlink.can_parse(_servo())
        assert mavlink.can_parse(_servo(discrete=True))

    def test_rejects_unhandled_messages(self):
        from kya.runtime.parsers import mavlink
        # HEARTBEAT is MAVLink but the parser doesn't canonicalise it
        # (it's pure presence info, not governance-relevant).
        assert not mavlink.can_parse({
            "mavpackettype": "HEARTBEAT",
            "sysid": 1, "compid": 1,
        })

    def test_rejects_non_mavlink(self):
        from kya.runtime.parsers import mavlink
        # Falco shape should NOT match
        assert not mavlink.can_parse({
            "rule": "Terminal shell in container",
            "priority": "Warning",
        })

    def test_rejects_missing_sysid(self):
        from kya.runtime.parsers import mavlink
        # sysid is required for principal binding
        assert not mavlink.can_parse({"mavpackettype": "COMMAND_LONG"})

    def test_rejects_out_of_range_sysid(self):
        from kya.runtime.parsers import mavlink
        # MAVLink sysid is 1 byte (0..255)
        assert not mavlink.can_parse({
            "mavpackettype": "COMMAND_LONG",
            "sysid": 300, "compid": 1,
        })

    def test_never_raises_on_garbage(self):
        from kya.runtime.parsers import mavlink
        for bad in (None, [], "string", 42, {"sysid": None}):
            assert mavlink.can_parse(bad) is False  # type: ignore[arg-type]


# ── Command canonicalisation ─────────────────────────────────────


class TestCommands:
    def test_arm(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_arm(param1=1.0))
        assert ev is not None
        assert ev.action == "arm"
        assert ev.severity == "high"
        assert ev.source_tool == "mavlink"
        assert ev.source_rule_id == "mavlink/COMMAND_LONG"

    def test_disarm(self):
        """Same command_id 400, param1=0 -> disarm. Governance-
        meaningfully different from arm."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_arm(param1=0.0))
        assert ev is not None
        assert ev.action == "disarm"

    @pytest.mark.parametrize("bad_param1,note", [
        (21196.0, "ArduPilot force-arm magic value"),
        (-1.0, "negative"),
        (2.0, "spec violation"),
        (float("nan"), "NaN"),
        (None, "missing param1"),
        ("1", "string"),
    ])
    def test_arm_invalid_for_out_of_spec_param1(self, bad_param1, note):
        """ARM with out-of-spec param1 (force-arm magic, NaN,
        anything not 0 or 1) MUST surface as arm_invalid with
        critical severity -- it's the attack signal a regulator
        wants, not a silent normal arm."""
        from kya.runtime.parsers import mavlink
        raw = _arm(param1=bad_param1) if bad_param1 is not None else _arm()
        if bad_param1 is None:
            raw.pop("param1", None)
        ev = mavlink.parse(raw)
        assert ev is not None
        assert ev.action == "arm_invalid", f"failed: {note}"
        assert ev.severity == "critical"

    def test_takeoff(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_takeoff(altitude=30.0))
        assert ev.action == "takeoff"
        assert ev.severity == "high"

    def test_flight_termination_is_critical(self):
        """MAV_CMD_DO_FLIGHT_TERMINATION (185) is the kill switch.
        Severity MUST be critical so it can't be lost in the
        high-severity noise floor."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "COMMAND_LONG",
            "sysid": 1, "compid": 1,
            "command": 185,  # MAV_CMD_DO_FLIGHT_TERMINATION
        })
        assert ev.action == "flight_termination"
        assert ev.severity == "critical"

    @pytest.mark.parametrize("cmd,action", [
        (177, "mission_jump"),
        (180, "set_parameter"),
        (185, "flight_termination"),
        (2510, "vtol_takeoff"),
        (2511, "vtol_land"),
        (223, "set_yaw_speed"),
    ])
    def test_attacker_favoured_commands_mapped(self, cmd, action):
        """The high-risk commands a Day-3 reviewer flagged as missing
        from the v0.1.8 vocabulary."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "COMMAND_LONG",
            "sysid": 1, "compid": 1, "command": cmd,
        })
        assert ev.action == action

    def test_unknown_command_id_falls_back(self):
        """An unmapped MAV_CMD enum gets the generic 'command'
        action -- the numeric id is preserved in raw for downstream
        rule authors."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "COMMAND_LONG",
            "sysid": 1, "compid": 1,
            "command": 99999,  # not in _COMMAND_LONG_ACTIONS
        })
        assert ev is not None
        assert ev.action == "command"
        assert ev.raw["command"] == 99999

    def test_command_without_command_id_returns_none(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "COMMAND_LONG",
            "sysid": 1, "compid": 1,
            # no `command` field
        })
        assert ev is None


# ── Mission waypoint ─────────────────────────────────────────────


class TestMissionItem:
    def test_waypoint_carries_geo(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_waypoint(seq=3, lat=37.5, lon=-122.3, alt=100.0))
        assert ev.action == "mission_waypoint"
        assert ev.geo_lat == 37.5
        assert ev.geo_lon == -122.3
        assert ev.geo_alt_m == 100.0
        # Frame=3 maps to MAV_FRAME_GLOBAL_RELATIVE_ALT (the
        # documented symbolic name, not the misleading
        # f"MAV_FRAME_{n}" placeholder).
        assert ev.vehicle.frame == "MAV_FRAME_GLOBAL_RELATIVE_ALT"

    def test_unknown_frame_returns_synthetic_name(self):
        """A numeric frame outside the documented MAV_FRAME table
        gets the ``MAV_FRAME_UNKNOWN_{n}`` form so readers can
        distinguish synthetic from authoritative names."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "MISSION_ITEM_INT",
            "sysid": 1, "compid": 1, "seq": 0,
            "x": 0, "y": 0, "z": 0, "frame": 99,
        })
        assert ev.vehicle.frame == "MAV_FRAME_UNKNOWN_99"

    def test_mission_item_v1_also_parsed(self):
        """The pre-MAVLink-2 MISSION_ITEM (not _INT) is also handled."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "MISSION_ITEM",
            "sysid": 1, "compid": 1, "seq": 0,
            "x": 0, "y": 0, "z": 10.0,
        })
        assert ev is not None
        assert ev.action == "mission_waypoint"


# ── Mode / param / status ────────────────────────────────────────


class TestOtherMessages:
    def test_set_mode(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_set_mode(base=29, custom=4))
        assert ev.action == "mode_transition"
        assert ev.severity == "high"
        assert "base=29" in ev.message
        assert "custom=4" in ev.message

    def test_param_set(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_param_set(name="FENCE_ENABLE", value=1.0))
        assert ev.action == "parameter_change"
        assert "FENCE_ENABLE" in ev.message
        assert ev.severity == "high"

    @pytest.mark.parametrize("sev_in,sev_out", [
        (0, "critical"),       # EMERGENCY
        (1, "critical"),       # ALERT
        (2, "critical"),       # CRITICAL
        (3, "high"),           # ERROR
        (4, "high"),           # WARNING
        (5, "low"),            # NOTICE -- "low" so ArduPilot's
                               # liberal NOTICE doesn't flood
                               # high-priority alert buckets
        (6, "informational"),  # INFO
        (7, "informational"),  # DEBUG
    ])
    def test_statustext_severity_mapping(self, sev_in, sev_out):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_statustext(severity=sev_in, text="test"))
        assert ev.severity == sev_out

    def test_statustext_text_truncated_at_1k(self):
        """Multi-MB text is bounded so the evidence chain doesn't
        HMAC-sign adversarial-size strings on every row."""
        from kya.runtime.parsers import mavlink
        big = "X" * 10_000  # 10x the cap
        ev = mavlink.parse(_statustext(severity=4, text=big))
        # message text is truncated
        assert len(ev.message) < 2000  # 1024 + small prefix overhead
        # And the rendered message body length is exactly the cap
        assert "X" * 1024 in ev.message
        assert "X" * 1025 not in ev.message

    def test_statustext_bytes_decoded(self):
        """A collector emitting bytes instead of str must not
        produce a b'...'-wrapped message."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "STATUSTEXT",
            "sysid": 1, "compid": 1,
            "severity": 4,
            "text": b"GPS lock acquired",
        })
        assert "GPS lock acquired" in ev.message
        assert "b'" not in ev.message

    def test_statustext_invalid_utf8_replaced(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "STATUSTEXT",
            "sysid": 1, "compid": 1,
            "severity": 4,
            "text": b"prefix\xff\xfesuffix",
        })
        # Replacement character lands in the message instead of
        # raising
        assert ev is not None
        assert "prefix" in ev.message
        assert "suffix" in ev.message

    def test_statustext_unknown_severity_defaults_informational(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_statustext(severity=99, text="t"))
        assert ev.severity == "informational"

    def test_statustext_no_severity_returns_none(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "STATUSTEXT",
            "sysid": 1, "compid": 1, "text": "no severity",
        })
        assert ev is None


# ── Actuator ─────────────────────────────────────────────────────


class TestActuator:
    def test_do_set_servo_is_high_severity_discrete_action(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_servo(servo=9, pwm=1800, discrete=True))
        assert ev.action == "actuator_action"
        assert ev.severity == "high"
        assert "DO_SET_SERVO" in ev.message

    def test_servo_output_raw_is_informational_telemetry(self):
        """SERVO_OUTPUT_RAW is high-rate telemetry; not a discrete
        command. Default severity informational so the bridge
        doesn't flood evidence-chain on every frame."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_servo(discrete=False))
        assert ev.action == "actuator_action"
        assert ev.severity == "informational"


# ── Identity hint ────────────────────────────────────────────────


class TestIdentityHint:
    def test_principal_hint_encodes_sysid_compid(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_arm(sysid=42, compid=1))
        hints = ev.principal_hints
        assert len(hints) == 1
        assert hints[0].kind == "mavlink_sysid"
        assert hints[0].value == "42:1"

    def test_vehicle_ref_carries_sysid_compid(self):
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_arm(sysid=7, compid=190))
        assert ev.vehicle.sysid == 7
        assert ev.vehicle.compid == 190

    def test_compid_defaults_to_1(self):
        """The MAVLink default component ID when one isn't supplied
        in the message is 1 (the autopilot's primary component)."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse({
            "mavpackettype": "COMMAND_LONG",
            "sysid": 1, "command": 400, "param1": 1.0,
            # no compid
        })
        assert ev.vehicle.compid == 1
        assert ev.principal_hints[0].value == "1:1"

    def test_sysid_zero_rejected(self):
        """sysid=0 is reserved by the MAVLink spec for broadcast /
        'any sender'. Allowing it would let adversarial traffic
        bind under the principal hint '0:1'. can_parse must
        return False and parse must return None."""
        from kya.runtime.parsers import mavlink
        raw = {
            "mavpackettype": "COMMAND_LONG",
            "sysid": 0, "compid": 1,
            "command": 400, "param1": 1.0,
        }
        assert mavlink.can_parse(raw) is False
        assert mavlink.parse(raw) is None


# ── Timestamps ───────────────────────────────────────────────────


class TestTimestamps:
    def test_time_unix_usec_is_used_when_present(self):
        """time_unix_usec is microseconds since UNIX epoch -- the
        most absolute clock a MAVLink message can carry."""
        from kya.runtime.parsers import mavlink
        ev = mavlink.parse(_arm())
        # _arm uses time_unix_usec=1_717_249_800_000_000 = 1717249800.0 sec
        assert ev.occurred_at_ts == 1_717_249_800.0

    def test_missing_timestamp_falls_back_to_now(self):
        """A MAVLink message without an absolute timestamp shouldn't
        be dropped -- the bridge needs SOME timestamp -- but a
        collector replaying a .tlog should set _ts explicitly to
        avoid every event landing at the same ingest moment."""
        import time as _time

        from kya.runtime.parsers import mavlink
        before = _time.time()
        ev = mavlink.parse({
            "mavpackettype": "PARAM_SET",
            "sysid": 1, "compid": 1,
            "param_id": "P", "param_value": 0.0,
        })
        after = _time.time()
        assert before <= ev.occurred_at_ts <= after

    def test_collector_supplied_ts_wins(self):
        """A collector replaying a .tlog supplies ``_ts`` per event;
        the parser MUST use that absolute clock, not time.time()."""
        from kya.runtime.parsers import mavlink
        replayed_ts = 1_600_000_000.0  # arbitrary past timestamp
        ev = mavlink.parse({
            "mavpackettype": "PARAM_SET",
            "sysid": 1, "compid": 1,
            "param_id": "P", "param_value": 0.0,
            "_ts": replayed_ts,
        })
        assert ev.occurred_at_ts == replayed_ts

    def test_time_boot_ms_does_not_corrupt_replay(self):
        """time_boot_ms is milliseconds since autopilot boot --
        relative to a per-vehicle epoch the parser cannot know.
        It must NOT be used as the event timestamp; the fallback
        chain skips it and lands on time.time() (or _ts when the
        collector supplied one). This test guards against a regression
        where time_boot_ms gets divided by 1000 and used as if it
        were a UNIX timestamp."""
        import time as _time

        from kya.runtime.parsers import mavlink
        before = _time.time()
        ev = mavlink.parse({
            "mavpackettype": "PARAM_SET",
            "sysid": 1, "compid": 1,
            "param_id": "P", "param_value": 0.0,
            "time_boot_ms": 5000,  # 5s since boot -- NOT a UNIX ts
        })
        after = _time.time()
        # The ts MUST NOT be ~5 (boot ms interpreted as seconds)
        # nor ~0.005 (boot ms / 1000_000); it must be current time.
        assert before <= ev.occurred_at_ts <= after


# ── Bridge integration ──────────────────────────────────────────


class TestBridgeIntegration:
    def setup_method(self):
        from kya.runtime import set_principal_resolver
        set_principal_resolver(None)

    def teardown_method(self):
        from kya.runtime import reset_principal_resolver_to_default
        reset_principal_resolver_to_default()

    def test_ingest_with_explicit_source_tool(self):
        """The bridge routes a MAVLink dict through the registered
        parser when source_tool='mavlink' is forced."""
        from kya.runtime import ingest
        result = ingest(_arm(), source_tool="mavlink")
        assert result.accepted is True
        assert result.source_tool == "mavlink"
        assert result.source_kind == "autonomy"

    def test_ingest_autodetect(self):
        """Autodetect picks up the MAVLink shape without a source
        hint."""
        from kya.runtime import ingest
        result = ingest(_arm())  # no source_tool=
        assert result.accepted is True
        assert result.source_tool == "mavlink"

    def test_autodetect_does_not_misfire_on_falco(self):
        """A Falco event must NOT autodetect as MAVLink."""
        from kya.runtime import ingest
        falco_alert = {
            "rule": "Terminal shell in container",
            "priority": "Warning",
            "output": "test",
            "time": "2026-06-01T10:00:00Z",
            "output_fields": {"container.id": "abc"},
        }
        result = ingest(falco_alert)
        # Falco autodetects to "falco", not "mavlink"
        assert result.source_tool == "falco"


# ── Resilience ──────────────────────────────────────────────────


class TestResilience:
    """The bridge contract is fail-soft: a parser MUST NOT raise
    on malformed input. It returns None and the bridge drops the
    event with a debug log."""

    @pytest.mark.parametrize("payload", [
        None,
        [],
        "string",
        42,
        {"mavpackettype": None},
        {"mavpackettype": "COMMAND_LONG"},  # no sysid
        {"sysid": 1},  # no mavpackettype
        {"mavpackettype": "STATUSTEXT", "sysid": 1, "compid": 1},  # no severity
        {"mavpackettype": "COMMAND_LONG", "sysid": "not_an_int",
         "compid": 1, "command": 400},
        {"mavpackettype": "COMMAND_LONG", "sysid": -1,
         "compid": 1, "command": 400},
    ])
    def test_parse_returns_none_or_handles_gracefully(self, payload):
        from kya.runtime.parsers import mavlink
        result = mavlink.parse(payload)  # type: ignore[arg-type]
        # None is the contract; any successful parse is also fine
        # (the dispatcher decides per message), but a raise is not.
        assert result is None or hasattr(result, "source_tool")
