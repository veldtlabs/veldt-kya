"""Live ArduPilot SITL integration test for the MAVLink parser.

Reads the JSON capture produced by ``scripts/mavlink_sitl_live_capture.py``
and asserts that the parser correctly canonicalises every
governance-relevant message family.

Skipped when:
  * the capture file isn't present (local dev run without SITL); or
  * pymavlink isn't installed (the collector dep that produced the
    capture).

The test deliberately does NOT spin SITL itself -- doing so inside
pytest would tie the test runtime to Docker, slow the unit suite,
and conflate parser correctness with infrastructure flakes. The
capture script runs in CI as a separate step; this test consumes
its artefact.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import pytest

_DEFAULT_CAPTURE = Path("/tmp/mavlink-sitl.json")
_CAPTURE_PATH = Path(os.environ.get("MAVLINK_SITL_CAPTURE", _DEFAULT_CAPTURE))


def _load_frames() -> list[dict]:
    if not _CAPTURE_PATH.exists():
        pytest.skip(
            f"no SITL capture at {_CAPTURE_PATH}; run "
            "`scripts/mavlink_sitl_live_capture.py` first or set "
            "MAVLINK_SITL_CAPTURE to an existing capture file.")
    frames = [
        json.loads(line)
        for line in _CAPTURE_PATH.read_text().splitlines()
        if line.strip()
    ]
    if not frames:
        pytest.skip(
            f"SITL capture at {_CAPTURE_PATH} exists but is empty "
            "-- re-run the capture script.")
    return frames


# ── Live tests ──────────────────────────────────────────────────


class TestLiveSitlCapture:
    """End-to-end: capture from a real ArduPilot SITL flight cycle
    should produce canonical AutonomyEvents for the governance-
    relevant message families the parser handles."""

    def test_capture_has_governance_relevant_frames(self):
        """The scripted mission MUST emit at least one frame from
        each handled family. If this fails, either SITL is
        misconfigured OR the parser silently dropped messages
        whose shape pymavlink emits (see _msg_type's key lookup)."""
        frames = _load_frames()
        # The capture marks handled frames; verify at least one
        # actually parsed through.
        from kya.runtime.parsers import mavlink
        parsed_count = sum(
            1 for f in frames if mavlink.parse(f) is not None)
        assert parsed_count > 0, (
            f"out of {len(frames)} captured frames, ZERO parsed "
            f"-- the parser is silently dropping every SITL message")

    def test_canonical_action_vocabulary_covered(self):
        """The scripted mission exercises arm + takeoff + waypoint +
        mode_transition + parameter_change at minimum. Every one
        must produce its expected canonical action."""
        from kya.runtime.parsers import mavlink
        frames = _load_frames()
        actions = Counter()
        for f in frames:
            ev = mavlink.parse(f)
            if ev is not None:
                actions[ev.action] += 1

        # The mission upload + arm + takeoff path MUST fire each of
        # these at least once. If one is missing, either the
        # scripted mission is incomplete OR the parser canonicalised
        # the message under a different action verb than expected.
        for required in (
            "mode_transition",  # SET_MODE
            "parameter_change",  # PARAM_SET FENCE_ENABLE
            "mission_waypoint",  # MISSION_ITEM_INT upload
            "arm",               # COMMAND_LONG MAV_CMD_COMPONENT_ARM_DISARM
            "takeoff",           # COMMAND_LONG MAV_CMD_NAV_TAKEOFF
        ):
            assert actions.get(required, 0) > 0, (
                f"action {required!r} did not appear in the live "
                f"SITL capture. Action histogram: {dict(actions)}")

    def test_principal_hints_have_real_sysid(self):
        """Every parsed event carries a mavlink_sysid hint encoding
        the autopilot's actual sysid. A test that captures from a
        real autopilot proves the wire-format contract: pymavlink's
        to_dict() shape matches the parser's expected key names.

        The expected sysid defaults to 1 (ArduPilot SITL default)
        but can be overridden via ``EXPECTED_SYSID`` env var when
        the SITL config sets a different SYSID_THISMAV.
        """
        import os

        from kya.runtime.parsers import mavlink
        frames = _load_frames()
        sysids_seen: set[str] = set()
        for f in frames:
            ev = mavlink.parse(f)
            if ev is None:
                continue
            for hint in ev.principal_hints:
                if hint.kind == "mavlink_sysid":
                    sysids_seen.add(hint.value)
        assert sysids_seen, (
            "no principal hints captured -- the parser is not "
            "extracting (sysid, compid) from the SITL frames")
        expected_sysid = os.environ.get("EXPECTED_SYSID", "1")
        # Match any compid for the expected sysid (autopilots emit
        # under multiple compids: 1=autopilot, 50=mavftp, etc.)
        matching = [s for s in sysids_seen
                    if s.startswith(f"{expected_sysid}:")]
        assert matching, (
            f"expected sysid={expected_sysid} from SITL, "
            f"saw: {sysids_seen}")

    def test_bridge_accepts_every_parsed_event(self):
        """End-to-end: every parsed SITL frame must survive the
        bridge's _validate_event_classification (the C3 fix from
        Day 2 review). If even one event raises ValueError here,
        the parser produced an inconsistent class/source_tool pair
        and audit-integrity is at risk."""
        from kya.runtime import (
            record_runtime_event,
            reset_principal_resolver_to_default,
            set_principal_resolver,
        )
        from kya.runtime.parsers import mavlink

        set_principal_resolver(None)
        try:
            frames = _load_frames()
            for f in frames:
                ev = mavlink.parse(f)
                if ev is None:
                    continue
                # ANY ValueError here breaks the test.
                result = record_runtime_event(ev)
                assert result.accepted is True
                assert result.source_kind == "autonomy"
                assert result.source_tool == "mavlink"
        finally:
            reset_principal_resolver_to_default()
