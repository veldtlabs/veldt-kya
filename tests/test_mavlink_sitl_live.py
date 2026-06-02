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


def _load_all_entries() -> list[dict]:
    """Raw NDJSON load -- includes any ``_meta`` records the
    capture script may have prepended."""
    if not _CAPTURE_PATH.exists():
        pytest.skip(
            f"no SITL capture at {_CAPTURE_PATH}; run "
            "`scripts/mavlink_sitl_live_capture.py` first or set "
            "MAVLINK_SITL_CAPTURE to an existing capture file.")
    raw = [
        json.loads(line)
        for line in _CAPTURE_PATH.read_text().splitlines()
        if line.strip()
    ]
    if not raw:
        pytest.skip(
            f"SITL capture at {_CAPTURE_PATH} exists but is empty "
            "-- re-run the capture script.")
    return raw


def _load_frames() -> list[dict]:
    """MAVLink frames only -- strips ``_meta`` header so existing
    parser-shape assertions don't see it."""
    return [e for e in _load_all_entries() if not e.get("_meta")]


def _load_meta() -> dict:
    """The ``_meta: "header"`` record the capture script writes
    at the top of the NDJSON. Single source of truth for
    ``gcs_sysid`` + phase counts so tests don't need their own
    copy of the env vars -- the writer wrote the values it used
    and the reader reads them back."""
    for entry in _load_all_entries():
        if entry.get("_meta") == "header":
            return entry
    pytest.skip(
        f"capture at {_CAPTURE_PATH} has no _meta header; "
        "regenerate with the current capture script.")
    return {}  # for type checker; pytest.skip raises


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

    def test_inbound_traffic_was_captured(self):
        """H1 regression guard, READ FROM ``_meta`` header (single
        source of truth with the writer).

        The script's writer side already dies on either
        ``inbound_during`` or ``inbound_after`` being empty, but
        this test exists as a defense-in-depth check that catches
        the regression even if a future change weakens the
        writer-side assertion.

        Critically, the writer wrote the SAME ``gcs_sysid`` it
        stamped on each operator frame -- so the reader doesn't
        need an env var to know which sysid was "operator". This
        closes the H1 review finding's env-consistency hole.
        """
        meta = _load_meta()

        # Phase counts both > 0 -- splits the canary so a future
        # drain() regression isn't masked by post-mission capture.
        assert meta.get("inbound_during_count", 0) > 0, (
            "ZERO inbound frames DURING the mission window per "
            "the capture _meta. drain() in _sitl_common may have "
            "regressed -- the COMMAND_ACK / mode-change STATUSTEXT "
            "bursts are no longer being drained between sends.")
        assert meta.get("inbound_after_count", 0) > 0, (
            "ZERO inbound frames AFTER the mission window per "
            "the capture _meta. capture() may have regressed -- "
            "or the autopilot crashed after the final command.")

        # Cross-check the meta counts against the actual sysid
        # distribution. The meta says "we wrote N inbound frames";
        # confirm at least that many frames carry a non-GCS sysid.
        gcs_sysid = meta["gcs_sysid"]
        frames = _load_frames()
        inbound_observed = [
            f for f in frames
            if f.get("sysid") not in (gcs_sysid, None)
        ]
        expected_total_inbound = (
            meta["inbound_during_count"] + meta["inbound_after_count"]
        )
        assert len(inbound_observed) >= expected_total_inbound, (
            f"_meta promised {expected_total_inbound} inbound frames "
            f"but only {len(inbound_observed)} carry non-GCS sysid. "
            f"meta + writer have drifted out of sync.")

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
