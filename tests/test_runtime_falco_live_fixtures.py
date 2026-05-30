"""Live-captured Falco fixtures -> KYA parser round-trip.

These fixtures were captured from a real Falco 0.39.2 daemon running
the **modern_ebpf** driver on a WSL2 kernel 5.15 host, observing real
workloads. They are NOT synthetic. The capture script lives in
``scripts/runtime_capture_falco.ps1`` so anyone can re-create them.

Each fixture exercises a different rule + output_fields shape, so the
parser is verified against the actual emitted Falco JSON contract
across multiple alert types -- not just one canonical example.

Why this layer matters
----------------------
The unit + real-format-sample tests (test_runtime_falco.py) use
hand-crafted SigmaHQ-style fixtures based on Falco docs. This file
uses payloads captured FROM A RUNNING FALCO. If Falco changes its
JSON shape in a minor version (e.g. 0.40), a unit-test pass might
still hide a real regression -- this layer catches it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kya.runtime import RuntimeEvent
from kya.runtime.parsers import falco

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "falco_live"


def _load(name: str) -> dict:
    path = _FIXTURE_DIR / f"{name}.json"
    # PowerShell writes utf-8 with BOM by default; strip if present.
    return json.loads(path.read_text(encoding="utf-8-sig").strip())


_FIXTURES = [
    "read_sensitive_file_untrusted",
    "redirect_stdout_stdin_to_network_connection_in_container",
    "packet_socket_created_in_container",
]


@pytest.mark.parametrize("name", _FIXTURES)
def test_live_fixture_parses_into_canonical_event(name):
    """Every live-captured Falco alert must parse cleanly into a
    RuntimeEvent with the core required fields populated. A regression
    here means the parser broke against the real Falco contract."""
    raw = _load(name)
    assert falco.can_parse(raw), name

    ev = falco.parse(raw)
    assert isinstance(ev, RuntimeEvent)
    assert ev.source_tool == "falco"
    assert ev.source_rule_id  # non-empty
    assert ev.severity in (
        "informational", "low", "medium", "high", "critical",
    )
    assert ev.action  # non-empty, snake_case derived from rule
    # The raw payload is round-trippable -- canonical event keeps the
    # original Falco JSON for the HMAC chain to hash.
    assert ev.raw["rule"] == raw["rule"]


def test_live_read_sensitive_file_untrusted_carries_mitre_credential_access():
    """One of Falco's signature credential-access alerts. Verify our
    parser surfaces the MITRE technique id Falco tagged."""
    raw = _load("read_sensitive_file_untrusted")
    ev = falco.parse(raw)
    assert ev is not None
    assert ev.severity == "high"  # priority=Warning -> high
    # Falco emits MITRE technique IDs directly as tags
    assert "T1555" in ev.tags
    assert "mitre_credential_access" in ev.tags


def test_live_redirect_stdout_carries_container_metadata():
    """The network-redirect rule fires from within a container; verify
    container.id + container.name landed in canonical fields."""
    raw = _load(
        "redirect_stdout_stdin_to_network_connection_in_container")
    ev = falco.parse(raw)
    assert ev is not None
    assert ev.container_id  # non-empty
    # Falco 0.39 emits 12-char short container ids
    assert len(ev.container_id) >= 12


def test_live_alerts_yield_process_user_principal_hint():
    """Falco default config doesn't enrich with container labels (it's
    opt-in), so the strongest hint a default Falco emits is the
    process user. Verify our parser produces it -- otherwise events
    would arrive at the bridge with NO hints and bind only via the
    explicit / fall-back paths."""
    for name in _FIXTURES:
        raw = _load(name)
        ev = falco.parse(raw)
        assert ev is not None, name
        kinds = [h.kind for h in ev.principal_hints]
        assert "process_user" in kinds, f"{name}: hints={kinds}"


def test_live_action_field_is_snake_case_and_stable():
    """The action field is the attack-chain rule's match target.
    Verify it's stable snake_case derived from the rule name -- if
    Falco renames a rule between versions, this test catches the
    behavior change."""
    raw = _load("read_sensitive_file_untrusted")
    ev = falco.parse(raw)
    assert ev is not None
    assert ev.action == "read_sensitive_file_untrusted"
    # Pure snake_case -- no spaces, no uppercase, no leading/trailing _
    assert ev.action == ev.action.strip("_")
    assert ev.action.islower()
    assert " " not in ev.action
