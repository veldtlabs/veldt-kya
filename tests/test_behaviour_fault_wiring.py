"""The behaviour-fault axis AS WIRED INTO THE LAB.

Separate from ``test_behaviour_faults.py`` on purpose. That file tests
the registry and the transformations in isolation, against plain
``PlannedAct`` lists. It imports nothing from ``experiment`` -- and
that gap is why a real regression shipped green:

A chain rule added for ``duplication`` matched on
``payload.tool == "file_read"`` alone. But ``sub_a``'s legitimate
``recon`` role IS a file_read, so injecting any file_read fault
(``emergent_sequence``, ``dangerous_argument``) gave one principal two
executed reads -- exactly what the rule looks for. It fired on 8 of 12
pre-existing fault cells with NO behaviour fault applied, and because
it matched at an earlier step it took over ``detected_by`` and
``detected_at`` from the rule that legitimately detected the chain.
Those are the lab's headline measurements.

``--check`` did not catch it: the ``EXPECTED`` table compares
``harmful_exec``, ``prevented_by`` and a BOOLEAN ``detected``, which
was already True for the affected cells. A change of *which* rule
detected, and *when*, passes that oracle unnoticed.

So these tests run the real thing.
"""
from __future__ import annotations

import os
import sys

import pytest

_LAB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "examples", "fault_injection",
)

#: Every pre-existing fault class, plus the no-fault baseline. These
#: are the runs whose published results a new rule must not disturb.
_PRE_EXISTING_FAULTS = (
    "none",
    "unauthorized_capability",
    "dangerous_argument",
    "emergent_sequence",
)

#: The modes in which the correlation layer is live. A rule cannot
#: fire where correlation is off, so the other modes prove nothing.
_CORRELATING_MODES = ("correlation", "layered")


#: Environment the lab sets AT IMPORT TIME, via `os.environ.setdefault`.
#:
#: Correct for a standalone script (`python experiment.py`), and a
#: landmine for a test that imports it into the shared pytest process:
#: every later test in the session inherits the lab's sqlite DB and
#: `KYA_RBAC_ENFORCEMENT=block`.
#:
#: That is not hypothetical. It cost 12 failures in the full suite --
#: `test_gateway_policy_pipeline_*` and
#: `test_gateway_verdict_allowlist_and_failclosed`, none of which this
#: branch touches. They passed in isolation (45/45) and failed only
#: when ordered after this file, which is the signature of leaked
#: global state rather than a real defect.
#:
#: The lab is a script, so the containment belongs here.
_LAB_ENV_KEYS = (
    "KYA_DB_URL",
    "KYA_RBAC_ENFORCEMENT",
    "KYA_EVIDENCE_SIGNING_KEY",
)


@pytest.fixture(scope="module")
def lab():
    """Import the lab, and undo its import-time environment.

    Function-scoped import, not module-scope: a top-level import would
    raise at COLLECTION time if the lab moved, aborting the whole suite
    instead of failing these tests.
    """
    saved = {k: os.environ.get(k) for k in _LAB_ENV_KEYS}
    if _LAB not in sys.path:
        sys.path.insert(0, _LAB)
    try:
        import experiment

        yield experiment
    finally:
        # Restore exactly, including "was absent" -- leaving a key set
        # to the empty string is not the same as unset, and some
        # readers treat them differently.
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if _LAB in sys.path:
            sys.path.remove(_LAB)


def _run(lab, topology, fault, mode, behaviour_fault=None):
    return lab.run(
        topology, "sub_a", fault, 600, 0, 40,
        verbose=False, mode=mode, behaviour_fault=behaviour_fault,
    )


def test_duplication_rule_never_fires_without_a_duplication(lab):
    """The regression, swept.

    For every topology x correlating mode x pre-existing fault, with
    NO behaviour fault applied, ``duplicate_action`` must not fire.
    Any hit means a new rule has rewritten a published measurement.
    """
    leaks = []
    for topology in sorted(lab.TOPOLOGIES):
        for mode in _CORRELATING_MODES:
            for fault in _PRE_EXISTING_FAULTS:
                r = _run(lab, topology, fault, mode)
                fired = r.get("fired_rules") or []
                if r.get("detected_by") == "duplicate_action" or (
                    "duplicate_action" in fired
                ):
                    leaks.append((topology, mode, fault,
                                  r.get("detected_by")))

    assert not leaks, (
        "duplicate_action fired on runs with no duplication fault, so "
        "it is matching reads that were never duplicated and has "
        "taken over detected_by/detected_at from the rule that "
        "legitimately detected the chain: {}".format(leaks)
    )


def test_duplication_rule_still_catches_a_real_duplication(lab):
    """The other direction, so the fix above cannot be "never fire".

    Guards against over-narrowing the rule until it stops detecting
    the thing it exists for.
    """
    r = _run(lab, "diamond", "none", "correlation",
             behaviour_fault="duplication")
    assert r.get("detected_by") == "duplicate_action", (
        "the duplication fault was not detected; the rule has been "
        "narrowed until it no longer matches a genuine repeat "
        "(detected_by={!r})".format(r.get("detected_by"))
    )


def test_the_rule_names_the_same_resource_the_role_reads(lab):
    """One fact, one definition.

    The duplicated action's path and the rule's path must be the same
    value. If the rule restated it, the two could drift and the rule
    would match reads that were never duplicated -- which is precisely
    how the regression above happened.
    """
    assert lab.RECON_PATH == lab.ROLE_ACTION["recon"]["path"], (
        "RECON_PATH has drifted from the role it is derived from"
    )


def test_corrupt_data_is_refused_and_attributed_to_the_right_layer(lab):
    """The wiring for corrupt_data, end to end through run().

    Not covered by the registry tests: they verify the transformation
    produces a payload override, not that the lab applies it, that the
    argument policy refuses it, or that the refusal is attributed.
    """
    r = _run(lab, "diamond", "none", "layered",
             behaviour_fault="corrupt_data")

    assert r["deviation_refused_by"] == "argument_policy", (
        "the corrupted payload was not refused by the argument "
        "policy (refused_by={!r}); the fault and the rule that is "
        "supposed to catch it have drifted apart".format(
            r["deviation_refused_by"])
    )
    assert r["blocked_actions"] >= 1, (
        "nothing was blocked, so the corruption was never actually "
        "applied to a payload the policy saw"
    )
    # The harm axis must stay clean: nothing harmful was attempted.
    assert r["harmful_attempted"] == 0
    assert r["prevented_by"] is None, (
        "a behaviour fault populated the HARM axis; the two axes must "
        "stay distinguishable in results.jsonl"
    )


def test_a_baseline_run_still_emits_the_deviation_fields(lab):
    """Schema stability through the real run path, not just the
    dataclass. A ragged results.jsonl forces every consumer to
    special-case the baseline."""
    r = _run(lab, "diamond", "none", "correlation")
    for key in ("deviation_fault", "deviation_kind",
                "deviation_planned_actions",
                "deviation_observed_actions",
                "deviation_took_effect", "deviation_detectable_by",
                "deviation_detected_by", "deviation_refused_by"):
        assert key in r, f"baseline run is missing {key}"
    assert r["deviation_fault"] is None
    assert r["deviation_took_effect"] is False


@pytest.mark.parametrize("name,expect_fewer", [
    ("omission", True),
    ("crash", True),
    ("duplication", False),
])
def test_planned_vs_observed_reflects_what_happened(lab, name,
                                                    expect_fewer):
    """planned vs observed is the arithmetic that makes omission and
    crash visible at all, so it has to be right through the real run
    path rather than asserted on a constructed record."""
    r = _run(lab, "diamond", "none", "correlation",
             behaviour_fault=name)
    planned = r["deviation_planned_actions"]
    observed = r["deviation_observed_actions"]
    if expect_fewer:
        assert observed < planned, (
            f"{name} should leave fewer actions executed than planned "
            f"(planned={planned} observed={observed})"
        )
    else:
        assert observed > planned, (
            f"{name} should leave more actions executed than planned "
            f"(planned={planned} observed={observed})"
        )
