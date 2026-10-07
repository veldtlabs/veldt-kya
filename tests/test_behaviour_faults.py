"""Behaviour faults: a second fault axis for the injection lab.

The lab's existing ``FAULTS`` all INSERT an extra harmful action, and
the whole result vocabulary follows from that -- ``harmful_attempted``,
``harmful_executed``, ``prevented_by``. Each class was chosen because a
different defensive layer can express the refusal.

The five classes added here are not commission faults. They TRANSFORM
the planned sequence: an action is dropped, delayed, repeated, the run
is truncated, or a payload is corrupted. Nothing extra is attempted, so
the harm vocabulary reports a clean run while something did go wrong --
which is why these carry their own ``Deviation`` record instead of
overloading the existing fields.

Written before the implementation, deliberately.
"""
from __future__ import annotations

import os
import sys

import pytest

_LAB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "examples", "fault_injection",
)


@pytest.fixture(scope="module")
def bf():
    """Import the lab module without a module-scope import.

    A top-level import would raise at COLLECTION time if the lab
    moved, aborting the whole suite rather than failing one test.
    """
    if _LAB not in sys.path:
        sys.path.insert(0, _LAB)
    import behaviour_faults

    return behaviour_faults


def _plan(bf):
    """Three principals, all legitimate work, no injected action."""
    A = bf.PlannedAct
    return [
        A(principal="parent", role="spawn", origin=None),
        A(principal="sub_a", role="recon", origin=None),
        A(principal="leaf", role="exfil", origin=None),
    ]


# -- The registry contract ----------------------------------------


def test_all_five_classes_are_registered(bf):
    """Named explicitly so a rename or silent drop fails rather than
    quietly shrinking the catalogue."""
    assert set(bf.BEHAVIOUR_FAULTS) >= {
        "omission", "slow", "duplication", "crash", "corrupt_data",
    }


def test_registering_a_new_class_needs_only_the_decorator(bf):
    """Extensibility is a requirement: adding a sixth class must not
    mean editing a dispatcher, the CLI or the reporter."""
    before = set(bf.BEHAVIOUR_FAULTS)
    try:

        @bf.behaviour_fault(
            "test_only_noop", kind="absence", detectable_by=None,
            doc="registered by a test",
        )
        def _noop(plan, *, inject_at):
            return bf.PlanChange(plan=list(plan))

        assert "test_only_noop" in bf.BEHAVIOUR_FAULTS
        spec = bf.BEHAVIOUR_FAULTS["test_only_noop"]
        assert spec.kind == "absence"
        assert spec.detectable_by is None
        assert spec.doc
    finally:
        bf.BEHAVIOUR_FAULTS.pop("test_only_noop", None)
    assert set(bf.BEHAVIOUR_FAULTS) == before


def test_duplicate_registration_is_refused(bf):
    """Two classes under one name would make results ambiguous, and
    which one won would depend on import order."""
    with pytest.raises(ValueError):

        @bf.behaviour_fault(
            "omission", kind="absence", detectable_by=None, doc="dup",
        )
        def _dup(plan, *, inject_at):
            return bf.PlanChange(plan=list(plan))


def test_every_class_declares_its_detection_hypothesis(bf):
    """``detectable_by`` is the DECLARED prediction of which layer
    should catch the class, with None meaning "nothing here can".
    Leaving it unset would let an undetectable class look like a
    detection failure instead of a declared architectural gap."""
    for name, spec in bf.BEHAVIOUR_FAULTS.items():
        assert spec.kind in bf.DEVIATION_KINDS, (name, spec.kind)
        assert spec.detectable_by is None or isinstance(
            spec.detectable_by, str
        ), name
        assert spec.doc and spec.doc.strip(), f"{name} has no rationale"


# -- The transformations ------------------------------------------


def test_omission_drops_the_targeted_principals_action(bf):
    plan = _plan(bf)
    change = bf.apply(plan, "omission", inject_at="sub_a")

    assert len(change.plan) == len(plan) - 1
    assert not any(a.principal == "sub_a" for a in change.plan)
    assert [a.principal for a in change.plan] == ["parent", "leaf"], (
        "omission disturbed the order of the surviving actions"
    )


def test_duplication_repeats_the_action_adjacently(bf):
    plan = _plan(bf)
    change = bf.apply(plan, "duplication", inject_at="sub_a")

    assert len(change.plan) == len(plan) + 1
    seq = [a.principal for a in change.plan]
    assert seq == ["parent", "sub_a", "sub_a", "leaf"], (
        "expected an adjacent repeat, got {} -- a non-adjacent repeat "
        "is a different fault, since it interleaves".format(seq)
    )


def test_crash_truncates_the_run_and_records_where(bf):
    plan = _plan(bf)
    change = bf.apply(plan, "crash", inject_at="sub_a")

    assert [a.principal for a in change.plan] == ["parent", "sub_a"], (
        "crash must keep actions up to and including the crash point "
        "and drop everything after"
    )
    assert change.truncated_after == 1, (
        "the crash index must be recorded, or a truncated run is "
        "indistinguishable from a legitimately short plan"
    )


def test_slow_delays_the_action_without_changing_the_sequence(bf):
    plan = _plan(bf)
    change = bf.apply(plan, "slow", inject_at="sub_a")

    assert [a.principal for a in change.plan] == [
        a.principal for a in plan
    ], "slow must not reorder or drop anything"
    assert change.delays, "slow recorded no delay"
    idx = next(i for i, a in enumerate(plan) if a.principal == "sub_a")
    assert change.delays.get(idx, 0) > 0, (
        "the delay must attach to the targeted principal's action"
    )


def test_corrupt_data_mutates_the_payload_not_the_sequence(bf):
    plan = _plan(bf)
    change = bf.apply(plan, "corrupt_data", inject_at="sub_a")

    assert [a.principal for a in change.plan] == [
        a.principal for a in plan
    ], "corruption must not reorder"
    idx = next(i for i, a in enumerate(plan) if a.principal == "sub_a")
    assert idx in change.corrupt, "no payload override recorded"
    assert change.corrupt[idx], "the payload override is empty"


def test_unknown_class_is_refused_not_silently_ignored(bf):
    """A typo must fail loudly. Silently running the unmodified plan
    would report a clean result for a fault that never ran."""
    with pytest.raises(KeyError):
        bf.apply(_plan(bf), "no_such_fault", inject_at="sub_a")


def test_a_fault_targeting_an_absent_principal_has_no_effect(bf):
    """If the injection point is not in the plan the transformation
    cannot take effect, and that must be visible rather than looking
    like a successful run."""
    change = bf.apply(_plan(bf), "omission", inject_at="not_a_principal")
    assert change.plan == _plan(bf)
    assert change.took_effect is False


def test_took_effect_is_true_when_the_plan_actually_changed(bf):
    for name in ("omission", "duplication", "crash", "slow",
                 "corrupt_data"):
        change = bf.apply(_plan(bf), name, inject_at="sub_a")
        assert change.took_effect is True, f"{name} reported no effect"


# -- The separate vocabulary --------------------------------------


def test_deviation_record_is_separate_from_the_harm_vocabulary(bf):
    """The point of the second axis.

    A behaviour fault attempts no extra action, so the harm fields
    describe a clean run. Folding the deviation into them would make an
    omitted action read as "0 harmful executed" -- the same way today's
    LLM runs mislead when a model refuses the injected instruction.
    """
    dev = bf.deviation_for(
        "omission", planned=3, observed=2, took_effect=True,
        detected_by=None,
    )
    for field in ("fault", "kind", "planned_actions", "observed_actions",
                  "took_effect", "detectable_by", "detected_by",
                  "refused_by", "truncated_after"):
        assert hasattr(dev, field), f"Deviation lacks {field}"
    assert dev.fault == "omission"
    assert dev.kind == "absence"
    assert dev.planned_actions == 3
    assert dev.observed_actions == 2
    assert dev.took_effect is True
    assert dev.detected_by is None
    for forbidden in ("harmful_executed", "harmful_attempted",
                      "prevented_by"):
        assert not hasattr(dev, forbidden), (
            "Deviation reuses {} from the harm vocabulary; the two axes "
            "must stay distinguishable in results.jsonl".format(forbidden)
        )


def test_deviation_serialises_to_a_namespaced_flat_dict(bf):
    dev = bf.deviation_for(
        "slow", planned=3, observed=3, took_effect=True,
        detected_by="latency",
    )
    d = dev.as_dict()
    assert d["deviation_fault"] == "slow"
    assert d["deviation_kind"] == "latency"
    assert d["deviation_detected_by"] == "latency"
    assert all(k.startswith("deviation_") for k in d), (
        "result keys must be namespaced so they cannot collide with the "
        "harm fields in results.jsonl: {}".format(sorted(d))
    )


def test_no_deviation_still_produces_a_record(bf):
    """A baseline run must emit the fields too, or results.jsonl has a
    ragged schema and every consumer has to special-case it."""
    dev = bf.deviation_for(
        None, planned=3, observed=3, took_effect=False, detected_by=None,
    )
    d = dev.as_dict()
    assert d["deviation_fault"] is None
    assert d["deviation_kind"] is None
    assert d["deviation_took_effect"] is False


# -- The declared hypothesis --------------------------------------


def test_three_classes_are_declared_unmatchable_by_any_rule(bf):
    """The finding, pinned -- and scoped.

    The chain engine fires when steps MATCH a payload. It has
    ``after`` ordering, ``within_seconds`` and a ``not:`` matcher, but
    no "a step did not arrive" primitive, so omission, crash and slow
    produce no event for any rule to fire on.

    SCOPE MATTERS. A review caught an earlier version of this claim
    overstating itself as "nothing in the lab can detect them". That
    is false for omission and crash: both shrink the executed count,
    so the planned-vs-observed arithmetic the lab already emits
    reveals them. Only ``slow`` is genuinely invisible, because
    nothing asserts a wall-clock budget.

    Declaring it here stops a later reader filing those rows as
    regressions -- and stops us publishing a gap wider than the real
    one.
    """
    undetectable = {
        n for n, s in bf.BEHAVIOUR_FAULTS.items()
        if s.detectable_by is None
    }
    assert undetectable >= {"omission", "crash", "slow"}, (
        "expected omission/crash/slow to be declared unmatchable by "
        "the content-matching layer, got {}".format(undetectable)
    )
    # The SCOPE of the claim has to live in the rationale, or the next
    # reader re-inflates it to "nothing can detect these". omission
    # and crash must record that the arithmetic reveals them.
    for name in ("omission", "crash"):
        doc = bf.BEHAVIOUR_FAULTS[name].doc
        assert "planned-vs-observed" in doc, (
            "{} is declared unmatchable but its rationale omits that "
            "the lab's own arithmetic reveals it -- that omission is "
            "exactly what overstated the gap".format(name)
        )
    for name in ("duplication", "corrupt_data"):
        assert bf.BEHAVIOUR_FAULTS[name].detectable_by, (
            "{} IS expressible as a chain rule and must declare the "
            "layer that catches it".format(name)
        )


def test_refused_by_is_distinct_from_the_harm_vocabulary(bf):
    """``refused_by`` records which layer refused the DEVIANT action.

    It must not be called ``prevented_by``: that name belongs to the
    harm axis, and a reader has to be able to tell "an extra harmful
    action was prevented" from "the agent's own action was refused
    because its data could not be real".
    """
    dev = bf.deviation_for(
        "corrupt_data", planned=4, observed=3, took_effect=True,
        detected_by=None, refused_by="argument_policy",
    )
    assert dev.refused_by == "argument_policy"
    assert dev.detected_by is None, (
        "a single-event refusal is not an after-the-fact detection; "
        "conflating them loses which layer acted"
    )
    assert dev.as_dict()["deviation_refused_by"] == "argument_policy"
    assert not hasattr(dev, "prevented_by")


def test_impossible_payload_is_refusable_but_wrong_one_is_not(bf):
    """The shared predicate, and its honest limit.

    A read cannot return a negative number of bytes, so a single-event
    rule can refuse it. A byte count that is merely WRONG is
    indistinguishable from a correct one at the moment of the event --
    which is the same limit the lab already demonstrates for
    dangerous_argument, and the reason corrupt_data is only partially
    covered.
    """
    f = bf.payload_is_structurally_impossible

    assert f(bf.CORRUPT_PAYLOAD) is True, (
        "the corrupt payload the fault injects is not refusable by the "
        "rule that is supposed to catch it — the two have drifted"
    )
    assert f({"bytes": -1}) is True
    assert f({"bytes": 0}) is False
    assert f({"bytes": 4096}) is False
    # Plausible but wrong: NOT refusable, and that is the point.
    assert f({"bytes": 999999}) is False
    # No size field at all, e.g. a spawn or a post.
    assert f({"tool": "agent_spawn"}) is False
    # bool is a subclass of int; True must not read as 1.
    assert f({"bytes": True}) is False
    assert f({"bytes": "-1"}) is False, (
        "a string must not be compared as a number"
    )


def test_corrupt_data_declares_the_layer_that_actually_refuses_it(bf):
    """Prediction and mechanism must agree.

    ``detectable_by`` is the declared hypothesis; the argument policy
    is what implements it. If someone changes one without the other,
    the results file reports a prediction nothing can fulfil.
    """
    spec = bf.BEHAVIOUR_FAULTS["corrupt_data"]
    assert spec.detectable_by == "argument_policy"
    assert bf.payload_is_structurally_impossible(bf.CORRUPT_PAYLOAD)


def test_crash_on_the_last_action_claims_no_effect(bf):
    """The one place the took_effect guarantee leaked.

    Crashing on the LAST action drops nothing -- the plan is
    unchanged. Recording truncated_after anyway made apply() derive
    took_effect=True for a run where nothing happened, so a fault
    claimed an effect it did not have.
    """
    plan = _plan(bf)
    last = plan[-1].principal

    change = bf.apply(plan, "crash", inject_at=last)

    assert change.plan == plan, "nothing should have been dropped"
    assert change.truncated_after is None, (
        "truncated_after was set for a crash that dropped nothing, "
        "which makes apply() report took_effect=True"
    )
    assert change.took_effect is False, (
        "a crash on the final action claimed an effect it did not have"
    )
    # And the mid-plan case must still work.
    mid = bf.apply(plan, "crash", inject_at=plan[1].principal)
    assert mid.took_effect is True
    assert mid.truncated_after == 1


def test_truncated_after_reaches_the_record(bf):
    """It existed so a truncated run is distinguishable from a short
    plan -- but it was computed, unit-tested, then dropped before the
    results file, leaving that purpose unfulfilled."""
    dev = bf.deviation_for(
        "crash", planned=4, observed=2, took_effect=True,
        detected_by=None, truncated_after=1,
    )
    assert dev.truncated_after == 1
    assert dev.as_dict()["deviation_truncated_after"] == 1
    # A non-crash run carries the key with None, so the schema stays
    # rectangular.
    other = bf.deviation_for(
        "omission", planned=4, observed=3, took_effect=True,
        detected_by=None,
    )
    assert other.as_dict()["deviation_truncated_after"] is None


def test_plan_change_defaults_cannot_be_mutated(bf):
    """A NamedTuple cannot take a default_factory, so a bare ``{}``
    default is a class-level singleton shared by every instance that
    omits it. An in-place write would contaminate every later
    PlanChange process-wide, silently."""
    import pytest as _pytest

    a = bf.PlanChange(plan=[])
    b = bf.PlanChange(plan=[])
    assert a.delays is b.delays, "expected a shared default sentinel"
    with _pytest.raises(TypeError):
        a.delays[0] = 1.0
    with _pytest.raises(TypeError):
        a.corrupt[0] = {"x": 1}
    assert b.delays == {}, "the shared default was contaminated"


# -- Edge cases the happy-path tests do not reach -----------------


def test_a_principal_appearing_twice_loses_only_its_first_action(bf):
    """Scope of the transformations, pinned.

    All the tests above use three DISTINCT principals, so this case
    was unexercised -- and it is not hypothetical: the lab's `chain`
    topology gives sub_a both `recon` and `exfil`.

    The classes therefore have different reach on the same principal,
    which is intended but must not be left to a reader's assumption:
    omission drops one action and the agent keeps working, while
    crash removes everything after the crash point.
    """
    A = bf.PlannedAct
    plan = [
        A(principal="parent", role="spawn", origin=None),
        A(principal="sub_a", role="recon", origin=None),
        A(principal="sub_a", role="exfil", origin=None),
    ]

    omitted = bf.apply(plan, "omission", inject_at="sub_a")
    assert [(a.principal, a.role) for a in omitted.plan] == [
        ("parent", "spawn"), ("sub_a", "exfil"),
    ], "omission must drop only the FIRST of the principal's actions"
    assert any(a.principal == "sub_a" for a in omitted.plan), (
        "the agent was silenced entirely; omission drops one action, "
        "it does not remove the principal"
    )

    crashed = bf.apply(plan, "crash", inject_at="sub_a")
    assert [(a.principal, a.role) for a in crashed.plan] == [
        ("parent", "spawn"), ("sub_a", "recon"),
    ], "crash must keep up to the crash point and drop the rest"

    dup = bf.apply(plan, "duplication", inject_at="sub_a")
    assert [a.role for a in dup.plan] == [
        "spawn", "recon", "recon", "exfil",
    ], "duplication must repeat the first action, adjacently"


@pytest.mark.parametrize("name", ["omission", "slow", "duplication",
                                  "crash", "corrupt_data"])
def test_an_empty_plan_is_a_no_effect_for_every_class(bf, name):
    """Unexercised before. Correct-by-accident is not the same as
    asserted: every class must report no effect rather than raising or
    inventing an action."""
    change = bf.apply([], name, inject_at="anyone")
    assert change.plan == []
    assert change.took_effect is False


@pytest.mark.parametrize("name,expect_effect", [
    ("omission", True),
    ("slow", True),
    ("duplication", True),
    ("crash", False),        # nothing after it to drop
    ("corrupt_data", True),
])
def test_a_single_action_plan(bf, name, expect_effect):
    """One action is the boundary for crash specifically: there is
    nothing after it, so truncating drops nothing."""
    A = bf.PlannedAct
    plan = [A(principal="solo", role="recon", origin=None)]
    change = bf.apply(plan, name, inject_at="solo")
    assert change.took_effect is expect_effect, (
        f"{name} on a one-action plan reported "
        f"took_effect={change.took_effect}, expected {expect_effect}"
    )
