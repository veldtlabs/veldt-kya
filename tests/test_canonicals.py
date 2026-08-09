"""Canonical vocabulary + alias-preservation tests."""
from __future__ import annotations

import pytest

from kya.canonicals import (
    CANONICAL_COMPOSITION_MODES,
    CANONICAL_EVIDENCE_KINDS,
    CANONICAL_LIFECYCLE_STATES,
    CANONICAL_OUTCOMES,
    CANONICAL_PRINCIPAL_KINDS,
    CANONICAL_SIGNAL_KINDS,
    CANONICAL_VERDICTS,
    COMPOSITION_MODE_ABAC_AUGMENTS_NATIVE,
    COMPOSITION_MODE_ABAC_ONLY,
    COMPOSITION_MODE_ABAC_THEN_NATIVE,
    COMPOSITION_MODE_NATIVE_THEN_ABAC,
    EVIDENCE_KIND_ABAC_DECISION,
    EVIDENCE_KIND_ABAC_NATIVE_OVERRIDE,
    EVIDENCE_KIND_ABAC_SHADOW_EVAL,
    EVIDENCE_KIND_ACTION_GATE_BLOCK,
    EVIDENCE_KIND_EXTERNAL_ALERT,
    EVIDENCE_KIND_PROMPT,
    LIFECYCLE_STATE_ACTIVE,
    LIFECYCLE_STATE_ARCHIVED,
    LIFECYCLE_STATE_DEPRECATED,
    LIFECYCLE_STATE_DRAFT,
    LIFECYCLE_STATE_STAGED,
    OUTCOME_IN_PROGRESS,
    OUTCOME_PENDING,
    OUTCOME_SUCCESS,
    PRINCIPAL_KIND_AGENT,
    PRINCIPAL_KIND_USER,
    SIGNAL_KIND_BUDGET_ERROR,
    SIGNAL_KIND_BUDGET_EXCEEDED,
    VERDICT_ALLOW,
    VERDICT_ANONYMIZE,
    VERDICT_BLOCK,
    VERDICT_DENY,
    VERDICT_FLAG_FOR_REVIEW,
    VERDICT_REDACT,
    VERDICT_THROTTLE,
)


# ── Canonical set membership ────────────────────────────────────────


def test_canonical_verdicts_contains_seven_core():
    assert CANONICAL_VERDICTS == frozenset({
        VERDICT_ALLOW,
        VERDICT_DENY,
        VERDICT_FLAG_FOR_REVIEW,
        VERDICT_BLOCK,
        VERDICT_REDACT,
        VERDICT_THROTTLE,
        VERDICT_ANONYMIZE,
    })


def test_canonical_outcomes_contains_ten_values():
    assert len(CANONICAL_OUTCOMES) == 10
    assert OUTCOME_SUCCESS in CANONICAL_OUTCOMES
    assert OUTCOME_PENDING in CANONICAL_OUTCOMES
    assert OUTCOME_IN_PROGRESS in CANONICAL_OUTCOMES


def test_canonical_evidence_kinds_includes_recent_additions():
    assert EVIDENCE_KIND_PROMPT in CANONICAL_EVIDENCE_KINDS
    assert EVIDENCE_KIND_ACTION_GATE_BLOCK in CANONICAL_EVIDENCE_KINDS
    assert EVIDENCE_KIND_EXTERNAL_ALERT in CANONICAL_EVIDENCE_KINDS
    assert EVIDENCE_KIND_ABAC_DECISION in CANONICAL_EVIDENCE_KINDS
    assert EVIDENCE_KIND_ABAC_SHADOW_EVAL in CANONICAL_EVIDENCE_KINDS
    assert EVIDENCE_KIND_ABAC_NATIVE_OVERRIDE in CANONICAL_EVIDENCE_KINDS


def test_canonical_principal_kinds_is_ordered_tuple():
    assert isinstance(CANONICAL_PRINCIPAL_KINDS, tuple)
    assert PRINCIPAL_KIND_USER in CANONICAL_PRINCIPAL_KINDS
    assert PRINCIPAL_KIND_AGENT in CANONICAL_PRINCIPAL_KINDS


def test_canonical_signal_kinds_includes_budget_family():
    assert SIGNAL_KIND_BUDGET_EXCEEDED in CANONICAL_SIGNAL_KINDS
    assert SIGNAL_KIND_BUDGET_ERROR in CANONICAL_SIGNAL_KINDS


def test_canonical_lifecycle_states_five_values():
    assert CANONICAL_LIFECYCLE_STATES == frozenset({
        LIFECYCLE_STATE_DRAFT,
        LIFECYCLE_STATE_STAGED,
        LIFECYCLE_STATE_ACTIVE,
        LIFECYCLE_STATE_DEPRECATED,
        LIFECYCLE_STATE_ARCHIVED,
    })


def test_canonical_composition_modes_four_values():
    assert CANONICAL_COMPOSITION_MODES == frozenset({
        COMPOSITION_MODE_ABAC_ONLY,
        COMPOSITION_MODE_ABAC_THEN_NATIVE,
        COMPOSITION_MODE_NATIVE_THEN_ABAC,
        COMPOSITION_MODE_ABAC_AUGMENTS_NATIVE,
    })


# ── ABAC-invariant sabotage ─────────────────────────────────────────


def test_composition_modes_reject_veto_native():
    """``abac_veto_native`` inverts fail-closed — must never enter the set."""
    assert "abac_veto_native" not in CANONICAL_COMPOSITION_MODES


# ── Alias-preservation for OSS whitelists ───────────────────────────


def test_valid_evidence_kinds_still_accepts_known():
    from kya.evidence import VALID_EVIDENCE_KINDS

    assert "prompt" in VALID_EVIDENCE_KINDS
    assert "action_gate_block" in VALID_EVIDENCE_KINDS
    assert "external_alert" in VALID_EVIDENCE_KINDS


def test_valid_evidence_kinds_is_mutable():
    """Pro ``.add()``s domain-specific kinds at import time."""
    from kya.evidence import VALID_EVIDENCE_KINDS

    assert isinstance(VALID_EVIDENCE_KINDS, set)


def test_valid_outcomes_alias_matches_canonical():
    from kya.invocations import VALID_OUTCOMES

    assert VALID_OUTCOMES == CANONICAL_OUTCOMES


def test_principal_kinds_alias_matches_canonical():
    from kya.principals import PRINCIPAL_KINDS

    assert PRINCIPAL_KINDS == CANONICAL_PRINCIPAL_KINDS


def test_allowed_signal_kinds_alias_matches_canonical():
    from kya.realtime import ALLOWED_SIGNAL_KINDS

    assert ALLOWED_SIGNAL_KINDS == CANONICAL_SIGNAL_KINDS


def test_gateway_valid_verdicts_alias_matches_canonical():
    from kya_gateway.policy_pipeline import _VALID_VERDICTS

    assert _VALID_VERDICTS == CANONICAL_VERDICTS
