"""Regression tests for SIGNAL_DELTAS budget-family coverage."""
from __future__ import annotations

from kya.users import SIGNAL_DELTAS

# Pre-fix baseline was 19 entries; adding budget_exceeded + budget_error.
_EXPECTED_SIZE = 21


def test_budget_exceeded_registered_with_negative_delta():
    """Exceeded-budget events must reduce trust."""
    assert "budget_exceeded" in SIGNAL_DELTAS
    assert SIGNAL_DELTAS["budget_exceeded"] < 0


def test_budget_error_registered():
    """Internal budget-check errors are not the agent's fault → non-negative."""
    assert "budget_error" in SIGNAL_DELTAS
    assert SIGNAL_DELTAS["budget_error"] >= 0


def test_signal_deltas_size_guard():
    """Regression guard against accidental removal of budget-family entries."""
    assert len(SIGNAL_DELTAS) == _EXPECTED_SIZE
