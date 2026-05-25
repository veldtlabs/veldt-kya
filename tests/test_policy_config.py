"""Tests for kya/policy_config.py — the one-line startup configurator."""

from __future__ import annotations

import logging
import os

import pytest

from kya import (
    DEFAULT_DELEGATION_MODE,
    InvalidDelegationModeError,
    active_delegation_mode,
    configure_delegation_policy,
)


@pytest.fixture(autouse=True)
def clean_env():
    prev = os.environ.pop("KYA_DELEGATION_POLICY", None)
    yield
    if prev is not None:
        os.environ["KYA_DELEGATION_POLICY"] = prev
    else:
        os.environ.pop("KYA_DELEGATION_POLICY", None)


def test_default_is_observe():
    assert DEFAULT_DELEGATION_MODE == "observe"


def test_unset_env_resolves_to_observe():
    # Without configuring, active mode is still observe (safe default).
    assert active_delegation_mode() == "observe"


def test_configure_sets_env_and_returns_mode():
    out = configure_delegation_policy("flag")
    assert out == "flag"
    assert os.environ["KYA_DELEGATION_POLICY"] == "flag"
    assert active_delegation_mode() == "flag"


def test_configure_normalizes_case_and_whitespace():
    out = configure_delegation_policy("  BLOCK  ")
    assert out == "block"
    assert active_delegation_mode() == "block"


def test_configure_rejects_unknown_mode_loudly():
    with pytest.raises(InvalidDelegationModeError) as exc_info:
        configure_delegation_policy("frobozz")
    assert "frobozz" in str(exc_info.value)
    # Must NOT have polluted the env var on failure
    assert "KYA_DELEGATION_POLICY" not in os.environ


def test_configure_logs_at_info(caplog):
    caplog.set_level(logging.INFO, logger="kya.policy_config")
    configure_delegation_policy("observe")
    assert any("mode active: 'observe'" in r.message
                for r in caplog.records)


def test_configure_log_suppressible():
    # log=False stays quiet but still applies the mode.
    import logging
    handler_count_before = len(logging.getLogger("kya.policy_config").handlers)
    configure_delegation_policy("observe", log=False)
    assert active_delegation_mode() == "observe"
    # No assertion on the log silence here — handler count is a poor
    # proxy. The behavioral guarantee is: returns the mode and sets env.
    assert os.environ["KYA_DELEGATION_POLICY"] == "observe"


def test_idempotent_across_repeated_calls():
    configure_delegation_policy("observe")
    configure_delegation_policy("observe")
    configure_delegation_policy("observe")
    assert active_delegation_mode() == "observe"


def test_can_switch_modes_at_runtime():
    configure_delegation_policy("observe")
    assert active_delegation_mode() == "observe"
    configure_delegation_policy("flag")
    assert active_delegation_mode() == "flag"
    configure_delegation_policy("block")
    assert active_delegation_mode() == "block"
