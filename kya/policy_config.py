"""
Delegation-policy configuration helper.

`observe` is already the implicit default (see delegation_policy.
_current_mode), but a one-line setter at startup buys three things:

  1. Explicit intent — code reads as "we chose observe", not "we forgot
     to set anything".
  2. Operator visibility — one INFO log line at boot confirms the
     mode KYA is enforcing.
  3. Loud config errors — an unknown mode raises at config time
     (InvalidDelegationModeError) rather than silently degrading to
     observe at runtime.

Recommended rollout: observe → flag → block (see delegation_policy
module docstring for the full rationale).

Usage
-----
At app startup::

    from kya import configure_delegation_policy
    configure_delegation_policy("observe")   # safe default

Optional dynamic lookup::

    from kya import active_delegation_mode
    if active_delegation_mode() == "block":
        ...

The helper is a tiny env-var wrapper — modular by being framework-
agnostic, DRY by single-sourcing the mode whitelist from
delegation_policy.DELEGATION_POLICY_MODES, and idempotent so multiple
calls from different init paths don't conflict.
"""

from __future__ import annotations

import logging
import os

from .delegation_policy import DELEGATION_POLICY_MODES

logger = logging.getLogger(__name__)


_ENV_KEY = "KYA_DELEGATION_POLICY"
DEFAULT_MODE = "observe"


class InvalidDelegationModeError(ValueError):
    """Raised when configure_delegation_policy() is given a mode that
    isn't in DELEGATION_POLICY_MODES. Loud-by-design — config errors
    belong at startup, not buried in DEBUG logs at runtime."""


def configure_delegation_policy(
    mode: str = DEFAULT_MODE,
    *,
    log: bool = True,
) -> str:
    """Set the active delegation-policy mode for this process.

    Validates ``mode`` against the closed set of supported modes,
    persists it to the KYA_DELEGATION_POLICY env var so every
    ``record_invocation`` call picks it up, and emits a single INFO
    log line for operator visibility (suppress with ``log=False``).

    Returns the mode string that was applied.

    Raises:
        InvalidDelegationModeError: when ``mode`` isn't a known mode.
    """
    normalized = (mode or "").lower().strip()
    if normalized not in DELEGATION_POLICY_MODES:
        raise InvalidDelegationModeError(
            f"Unknown delegation-policy mode: {mode!r}. "
            f"Must be one of: {sorted(DELEGATION_POLICY_MODES)}"
        )
    os.environ[_ENV_KEY] = normalized
    if log:
        logger.info(
            "[KYA-DELEG] delegation policy mode active: '%s'", normalized)
    return normalized


def active_delegation_mode() -> str:
    """Return the currently-active mode (defaults to 'observe' when
    the env var is unset or invalid). Cheap — single env lookup."""
    from .delegation_policy import _current_mode
    return _current_mode()
