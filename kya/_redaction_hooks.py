"""OSS-level RedactionHook registry — single source of truth.

Motivation
----------
Before this module, the RedactionHook lived only in
``kya_gateway.policy_pipeline``. The gateway's evidence writer
(``_record_verdict_evidence``) called it explicitly. Every OTHER caller
of :func:`kya.evidence.record_evidence` — including all Pro plugins —
had to remember to plumb the hook themselves. That's bug-prone-by-
convention: any new caller silently ships unredacted payloads.

Fix — move the hook registry OUT of the gateway package and into the
OSS ``kya`` namespace so :func:`kya.evidence.record_evidence` can call
it directly, giving every caller redaction for free.

Layering
--------
``kya`` MUST NOT import from ``kya_gateway`` (the gateway sits on top
of the OSS core). The prior location of the registry in
``kya_gateway.policy_pipeline`` therefore blocked ``kya.evidence`` from
using it. Moving the registry to ``kya._redaction_hooks`` restores
correct layering: the gateway still exposes its own
``set_redaction_hook`` / ``get_redaction_hook`` as backward-compat
pass-throughs, but both now delegate to this module.

Contract
--------
A ``RedactionHook`` implementation is any object with a
``redact_attrs(attrs: dict) -> dict`` method. Implementations MUST:

  * Be idempotent (redacting twice yields the same result).
  * Be non-mutating on the input — return a NEW dict.
  * Pass non-string values through unchanged.
  * Fail-soft — a raise here is caught by callers and the payload is
    written unredacted with a WARN log. Never take down the write path.

The default hook is :class:`_NoopRedactionHook` — passthrough, zero
cost. Pro plugs in ``PresidioRedactionHook`` at boot via
:func:`set_redaction_hook`.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class RedactionHook(Protocol):
    """Redact secret-bearing string values in an attrs dict.

    Implementations MUST be idempotent and non-mutating on the input —
    return a NEW dict; do not modify the argument. Non-string values
    are passed through unchanged.
    """

    def redact_attrs(self, attrs: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover
        ...


class _NoopRedactionHook:
    """Default OSS hook — passthrough, zero cost.

    Returns a shallow copy so callers can mutate the returned dict
    without affecting the source (matches the contract implementers
    like ``PresidioRedactionHook`` must obey).
    """

    def redact_attrs(self, attrs: dict[str, Any]) -> dict[str, Any]:
        return dict(attrs) if attrs else {}


_REDACTION_HOOK: RedactionHook = _NoopRedactionHook()


def set_redaction_hook(hook: RedactionHook | None) -> None:
    """Install a process-wide RedactionHook.

    Called once at Pro boot (see ``kya_pro.policy._redaction_hook``)
    to plug Presidio into the seam. Passing ``None`` resets to the
    OSS no-op passthrough — used by tests to assert feature-flag OFF
    parity with pre-hook behaviour.
    """
    global _REDACTION_HOOK
    _REDACTION_HOOK = hook if hook is not None else _NoopRedactionHook()


def get_redaction_hook() -> RedactionHook:
    """Return the currently-installed RedactionHook.

    Never returns ``None``. Called by
    :func:`kya.evidence.record_evidence` (and by the gateway's
    evidence writer via the backward-compat pass-through in
    ``kya_gateway.policy_pipeline``).
    """
    return _REDACTION_HOOK


__all__ = [
    "RedactionHook",
    "_NoopRedactionHook",
    "get_redaction_hook",
    "set_redaction_hook",
]
