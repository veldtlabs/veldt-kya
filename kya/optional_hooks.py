"""Optional-hooks registry for pluggable capability discovery.

This module provides a tiny, dependency-free registry that lets
third-party packages and plugins inject optional capabilities into
KYA at import time, without KYA having to know their module layout.

Pattern
-------
* At import time, a plugin package calls :func:`register_hook` with a
  well-known name (see the ``HOOK_*`` constants below) and its
  implementation (a callable, class, exception type, or object).
* At call time, KYA looks the capability up with :func:`get_hook`.
* If no plugin registered a hook under that name, :func:`get_hook`
  returns ``None``. Callers MUST handle the ``None`` case — a missing
  hook is a supported deployment shape (feature simply degrades to
  a documented default), not an error.

Design notes
------------
* Registration is process-global; the registry is a plain dict guarded
  only by Python's GIL. Hooks are expected to be registered exactly
  once, at plugin import time. Later re-registration silently replaces
  the prior entry — plugin ordering decides the winner.
* The registry never imports the plugin; it stores whatever object the
  plugin hands it. This keeps the registry free of any cross-package
  references and lets plugins pick their own module layout.
* Hook names are strings. Add a new well-known name here as a module-
  level constant when introducing a new extension point, and document
  the expected shape (callable signature, class contract) alongside it
  so plugins have a stable target.
"""
from __future__ import annotations

from typing import Any

# ── Well-known hook names ────────────────────────────────────────────
# Each constant below names an extension point KYA looks up at call
# time. Adding a new one is a two-line change (constant here + a
# ``get_hook(...)`` call at the use site). Removing one is a public-
# API break — treat with the same care as any other exported symbol.

HOOK_REVOCATION_CHECKER = "revocation_checker"
"""Optional revocation checker used by the gateway's identity layer.

Expected shape: an object exposing ``check(verified) -> None`` that
raises the exception class registered under
:data:`HOOK_REVOCATION_ERROR` when a credential is revoked or its
status list is unavailable in ``fail_mode="closed"``.

Plugins that need construction-time configuration (HTTP fetch fn,
trusted issuers, cache TTL, fail mode) should register a **factory
callable** here — see the identity layer's usage site for the exact
call signature it invokes.
"""

HOOK_REVOCATION_CHECKER_FACTORY = "revocation_checker_factory"
"""Factory callable that constructs a revocation checker on demand.

Expected shape: ``factory(*, http_fetch, trusted_issuers,
cache_ttl_seconds, fail_mode) -> checker`` where ``checker`` matches
the contract described on :data:`HOOK_REVOCATION_CHECKER`.

Registered separately from :data:`HOOK_REVOCATION_CHECKER` so plugins
can either pre-construct a checker (simple deploys) or defer
construction to first-use with runtime-derived config (the common
gateway path).
"""

HOOK_REVOCATION_ERROR = "revocation_error"
"""Exception CLASS raised by the registered revocation checker on
revocation failures.

Registered as a class, not an instance. Callers use
``isinstance(exc, get_hook(HOOK_REVOCATION_ERROR))`` to distinguish
revocation-blocked failures from generic errors, so the gateway can
emit a specific ``revocation_blocked`` security event.
"""

HOOK_HITL_ENCRYPT = "hitl_encrypt"
"""Optional at-rest encryption for human-in-the-loop pending bodies.

Expected shape: ``encrypt(body: bytes, *, tenant_id: str) -> bytes``.
When no hook is registered, pending bodies are stored as plaintext —
the documented default for deployments without a KMS integration.
"""


# ── Registry ─────────────────────────────────────────────────────────

_HOOKS: dict[str, Any] = {}


def register_hook(name: str, impl: Any) -> None:
    """Register ``impl`` as the implementation for the hook ``name``.

    Called by a plugin package at import time. Re-registering an
    existing name silently replaces the prior entry.
    """
    _HOOKS[name] = impl


def get_hook(name: str) -> Any | None:
    """Return the implementation registered for ``name``, or ``None``.

    Callers MUST handle ``None`` — an unregistered hook is a
    supported deployment shape, not an error.
    """
    return _HOOKS.get(name)


def list_hooks() -> list[str]:
    """Return the sorted list of registered hook names. Debug only."""
    return sorted(_HOOKS.keys())


def _clear_hooks_for_tests() -> None:
    """Test-only helper — wipe the registry.

    Not part of the public API. Tests that register hooks temporarily
    must restore prior state themselves; this exists so test fixtures
    can start from a known-empty registry.
    """
    _HOOKS.clear()


__all__ = [
    "HOOK_HITL_ENCRYPT",
    "HOOK_REVOCATION_CHECKER",
    "HOOK_REVOCATION_CHECKER_FACTORY",
    "HOOK_REVOCATION_ERROR",
    "get_hook",
    "list_hooks",
    "register_hook",
]
