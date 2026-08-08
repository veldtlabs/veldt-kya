"""Policy evaluator abstraction — the upstream layer that produces
verdicts, distinct from ``policy_verdicts`` which handles them.

Motivation
----------
Before this module, the OSS "what verdict fires for this call?"
decision was implicit — scattered across the gateway server, the
budget subsystem, and the RBAC check. Composing a new deployment
(e.g. a Pro build that wants to layer LLM-judge signals on top of
the OSS rules) meant editing the pipeline or duplicating logic.

This module inverts that: a ``PolicyEvaluator`` produces a
``VerdictResult``; ``policy_verdicts.apply()`` consumes it. Two clean
seams:

    EvaluationInput → PolicyEvaluator.evaluate() → VerdictResult
                                                      │
                                                      ▼
                                            VerdictContext(verdict=…)
                                                      │
                                                      ▼
                                          VerdictHandler.apply() → HandlerResult

The registry is copy-on-write (mirrors ``policy_verdicts._REGISTRY_LOCK``)
so hot-path readers stay lock-free while writers cycle a fresh dict
under a lock. Registration is idempotent by name — re-registering the
same name silently replaces the prior binding, matching the ergonomics
of the verdict-handler registry.

Design invariants
-----------------
* ``EvaluationInput`` and ``VerdictResult`` are frozen dataclasses.
  Evaluators MUST NOT mutate their input — the contract test enforces
  this via before/after ``dataclasses.replace`` equality.
* Evaluators MUST populate ``policy_hash`` by delegating to
  ``kya.policy_hash`` — never re-implementing canonicalisation inline.
  The composition rule keeps hashes cross-runtime stable.
* Evaluators MUST NOT raise from ``evaluate()``. Silent-failure traps
  are handled by the evaluator itself, which should log and either
  degrade the rule (skip it) or fail closed by returning
  ``verdict="deny"`` with an ``evaluator_error`` reason.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


# ── Types ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class EvaluationInput:
    """Everything a policy evaluator needs to reach a verdict.

    Frozen so an evaluator cannot mutate what a downstream evaluator
    or the caller sees. Optional per-call context (data classification,
    estimated cost, chain-of-custody, ...) rides in ``attributes`` +
    ``chain`` — free-form bags so new signals don't require expanding
    this class.
    """
    tenant_id: str
    principal_kind: str        # "agent" | "human" | "service"
    principal_id: str
    action: str                # "invoke_tool" | "call_llm" | ...
    resource: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    chain: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VerdictResult:
    """A policy evaluator's decision.

    ``verdict`` is one of the paper §Figure-4 canonical values; the
    downstream ``VerdictHandler.apply()`` maps them onto wire-level
    responses. ``evidence_payload`` carries structured breadcrumbs the
    caller can persist (e.g. the ``current_spend`` / ``threshold`` the
    budget rule saw). ``policy_hash`` is the cryptographic handle on
    the effective policy at decision time — populated via
    ``kya.policy_hash`` so all layers agree bit-for-bit.

    ``reasons`` is coerced to ``tuple`` in ``__post_init__`` so a
    caller that accidentally passes ``["reason"]`` doesn't silently
    land a mutable list in downstream evidence consumers. The frozen-
    dataclass immutability guarantee only holds if the fields are
    themselves immutable — that coercion enforces it.
    """
    verdict: str
    reasons: tuple[str, ...] = ()
    evidence_payload: dict[str, Any] = field(default_factory=dict)
    policy_hash: str = ""
    evaluator_name: str = ""
    signal_kind: str | None = None

    def __post_init__(self) -> None:  # noqa: D401
        # object.__setattr__ is the sanctioned way to mutate a frozen
        # dataclass from inside __post_init__.
        if not isinstance(self.reasons, tuple):
            object.__setattr__(self, "reasons", tuple(self.reasons))


@runtime_checkable
class PolicyEvaluator(Protocol):
    """Duck-typed evaluator interface.

    Anything with a string ``name`` attribute + a callable ``evaluate``
    passes ``isinstance(x, PolicyEvaluator)`` at runtime. That lets
    tests use inline stubs interchangeably with production evaluators
    without forcing a base class.
    """
    name: str
    def evaluate(self, inp: EvaluationInput) -> VerdictResult: ...


# ── Registry ─────────────────────────────────────────────────────────


# Copy-on-write mirror of ``policy_verdicts._REGISTRY_LOCK``. Writers
# acquire the lock, build a NEW dict, then atomically reassign the
# module-global ``_REGISTRY`` reference. Readers (``get_evaluator``)
# capture the current reference once and do their lookup against that
# snapshot. CPython reference assignment is GIL-atomic, so a reader
# never observes a torn dict — it sees the pre-swap snapshot end-to-
# end or the post-swap snapshot end-to-end. Same trade-off analysis
# as the verdict-handler registry: O(n) copy per write, lock-free
# reads on the hot path.
_REGISTRY: dict[str, PolicyEvaluator] = {}
_REGISTRY_LOCK = threading.Lock()


def _validate_evaluator(candidate: Any) -> None:
    """Reject broken evaluators at ``register_evaluator()`` time.

    Attribute-existence checks alone would let a subclass with a
    non-callable ``evaluate`` slip in and blow up the first user who
    triggered it. This validates the real invariants: ``name`` is a
    non-empty string and ``evaluate`` is callable.
    """
    name = getattr(candidate, "name", None)
    if not isinstance(name, str) or not name:
        raise TypeError(
            f"evaluator.name must be a non-empty str, got {name!r}"
        )
    if not callable(getattr(candidate, "evaluate", None)):
        raise TypeError(
            f"evaluator.evaluate must be callable, got "
            f"{type(getattr(candidate, 'evaluate', None)).__name__}"
        )


def register_evaluator(name: str, evaluator: PolicyEvaluator) -> None:
    """Register (or re-register) an evaluator under ``name``.

    Idempotent — re-registering the same name silently overrides the
    prior binding, matching the ergonomics of ``policy_verdicts.register``.
    Copy-on-write: a concurrent ``get_evaluator`` sees either the
    pre-register snapshot or the post-register snapshot, never a torn
    dict.
    """
    global _REGISTRY
    _validate_evaluator(evaluator)
    if not isinstance(name, str) or not name:
        raise TypeError(f"name must be a non-empty str, got {name!r}")
    with _REGISTRY_LOCK:
        new_registry = dict(_REGISTRY)
        new_registry[name] = evaluator
        _REGISTRY = new_registry


def get_evaluator(name: str) -> PolicyEvaluator:
    """Return the evaluator registered under ``name``.

    Raises ``KeyError`` if not registered — callers that want a
    "maybe missing" lookup should check ``name in _REGISTRY`` first.
    Lock-free via the copy-on-write pattern.
    """
    snapshot = _REGISTRY
    if name not in snapshot:
        raise KeyError(f"no evaluator registered under name={name!r}")
    return snapshot[name]


def unregister_evaluator(name: str) -> None:
    """Remove ``name`` from the registry. No-op if absent.

    Primarily for tests + hot-reload scenarios. Matches
    ``dict.pop(..., None)`` semantics so callers don't have to guard
    the call.
    """
    global _REGISTRY
    with _REGISTRY_LOCK:
        if name not in _REGISTRY:
            return
        new_registry = dict(_REGISTRY)
        del new_registry[name]
        _REGISTRY = new_registry


# ── Bootstrap ────────────────────────────────────────────────────────
# Registration of the OSS default (``"native"``) is done by the top-
# level ``kya/__init__.py`` AFTER both this module and
# ``_native_evaluator`` finish loading — auto-registering here would
# create a circular import (this module → ``_native_evaluator`` →
# this module for the ``EvaluationInput`` / ``VerdictResult`` types).
#
# The bootstrap helper is exposed so tests + hot-reload scenarios can
# restore the default without importing the concrete class themselves.


def _register_native_default() -> None:
    """Register ``NativeEvaluator`` under the reserved name ``"native"``.

    Called by ``kya/__init__.py`` at package-load time and re-called
    by test fixtures that clear the registry between tests.
    """
    # Local import — resolved lazily so this function is safe to call
    # from any load order.
    from ._native_evaluator import NativeEvaluator

    register_evaluator("native", NativeEvaluator())


__all__ = [
    "EvaluationInput",
    "VerdictResult",
    "PolicyEvaluator",
    "register_evaluator",
    "get_evaluator",
    "unregister_evaluator",
]
