"""Prove the missing-primitive guards can fail.

    python tests/sabotage_gateway_primitive_guards.py

A guard that has never been seen to fail is decoration. The pipeline
skips an enforcement stage whose primitive will not import, and the
only thing standing between that and an operator's attention is the log
level it is reported at. This script removes that one mechanism and
requires the condition to become invisible -- which is what the guard
tests assert against.

It also runs a control that removes nothing and requires the signal to
be present. A script that reports everything broken detects nothing.
"""
from __future__ import annotations

import logging
import os
import sys
import types

# This file lives in tests/, so a bare `python tests/<this>.py` puts
# tests/ on sys.path and `kya` resolves to whatever is installed in
# site-packages -- not the tree being changed. Pin the repo root first
# so the script measures this working copy, which is the only thing it
# is claiming anything about.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.path[0] != _ROOT:
    sys.path.insert(0, _ROOT)

from kya_gateway.config import BudgetConfig, PolicyConfig
from kya_gateway.identity import BoundPrincipal
from kya_gateway import policy_pipeline as PP

RESULTS: list[tuple[str, bool, str]] = []


def note(name: str, caught: bool, detail: str = "") -> None:
    RESULTS.append((name, caught, detail))
    print(f"  {'CAUGHT ' if caught else 'MISSED '} {name:46} {detail}")


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _principal() -> BoundPrincipal:
    return BoundPrincipal(
        principal_kind="agent",
        principal_id="planner",
        method="bearer_jwt",
        external_subject="planner",
        external_issuer=None,
    )


def _absent_module(name: str) -> types.ModuleType:
    """A module with no attributes, so ``from name import x`` raises."""
    return types.ModuleType(name)


def run_once() -> list[logging.LogRecord]:
    """Drive the tenant-budget stage with its primitive unimportable.

    Any of the pipeline's guarded stages would do. Budget is used
    because it is still present: the replay stage this script originally
    targeted was removed, since it could not fire on the real request
    path, and a sabotage needs a live mechanism to break.
    """
    cap = _Capture()
    logger = logging.getLogger("kya_gateway.policy_pipeline")
    logger.addHandler(cap)
    prior_level, logger.level = logger.level, logging.DEBUG
    prior_mod = sys.modules.get("kya.tenant_budget")
    sys.modules["kya.tenant_budget"] = _absent_module("kya.tenant_budget")
    try:
        PP.evaluate(
            db=None,
            tenant_id="tenant-alpha",
            principal=_principal(),
            action="mcp.x.read",
            payload_bytes=100,
            invocation_id=None,
            # a configured budget is what makes the stage run at all
            cfg=PolicyConfig(min_trust=0,
                             tenant_budget=BudgetConfig(daily_usd=10.0)),
        )
    finally:
        if prior_mod is None:
            sys.modules.pop("kya.tenant_budget", None)
        else:
            sys.modules["kya.tenant_budget"] = prior_mod
        logger.removeHandler(cap)
        logger.level = prior_level
    return cap.records


def visible(records: list[logging.LogRecord]) -> bool:
    """Would an operator reading ERROR learn the stage was skipped?"""
    return any(
        r.levelno >= logging.ERROR and "SKIPPED" in r.getMessage()
        for r in records
    )


def main() -> int:
    print()
    print("  sabotaging the missing-primitive guards")
    print(f"  kya_gateway under test: {os.path.dirname(PP.__file__)}")
    print()

    # ── control first: with nothing removed the signal must be there.
    #    Running it first means a broken harness is caught before any
    #    sabotage result is believed.
    records = run_once()
    note("control: nothing removed (must be VISIBLE)",
         visible(records),
         f"{sum(r.levelno >= logging.ERROR for r in records)} error record(s)")
    control_ok = visible(records)

    # ── sabotage 1: the fix reverted -- ERROR downgraded to DEBUG.
    real_error = PP.logger.error
    PP.logger.error = PP.logger.debug          # type: ignore[method-assign]
    try:
        records = run_once()
    finally:
        PP.logger.error = real_error           # type: ignore[method-assign]
    note("error downgraded to debug (the original defect)",
         not visible(records),
         "skip is invisible at ERROR" if not visible(records)
         else "STILL VISIBLE -- the guard is not reading the level")

    # ── sabotage 2: the report removed outright.
    PP.logger.error = lambda *a, **k: None     # type: ignore[method-assign]
    try:
        records = run_once()
    finally:
        PP.logger.error = real_error           # type: ignore[method-assign]
    note("report removed entirely",
         not visible(records),
         "skip is unreported" if not visible(records)
         else "STILL VISIBLE -- something else is logging it")

    # ── sabotage 3: the message loses the marker the guard matches on.
    PP.logger.error = lambda *a, **k: real_error("stage issue")  # type: ignore[method-assign]
    try:
        records = run_once()
    finally:
        PP.logger.error = real_error           # type: ignore[method-assign]
    note("marker dropped from the message",
         not visible(records),
         "guard can no longer identify the stage" if not visible(records)
         else "STILL MATCHED -- the guard is not reading the message")

    caught = sum(1 for _, c, _ in RESULTS[1:] if c)
    total = len(RESULTS) - 1
    print()
    if not control_ok:
        print("  CONTROL FAILED -- the signal is absent with nothing "
              "removed, so no sabotage result below means anything")
        return 1
    print(f"  {caught}/{total} sabotages caught, control holds")
    return 0 if caught == total else 1


if __name__ == "__main__":
    sys.exit(main())
