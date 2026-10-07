"""Prove the replay-protection assertions can fail.

    KYA_VALKEY_URL=redis://localhost:6379/0 python tests/sabotage_replay_protection.py

The gateway's replay stage shipped dead for every release of this
package, and two tests passed throughout because they synthesised the
module they were checking. So the assertions that replaced them are held
to the standard the rest of this repo uses: break one mechanism at a
time and require the condition to stop holding.

A control that removes nothing runs first. If the control does not hold,
nothing below it means anything.
"""
from __future__ import annotations

import os
import sys
import uuid

# tests/ on sys.path makes `kya` resolve to site-packages rather than the
# tree being changed. Pin the repo root so this measures the working copy.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.path[0] != _ROOT:
    sys.path.insert(0, _ROOT)

from kya_gateway.config import PolicyConfig          # noqa: E402
from kya_gateway.identity import BoundPrincipal      # noqa: E402
from kya_gateway import policy_pipeline as PP        # noqa: E402
import kya.replay_protection as RP                   # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def note(name: str, caught: bool, detail: str = "") -> None:
    RESULTS.append((name, caught, detail))
    print(f"  {'CAUGHT ' if caught else 'MISSED '} {name:44} {detail}")


def _principal(pid: str = "planner") -> BoundPrincipal:
    return BoundPrincipal(
        principal_kind="agent",
        principal_id=pid,
        method="bearer_jwt",
        external_subject=pid,
        external_issuer=None,
    )


def _evaluate(tenant: str, invocation: int, pid: str = "planner"):
    return PP.evaluate(
        db=None,
        tenant_id=tenant,
        principal=_principal(pid),
        action="mcp.x.read",
        payload_bytes=100,
        invocation_id=invocation,
        cfg=PolicyConfig(min_trust=0),
    )


def replay_is_denied() -> bool:
    """Does a second use of one invocation id get refused?"""
    tenant = "sab-" + uuid.uuid4().hex[:10]
    inv = 900001
    _evaluate(tenant, inv)
    second = _evaluate(tenant, inv)
    return (second.verdict == "deny"
            and "REPLAY_DETECTED" in second.reason_codes)


def scoping_holds() -> bool:
    """Is one tenant's reservation invisible to another tenant?"""
    inv = 900002
    _evaluate("sab-" + uuid.uuid4().hex[:10], inv)
    other = _evaluate("sab-" + uuid.uuid4().hex[:10], inv)
    return "REPLAY_DETECTED" not in other.reason_codes


def main() -> int:
    url = os.environ.get("KYA_VALKEY_URL", "").strip()
    if not url:
        print()
        print("  KYA_VALKEY_URL is unset. Replay protection is fail-open "
              "without a store,")
        print("  so every sabotage below would 'pass' while proving "
              "nothing. Refusing to run.")
        return 2
    os.environ["KYA_REPLAY_PROTECTION"] = "on"

    print()
    print("  sabotaging replay protection")
    print(f"  kya under test: {os.path.dirname(RP.__file__)}")
    print()

    # ── control first ────────────────────────────────────────────────
    ctl_denied = replay_is_denied()
    ctl_scoped = scoping_holds()
    note("control: nothing removed (must HOLD)",
         ctl_denied and ctl_scoped,
         f"replay denied={ctl_denied} scoping={ctl_scoped}")
    if not (ctl_denied and ctl_scoped):
        print()
        print("  CONTROL FAILED -- the mechanism is not working with "
              "nothing removed,")
        print("  so no sabotage result below means anything.")
        return 1

    real_check = RP.check_invocation_replay
    real_nonce = RP.verify_request_nonce

    # ── sabotage 1: the check always allows (the dead-stage behaviour)
    RP.check_invocation_replay = lambda *a, **k: True
    try:
        broke = not replay_is_denied()
    finally:
        RP.check_invocation_replay = real_check
    note("check always returns True", broke,
         "replay no longer denied" if broke
         else "STILL DENIED -- something else is refusing it")

    # ── sabotage 2: the symbol genuinely absent, which is how 0.5.12
    #    shipped. delattr is deliberate: assigning None instead raises
    #    TypeError inside the stage, and the pipeline's exception path
    #    denies with REPLAY_ERROR -- a refusal for the wrong reason,
    #    which would make this sabotage look caught while reproducing a
    #    different fault. Only a missing attribute reproduces the
    #    ImportError the shipped package actually hit.
    delattr(RP, "check_invocation_replay")
    try:
        verdicts = []
        tenant = "sab-" + uuid.uuid4().hex[:10]
        inv = 900003
        verdicts.append(_evaluate(tenant, inv))
        verdicts.append(_evaluate(tenant, inv))
        second = verdicts[1]
        broke = (second.verdict != "deny"
                 or "REPLAY_DETECTED" not in second.reason_codes)
        detail = (f"second call verdict={second.verdict} "
                  f"codes={second.reason_codes or []}")
    finally:
        RP.check_invocation_replay = real_check
    note("symbol absent (as shipped in 0.5.12)", broke, detail)

    # ── sabotage 3: tenant scoping collapsed to one namespace
    def unscoped(**kw):
        kw["tenant_id"] = "_global"
        kw["principal_id"] = "_global"
        return real_nonce(**kw)

    RP.verify_request_nonce = unscoped
    try:
        broke = not scoping_holds()
    finally:
        RP.verify_request_nonce = real_nonce
    note("tenant/principal scoping removed", broke,
         "one tenant now masks another" if broke
         else "STILL SCOPED -- the scoping args are not load-bearing")

    caught = sum(1 for _, c, _ in RESULTS[1:] if c)
    total = len(RESULTS) - 1
    print()
    print(f"  {caught}/{total} sabotages caught, control holds")
    return 0 if caught == total else 1


if __name__ == "__main__":
    sys.exit(main())
