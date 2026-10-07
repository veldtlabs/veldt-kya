"""Prove the surviving replay-protection assertions can fail.

    KYA_VALKEY_URL=redis://localhost:6379/0 python tests/sabotage_replay_nonce_scoping.py

Successor to ``tests/sabotage_replay_protection.py``, which was deleted
along with the gateway replay stage it exercised. That deletion was
correct for three of its four rounds -- their target no longer exists:
``check_invocation_replay`` is gone, and so is the pipeline stage that
called it. The stage could never have worked anyway, because
``_record_invocation_pre_policy`` returns a fresh autoincrement row id
on every request, so a reservation keyed on that id cannot collide.

But one promise survived the deletion and lost its guard: the nonce
keyspace in ``verify_request_nonce`` is scoped by tenant AND principal.
If either segment is dropped, one tenant's nonce blocks another's, or
one principal's blocks another's -- a cross-tenant denial of service
wearing replay protection's clothes. That promise is still real, it
just moved down a layer from the gateway to the primitive.

So the rounds below break one segment at a time and require a specific
test to stop holding. A control that removes nothing runs first; if the
control does not hold, nothing after it means anything.

NOTE ON COVERAGE, because it matters more than the rounds do.
``KYA_VALKEY_URL`` is unset in a default environment, so the tests
these rounds target SKIP in a normal run -- including CI. A skipped
assertion proves nothing, and that is the state these promises are in
unless a store is wired. Running this file is how you find out whether
they hold.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

# tests/ on sys.path makes `kya` resolve to site-packages rather than
# the tree being changed. Pin the repo root so this measures the
# working copy.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.path[0] != _ROOT:
    sys.path.insert(0, _ROOT)

_TARGET = os.path.join(_ROOT, "kya", "replay_protection.py")
_TESTS = os.path.join("tests", "test_replay_protection.py")

#: (label, old, new, the test that MUST go red)
ROUNDS: list[tuple[str, str, str, str]] = [
    (
        "tenant_id dropped from the nonce key",
        'f"kya:nonce:{len(tenant_id)}:{tenant_id}"',
        'f"kya:nonce:"',
        "test_different_tenants_can_reuse_nonce",
    ),
    (
        "principal_id dropped from the nonce key",
        'f":{len(principal_id)}:{principal_id}"',
        '":"',
        "test_different_principals_can_reuse_nonce",
    ),
    (
        "SET NX replaced by an unconditional accept",
        "nx=True",
        "nx=False",
        "test_first_request_accepted_then_replay_rejected",
    ),
]


def _run(selector: str | None) -> tuple[int, str]:
    cmd = [sys.executable, "-m", "pytest", _TESTS,
           "-p", "no:cacheprovider", "-q", "--no-header", "--tb=no"]
    if selector:
        cmd += ["-k", selector]
    p = subprocess.run(cmd, cwd=_ROOT, capture_output=True, text=True)
    tail = (p.stdout.strip().splitlines() or ["<no output>"])[-1]
    return p.returncode, tail


def main() -> int:
    if not os.environ.get("KYA_VALKEY_URL"):
        print("  KYA_VALKEY_URL is unset. The tests these rounds target")
        print("  SKIP without a store, and a skipped assertion proves")
        print("  nothing -- which is exactly what this file exists to")
        print("  surface. Set it and re-run.")
        return 2

    print("Sabotage-verifying the surviving replay promises...")
    print()

    rc, tail = _run(None)
    if rc != 0:
        print(f"CONTROL FAILED before any sabotage: {tail}")
        print("Nothing below this would mean anything. Stopping.")
        return 1
    if " skipped" in tail and " passed" not in tail:
        print(f"CONTROL SKIPPED: {tail}")
        print("The store is not reachable, so nothing is being proven.")
        return 2
    print(f"OK   control (nothing removed): {tail}")

    backup = _TARGET + ".sabotage-backup"
    shutil.copyfile(_TARGET, backup)
    all_ok = True
    try:
        for label, old, new, expect_red in ROUNDS:
            src = open(_TARGET, encoding="utf-8").read()
            if src.count(old) != 1:
                print(f"SKIP sabotage {label!r}: anchor appears "
                      f"{src.count(old)}x -- the code moved and this "
                      f"round is no longer valid.")
                all_ok = False
                continue
            with open(_TARGET, "w", encoding="utf-8", newline="") as fh:
                fh.write(src.replace(old, new))
            try:
                rc, tail = _run(expect_red)
                if rc == 0:
                    print(f"FAIL sabotage {label!r}: "
                          f"{expect_red} still passed -- it was not "
                          f"proving what it claimed. ({tail})")
                    all_ok = False
                else:
                    print(f"OK   sabotage {label!r}: "
                          f"{expect_red} went RED as required.")
            finally:
                shutil.copyfile(backup, _TARGET)
    finally:
        shutil.copyfile(backup, _TARGET)
        os.remove(backup)

    print()
    if all_ok:
        print("Surviving replay promises sabotage-verified.")
        return 0
    print("FAILURE: at least one promise was not actually being proven.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
