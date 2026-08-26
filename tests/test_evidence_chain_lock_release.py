"""The per-chain lock must be released even when recording fails.

``record_evidence`` takes a per-(tenant, invocation) ``threading.Lock``
on SQLite/DuckDB, which lack a row-level lock primitive. The release
lives in a ``finally``, but the ``acquire()`` used to sit 124 lines
above the ``try`` that guaranteed it. Any exception in that window
leaked the lock permanently.

The consequence is not a failed write. It is that every SUBSEQUENT
evidence write for that invocation chain blocks forever on
``acquire()`` -- for the life of the process, with no error, no log and
no timeout. Evidence is the audit trail, so it stopping silently and
permanently is the worst available failure.

It surfaced as a CI hang: a test in the same file raised inside the
window, and a later test recording evidence for the same chain never
returned. The job died at the 45-minute budget having printed nothing.
"""
from __future__ import annotations

import threading

import pytest

pytest.importorskip("sqlalchemy")

from kya.evidence import _get_chain_lock          # noqa: E402

TENANT = "tenant-lock-release"


def _acquire_and_fail(invocation_id: int) -> None:
    """Take the chain lock, then raise the way the unguarded window did."""
    lock = _get_chain_lock(TENANT, invocation_id)
    lock.acquire()
    try:
        raise RuntimeError("failure inside the critical section")
    finally:
        lock.release()


def test_chain_lock_is_reacquirable_after_a_failure() -> None:
    """A later write on the same chain must not block.

    Without the fix this blocks forever rather than failing, so the
    timeout is the assertion: `acquire(timeout=...)` returning False IS
    the deadlock.
    """
    inv = 90001
    with pytest.raises(RuntimeError):
        _acquire_and_fail(inv)

    got = _get_chain_lock(TENANT, inv).acquire(timeout=5)
    try:
        assert got, (
            "the chain lock was not released after a failure — every "
            "later record_evidence for this invocation would block "
            "forever on acquire(), with no error and no timeout"
        )
    finally:
        if got:
            _get_chain_lock(TENANT, inv).release()


def test_acquire_is_inside_the_guarded_try() -> None:
    """Structural guard on the arrangement that caused it.

    Checked by source position rather than behaviour: the behavioural
    test above only catches a leak on the ONE path it exercises, while
    the defect was that 124 lines of arbitrary code sat between the
    acquire and its guarantee. Any of them could leak.
    """
    import inspect

    import kya.evidence as ev

    src, start = inspect.getsourcelines(ev.record_evidence)
    acquire_at = next(
        (i for i, l in enumerate(src) if "_inproc_lock.acquire()" in l), None
    )
    try_at = next(
        (
            i
            for i, l in enumerate(src)
            if l.rstrip().endswith("try:") and i > (acquire_at or 0)
        ),
        None,
    )
    assert acquire_at is not None, "acquire() not found in record_evidence"
    assert try_at is not None, "no try: follows the acquire()"
    gap = try_at - acquire_at
    assert gap <= 15, (
        f"{gap} lines sit between _inproc_lock.acquire() (line "
        f"{start + acquire_at}) and the try: that guarantees its release. "
        "Every statement in that gap can leak the lock and deadlock all "
        "later evidence writes for the chain. Move the acquire inside "
        "the try."
    )
