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


def _sqlite_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool

    from kya.evidence import init_evidence_table

    eng = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with Session(eng) as db:
        init_evidence_table(db)
        db.commit()
    return eng


def test_chain_lock_is_released_when_record_evidence_raises(monkeypatch):
    """Drive the REAL production path, not the lock primitive.

    An earlier version of this test acquired and released the lock via a
    local helper. Sabotage exposed it: deleting the ``release()`` from
    record_evidence's finally left the test green, because the test
    never went through that code. It asserted nothing.

    This calls record_evidence for real, forces a failure inside the
    critical section, then records again on the SAME chain. Without the
    release the second call blocks forever, so the timeout is the
    assertion.
    """
    from sqlalchemy.orm import Session

    import kya.evidence as ev

    eng = _sqlite_session()
    inv = 90002

    # Force the failure INSIDE the critical section -- after acquire(),
    # in the window that used to sit outside the try. _hmac_sign is
    # called only there (evidence.py:952 and :1000); _canonicalize was
    # the wrong choice, it also runs at :863 BEFORE the acquire, so the
    # injection fired before any lock was held and the test passed
    # whether or not the release existed.
    def _explode(*_a, **_k):
        raise RuntimeError("failure inside the critical section")

    monkeypatch.setattr(ev, "_hmac_sign", _explode)

    with Session(eng) as db:
        with pytest.raises(Exception):
            ev.record_evidence(
                db, tenant_id=TENANT, invocation_id=inv,
                evidence_kind="system_message", role="record",
                payload={"kind": "probe"},
            )

    # The chain must not be wedged.
    got = ev._get_chain_lock(TENANT, inv).acquire(timeout=5)
    try:
        assert got, (
            "record_evidence left the chain lock held after failing — "
            "every later evidence write for this invocation would block "
            "forever on acquire(), with no error and no timeout"
        )
    finally:
        if got:
            ev._get_chain_lock(TENANT, inv).release()


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
