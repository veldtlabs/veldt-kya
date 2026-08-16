"""Tamper-anchor regression tests for the evidence chain.

Covers the two anchors bolted onto ``verify_chain`` on top of the
existing per-row HMAC hash-walk:

1. Row-count anchor - ``kya_invocations.evidence_row_count`` counts
   every successful ``record_evidence`` call. Mismatch = rows deleted
   from the tail (or the whole chain wiped) even though surviving rows
   still HMAC-verify against each other.
2. Genesis anchor - ``record_evidence`` auto-inserts a ``chain_genesis``
   row on first write. Missing genesis at position 0 = head row was
   deleted.

Legacy chains (rows written before either anchor existed) leave
``evidence_row_count`` NULL and have no genesis row - verify_chain
falls back to the pre-anchor hash-walk semantics so an upgrade does
not spuriously flag pre-existing chains.
"""
from __future__ import annotations

import base64
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya.canonicals import EVIDENCE_KIND_CHAIN_GENESIS
from kya.evidence import init_evidence_table, record_evidence, verify_chain
from kya.invocations import ensure_invocations_table, record_invocation


def setup_module(_module):
    # Deterministic 32-byte key so the HMAC hash-walk itself is stable
    # across test runs (rules out signing-key noise as a source of
    # spurious failures).
    if not os.environ.get("KYA_EVIDENCE_SIGNING_KEY"):
        os.environ["KYA_EVIDENCE_SIGNING_KEY"] = base64.b64encode(
            b"tamper-anchor-tests-key-32bytes!"
        ).decode()


TENANT = "t-anchor-tests"


@pytest.fixture
def db():
    """Fresh in-memory SQLite session with the full KYA schema."""
    engine = create_engine("sqlite:///:memory:", future=True)
    session = sessionmaker(bind=engine)()
    ensure_invocations_table(session)
    init_evidence_table(session)
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _new_inv(db) -> int:
    return record_invocation(
        db, tenant_id=TENANT, agent_key="agent-anchor",
        principal_kind="agent", principal_id="agent-anchor",
        mode="observed", outcome="success",
    )


def _record_n_rows(db, inv: int, n: int) -> None:
    for i in range(n):
        record_evidence(
            db, tenant_id=TENANT, invocation_id=inv,
            evidence_kind="tool_call",
            payload={"i": i, "note": f"row-{i}"},
        )
    db.commit()


def _count_rows(db, inv: int) -> int:
    return db.execute(
        text(
            "SELECT COUNT(*) FROM kya_evidence "
            "WHERE tenant_id = :t AND invocation_id = :i"
        ),
        {"t": TENANT, "i": inv},
    ).scalar()


def test_tail_truncation_flagged_by_row_count_anchor(db):
    """Delete the last 2 rows -> verify_chain flags row-count mismatch."""
    inv = _new_inv(db)
    _record_n_rows(db, inv, 4)
    # 4 caller rows + 1 auto-genesis = 5 total.
    assert _count_rows(db, inv) == 5

    db.execute(
        text(
            "DELETE FROM kya_evidence WHERE id IN ("
            "  SELECT id FROM kya_evidence "
            "  WHERE tenant_id = :t AND invocation_id = :i "
            "  ORDER BY id DESC LIMIT 2"
            ")"
        ),
        {"t": TENANT, "i": inv},
    )
    db.commit()

    r = verify_chain(db, TENANT, inv)
    assert r["valid"] is False, r
    assert "row count mismatch" in (r["reason"] or "")
    assert r["expected_count"] == 5
    assert r["checked"] == 3


def test_full_wipe_flagged_by_row_count_anchor(db):
    """Delete every evidence row -> verify_chain flags full wipe."""
    inv = _new_inv(db)
    _record_n_rows(db, inv, 3)
    # 3 caller rows + 1 auto-genesis = 4 total.
    assert _count_rows(db, inv) == 4

    db.execute(
        text(
            "DELETE FROM kya_evidence "
            "WHERE tenant_id = :t AND invocation_id = :i"
        ),
        {"t": TENANT, "i": inv},
    )
    db.commit()

    r = verify_chain(db, TENANT, inv)
    assert r["valid"] is False, r
    reason = r["reason"] or ""
    assert ("row count mismatch" in reason) or ("wipe detected" in reason)
    assert r["expected_count"] == 4
    assert r["checked"] == 0


def test_genesis_deletion_flagged(db):
    """Delete only the genesis row -> verify_chain flags missing anchor.

    Setup manoeuvres around the row-count anchor so we isolate the
    genesis check: we delete the genesis AND fix up
    ``evidence_row_count`` to match the surviving row count. Without
    the genesis anchor an attacker could delete both the genesis and
    decrement the counter to bypass row-count detection; the genesis
    check is the second line of defense against head-truncation.
    """
    inv = _new_inv(db)
    _record_n_rows(db, inv, 3)
    # 3 caller rows + 1 auto-genesis = 4.
    assert _count_rows(db, inv) == 4

    db.execute(
        text(
            "DELETE FROM kya_evidence "
            "WHERE tenant_id = :t AND invocation_id = :i "
            "AND evidence_kind = :k"
        ),
        {"t": TENANT, "i": inv, "k": EVIDENCE_KIND_CHAIN_GENESIS},
    )
    # Fake up the counter so the row-count check passes and the
    # genesis check is the one that has to catch the tamper.
    db.execute(
        text(
            "UPDATE kya_invocations SET evidence_row_count = 3 "
            "WHERE tenant_id = :t AND id = :i"
        ),
        {"t": TENANT, "i": inv},
    )
    db.commit()

    r = verify_chain(db, TENANT, inv)
    assert r["valid"] is False, r
    assert "missing genesis" in (r["reason"] or "")


def test_legacy_null_count_preserves_current_behavior(db):
    """Legacy chains (evidence_row_count IS NULL) fall back to hash-walk.

    Migration bridge: chains written before the anchor existed leave
    the counter NULL. verify_chain must not spuriously flag them just
    because rows were later pruned - the pre-anchor semantics were
    "chain valid iff surviving rows HMAC-verify," and legacy chains
    must keep that contract.
    """
    inv = _new_inv(db)
    _record_n_rows(db, inv, 3)
    # Simulate a pre-anchor chain by nulling the counter.
    db.execute(
        text(
            "UPDATE kya_invocations SET evidence_row_count = NULL "
            "WHERE tenant_id = :t AND id = :i"
        ),
        {"t": TENANT, "i": inv},
    )
    db.commit()

    # Delete one tail row. Under legacy semantics the surviving rows
    # still HMAC-verify (prev_hash chain remains linked up to the
    # deleted tail), so verify_chain should NOT flag this.
    db.execute(
        text(
            "DELETE FROM kya_evidence WHERE id IN ("
            "  SELECT id FROM kya_evidence "
            "  WHERE tenant_id = :t AND invocation_id = :i "
            "  ORDER BY id DESC LIMIT 1"
            ")"
        ),
        {"t": TENANT, "i": inv},
    )
    db.commit()

    r = verify_chain(db, TENANT, inv)
    assert r["valid"] is True, r
    assert r["expected_count"] is None


def test_assessment_windowed_pass_flags_wiped_chain(db):
    """The evidence pillar in kya.assessment must flag wiped chains.

    Integration test - proves the fix reaches the actual caller path
    that was silently swallowing wipe events.
    """
    from kya.assessment import pillar_evidence_chain_review

    inv = _new_inv(db)
    _record_n_rows(db, inv, 3)
    # Wipe all evidence rows for the invocation.
    db.execute(
        text(
            "DELETE FROM kya_evidence "
            "WHERE tenant_id = :t AND invocation_id = :i"
        ),
        {"t": TENANT, "i": inv},
    )
    db.commit()

    findings, _ = pillar_evidence_chain_review(
        db, tenant_id=TENANT, agent_keys=["agent-anchor"],
        window_days=1,
    )
    # Expect a critical "broken evidence chain(s) detected" finding -
    # NOT the informational "All N chain(s) verified" one.
    assert findings, "pillar returned no findings at all"
    top = findings[0]
    assert top.severity == "critical", (
        f"expected critical finding, got severity={top.severity!r} "
        f"title={top.title!r}"
    )
    assert "broken" in top.title.lower()


def test_record_evidence_auto_inserts_genesis_on_first_call(db):
    """First record_evidence call on an empty chain auto-inserts genesis."""
    inv = _new_inv(db)
    record_evidence(
        db, tenant_id=TENANT, invocation_id=inv,
        evidence_kind="tool_call",
        payload={"tool": "search", "arg": "x"},
    )
    db.commit()

    rows = db.execute(
        text(
            "SELECT evidence_kind, payload FROM kya_evidence "
            "WHERE tenant_id = :t AND invocation_id = :i "
            "ORDER BY id ASC"
        ),
        {"t": TENANT, "i": inv},
    ).all()
    assert len(rows) == 2, f"expected 2 rows (genesis + caller), got {rows}"
    assert rows[0][0] == EVIDENCE_KIND_CHAIN_GENESIS
    # Payload sanity - genesis must anchor the (tenant, invocation) pair.
    import json as _json
    p0 = rows[0][1] if isinstance(rows[0][1], dict) else _json.loads(rows[0][1])
    assert p0["tenant_id"] == TENANT
    assert p0["invocation_id"] == inv
    assert p0["chain_version"] == 1
    assert rows[1][0] == "tool_call"


def test_record_evidence_no_double_genesis_when_caller_passes_it(db):
    """Caller-supplied genesis skips the auto-insert path."""
    inv = _new_inv(db)
    record_evidence(
        db, tenant_id=TENANT, invocation_id=inv,
        evidence_kind=EVIDENCE_KIND_CHAIN_GENESIS,
        payload={"tenant_id": TENANT, "invocation_id": inv,
                 "created_at": "2026-08-16T00:00:00+00:00",
                 "chain_version": 1},
    )
    db.commit()

    rows = db.execute(
        text(
            "SELECT evidence_kind FROM kya_evidence "
            "WHERE tenant_id = :t AND invocation_id = :i "
            "ORDER BY id ASC"
        ),
        {"t": TENANT, "i": inv},
    ).all()
    assert len(rows) == 1, (
        f"caller-supplied genesis should not trigger auto-insert; "
        f"got {rows}"
    )
    assert rows[0][0] == EVIDENCE_KIND_CHAIN_GENESIS
