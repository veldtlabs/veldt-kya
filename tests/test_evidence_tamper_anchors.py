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
    ``evidence_row_count`` to match the surviving row count AND
    recompute the signature over the forged counter (simulating an
    attacker who somehow obtained the signing key — which lets us
    exercise the genesis check in isolation without the counter
    signature short-circuiting the verify path first). The genesis
    check is a defense-in-depth layer for the case where the
    signature guard is bypassed via key compromise.
    """
    from kya.evidence import _counter_signature, _get_signing_key
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
    # Fake up the counter AND the counter signature so neither the
    # row-count nor the counter-signature check flags the tamper.
    # The genesis check is then the one that has to catch it.
    _key, _ = _get_signing_key()
    forged_sig = _counter_signature(_key, TENANT, inv, 3)
    db.execute(
        text(
            "UPDATE kya_invocations SET evidence_row_count = 3, "
            "evidence_row_count_signature = :s "
            "WHERE tenant_id = :t AND id = :i"
        ),
        {"s": forged_sig, "t": TENANT, "i": inv},
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


def test_counter_forgery_detected_by_signature(db):
    """Attacker deletes rows AND rewrites the counter -> signature catches it.

    Simulates a DBA with UPDATE on ``kya_invocations`` who:
    (a) DELETEs half the evidence rows via raw SQL, and
    (b) rewrites ``evidence_row_count`` to match the surviving count.
    The row-count check alone would say "counter matches survivors,
    all good." The counter-signature check must catch the tamper
    because the attacker does not have the signing key and cannot
    forge a matching signature.
    """
    inv = _new_inv(db)
    _record_n_rows(db, inv, 3)
    # 3 caller rows + 1 auto-genesis = 4.
    assert _count_rows(db, inv) == 4

    # DELETE the last 2 rows via raw SQL.
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
    # Rewrite the counter to match the surviving row count. The
    # signature is NOT re-signed - the attacker cannot forge it
    # without the signing key.
    db.execute(
        text(
            "UPDATE kya_invocations SET evidence_row_count = 2 "
            "WHERE tenant_id = :t AND id = :i"
        ),
        {"t": TENANT, "i": inv},
    )
    db.commit()

    r = verify_chain(db, TENANT, inv)
    assert r["valid"] is False, r
    reason = r["reason"] or ""
    assert (
        "counter signature" in reason.lower()
        or "counter was rewritten" in reason.lower()
    ), r
    assert r["expected_count_signature_verified"] is False, r


def test_counter_signature_survives_legitimate_bump(db):
    """Legitimate record_evidence writes leave a verifying signature."""
    inv = _new_inv(db)
    _record_n_rows(db, inv, 3)

    # Read the persisted counter + signature straight from the table.
    row = db.execute(
        text(
            "SELECT evidence_row_count, evidence_row_count_signature "
            "FROM kya_invocations WHERE tenant_id = :t AND id = :i"
        ),
        {"t": TENANT, "i": inv},
    ).first()
    assert row is not None
    persisted_count, persisted_sig = row[0], row[1]
    assert persisted_count is not None, "counter must be non-NULL"
    assert persisted_sig is not None, "signature must be non-NULL"

    # Signature must verify against the persisted counter.
    from kya.evidence import _counter_signature, _get_signing_key
    _key, _ = _get_signing_key()
    expected = _counter_signature(_key, TENANT, inv, int(persisted_count))
    assert persisted_sig == expected

    # verify_chain must report the happy-path signature outcome.
    r = verify_chain(db, TENANT, inv)
    assert r["valid"] is True, r
    assert r["expected_count_signature_verified"] is True, r


def test_null_signature_downgrade_attack_detected(db):
    """An attacker who deletes rows AND nulls the signature is caught.

    Post-migration, ``evidence_row_count`` populated but
    ``evidence_row_count_signature`` NULL is unambiguous tampering —
    the reconciler backfills every pre-existing 0.5.2 row at boot, so
    only an attacker who UPDATEd the column to NULL can produce this
    state. verify_chain fails-closed with a specific reason string.
    """
    inv = _new_inv(db)
    _record_n_rows(db, inv, 3)
    # Attack: delete tail-2 rows, rewrite counter to match, AND null
    # the signature to try to force the fall-through path.
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
    db.execute(
        text(
            "UPDATE kya_invocations SET evidence_row_count = 2, "
            "evidence_row_count_signature = NULL "
            "WHERE tenant_id = :t AND id = :i"
        ),
        {"t": TENANT, "i": inv},
    )
    db.commit()

    r = verify_chain(db, TENANT, inv)
    assert r["valid"] is False, r
    assert "signature missing" in (r["reason"] or ""), r
    assert r["expected_count_signature_verified"] is False, r


def test_verify_chain_return_includes_expected_count_signature_verified(db):
    """Envelope contract: the new field is present in every return branch."""
    # Happy path -> True.
    inv_ok = _new_inv(db)
    _record_n_rows(db, inv_ok, 2)
    r_ok = verify_chain(db, TENANT, inv_ok)
    assert "expected_count_signature_verified" in r_ok, r_ok
    assert r_ok["expected_count_signature_verified"] is True, r_ok

    # Legacy chain (counter NULL, no signature) -> None.
    inv_legacy = _new_inv(db)
    _record_n_rows(db, inv_legacy, 2)
    db.execute(
        text(
            "UPDATE kya_invocations SET evidence_row_count = NULL, "
            "evidence_row_count_signature = NULL "
            "WHERE tenant_id = :t AND id = :i"
        ),
        {"t": TENANT, "i": inv_legacy},
    )
    db.commit()
    r_legacy = verify_chain(db, TENANT, inv_legacy)
    assert "expected_count_signature_verified" in r_legacy, r_legacy
    assert r_legacy["expected_count_signature_verified"] is None, r_legacy

    # Null-signature-with-count (attack surface) -> False under Option A.
    # The reconciler backfills 0.5.2 rows at boot, so post-migration a
    # NULL signature on a row with a non-NULL count is unambiguous
    # tampering rather than a legitimate migration bridge.
    inv_pre = _new_inv(db)
    _record_n_rows(db, inv_pre, 2)
    db.execute(
        text(
            "UPDATE kya_invocations SET evidence_row_count_signature = NULL "
            "WHERE tenant_id = :t AND id = :i"
        ),
        {"t": TENANT, "i": inv_pre},
    )
    db.commit()
    r_pre = verify_chain(db, TENANT, inv_pre)
    assert "expected_count_signature_verified" in r_pre, r_pre
    assert r_pre["expected_count_signature_verified"] is False, r_pre
    assert r_pre["valid"] is False, r_pre

    # Counter-forgery path -> False.
    inv_forge = _new_inv(db)
    _record_n_rows(db, inv_forge, 3)
    db.execute(
        text(
            "DELETE FROM kya_evidence WHERE id IN ("
            "  SELECT id FROM kya_evidence "
            "  WHERE tenant_id = :t AND invocation_id = :i "
            "  ORDER BY id DESC LIMIT 1"
            ")"
        ),
        {"t": TENANT, "i": inv_forge},
    )
    db.execute(
        text(
            "UPDATE kya_invocations SET evidence_row_count = 3 "
            "WHERE tenant_id = :t AND id = :i"
        ),
        {"t": TENANT, "i": inv_forge},
    )
    db.commit()
    r_forge = verify_chain(db, TENANT, inv_forge)
    assert "expected_count_signature_verified" in r_forge, r_forge
    assert r_forge["expected_count_signature_verified"] is False, r_forge


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


def test_reconciler_backfills_at_alter_time_on_pre_existing_rows():
    """Fresh-ALTER migration path — 0.5.2 rows get sigs on 0.5.3 boot.

    Simulates the exact prod upgrade shape: a live 0.5.2 install
    already has ``kya_invocations`` rows with ``evidence_row_count``
    populated but no signature column at all. On 0.5.3 boot the
    reconciler ADDs the column AND backfills every existing row in
    the same call.

    Backfill deliberately runs ONLY on the fresh-ALTER branch — it
    must NOT run on subsequent reconciler calls (attacker-nulled sigs
    would otherwise be silently re-healed on the next verify_chain).
    """
    from sqlalchemy import inspect

    from kya.invocations import _reconcile_evidence_row_count_signature_column
    engine = create_engine("sqlite:///:memory:", future=True)
    with engine.begin() as conn:
        # Legacy 0.5.2 schema: has evidence_row_count but no signature.
        conn.execute(text(
            "CREATE TABLE kya_invocations ("
            "  id INTEGER PRIMARY KEY,"
            "  tenant_id TEXT NOT NULL,"
            "  agent_key TEXT,"
            "  evidence_row_count INTEGER"
            ")"
        ))
        # Two pre-existing rows with count populated but no sig column.
        conn.execute(text(
            "INSERT INTO kya_invocations (id, tenant_id, evidence_row_count) "
            "VALUES (1, :t, 3), (2, :t, 5)"
        ), {"t": TENANT})

    # Reconciler run: ALTER + backfill in one call.
    with engine.begin() as conn:
        cols_before = {c["name"] for c in inspect(conn).get_columns("kya_invocations")}
        assert "evidence_row_count_signature" not in cols_before
        _reconcile_evidence_row_count_signature_column(conn)
        cols_after = {c["name"] for c in inspect(conn).get_columns("kya_invocations")}
        assert "evidence_row_count_signature" in cols_after

    # Verify backfill populated every pre-existing row.
    with engine.begin() as conn:
        rows = conn.execute(text(
            "SELECT id, evidence_row_count_signature FROM kya_invocations "
            "ORDER BY id"
        )).all()
    assert len(rows) == 2
    assert all(sig is not None and len(sig) == 64 for _id, sig in rows), rows

    # Second reconciler call MUST NOT re-backfill anything (column
    # already present → early return before backfill fires). Attacker-
    # nulled sigs would otherwise get silently healed on next read.
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE kya_invocations SET evidence_row_count_signature = NULL "
            "WHERE id = 1"
        ))
    with engine.begin() as conn:
        _reconcile_evidence_row_count_signature_column(conn)
        sig_row_1 = conn.execute(text(
            "SELECT evidence_row_count_signature FROM kya_invocations "
            "WHERE id = 1"
        )).scalar()
    assert sig_row_1 is None, (
        "reconciler must NOT re-backfill on subsequent runs — attacker "
        "nulled sigs get silently healed if it does"
    )
    engine.dispose()


def test_reconciler_adds_column_on_pre_existing_table():
    """Reconciler ALTER path — table exists without the signature column."""
    from sqlalchemy import inspect

    from kya.invocations import _reconcile_evidence_row_count_signature_column
    engine = create_engine("sqlite:///:memory:", future=True)
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE kya_invocations ("
            "  id INTEGER PRIMARY KEY,"
            "  tenant_id TEXT,"
            "  agent_key TEXT,"
            "  evidence_row_count INTEGER"
            ")"
        ))
    with engine.begin() as conn:
        cols_before = {c["name"] for c in inspect(conn).get_columns("kya_invocations")}
        assert "evidence_row_count_signature" not in cols_before

        _reconcile_evidence_row_count_signature_column(conn)

        cols_after = {c["name"] for c in inspect(conn).get_columns("kya_invocations")}
        assert "evidence_row_count_signature" in cols_after
    engine.dispose()
