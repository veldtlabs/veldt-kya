"""Whitelist regression tests for evidence_kind normalization."""
from __future__ import annotations

import pytest

from kya.evidence import VALID_EVIDENCE_KINDS, init_evidence_table, record_evidence


def _session():
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from sqlalchemy.orm import sessionmaker

    engine = sqlalchemy.create_engine("sqlite:///:memory:")
    return sqlalchemy, sessionmaker(bind=engine)()


def _read_kind(sqlalchemy, session, evidence_id: int) -> str:
    row = session.execute(
        sqlalchemy.text(
            "SELECT evidence_kind FROM kya_evidence WHERE id = :i"
        ),
        {"i": evidence_id},
    ).scalar()
    return row


def test_action_gate_block_is_valid_kind():
    """action_gate_block survives the normalizer end-to-end."""
    assert "action_gate_block" in VALID_EVIDENCE_KINDS
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        rid = record_evidence(
            session, tenant_id="t", invocation_id=1,
            evidence_kind="action_gate_block",
            payload={"verdict": "block"}, source="test",
        )
        assert _read_kind(sqlalchemy, session, rid) == "action_gate_block"
    finally:
        session.close()


def test_external_alert_is_valid_kind():
    """external_alert survives the normalizer end-to-end."""
    assert "external_alert" in VALID_EVIDENCE_KINDS
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        rid = record_evidence(
            session, tenant_id="t", invocation_id=1,
            evidence_kind="external_alert",
            payload={"detector": "fiddler"}, source="test",
        )
        assert _read_kind(sqlalchemy, session, rid) == "external_alert"
    finally:
        session.close()


def test_unknown_kind_still_normalizes():
    """Negative control — genuinely unknown kinds still fall through."""
    assert "totally_made_up_kind" not in VALID_EVIDENCE_KINDS
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        rid = record_evidence(
            session, tenant_id="t", invocation_id=1,
            evidence_kind="totally_made_up_kind",
            payload={}, source="test",
        )
        assert _read_kind(sqlalchemy, session, rid) == "system_message"
    finally:
        session.close()
