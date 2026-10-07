"""Rogue signals must be attributed to the SUBJECT agent.

`get_rogue_signals(agent_key)` reads
``kya_principal_trust.signal_counts`` for that agent. But the recorders
only mirrored signals onto two OTHER principals — the invoking user
(`_emit_user_signal`) and a calling agent (`_emit_actor_agent_signal`)
— and never onto ``agent_key`` itself. There was no
``_emit_agent_signal`` at all.

Net effect: the rogue read path was inert for EVERY signal type, not
just leaks. Reproduced before the fix — three ``record_data_leak``
calls logged three leaks, and the report returned ``data_leaks == 0``
with no row for the agent.

Same family as "a principal has two names": the fact was written under
names the reader never queries.

Note the session-factory requirement. Without
``kya.set_session_factory(...)`` every mirror write is a no-op — which
masked this defect on the first attempt to reproduce it, so these
tests configure it explicitly.
"""
from __future__ import annotations

import uuid

import pytest

sa = pytest.importorskip("sqlalchemy")


@pytest.fixture
def rogue_db(tmp_path, monkeypatch):
    """Real engine + a configured session factory. Yields (Session, tenant)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    import kya
    from kya.principals import ensure_principal_table

    url = f"sqlite:///{tmp_path}/rogue.db"
    monkeypatch.setenv("KYA_DB_URL", url)
    engine = create_engine(url)
    with Session(engine) as db:
        ensure_principal_table(db)
        db.commit()
    kya.set_session_factory(sessionmaker(bind=engine))
    yield engine, f"t-{uuid.uuid4().hex[:8]}"


def _counts(engine, agent_key):
    from sqlalchemy import text

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT signal_counts FROM kya_principal_trust "
                "WHERE principal_id = :a AND principal_kind = 'agent'"
            ),
            {"a": agent_key},
        ).fetchone()
    return row[0] if row else None


def test_every_recorder_attributes_to_the_subject_agent(rogue_db):
    """All four recorders, one agent, one report."""
    from sqlalchemy.orm import Session

    from kya.rogue import (
        get_rogue_signals,
        record_cross_tenant_attempt,
        record_data_leak,
        record_oos_tool_attempt,
        record_policy_violation,
    )

    engine, tenant = rogue_db
    agent = "subject-agent"

    record_data_leak(agent_key=agent, data_class="pii.ssn", tenant_id=tenant)
    record_data_leak(agent_key=agent, data_class="pii.email", tenant_id=tenant)
    record_oos_tool_attempt(agent_key=agent, tool="shell", tenant_id=tenant)
    record_cross_tenant_attempt(
        agent_key=agent, expected_tid=tenant, actual_tid="other",
    )
    record_policy_violation(
        agent_key=agent, violation_kind="no-pii", tenant_id=tenant,
    )

    counts = _counts(engine, agent)
    assert counts is not None, (
        "no kya_principal_trust row for the offending agent — signals "
        "are being written under other principals only, so "
        "get_rogue_signals() reads nothing"
    )

    with Session(engine) as db:
        report = get_rogue_signals(agent, db=db, tenant_id=tenant)

    assert report.data_leaks == 2, (
        f"recorded 2 leaks, report says {report.data_leaks}; "
        f"signal_counts={counts}"
    )
    assert report.oos_tool_attempts == 1, f"signal_counts={counts}"
    assert report.cross_tenant_attempts == 1, f"signal_counts={counts}"
    assert report.policy_violations == 1, f"signal_counts={counts}"


def test_other_attributions_are_not_broken(rogue_db):
    """The subject-agent signal is ADDITIVE. The user and calling-agent
    mirrors must still fire — they were the only ones working before,
    and collapsing them onto the shared writer must not drop them."""
    from kya.rogue import record_data_leak
    from sqlalchemy import text

    engine, tenant = rogue_db
    record_data_leak(
        agent_key="subject", data_class="pii.ssn", tenant_id=tenant,
        user_id="user-9", actor_agent_key="caller-agent",
    )

    with engine.connect() as conn:
        rows = {
            (r[0], r[1]): r[2]
            for r in conn.execute(text(
                "SELECT principal_kind, principal_id, signal_counts "
                "FROM kya_principal_trust"
            ))
        }
    assert ("agent", "subject") in rows, "subject agent missing"
    assert ("agent", "caller-agent") in rows, "calling-agent mirror lost"
    assert ("user", "user-9") in rows, "user mirror lost"


def test_no_session_factory_is_a_silent_noop_not_a_crash(tmp_path, monkeypatch):
    """The documented posture: without a session factory the mirrors
    no-op. A guardrail that detected a leak must never be broken by
    the trust mirror failing."""
    import kya
    from kya.rogue import record_data_leak

    monkeypatch.setattr(kya, "_SESSION_FACTORY", None, raising=False)
    try:
        from kya import _session_factory as sf
        monkeypatch.setattr(sf, "get_session", lambda: None)
    except Exception:
        pass

    # Must not raise.
    record_data_leak(
        agent_key="a", data_class="pii.ssn", tenant_id="t",
    )


def test_self_driving_agent_is_counted_once_not_twice(rogue_db):
    """Subject and actor are the SAME principal in the single-agent and
    self-driving cases, and both emitters write to kya_principal_trust
    under ("agent", key). Emitting both counted ONE event TWICE and
    applied the trust penalty twice — one data leak read back as
    {"data_leak": 2} with trust 30 instead of 40.

    The sibling tests all use DISTINCT subject/actor keys, which is
    exactly why this shipped unnoticed.
    """
    import json

    from kya.rogue import record_data_leak

    engine, tenant = rogue_db
    same = "agt-self-" + uuid.uuid4().hex[:6]

    record_data_leak(
        agent_key=same, data_class="pii.ssn", tenant_id=tenant,
        user_id="u-1", actor_agent_key=same,
    )

    raw = _counts(engine, same)
    counts = json.loads(raw) if isinstance(raw, str) else (raw or {})
    assert counts.get("data_leak") == 1, (
        f"one leak was counted {counts.get('data_leak')} times because "
        f"the subject and actor emitters collapsed onto the same "
        f"principal key; the trust penalty is applied twice too"
    )


def test_distinct_actor_still_gets_its_own_signal(rogue_db):
    """The other side of the dedup: when the actor really is a
    different principal it must keep its own attribution. Guards
    against fixing the double-count by dropping actor mirroring."""
    import json

    from kya.rogue import record_data_leak

    engine, tenant = rogue_db
    subj = "agt-subj-" + uuid.uuid4().hex[:6]
    actor = "agt-actor-" + uuid.uuid4().hex[:6]

    record_data_leak(
        agent_key=subj, data_class="pii.ssn", tenant_id=tenant,
        user_id="u-1", actor_agent_key=actor,
    )

    for who in (subj, actor):
        raw = _counts(engine, who)
        counts = json.loads(raw) if isinstance(raw, str) else (raw or {})
        assert counts.get("data_leak") == 1, (
            f"{who} should carry exactly one data_leak signal, got "
            f"{counts!r} — actor attribution was lost"
        )
