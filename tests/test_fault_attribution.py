"""agent_divergence_score: what it counts, and what it cannot tell you."""
from __future__ import annotations

import pathlib
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("sqlalchemy")


@pytest.fixture()
def db(monkeypatch):
    # monkeypatch, not os.environ directly: a leaked KYA_DB_URL is
    # inherited by subprocesses that later tests spawn, and they then
    # open this empty scratch database instead of their own.
    tmp = tempfile.mkdtemp()
    monkeypatch.setenv(
        "KYA_DB_URL",
        "sqlite:///" + pathlib.Path(tmp, "fa.db").as_posix())
    import kya
    with kya.default_session() as session:
        kya.ensure_invocations_table(session)
        yield session


def _seed(kya, session, agent_key, outcome, n=12, started_at=None,
          tenant="fa-test"):
    for _ in range(n):
        kya.record_invocation(
            session, tenant_id=tenant, agent_key=agent_key,
            principal_kind="agent", principal_id="p", mode="enforce",
            outcome=outcome, duration_ms=5, started_at=started_at)
    session.commit()


def test_scores_rows_written_without_started_at(db):
    """`started_at` is optional; omitting it must not hide the rows.

    Regression: the window filtered on `started_at` alone, so invocations
    recorded through the documented API without that optional argument
    were reported as "No invocations recorded in this window" while
    sitting in the table.
    """
    import kya
    from kya.fault_attribution import agent_divergence_score

    _seed(kya, db, "no-started-at", "blocked")
    report = agent_divergence_score(db, "fa-test", "no-started-at")

    assert report.total_invocations == 12
    assert report.blocked_count == 12
    assert report.classification != "insufficient_data"


def test_scores_rows_written_with_started_at(db):
    import kya
    from kya.fault_attribution import agent_divergence_score

    _seed(kya, db, "with-started-at", "blocked",
          started_at=datetime.now(timezone.utc))
    report = agent_divergence_score(db, "fa-test", "with-started-at")

    assert report.total_invocations == 12


def test_rows_outside_the_window_are_excluded(db):
    """The COALESCE fallback must not widen the window."""
    import kya
    from kya.fault_attribution import agent_divergence_score

    old = datetime.now(timezone.utc) - timedelta(days=40)
    _seed(kya, db, "ancient", "blocked", started_at=old)
    report = agent_divergence_score(db, "fa-test", "ancient", window_days=7)

    assert report.total_invocations == 0
    assert report.classification == "insufficient_data"


def test_documented_formula_matches_the_implementation(db):
    """The header specifies the weights; this pins them.

    A previous header documented a rogue-signal term weighted 2.0 that the
    code did not implement, and omitted the error term that it did.
    """
    import kya
    from kya.fault_attribution import agent_divergence_score

    _seed(kya, db, "half-blocked", "blocked", n=6)
    _seed(kya, db, "half-blocked", "success", n=6)
    report = agent_divergence_score(db, "fa-test", "half-blocked")

    assert report.total_invocations == 12
    assert report.blocked_count == 6
    # (6/12) * 1.5
    assert report.divergence_score == pytest.approx(0.75)


def test_below_the_sample_floor_is_insufficient_data(db):
    import kya
    from kya.fault_attribution import agent_divergence_score

    _seed(kya, db, "sparse", "blocked", n=3)
    report = agent_divergence_score(db, "fa-test", "sparse")

    assert report.classification == "insufficient_data"


def test_score_does_not_identify_where_a_fault_originated(db):
    """The documented limitation, pinned so it cannot change by accident.

    The score is a rate of governance intervention against one agent. It
    reads no delegation lineage, so given user -> orchestrator -> delegate
    it cannot tell a delegate acting on its own from one carrying out
    exactly what it was asked: the delegate is the one that reaches for
    the resource, so the delegate is the one refused, in every case.

    If this test starts failing because the score became lineage-aware,
    that is a deliberate change — update the Limitations section in the
    module docstring and the bucket text along with it.
    """
    import kya
    from kya.fault_attribution import agent_divergence_score

    for scenario in ("user_originated", "orchestrator_originated",
                     "delegate_originated"):
        _seed(kya, db, f"{scenario}:user", "success")
        _seed(kya, db, f"{scenario}:orchestrator", "success")
        _seed(kya, db, f"{scenario}:delegate", "blocked")

    scores = {
        scenario: agent_divergence_score(
            db, "fa-test", f"{scenario}:delegate").divergence_score
        for scenario in ("user_originated", "orchestrator_originated",
                         "delegate_originated")
    }
    assert len(set(scores.values())) == 1, (
        "the score distinguished scenarios it has no lineage to "
        f"distinguish: {scores}")

    # And the level that was actually at fault is not the one scored.
    user_side = agent_divergence_score(
        db, "fa-test", "user_originated:user")
    assert user_side.divergence_score == 0.0


def test_bucket_text_describes_the_measurement_not_a_cause(db):
    """The interpretation says what was measured, not who is to blame.

    The banned phrases are the exact claims the text used to make, not the
    word "cause" — the current text says "not a finding that it is the
    root cause", and a naive substring ban fails on that disclaimer while
    still passing on a fresh overclaim like "the agent did it".
    """
    import kya
    from kya.fault_attribution import agent_divergence_score

    _seed(kya, db, "always-blocked", "blocked")
    report = agent_divergence_score(db, "fa-test", "always-blocked")
    text = report.interpretation.lower()

    assert report.classification == "agent_misbehavior"
    for overclaim in ("the agent is the likely root cause",
                      "bias attribution away"):
        assert overclaim not in text, (
            f"the bucket text asserts a cause the score cannot "
            f"establish: {overclaim!r}")
    # It has to say what it DID measure, or it says nothing useful.
    assert "governance intervened" in text
    # And it has to carry the caveat, since the number alone reads as guilt.
    assert "strict policy" in text or "not a finding" in text
