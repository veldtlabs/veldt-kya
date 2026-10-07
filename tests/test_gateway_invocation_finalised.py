"""The pre-policy invocation row must reach a terminal outcome.

``kya_gateway.server._record_invocation_pre_policy`` reserves a row
with ``OUTCOME_PENDING`` on EVERY gateway request, and the outcome
vocabulary in ``kya.invocations`` promises it is "updated to a
terminal outcome after the decision". Nothing implemented that: no
code anywhere read ``request.state.kya_invocation_id`` and the gateway
never updated an outcome. So every request left a permanently
non-terminal row, and the audit surface could not distinguish "still
running" from "nobody ever closed it".

``flag_for_review`` is the deliberate exception. The same vocabulary
says ``pending`` is "also used by external approval queue writers that
reserve an id before the human / external system decides" — those rows
are genuinely unfinished, so closing them would destroy the HITL
queue's semantics.

Real SQLite engine, real gateway app, real TestClient POST, and the
assertion is a SELECT on the row. Reuses the harness from
``test_gateway_flag_for_review_pending`` rather than building a second
one.
"""
from __future__ import annotations

import pytest


def _harness():
    """Import the sibling harness INSIDE a function.

    A module-scope import of a sibling test module raises at
    COLLECTION time if ``tests`` is not a package, which aborts the
    entire suite rather than failing one file.
    """
    from test_gateway_flag_for_review_pending import (
        _build_gateway,
        _install_real_kya_with_engine,
        _mcp_call_body,
    )
    return _build_gateway, _install_real_kya_with_engine, _mcp_call_body


def _fresh_engine(tmp_path, monkeypatch):
    """Real SQLite engine wired into kya, with ``record_invocation``
    LEFT REAL.

    The sibling harness stubs ``record_invocation`` to return a fixed
    id without writing anything — fine for its purpose, useless here,
    because the row IS what this test asserts on. Everything else
    (``_build_gateway``, ``_mcp_call_body``) is reused from it.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    engine = create_engine(f"sqlite:///{tmp_path}/gw-final.db")

    from kya.pending_invocations import _ENSURED_ENGINES, ensure_table
    _ENSURED_ENGINES.clear()
    ensure_table(engine)

    from kya.invocations import ensure_invocations_table
    with Session(engine) as _db:
        ensure_invocations_table(_db)
        _db.commit()

    import kya as _real_kya

    class _Sess(Session):
        def __init__(self):
            super().__init__(bind=engine)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.close()
            return False

    monkeypatch.setattr(_real_kya, "default_session", lambda: _Sess())
    # record_invocation deliberately NOT patched. The rest are stubbed
    # for isolation, matching the sibling harness.
    monkeypatch.setattr(_real_kya, "record_evidence", lambda db, **kw: 1)
    monkeypatch.setattr(
        _real_kya, "record_principal_signal", lambda db, **kw: 1,
    )
    monkeypatch.setattr(_real_kya, "require_action", lambda *a, **k: True)
    return engine


def _outcomes(engine) -> list[str]:
    from sqlalchemy import text as _sql

    with engine.connect() as conn:
        return [
            r[0] for r in conn.execute(
                _sql("SELECT outcome FROM kya_invocations ORDER BY id"),
            )
        ]


@pytest.mark.parametrize("verdict,expected", [
    ("allow", "success"),
    ("deny", "denied"),
])
def test_decided_request_leaves_a_terminal_invocation(
    monkeypatch, tmp_path, verdict, expected,
):
    """A decided request must not leave a ``pending`` row behind."""
    from fastapi.testclient import TestClient

    _build_gateway, _, _mcp_call_body = _harness()
    engine = _fresh_engine(tmp_path, monkeypatch)
    gw = _build_gateway(monkeypatch, verdict)

    client = TestClient(gw.app)
    client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer secret-token-do-not-persist",
    })

    outcomes = _outcomes(engine)
    assert outcomes, "no invocation row was recorded at all"
    assert "pending" not in outcomes, (
        f"the pre-policy row was never finalised: {outcomes}. Every "
        f"gateway request leaves a permanently non-terminal row and "
        f"the audit surface reports it as unfinished forever."
    )
    assert expected in outcomes, (
        f"expected a {expected!r} outcome for verdict {verdict!r}; "
        f"got {outcomes}"
    )


def test_flag_for_review_deliberately_stays_pending(monkeypatch, tmp_path):
    """The exception, and it is load-bearing.

    A ``flag_for_review`` invocation is waiting on a human. Closing it
    would make the approval queue's own rows look decided, so the
    verdict is deliberately absent from the mapping. If someone
    "completes" that mapping, this fails.
    """
    from fastapi.testclient import TestClient

    _build_gateway, _, _mcp_call_body = _harness()
    engine = _fresh_engine(tmp_path, monkeypatch)
    gw = _build_gateway(monkeypatch, "flag_for_review")

    client = TestClient(gw.app)
    r = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer secret-token-do-not-persist",
    })
    assert r.status_code == 428, r.text

    outcomes = _outcomes(engine)
    assert "pending" in outcomes, (
        f"a flag_for_review invocation was finalised: {outcomes}. It is "
        f"still awaiting a human decision, so closing it makes the "
        f"approval queue report decided rows that nobody decided."
    )


# ── Facts the first pass left unanchored ─────────────────────────
#
# A review ran six sabotages against this file; four stayed GREEN:
# removing the /v1/policy/decide finalise, deleting the transition
# guard from the UPDATE, making the primitive always return True, and
# collapsing the derived TERMINAL_OUTCOMES. Each is pinned below.


def test_every_canonical_verdict_is_mapped_or_deliberately_pending():
    """No verdict may leak silently.

    Only ``allow``/``deny`` were mapped at first, so ``block``,
    ``throttle``, ``redact`` and ``anonymize`` — all DECIDED and
    refused, nobody waiting on a human — left permanently
    non-terminal rows. Iterating the canonical set means the next
    verdict added fails here instead of leaking.
    """
    from kya.canonicals import CANONICAL_VERDICTS
    from kya_gateway.server import (
        _DELIBERATELY_PENDING_VERDICTS,
        _VERDICT_TO_TERMINAL_OUTCOME,
    )

    unhandled = sorted(
        set(CANONICAL_VERDICTS)
        - set(_VERDICT_TO_TERMINAL_OUTCOME)
        - set(_DELIBERATELY_PENDING_VERDICTS)
    )
    assert not unhandled, (
        f"verdict(s) {unhandled} neither map to a terminal outcome nor "
        f"are declared deliberately-pending, so a decided request "
        f"leaves a permanently non-terminal row"
    )


def test_mapped_outcomes_are_all_terminal():
    """A mapping entry pointing at a non-terminal outcome would make
    ``finalize_invocation_outcome`` raise at runtime, on the request
    path, for every request with that verdict."""
    from kya.canonicals import TERMINAL_OUTCOMES
    from kya_gateway.server import _VERDICT_TO_TERMINAL_OUTCOME

    bad = {
        v: o for v, o in _VERDICT_TO_TERMINAL_OUTCOME.items()
        if o not in TERMINAL_OUTCOMES
    }
    assert not bad, f"mapping points at non-terminal outcome(s): {bad}"


def test_terminal_outcomes_is_derived_not_duplicated():
    """``TERMINAL_OUTCOMES`` must stay a derivation. Hardcoding it is
    how the two sets drift when an outcome is added."""
    from kya.canonicals import (
        CANONICAL_OUTCOMES,
        NON_TERMINAL_OUTCOMES,
        TERMINAL_OUTCOMES,
    )

    assert TERMINAL_OUTCOMES == CANONICAL_OUTCOMES - NON_TERMINAL_OUTCOMES
    assert not (TERMINAL_OUTCOMES & NON_TERMINAL_OUTCOMES), (
        "the two sets overlap — an outcome is both terminal and not"
    )
    assert TERMINAL_OUTCOMES | NON_TERMINAL_OUTCOMES == CANONICAL_OUTCOMES, (
        "the partition does not cover the vocabulary"
    )


def _reserved_row(tmp_path):
    """A real pending invocation row on a real engine."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from kya.invocations import (
        ensure_invocations_table, record_invocation,
    )

    engine = create_engine(f"sqlite:///{tmp_path}/fin-unit.db")
    with Session(engine) as db:
        ensure_invocations_table(db)
        inv = record_invocation(
            db, tenant_id="t", agent_key="a", principal_kind="agent",
            principal_id="p", mode="observed", outcome="pending",
        )
        db.commit()
    return engine, inv


def test_transition_guard_never_rewrites_a_terminal_row(tmp_path):
    """The single most important line in the primitive: the UPDATE's
    ``outcome IN NON_TERMINAL_OUTCOMES`` clause. Without it a late or
    duplicate finalise silently overwrites a recorded disposition."""
    from sqlalchemy import text
    from sqlalchemy.orm import Session
    from kya.invocations import finalize_invocation_outcome

    engine, inv = _reserved_row(tmp_path)
    with Session(engine) as db:
        assert finalize_invocation_outcome(
            db, invocation_id=inv, outcome="denied", tenant_id="t") is True
        db.commit()
        # A second, DIFFERENT finalise must not take.
        assert finalize_invocation_outcome(
            db, invocation_id=inv, outcome="success", tenant_id="t") is False
        db.commit()
        got = db.execute(
            text("SELECT outcome FROM kya_invocations WHERE id=:i"),
            {"i": inv},
        ).scalar()
    assert got == "denied", (
        f"a terminal row was rewritten to {got!r} — history is being "
        f"overwritten by a duplicate finalise"
    )


def test_rowcount_contract_and_tenant_scoping(tmp_path):
    """``False`` must mean "nothing transitioned", not "done". A
    primitive that always returns True makes every caller blind."""
    from sqlalchemy.orm import Session
    from kya.invocations import finalize_invocation_outcome

    engine, inv = _reserved_row(tmp_path)
    with Session(engine) as db:
        assert finalize_invocation_outcome(
            db, invocation_id=inv, outcome="success",
            tenant_id="someone-else") is False, (
            "closed a row belonging to another tenant"
        )
        assert finalize_invocation_outcome(
            db, invocation_id=999999, outcome="success",
            tenant_id="t") is False, "claimed to close an unknown id"
        assert finalize_invocation_outcome(
            db, invocation_id=None, outcome="success") is False


@pytest.mark.parametrize("verdict,expected", [
    ("block", "blocked"),
    ("throttle", "throttled"),
])
def test_refused_verdicts_also_reach_a_terminal_outcome(
    monkeypatch, tmp_path, verdict, expected,
):
    """``block`` and ``throttle`` are decided refusals — nobody is
    waiting on a human — so they must not stay pending."""
    from fastapi.testclient import TestClient

    import kya_gateway.server as S
    from kya_gateway.policy_pipeline import Verdict

    _build_gateway, _, _mcp_call_body = _harness()
    engine = _fresh_engine(tmp_path, monkeypatch)
    gw = _build_gateway(monkeypatch, "deny")

    # These four verdicts are NOT reachable from the built-in config,
    # which emits allow / deny / flag_for_review. They arrive from a
    # third-party evaluator plugin, which policy_pipeline admits into
    # Verdict.verdict. Forcing the Verdict is therefore the faithful
    # reproduction, not a shortcut: config alone falls back to allow,
    # which is why the first version of this test passed vacuously.
    monkeypatch.setattr(
        S, "_run_policy",
        lambda **kw: Verdict(
            verdict=verdict, reason_codes=["TEST"],
            signal_kind="test", rich=None,
        ),
    )

    client = TestClient(gw.app)
    client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer secret-token-do-not-persist",
    })

    outcomes = _outcomes(engine)
    assert "pending" not in outcomes, (
        f"verdict {verdict!r} left a pending row: {outcomes}"
    )
    assert expected in outcomes, f"expected {expected!r}, got {outcomes}"


def test_pipeline_crash_closes_the_row_as_error(monkeypatch, tmp_path):
    """A pipeline crash is a decided, fail-closed deny. The crash
    handlers return BEFORE the normal finalise, so without an explicit
    close every evaluator crash leaks a non-terminal row — and those
    are the incidents where the audit trail matters most."""
    from fastapi.testclient import TestClient
    import kya_gateway.server as S

    _build_gateway, _, _mcp_call_body = _harness()
    engine = _fresh_engine(tmp_path, monkeypatch)
    gw = _build_gateway(monkeypatch, "allow")

    def _boom(*a, **k):
        raise RuntimeError("evaluator exploded")

    monkeypatch.setattr(S, "_run_policy", _boom)

    client = TestClient(gw.app)
    r = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer secret-token-do-not-persist",
    })
    assert r.status_code == 500, r.text

    outcomes = _outcomes(engine)
    assert "pending" not in outcomes, (
        f"a pipeline crash left a pending row: {outcomes}"
    )
    assert "error" in outcomes, f"expected 'error', got {outcomes}"


@pytest.mark.parametrize("verdict,expected", [
    ("allow", "success"),
    ("deny", "denied"),
])
def test_decide_endpoint_also_finalises(
    monkeypatch, tmp_path, verdict, expected,
):
    """``/v1/policy/decide`` reserves its own row and has its own
    finalise call. Removing that call left the whole suite green, so
    the second handler's wire-up was dead-code-indistinguishable.
    """
    from fastapi.testclient import TestClient

    _build_gateway, _, _ = _harness()
    engine = _fresh_engine(tmp_path, monkeypatch)
    gw = _build_gateway(monkeypatch, verdict)

    client = TestClient(gw.app)
    r = client.post("/v1/policy/decide", json={
        "tool_name": "filesystem.delete_file",
        "tool_input": {"path": "/tmp/x"},
    }, headers={"Authorization": "Bearer secret-token-do-not-persist"})
    assert r.status_code in (200, 403), r.text

    outcomes = _outcomes(engine)
    assert outcomes, "the decide path recorded no invocation at all"
    assert "pending" not in outcomes, (
        f"/v1/policy/decide left a pending row: {outcomes}"
    )
    assert expected in outcomes, f"expected {expected!r}, got {outcomes}"


def test_decide_pipeline_crash_closes_the_row_as_error(monkeypatch, tmp_path):
    """The decide handler reserves its id INSIDE the try, so its crash
    handler could not even see the id until it was hoisted. Pins both
    the hoist and the finalise."""
    from fastapi.testclient import TestClient
    import kya_gateway.server as S

    _build_gateway, _, _ = _harness()
    engine = _fresh_engine(tmp_path, monkeypatch)
    gw = _build_gateway(monkeypatch, "allow")

    def _boom(*a, **k):
        raise RuntimeError("evaluator exploded")

    monkeypatch.setattr(S, "_run_policy", _boom)

    client = TestClient(gw.app)
    r = client.post("/v1/policy/decide", json={
        "tool_name": "filesystem.delete_file",
        "tool_input": {"path": "/tmp/x"},
    }, headers={"Authorization": "Bearer secret-token-do-not-persist"})
    assert r.status_code == 500, r.text

    outcomes = _outcomes(engine)
    assert "pending" not in outcomes, (
        f"a decide-path crash left a pending row: {outcomes}"
    )
    assert "error" in outcomes, f"expected 'error', got {outcomes}"
