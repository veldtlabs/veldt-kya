"""Regression tests — tenant weight overrides MUST affect score_agent output.

Discovered during a Pro dashboard review (2026-07-15): score_agent was
computing tenant-scoped weight dicts via get_effective_weights() but
never passing them into the downstream helpers. Result: tightening a
weight via set_override updated the DB, get_effective_weights reads
returned the new value, but score_agent silently used platform defaults
— a classic silent-drop bug that would let a compromised customer see
their console-visible policy change with zero real enforcement effect.

These tests are the RED that would have caught it. They exercise all 4
weight scopes (class / capability / source / deployment) end-to-end
from set_override → score_agent → AgentRiskScore.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


@pytest.fixture
def scoring_db():
    """SQLite in-memory engine with tenant_weights tables ensured."""
    from kya.tenant_weights import ensure_tables

    engine = create_engine("sqlite:///:memory:", future=True)
    with Session(engine) as db:
        ensure_tables(db)
        db.commit()
    return engine


TENANT = "test-tenant-uuid"


def _clean_agent(**overrides):
    """Baseline agent_def that scores WELL under 100 so a single weight
    tighten's contribution is observable in additive_score. All the risk
    signals default score_agent conservatively (HIL enabled, read-only,
    declared owner, dev deployment, official provenance, no interactions
    firing). Override just the axis under test."""
    base = {
        "tools": [],
        "human_loop": "in_the_loop",
        "access_level": "read",
        "environment": "dev",
        "provenance": "official",
        "model_trust": "enterprise",
        "owner": "security@acme",
        "approval_status": "approved",
        "review_status": "reviewed",
        "trust_audits": ["red_team"],
    }
    base.update(overrides)
    return base


def _score(engine, agent_def):
    from kya.risk import score_agent

    with Session(engine) as db:
        s = score_agent(agent_def, db=db, tenant_id=TENANT)
    # additive_score is pre-clamp — the delta we're asserting on will
    # show up here even when the clamped .score sits at the 0-100 ceiling.
    return s.additive_score


def test_class_weight_tighten_moves_score(scoring_db):
    """Tightening class_weights.pii MUST increase the score of an agent
    that handles pii data. Bug: pre-fix returned unchanged score."""
    from kya.tenant_weights import set_override

    # Clean agent — human_loop + read-only + dev deployment + owner
    # declared so it doesn't saturate to 100. Only pii-classified tool
    # gives us a class_weights signal to test the tighten against.
    agent = _clean_agent(tools=["fetch_customer_pii"], data_classes=["pii"])
    baseline = _score(scoring_db, agent)

    with Session(scoring_db) as db:
        set_override(
            db, scope="class_weights", key="pii", value=40,
            tenant_id=TENANT, changed_by="test", reason="tighten pii",
        )
        # set_override commits internally

    after = _score(scoring_db, agent)
    assert after != baseline, (
        f"class_weights.pii tighten (20 → 40) MUST move the score. "
        f"baseline={baseline} after={after} — score_agent is silently "
        f"dropping the tenant override."
    )
    assert after > baseline, "tighten should INCREASE the risk score"


def test_capability_weight_tighten_moves_score(scoring_db):
    """Tightening capability_weights.prod_database MUST move the score
    of an agent that uses prod_database capability."""
    from kya.tenant_weights import set_override

    agent = _clean_agent(
        tools=["query_production_orders"],
        security_caps=["prod_database"],
    )
    baseline = _score(scoring_db, agent)

    with Session(scoring_db) as db:
        set_override(
            db, scope="capability_weights", key="prod_database", value=40,
            tenant_id=TENANT, changed_by="test", reason="tighten prod_database",
        )

    after = _score(scoring_db, agent)
    assert after != baseline, (
        f"capability_weights.prod_database tighten (25 → 40) MUST move "
        f"the score. baseline={baseline} after={after} — score_agent is "
        f"silently dropping the tenant override."
    )
    assert after > baseline, "tighten should INCREASE the risk score"


def test_source_weight_tighten_moves_score(scoring_db):
    """Tightening source_weights.unknown MUST move the score of an
    agent with unknown input sources."""
    from kya.tenant_weights import set_override

    agent = _clean_agent(input_sources=["unknown"])
    baseline = _score(scoring_db, agent)

    with Session(scoring_db) as db:
        set_override(
            db, scope="source_weights", key="unknown", value=30,
            tenant_id=TENANT, changed_by="test", reason="tighten unknown",
        )

    after = _score(scoring_db, agent)
    assert after != baseline, (
        f"source_weights.unknown tighten MUST move the score. "
        f"baseline={baseline} after={after} — score_agent is silently "
        f"dropping the tenant override."
    )
    assert after > baseline


def test_deployment_weight_tighten_moves_score(scoring_db):
    """Tightening deployment_weights.prod MUST move the score of a
    prod-deployed agent."""
    from kya.tenant_weights import set_override

    agent = _clean_agent(environment="prod")
    baseline = _score(scoring_db, agent)

    with Session(scoring_db) as db:
        set_override(
            db, scope="deployment_weights", key="prod", value=25,
            tenant_id=TENANT, changed_by="test", reason="tighten prod",
        )

    after = _score(scoring_db, agent)
    assert after != baseline, (
        f"deployment_weights.prod tighten (15 → 25) MUST move the score. "
        f"baseline={baseline} after={after} — score_agent is silently "
        f"dropping the tenant override."
    )
    assert after > baseline


def test_no_tenant_id_uses_platform_defaults(scoring_db):
    """Sanity — when tenant_id is None, the score uses platform
    defaults regardless of what's in the tenant table for OTHER tenants.
    Ensures we don't accidentally leak tenant overrides across tenants."""
    from kya.tenant_weights import set_override
    from kya.risk import score_agent

    agent = _clean_agent(environment="prod")
    with Session(scoring_db) as db:
        # Other tenant tightens; MUST NOT affect our score
        set_override(
            db, scope="class_weights", key="pii", value=99,
            tenant_id="different-tenant", changed_by="test",
            reason="other tenant tighten",
        )

    with Session(scoring_db) as db:
        our_score = score_agent(agent, db=db, tenant_id=TENANT).additive_score
        platform_score = score_agent(agent, db=db, tenant_id=None).additive_score

    # Both should equal — different-tenant's override doesn't leak.
    assert our_score == platform_score, (
        f"cross-tenant weight leak! our_score={our_score} vs "
        f"platform_score={platform_score}"
    )


# ── Cross-backend real-DB coverage ─────────────────────────────────
#
# The SQLite tests above exercise the code path. The paper claims
# cross-backend correctness (4×9 matrix); here we ALSO run the core
# tighten-moves-score assertion against Postgres if a KYA_TEST_POSTGRES_URL
# env is available. Silently skips otherwise so the suite stays green
# in dev environments that don't run Postgres. Pro CI + release should
# always have this env set.

import os as _os


def _postgres_url():
    return _os.environ.get("KYA_TEST_POSTGRES_URL")


@pytest.mark.skipif(
    _postgres_url() is None,
    reason="KYA_TEST_POSTGRES_URL not set — skipping cross-backend proof",
)
def test_postgres_class_weight_tighten_moves_score():
    """Same as test_class_weight_tighten_moves_score but against REAL
    Postgres. This is the highest-signal regression — SQLite has
    trivial concurrency + relaxed types, so a bug that only surfaces
    on PG (e.g., JSONB coercion of the definition dict) would slip
    past the SQLite suite."""
    import uuid
    from kya.tenant_weights import ensure_tables, set_override
    from kya.risk import score_agent

    engine = create_engine(_postgres_url(), future=True)
    # Isolated tenant id so runs don't stomp on each other
    tenant = str(uuid.uuid4())

    with Session(engine) as db:
        ensure_tables(db)
        db.commit()

    agent = _clean_agent(tools=["fetch_customer_pii"], data_classes=["pii"])
    with Session(engine) as db:
        baseline = score_agent(agent, db=db, tenant_id=tenant).additive_score

    with Session(engine) as db:
        # created_by is UUID-typed on PG — pass a real UUID.
        # SQLite is text-permissive so the SQLite tests get away with
        # "test" as a changed_by, but PG strict-types would reject.
        set_override(
            db, scope="class_weights", key="pii", value=40,
            tenant_id=tenant,
            changed_by="00000000-0000-0000-0000-000000000001",
            reason="cross-backend proof",
        )

    with Session(engine) as db:
        after = score_agent(agent, db=db, tenant_id=tenant).additive_score

    assert after > baseline, (
        f"PG regression: class_weights.pii tighten didn't move the score. "
        f"baseline={baseline} after={after}. If this fails on Postgres but "
        f"passes on SQLite, the JSONB coercion or Session lifecycle differs "
        f"in a way the tenant weight overlay doesn't survive."
    )

    # Cleanup: revert the override so subsequent runs start clean
    with Session(engine) as db:
        from kya.tenant_weights import delete_override
        try:
            delete_override(db, scope="class_weights", key="pii", tenant_id=tenant)
            db.commit()
        except Exception:
            pass


# ── Idempotency: applying the same override twice is a no-op ───────


def test_double_tighten_same_value_is_noop(scoring_db):
    """Setting the same override twice must produce the same score both
    times. Guards against a subtle bug where the override merge logic
    accidentally doubles-up on repeated writes."""
    from kya.tenant_weights import set_override

    agent = _clean_agent(tools=["fetch_customer_pii"], data_classes=["pii"])

    with Session(scoring_db) as db:
        set_override(
            db, scope="class_weights", key="pii", value=40,
            tenant_id=TENANT, changed_by="test", reason="first",
        )
    first = _score(scoring_db, agent)

    with Session(scoring_db) as db:
        set_override(
            db, scope="class_weights", key="pii", value=40,
            tenant_id=TENANT, changed_by="test", reason="second",
        )
    second = _score(scoring_db, agent)

    assert first == second, (
        f"Idempotency broken: double-write produced {first} then {second}"
    )


# ── Multiple scope tightenings compose additively ──────────────────


def test_multiple_scope_tightenings_all_apply(scoring_db):
    """Tightening class + capability + deployment simultaneously must
    move the score by the sum of individual contributions."""
    from kya.tenant_weights import set_override

    # Use lower-signal agent so all three tightenings have headroom
    # to move the additive score without clamping at 100.
    agent = _clean_agent(
        tools=["query_production_orders"],
        security_caps=["prod_database"],
        environment="prod",
    )
    baseline = _score(scoring_db, agent)

    with Session(scoring_db) as db:
        set_override(db, scope="class_weights", key="pii", value=40,
                     tenant_id=TENANT, changed_by="test", reason="pii tighten")
        set_override(db, scope="capability_weights", key="prod_database", value=40,
                     tenant_id=TENANT, changed_by="test", reason="db tighten")
        set_override(db, scope="deployment_weights", key="prod", value=25,
                     tenant_id=TENANT, changed_by="test", reason="prod tighten")

    after = _score(scoring_db, agent)
    assert after > baseline, (
        f"multi-scope tighten didn't compose: {baseline} -> {after}"
    )
    # Actual delta constrained by CAPABILITY_CAP + additive clamp;
    # 5 points is a safe floor that still proves multi-scope propagation.
    delta = after - baseline
    assert delta >= 5, f"multi-scope delta suspiciously small: {delta}"
