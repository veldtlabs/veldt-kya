"""Regression tests for two PG-only bugs surfaced by the 4-backend e2e:

1. `kya/users.py:_upsert_with_delta` PG path — `jsonb_build_object(:kind, 1)`
   and `ARRAY[:kind]` hit psycopg3 `AmbiguousParameter` because the param
   appears in contexts where the OID can't be inferred. Fix: explicit
   `CAST(:kind AS text)` at each use.

2. `kya/storage.py:_table_exists` — `has_table(name)` without a `schema=`
   arg checks `current_schema()` only (default `public` on PG). When an
   operator sets `KYA_VERSIONS_SCHEMA` to a non-default value (the
   `veldt-decisions` monorepo and the e2e use `"prov_schema"`; pro /
   multi-tenant operators may use their own), tables get created in
   that schema but the probe still looks in `public` — false-skip.
   Default `public` deployments (the OSS PyPI default) are unaffected.
   Fix: pass the configured schema and fall back to the default schema
   for resilience.

Both reproduce only on PostgreSQL. Skipped when KYA_TEST_PG_URL is unset.
"""
from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

PG_URL = os.environ.get("KYA_TEST_PG_URL")
pytestmark = pytest.mark.skipif(
    not PG_URL, reason="KYA_TEST_PG_URL not set — PG bugs are PG-only"
)

PROV_SCHEMA = "prov_schema"
_KYA_TABLES = (
    "agent_versions", "kya_invocations", "kya_principal_trust",
    "kya_evidence", "kya_agent_aliases", "kya_user_trust",
    "kya_weight_overrides", "kya_weight_changes",
    "kya_weight_suggestions", "kya_breach_notifications",
    "kya_redteam_campaigns", "kya_redteam_findings",
    "kya_redteam_tenant_policy", "kya_redteam_runs",
    "kya_redteam_targets", "kya_redteam_target_secrets",
    "kya_inbound_recommendations",
)


@pytest.fixture
def pg_engine(monkeypatch):
    """Fresh PG engine with KYA tables dropped + prov_schema ready.

    Uses monkeypatch so KYA_VERSIONS_SCHEMA is restored on test exit —
    otherwise the env leaks across tests in the same pytest session
    and the 4db_review suite (which assumes default public schema)
    creates tables in prov_schema and then can't find them when it
    inspects public.
    """
    monkeypatch.setenv("KYA_VERSIONS_SCHEMA", PROV_SCHEMA)
    e = create_engine(PG_URL)
    with e.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {PROV_SCHEMA}"))
        for t in _KYA_TABLES:
            conn.execute(text(f"DROP TABLE IF EXISTS {PROV_SCHEMA}.{t} CASCADE"))
    yield e
    e.dispose()


# ── Bug 1 — user_trust AmbiguousParameter ────────────────────────────


def test_record_user_signal_succeeds_on_pg(pg_engine):
    """Pre-fix: psycopg.errors.AmbiguousParameter on $4 (the signal_kind
    inside jsonb_build_object). Post-fix: signal recorded, score
    decremented, signal_counts JSONB accumulates per kind."""
    with Session(pg_engine) as db:
        from kya.users import ensure_user_trust_table, record_user_signal
        ensure_user_trust_table(db)
        db.commit()
        tid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        s1 = record_user_signal(db, tid, uid, "rogue_burst")
        s2 = record_user_signal(db, tid, uid, "rogue_burst")
        s3 = record_user_signal(db, tid, uid, "data_leak_attempt")
    assert s1 < 50, f"first signal should decrement from STARTING_TRUST=50; got {s1}"
    assert s2 < s1, f"second signal should decrement further; got {s2} vs {s1}"
    assert s3 < s2, f"different kind should decrement; got {s3} vs {s2}"

    with pg_engine.connect() as conn:
        row = conn.execute(
            text(f"SELECT signal_counts FROM {PROV_SCHEMA}.kya_user_trust "
                 f"WHERE user_id = :u"),
            {"u": uid},
        ).fetchone()
    assert row is not None
    counts = row[0]
    assert counts.get("rogue_burst") == 2, f"counts={counts}"
    assert counts.get("data_leak_attempt") == 1, f"counts={counts}"


def test_record_user_clean_succeeds_on_pg(pg_engine):
    """Same AmbiguousParameter blocked record_user_clean too —
    same SQL path with `clean_invocation` kind."""
    with Session(pg_engine) as db:
        from kya.users import ensure_user_trust_table, record_user_clean
        ensure_user_trust_table(db)
        db.commit()
        tid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        s = record_user_clean(db, tid, uid)
    assert s >= 50, f"first clean signal should not drop below STARTING_TRUST; got {s}"


# ── Bug 2 — init_storage false-skip on non-default schema ────────────


def test_init_storage_no_false_skip_on_pg(pg_engine):
    """Pre-fix: kya_weight_overrides+changes reported as 'ensure_*
    returned but table not in catalog' because _table_exists probed
    default schema. Post-fix: all 17 tables succeed."""
    with Session(pg_engine) as db:
        from kya import storage
        report = storage.init_storage(db)
        db.commit()

    # All 17 entries in _TABLE_SETUP_PLAN should succeed (modules
    # available + tables in catalog). If new entries are added to
    # the plan this assertion needs updating — that's fine, it's a
    # check that nothing got false-skipped.
    assert len(report["skipped"]) == 0, (
        f"unexpected skipped entries: {report['skipped']}"
    )
    # Sanity: the previously-false-skipped one is in `succeeded`
    assert "kya_weight_overrides+changes" in report["succeeded"], (
        f"kya_weight_overrides+changes missing from succeeded: "
        f"{report['succeeded']}"
    )

    # Both tables ARE actually in the catalog (not just reported so)
    insp = inspect(pg_engine)
    schema_tables = set(insp.get_table_names(schema=PROV_SCHEMA))
    assert "kya_weight_overrides" in schema_tables
    assert "kya_weight_changes" in schema_tables


def test_init_storage_succeeded_count_matches_plan_on_pg(pg_engine):
    """Confirm the count is exactly the plan size (catches regressions
    where a future skip would go silently)."""
    from kya.storage import _TABLE_SETUP_PLAN

    with Session(pg_engine) as db:
        from kya import storage
        report = storage.init_storage(db)
        db.commit()

    assert len(report["succeeded"]) == len(_TABLE_SETUP_PLAN), (
        f"succeeded={len(report['succeeded'])} != plan size="
        f"{len(_TABLE_SETUP_PLAN)} | skipped={report['skipped']}"
    )


# ── Cross-bug: combined e2e under non-default schema ─────────────────


def test_pg_e2e_init_storage_then_record_user_signal(pg_engine):
    """Both fixes together: init_storage on prov_schema → record signal →
    table row visible. Mirrors the e2e verifier's PG path."""
    with Session(pg_engine) as db:
        from kya import storage
        report = storage.init_storage(db)
        db.commit()
    assert report["all_ok"], report["skipped"]

    from kya.users import record_user_signal
    with Session(pg_engine) as db:
        tid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        record_user_signal(db, tid, uid, "rogue_burst")

    with pg_engine.connect() as conn:
        n = conn.execute(
            text(f"SELECT COUNT(*) FROM {PROV_SCHEMA}.kya_user_trust")
        ).scalar()
    assert n == 1
