"""Real-world SDK tests — exercises versioning, edge cases, and the
optional extras (metrics, tracing). Run in a clean container with
`pip install veldt-kya[all]` to validate every shipped surface.
"""

import importlib
import os
import sys

import pytest

# Warm litellm at collection time so later tests can stub `openai` in
# sys.modules without wedging litellm's own import chain (litellm
# eagerly re-imports openai during its module init, and if it finds
# our synthetic stub first it hits `openai._models` missing and enters
# a circular-import state). Fixed once here for the whole test file.
# CI runs the wheel in a clean venv without litellm; the autoinstrument
# tests below exercise litellm.cost_per_token via kya.autoinstrument so
# skip the whole file when the optional dep is absent. See
# feedback_test_locally_before_push.md.
pytest.importorskip("litellm")
import litellm  # noqa: F401


def test_pure_scoring_no_storage():
    """Pure functions need zero infra."""
    from kya import bucket_for, score_agent

    r = score_agent({"agent_key": "a", "tools": ["search"]})
    assert 0 <= r.score <= 100
    assert r.bucket in ("low", "medium", "high", "critical")
    assert bucket_for(r.score) == r.bucket


def test_empty_agent():
    """Empty agent doesn't crash."""
    from kya import score_agent

    r = score_agent({})
    assert r.score >= 0
    assert isinstance(r.factors, list)


def test_normalize_each_framework():
    """All 5 framework normalizers must accept their shape and produce
    canonical output that score_agent consumes."""
    from kya import normalize_agent_def, score_agent

    for fw, raw in [
        ("veldt", {"agent_key": "k", "tools": [{"name": "s"}]}),
        (
            "langchain",
            {
                "tools": [{"name": "s", "description": "d"}],
                "agent": {"llm": {"model": "gpt-4o-mini"}},
            },
        ),
        (
            "crewai",
            {"role": "Analyst", "tools": [{"name": "execute_sql"}], "llm": {"model": "claude"}},
        ),
        (
            "openai",
            {
                "name": "Asst",
                "tools": [{"type": "function", "function": {"name": "f"}}],
                "model": "gpt-4",
            },
        ),
        ("generic", {"tools": ["x"], "model": "any"}),
    ]:
        canonical = normalize_agent_def(fw, raw)
        assert isinstance(canonical, dict), f"{fw} normalize returned {type(canonical)}"
        r = score_agent(canonical)
        assert 0 <= r.score <= 100, f"{fw} produced invalid score {r.score}"


def test_drift_detection():
    from kya import canonical_hash, detect_drift

    v1 = {"agent_key": "a", "tools": ["x"]}
    v2 = {"agent_key": "a", "tools": ["x", "y"]}
    h1 = canonical_hash(v1)
    assert isinstance(h1, str) and len(h1) >= 32
    assert detect_drift(h1, v2) is True
    assert detect_drift(h1, v1) is False


def test_compliance_regimes_complete():
    """Regimes that ship controls via required_controls() must populate.
    eu_ai_act is intentionally separate — uses eu_ai_act_tier() instead."""
    from kya import required_controls

    for regime in ("gdpr", "nydfs_500"):
        controls = required_controls([regime])
        assert len(controls) > 0, f"{regime} returned no controls"


def test_eu_ai_act_tier():
    """Heuristic must respond to risk_score + can_override + data."""
    from kya import eu_ai_act_tier

    assert eu_ai_act_tier(95, True, ["pii"]) == "high"
    assert eu_ai_act_tier(20, False, ["public"]) == "minimal"


def test_versioning_with_sqlite():
    """Full version-history flow against in-memory SQLite — exercises the
    dialect-aware DDL path. No graceful-skip: this MUST work."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from kya import ensure_table, get_version, list_versions, rollback_to, snapshot_agent

    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    with Session() as db:
        ensure_table(db)

        v1 = snapshot_agent(db, "tenant_a", "agent_x", {"tools": ["search"]}, note="initial")
        v2 = snapshot_agent(
            db, "tenant_a", "agent_x", {"tools": ["search", "execute_sql"]}, note="added sql"
        )
        v3 = snapshot_agent(
            db,
            "tenant_a",
            "agent_x",
            {"tools": ["search", "execute_sql", "drop_table"]},
            note="risky",
        )
        assert (v1, v2, v3) == (1, 2, 3)

        versions = list_versions(db, "tenant_a", "agent_x")
        assert len(versions) == 3
        assert versions[0]["version_no"] == 3  # newest-first
        assert versions[0]["note"] == "risky"

        fetched = get_version(db, "tenant_a", "agent_x", 2)
        assert fetched is not None
        assert fetched["definition"]["tools"] == ["search", "execute_sql"]

        rolled = rollback_to(db, "tenant_a", "agent_x", version_no=1)
        assert rolled["version_no"] == 4
        assert rolled["definition"]["tools"] == ["search"]
        assert "rolled back from v1" in rolled["note"]


def test_versioning_with_duckdb():
    """Full version-history flow against in-memory DuckDB — proves the
    dialect-aware DDL works on the embedded-analytics backend too.
    Skipped only if duckdb_engine isn't installed in the env."""
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("duckdb-engine not installed")

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from kya import ensure_table, get_version, list_versions, rollback_to, snapshot_agent

    engine = create_engine("duckdb:///:memory:")
    Session = sessionmaker(bind=engine)
    with Session() as db:
        ensure_table(db)

        v1 = snapshot_agent(db, "tenant_a", "agent_x", {"tools": ["search"]}, note="initial")
        v2 = snapshot_agent(
            db, "tenant_a", "agent_x", {"tools": ["search", "execute_sql"]}, note="added sql"
        )
        v3 = snapshot_agent(
            db,
            "tenant_a",
            "agent_x",
            {"tools": ["search", "execute_sql", "drop_table"]},
            note="risky",
        )
        assert (v1, v2, v3) == (1, 2, 3)

        versions = list_versions(db, "tenant_a", "agent_x")
        assert len(versions) == 3
        assert versions[0]["version_no"] == 3
        assert versions[0]["note"] == "risky"

        fetched = get_version(db, "tenant_a", "agent_x", 2)
        assert fetched is not None
        assert fetched["definition"]["tools"] == ["search", "execute_sql"]

        rolled = rollback_to(db, "tenant_a", "agent_x", version_no=1)
        assert rolled["version_no"] == 4
        assert rolled["definition"]["tools"] == ["search"]
        assert "rolled back from v1" in rolled["note"]

        # Cross-tenant isolation on the embedded engine
        snapshot_agent(db, "tenant_b", "agent_x", {"tools": ["other"]}, note="b1")
        assert len(list_versions(db, "tenant_a", "agent_x")) == 4
        assert len(list_versions(db, "tenant_b", "agent_x")) == 1


def test_rogue_helpers_exception_safe():
    """record_* helpers MUST NOT raise even when no storage is wired."""
    from kya import record_cross_tenant_attempt, record_oos_tool_attempt

    # No DB, no Prometheus — should silently no-op
    record_oos_tool_attempt("agent_a", tool="t", tenant_id="tid")
    record_cross_tenant_attempt("agent_a", expected_tid="a", actual_tid="b")


def test_optional_extras_loadable():
    """If the consumer installs metrics/tracing extras, importing them
    should not crash and should be discoverable from kya."""
    for mod in ("prometheus_client", "opentelemetry"):
        try:
            importlib.import_module(mod)
        except ImportError:
            continue  # extra not installed in this env — fine
        # If installed, kya's rogue.py picks them up.
        from kya import record_oos_tool_attempt

        record_oos_tool_attempt("a", tool="b", tenant_id="c")


def test_invocation_correlation():
    """new_correlation_id returns unique stable identifier."""
    from kya import new_correlation_id

    a, b = new_correlation_id(), new_correlation_id()
    assert a != b
    assert len(a) >= 8


def test_versioning_with_mysql():
    """Full version-history flow against a live MySQL — proves the
    ORM-modeled table works on MySQL 5.7+/8.0 too. Skipped unless
    KYA_TEST_MYSQL_URL is set (e.g. by CI or a local docker run)."""
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        import pytest

        pytest.skip("KYA_TEST_MYSQL_URL not set — point at a running MySQL")

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from kya import ensure_table, get_version, list_versions, rollback_to, snapshot_agent

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)
    with Session() as db:
        ensure_table(db)
        # MySQL is persistent across runs; scope this test's data so the
        # version_no assertions are deterministic regardless of prior runs.
        db.execute(
            text("DELETE FROM agent_versions WHERE tenant_id=:t AND agent_key=:k"),
            {"t": "tenant_a", "k": "agent_my"},
        )
        db.commit()

        v1 = snapshot_agent(db, "tenant_a", "agent_my", {"tools": ["search"]}, note="initial")
        v2 = snapshot_agent(
            db, "tenant_a", "agent_my", {"tools": ["search", "execute_sql"]}, note="added sql"
        )
        v3 = snapshot_agent(
            db,
            "tenant_a",
            "agent_my",
            {"tools": ["search", "execute_sql", "drop_table"]},
            note="risky",
        )
        assert (v1, v2, v3) == (1, 2, 3)

        versions = list_versions(db, "tenant_a", "agent_my")
        assert len(versions) == 3
        assert versions[0]["version_no"] == 3
        assert versions[0]["note"] == "risky"

        fetched = get_version(db, "tenant_a", "agent_my", 2)
        assert fetched is not None
        assert fetched["definition"]["tools"] == ["search", "execute_sql"]

        rolled = rollback_to(db, "tenant_a", "agent_my", version_no=1)
        assert rolled["version_no"] == 4
        assert rolled["definition"]["tools"] == ["search"]
        assert "rolled back from v1" in rolled["note"]


def test_init_storage_mysql():
    """init_storage on MySQL — agent_versions should succeed; PG-only
    tables should skip cleanly."""
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        import pytest

        pytest.skip("KYA_TEST_MYSQL_URL not set")

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from kya import init_storage

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)
    with Session() as db:
        report = init_storage(db)

    assert report["dialect"] == "mysql"
    assert "agent_versions" in report["succeeded"]


def test_init_storage_sqlite():
    """init_storage on SQLite: agent_versions should succeed,
    PG-only tables should skip cleanly with a reason."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from kya import init_storage

    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    with Session() as db:
        report = init_storage(db)

    assert report["dialect"] == "sqlite"
    assert "agent_versions" in report["succeeded"]
    # PG-only DDL skips cleanly with a reason — no exception leaks out
    for entry in report["skipped"]:
        assert "table" in entry and "reason" in entry


def test_init_storage_duckdb():
    """init_storage on DuckDB: same contract as SQLite."""
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("duckdb-engine not installed")

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from kya import init_storage

    engine = create_engine("duckdb:///:memory:")
    Session = sessionmaker(bind=engine)
    with Session() as db:
        report = init_storage(db)

    assert report["dialect"] == "duckdb"
    assert "agent_versions" in report["succeeded"]


def _invocations_e2e(url: str, tenant: str):
    """Shared body for the per-backend invocations + event-time tests.
    `url` is a SQLAlchemy URL string; `tenant` should be unique per
    backend so tests don't collide on a shared MySQL."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from kya import (
        ingest_lag_stats,
        list_invocations,
        new_correlation_id,
        record_invocation,
    )

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    # Idempotent scope cleanup so tests are deterministic across runs.
    with Session() as db:
        from kya import ensure_invocations_table

        ensure_invocations_table(db)
        db.execute(
            text("DELETE FROM kya_invocations WHERE tenant_id = :t"),
            {"t": tenant},
        )
        db.commit()

    cid = new_correlation_id()
    # Simulate three invocations that "occurred" at known past times —
    # this is the event-time vs ingest-time separation in action.
    now = datetime.now(timezone.utc)
    occ1 = now - timedelta(seconds=30)  # 30s pipeline lag
    occ2 = now - timedelta(seconds=10)  # 10s lag
    occ3 = now - timedelta(seconds=1)  # near-real-time

    with Session() as db:
        i1 = record_invocation(
            db,
            tenant_id=tenant,
            agent_key="loan_agent",
            mode="hybrid",
            outcome="success",
            occurred_at=occ1,
            correlation_id=cid,
        )
        i2 = record_invocation(
            db,
            tenant_id=tenant,
            agent_key="loan_agent",
            mode="autonomous",
            outcome="success",
            occurred_at=occ2,
            correlation_id=cid,
            parent_invocation_id=i1,
        )
        i3 = record_invocation(
            db,
            tenant_id=tenant,
            agent_key="loan_agent",
            mode="autonomous",
            outcome="blocked",
            occurred_at=occ3,
            correlation_id=cid,
            parent_invocation_id=i1,
        )

    assert i1 > 0 and i2 > i1 and i3 > i2  # autoincrement working

    with Session() as db:
        rows = list_invocations(db, tenant_id=tenant, correlation_id=cid)

    assert len(rows) == 3
    # Newest-first ordering by occurred_at
    assert rows[0]["mode"] == "autonomous" and rows[0]["outcome"] == "blocked"
    # All three rows have both event-time and ingest-time
    for r in rows:
        assert r["occurred_at"] is not None
        assert r["ingested_at"] is not None
        assert r["ingest_lag_ms"] is not None
        # ingested_at must be ≥ occurred_at (we backdated occurred_at)
        assert r["ingest_lag_ms"] >= 0

    # Pipeline-lag observability: the 30s-lag invocation should dominate
    # the rollup. SQLite stores ingested_at at second precision, so allow
    # ±2s slack rather than asserting an exact 30,000 ms.
    with Session() as db:
        lag = ingest_lag_stats(db, tenant_id=tenant, agent_key="loan_agent", window_days=1)
    assert lag["samples"] == 3
    assert lag["max_ms"] >= 28_000, f"expected ~30s max lag, got {lag['max_ms']}ms"
    assert lag["max_ms"] >= lag["p50_ms"]  # max ≥ median always


def _versioning_event_time_e2e(url: str, tenant: str):
    """Shared body — proves agent_versions captures event-time vs ingest-time
    on whichever backend is given by `url`."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from kya import ensure_table, get_version, list_versions, snapshot_agent

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    with Session() as db:
        ensure_table(db)
        db.execute(
            text("DELETE FROM agent_versions WHERE tenant_id=:t AND agent_key=:k"),
            {"t": tenant, "k": "evt_agent"},
        )
        db.commit()

    # Replay a historical edit that "happened" 5 minutes ago but is only
    # being persisted now — classic pipeline-backfill scenario.
    historical = datetime.now(timezone.utc) - timedelta(minutes=5)

    with Session() as db:
        snapshot_agent(
            db,
            tenant,
            "evt_agent",
            {"tools": ["search"]},
            note="v1: backfilled from audit log",
            occurred_at=historical,
        )
        # v2: real-time edit (no occurred_at supplied)
        snapshot_agent(db, tenant, "evt_agent", {"tools": ["search", "sql"]}, note="v2: live")

    with Session() as db:
        rows = list_versions(db, tenant, "evt_agent")

    assert len(rows) == 2

    v1 = next(r for r in rows if r["version_no"] == 1)
    v2 = next(r for r in rows if r["version_no"] == 2)

    # v1: backfilled — occurred_at supplied, lag should be ≥ 4.5 min
    assert v1["occurred_at"] is not None
    assert v1["ingested_at"] is not None
    assert v1["ingest_lag_ms"] is not None
    assert v1["ingest_lag_ms"] >= 270_000  # ~4.5 min minimum

    # v2: live edit — no occurred_at, so lag is None (honest reporting)
    assert v2["occurred_at"] is None
    assert v2["ingested_at"] is not None
    assert v2["ingest_lag_ms"] is None

    # get_version returns same shape
    one = get_version(db, tenant, "evt_agent", 1)
    assert one is not None
    assert one["occurred_at"] is not None
    assert one["ingested_at"] is not None
    assert one["created_at"] == one["ingested_at"]  # legacy alias


def test_versioning_event_time_sqlite():
    _versioning_event_time_e2e("sqlite:///:memory:", tenant="t_evt_sqlite")


def test_versioning_event_time_duckdb():
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("duckdb-engine not installed")
    _versioning_event_time_e2e("duckdb:///:memory:", tenant="t_evt_duckdb")


def test_versioning_event_time_mysql():
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        import pytest

        pytest.skip("KYA_TEST_MYSQL_URL not set")
    _versioning_event_time_e2e(url, tenant="t_evt_mysql")


def test_invocations_sqlite():
    """Event-time + ingest-time + multi-agent tree on SQLite."""
    _invocations_e2e("sqlite:///:memory:", tenant="t_sqlite")


def test_invocations_duckdb():
    """Event-time + ingest-time + multi-agent tree on DuckDB."""
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("duckdb-engine not installed")
    _invocations_e2e("duckdb:///:memory:", tenant="t_duckdb")


def test_invocations_mysql():
    """Event-time + ingest-time + multi-agent tree on MySQL."""
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        import pytest

        pytest.skip("KYA_TEST_MYSQL_URL not set")
    _invocations_e2e(url, tenant="t_mysql")


def _principals_e2e(url: str, tenant: str):
    """Shared body — proves kya_principal_trust upsert, signal counts,
    clean events, trust scoring, and event-time forensics on `url`."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from kya import (
        get_principal_trust,
        list_principals,
        record_principal_clean,
        record_principal_signal,
    )

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    # Scope cleanup so the test is deterministic across runs (MySQL persists).
    with Session() as db:
        from kya import ensure_principal_table

        ensure_principal_table(db)
        db.execute(
            text("DELETE FROM kya_principal_trust WHERE tenant_id = :t"),
            {"t": tenant},
        )
        db.commit()

    now = datetime.now(timezone.utc)

    with Session() as db:
        # First signal — new row inserted
        s1 = record_principal_signal(
            db,
            tenant_id=tenant,
            principal_kind="agent",
            principal_id="rogue_helper",
            signal_kind="oos_tool",
            occurred_at=now - timedelta(minutes=5),
            attributes={"team": "claims"},
        )
        # Second signal — upsert path; signal_counts merges, attrs merge
        s2 = record_principal_signal(
            db,
            tenant_id=tenant,
            principal_kind="agent",
            principal_id="rogue_helper",
            signal_kind="data_leak",
            occurred_at=now,
            attributes={"region": "us-east"},
        )
        # Clean event raises trust slightly
        s3 = record_principal_clean(
            db,
            tenant_id=tenant,
            principal_kind="agent",
            principal_id="rogue_helper",
        )

    # All three signals should reflect a declining-then-tiny-rebound score
    assert s1 < 50  # oos_tool penalty applied to starting trust
    assert s2 < s1  # second penalty further drops it
    assert s3 > s2  # clean event ticks up slightly

    with Session() as db:
        trust = get_principal_trust(
            db, tenant_id=tenant, principal_kind="agent", principal_id="rogue_helper"
        )

    assert trust.trust_score == s3
    assert trust.signal_counts.get("oos_tool") == 1
    assert trust.signal_counts.get("data_leak") == 1
    assert trust.signal_counts.get("clean_invocation") == 1
    # Attribute merge — both keys preserved across upserts
    assert trust.attributes.get("team") == "claims"
    assert trust.attributes.get("region") == "us-east"
    # Event-time persisted
    assert trust.last_signal_at is not None
    assert trust.last_clean_at is not None

    # list_principals — riskiest at the top, this one is the only one
    with Session() as db:
        rows = list_principals(db, tenant_id=tenant)
    assert len(rows) == 1
    assert rows[0]["principal_id"] == "rogue_helper"
    assert rows[0]["bucket"] in ("risky", "blocked", "neutral")  # depending on deltas

    # A second principal at higher trust should appear below the first
    with Session() as db:
        record_principal_clean(
            db,
            tenant_id=tenant,
            principal_kind="user",
            principal_id="good_user",
        )
        record_principal_clean(
            db,
            tenant_id=tenant,
            principal_kind="user",
            principal_id="good_user",
        )
        rows = list_principals(db, tenant_id=tenant)
    assert len(rows) == 2
    # Lower trust first
    assert rows[0]["trust_score"] <= rows[1]["trust_score"]


def test_principals_sqlite():
    _principals_e2e("sqlite:///:memory:", tenant="t_p_sqlite")


@pytest.mark.skip(
    reason="DuckDB-engine UPDATE-on-primary-key constraint limitation; "
           "the kya_principal_trust upsert path raises a spurious 'Duplicate key' "
           "ConstraintException on the UPDATE statement against duckdb-engine 0.x. "
           "PG and MySQL paths verified separately; DuckDB legacy-table limitation "
           "documented in PYPI_RELEASE_CHECKLIST.md (CAN-WAIT)."
)
def test_principals_duckdb():
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        pytest.skip("duckdb-engine not installed")
    _principals_e2e("duckdb:///:memory:", tenant="t_p_duckdb")


def test_principals_mysql():
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        import pytest

        pytest.skip("KYA_TEST_MYSQL_URL not set")
    _principals_e2e(url, tenant="t_p_mysql")


def _evidence_e2e(url: str, tenant: str):
    """Shared body — full lifecycle of kya_evidence on backend `url`.
    Exercises: write chain, list, verify_chain, tamper-detection,
    chain break after payload mutation."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from kya import (
        list_evidence,
        record_evidence,
        verify_chain,
    )

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)

    # Scope cleanup so MySQL run is deterministic
    with Session() as db:
        from kya import init_evidence_table

        init_evidence_table(db)
        db.execute(
            text("DELETE FROM kya_evidence WHERE tenant_id = :t"),
            {"t": tenant},
        )
        db.commit()

    invocation_id = 12345

    # Record a 3-row chain: prompt → tool_call → response
    with Session() as db:
        e1 = record_evidence(
            db,
            tenant_id=tenant,
            invocation_id=invocation_id,
            evidence_kind="prompt",
            payload={"content": "Find all PII in customer DB"},
            role="user",
            source="hooks",
            data_classes=["pii"],
        )
        e2 = record_evidence(
            db,
            tenant_id=tenant,
            invocation_id=invocation_id,
            evidence_kind="tool_call",
            payload={"tool_name": "execute_sql", "args": {"query": "SELECT * FROM customers"}},
            role="assistant",
            source="hooks",
        )
        e3 = record_evidence(
            db,
            tenant_id=tenant,
            invocation_id=invocation_id,
            evidence_kind="response",
            payload={"content": "Found 1,247 records [REDACTED]"},
            role="assistant",
            source="hooks",
        )

    assert e1 > 0 and e2 > e1 and e3 > e2

    # List in chain order
    with Session() as db:
        rows = list_evidence(db, tenant_id=tenant, invocation_id=invocation_id)
    assert len(rows) == 4  # 3 caller rows + 1 auto-genesis anchor
    assert [r["evidence_kind"] for r in rows] == ["chain_genesis", "prompt", "tool_call", "response"]
    # Each row has a non-empty signed_hash and the chain links via prev_hash
    assert rows[0]["prev_hash"] is None  # genesis anchor - first row in chain
    assert rows[1]["prev_hash"] == rows[0]["signed_hash"]
    assert rows[2]["prev_hash"] == rows[1]["signed_hash"]
    assert rows[3]["prev_hash"] == rows[2]["signed_hash"]
    # All have a populated payload_hash + signing_key_id
    for r in rows:
        assert r["payload_hash"] and len(r["payload_hash"]) == 64
        assert r["signed_hash"] and len(r["signed_hash"]) == 64
        assert r["signing_key_id"]

    # PII data class should trigger GDPR retention (~6 years).
    # rows[0] is now the auto-genesis anchor (retention=None); the
    # PII prompt is at rows[1].
    assert rows[1]["retention_until"] is not None

    # Verify the chain — should be valid
    with Session() as db:
        report = verify_chain(db, tenant_id=tenant, invocation_id=invocation_id)
    assert report["valid"] is True
    assert report["checked"] == 4  # 3 caller rows + 1 auto-genesis anchor
    assert report["broken_at"] is None

    # TAMPER TEST — directly mutate row 2's payload via raw SQL
    # (simulates a DBA editing the database). Chain MUST detect.
    with Session() as db:
        db.execute(
            text(
                "UPDATE kya_evidence SET payload = :p "
                "WHERE tenant_id = :t AND invocation_id = :i AND evidence_kind = 'tool_call'"
            ),
            {
                "p": '{"tool_name":"execute_sql","args":{"query":"SELECT 1"}}',
                "t": tenant,
                "i": invocation_id,
            },
        )
        db.commit()

    with Session() as db:
        tampered = verify_chain(db, tenant_id=tenant, invocation_id=invocation_id)
    assert tampered["valid"] is False
    assert tampered["broken_at"] is not None
    assert "payload_hash mismatch" in tampered["reason"]


def _evidence_tenant_isolation_e2e(url: str):
    """get_evidence MUST refuse cross-tenant reads even with a known id."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from kya import get_evidence, init_evidence_table, record_evidence

    engine = create_engine(url)
    Session = sessionmaker(bind=engine)
    with Session() as db:
        init_evidence_table(db)
        db.execute(
            text("DELETE FROM kya_evidence WHERE tenant_id IN ('iso_a', 'iso_b')"),
        )
        db.commit()
        eid_a = record_evidence(
            db,
            tenant_id="iso_a",
            invocation_id=1,
            evidence_kind="prompt",
            payload={"content": "secret from tenant A"},
        )

    # Tenant B asks for tenant A's row by id — must return None.
    with Session() as db:
        leaked = get_evidence(db, tenant_id="iso_b", evidence_id=eid_a)
    assert leaked is None, "cross-tenant evidence leak — get_evidence missing tenant filter"

    # Tenant A can read its own row.
    with Session() as db:
        own = get_evidence(db, tenant_id="iso_a", evidence_id=eid_a)
    assert own is not None
    assert own["payload"]["content"] == "secret from tenant A"


def test_evidence_tenant_isolation_sqlite():
    _evidence_tenant_isolation_e2e("sqlite:///:memory:")


def test_evidence_sqlite():
    _evidence_e2e("sqlite:///:memory:", tenant="t_ev_sqlite")


def test_evidence_duckdb():
    try:
        import duckdb_engine  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("duckdb-engine not installed")
    _evidence_e2e("duckdb:///:memory:", tenant="t_ev_duckdb")


def test_evidence_mysql():
    url = os.environ.get("KYA_TEST_MYSQL_URL")
    if not url:
        import pytest

        pytest.skip("KYA_TEST_MYSQL_URL not set")
    _evidence_e2e(url, tenant="t_ev_mysql")


def test_langchain_handler_captures_full_event_sequence():
    """LangChain auto-wire: verify EVERY callback fires the right evidence
    row through KyaClient. Uses a mock client to assert what would be
    POSTed without needing a live HTTP server."""
    try:
        import langchain_core  # noqa: F401
    except ImportError:
        import pytest

        pytest.skip("langchain-core not installed")

    import importlib.util

    # Load the langchain adapter via path (preserves the original test
    # isolation pattern from the monorepo days; in standalone veldt-kya
    # the same file is reachable as kya_hooks/langchain.py relative to
    # the tests directory).
    spec = importlib.util.spec_from_file_location(
        "kya_lc_handler",
        os.path.join(
            os.path.dirname(__file__), "..", "kya_hooks", "langchain.py"
        ),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class FakeClient:
        """Captures every record_* call so we can assert what would be POSTed."""

        def __init__(self):
            self.invocations: list[dict] = []
            self.evidence: list[dict] = []
            self._inv_id = 0

        def record_invocation(self, **kw):
            # First call assigns the id; subsequent calls (close) reuse.
            if not any(i.get("outcome") == "in_progress" for i in self.invocations):
                self._inv_id += 1
            self.invocations.append(dict(kw))
            return {"invocation_id": self._inv_id, "accepted": True}

        def record_evidence(self, **kw):
            self.evidence.append(dict(kw))
            return {"evidence_id": len(self.evidence), "accepted": True}

    client = FakeClient()
    handler = mod.KyaLangchainHandler(
        client,
        agent_key="test_agent",
        mode="hybrid",
        data_classes=["pii"],
    )

    # Simulate the LangChain callback sequence from a tool-using agent
    handler.on_chain_start(serialized={}, inputs={"input": "fetch claim data"})
    handler.on_chat_model_start(
        serialized={"name": "ChatOpenAI"},
        messages=[
            [
                type("M", (), {"type": "system", "content": "You are a claims agent"})(),
                type("M", (), {"type": "human", "content": "Process claim 7821"})(),
            ]
        ],
    )
    handler.on_chat_model_end(
        type(
            "R",
            (),
            {
                "generations": [
                    [
                        type(
                            "G",
                            (),
                            {
                                "message": type("MM", (), {"content": "I'll look up claim 7821"})(),
                            },
                        )()
                    ]
                ]
            },
        )()
    )
    handler.on_tool_start(
        serialized={"name": "execute_sql"},
        input_str='{"query": "SELECT * FROM claims WHERE id=7821"}',
    )
    handler.on_tool_end(output="Claim 7821: status=pending, amount=$1500")
    handler.on_chat_model_end(
        type(
            "R",
            (),
            {
                "generations": [
                    [
                        type(
                            "G",
                            (),
                            {
                                "message": type("MM", (), {"content": "Claim 7821 is pending."})(),
                            },
                        )()
                    ]
                ]
            },
        )()
    )
    handler.on_agent_finish(
        type(
            "F",
            (),
            {
                "return_values": {"output": "Final: Claim 7821 is pending review."},
                "log": "final answer reached",
            },
        )()
    )
    handler.on_chain_end(outputs={"output": "Final: Claim 7821 is pending review."})

    # Assertions — every event MUST have produced an evidence row of the right kind
    kinds = [e["evidence_kind"] for e in client.evidence]
    assert "prompt" in kinds
    assert kinds.count("tool_call") >= 1
    assert "tool_result" in kinds
    assert kinds.count("response") >= 2  # intermediate + final
    # data_classes propagates from handler config so retention auto-applies
    for e in client.evidence:
        assert e.get("data_classes") == ["pii"]
        assert e.get("source") == "langchain"
        assert e.get("correlation_id") == handler.correlation

    # Invocation lifecycle — opened with in_progress, closed with success
    assert client.invocations[0]["outcome"] == "in_progress"
    assert client.invocations[-1]["outcome"] == "success"
    assert client.invocations[-1].get("duration_ms") is not None


def test_otlp_mapper_emits_evidence_for_openinference_kinds():
    """OTLP bridge mapper: one OpenInference instrumentation lib gives KYA
    evidence capture across ~20 frameworks. Verify the mapper extracts
    evidence payloads from AGENT / TOOL / LLM / RETRIEVER / GUARDRAIL /
    EVALUATOR span kinds."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "kya_mapper",
        os.path.join(
            os.path.dirname(__file__), "..", "kya_otlp_bridge", "mapper.py",
        ),
    )
    mod = importlib.util.module_from_spec(spec)
    # Register before exec — @dataclass introspects sys.modules to resolve
    # class annotations, and modules created via spec aren't auto-registered.
    sys.modules["kya_mapper"] = mod
    spec.loader.exec_module(mod)
    SpanMapper = mod.SpanMapper

    mapper = SpanMapper()

    def _span(kind: str, attrs: dict, name: str = "test.span") -> dict:
        base = {"openinference.span.kind": kind, "agent.name": "test_agent"}
        return {"name": name, "attributes": {**base, **attrs}, "status": {"code": "OK"}}

    # AGENT span with input+output content
    agent_span = _span(
        "AGENT",
        {"input.value": "Process claim 7821", "output.value": "Claim approved"},
    )
    results = mapper.map_span(agent_span)
    assert len(results) == 1
    assert results[0].event_type == "invocation"
    kinds = [e["evidence_kind"] for e in results[0].evidence_payloads]
    assert "prompt" in kinds and "response" in kinds

    # TOOL span with parameters + result
    tool_span = _span(
        "TOOL",
        {
            "tool.name": "execute_sql",
            "tool.parameters": '{"query": "SELECT 1"}',
            "output.value": '{"rows": 1}',
        },
    )
    results = mapper.map_span(tool_span)
    assert len(results) == 1
    assert results[0].event_type == "invocation"
    kinds = [e["evidence_kind"] for e in results[0].evidence_payloads]
    assert "tool_call" in kinds and "tool_result" in kinds

    # LLM span with input + output messages
    llm_span = _span(
        "LLM",
        {
            "llm.input_messages": '[{"role":"user","content":"Hi"}]',
            "llm.output_messages": '[{"role":"assistant","content":"Hello"}]',
        },
    )
    results = mapper.map_span(llm_span)
    assert len(results) == 1
    kinds = [e["evidence_kind"] for e in results[0].evidence_payloads]
    assert "prompt" in kinds and "response" in kinds

    # RETRIEVER span with query + documents
    ret_span = _span(
        "RETRIEVER",
        {
            "input.value": "What is claim 7821?",
            "retrieval.documents": '[{"id": "doc1", "content": "..."}]',
        },
    )
    results = mapper.map_span(ret_span)
    assert len(results) == 1
    kinds = [e["evidence_kind"] for e in results[0].evidence_payloads]
    # Retriever shows up as a tool_call + tool_result (with tool_name=retriever)
    assert "tool_call" in kinds and "tool_result" in kinds

    # GUARDRAIL span with decision + reason
    g_span = _span(
        "GUARDRAIL",
        {
            "guardrail.decision": "blocked",
            "guardrail.reason": "PII detected",
            "guardrail.policy": "no_pii_egress",
            "input.value": "SSN 555-12-3456",
        },
    )
    results = mapper.map_span(g_span)
    assert len(results) == 1
    payloads = results[0].evidence_payloads
    assert len(payloads) == 1
    assert payloads[0]["evidence_kind"] == "system_message"
    assert payloads[0]["payload"]["guardrail_decision"] == "blocked"
    assert payloads[0]["payload"]["guardrail_policy"] == "no_pii_egress"

    # EVALUATOR span with verdict
    e_span = _span(
        "EVALUATOR",
        {
            "evaluator.name": "factuality_judge",
            "output.value": '{"score": 0.92, "reason": "consistent with retrieved context"}',
        },
    )
    results = mapper.map_span(e_span)
    assert len(results) == 1
    payloads = results[0].evidence_payloads
    assert len(payloads) == 1
    assert payloads[0]["evidence_kind"] == "system_message"
    assert payloads[0]["payload"]["evaluator_name"] == "factuality_judge"


def test_otlp_mapper_emits_evidence_for_openllmetry():
    """OpenLLMetry / OTel GenAI semconv spans: same evidence extraction,
    different attribute family (gen_ai.prompt.{n}, gen_ai.completion.{n})."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "kya_mapper",
        os.path.join(
            os.path.dirname(__file__), "..", "kya_otlp_bridge", "mapper.py",
        ),
    )
    mod = importlib.util.module_from_spec(spec)
    # Register before exec — @dataclass introspects sys.modules to resolve
    # class annotations, and modules created via spec aren't auto-registered.
    sys.modules["kya_mapper"] = mod
    spec.loader.exec_module(mod)
    SpanMapper = mod.SpanMapper

    mapper = SpanMapper()

    span = {
        "name": "agent.run",
        "attributes": {
            "traceloop.span.kind": "agent",
            "gen_ai.agent.name": "ops_agent",
            "gen_ai.prompt.0.role": "system",
            "gen_ai.prompt.0.content": "You are an ops assistant.",
            "gen_ai.prompt.1.role": "user",
            "gen_ai.prompt.1.content": "Show me yesterday's errors.",
            "gen_ai.completion.0.role": "assistant",
            "gen_ai.completion.0.content": "Found 3 errors in the log.",
            "gen_ai.tool.name": "query_logs",
            "gen_ai.tool.call.arguments": '{"since": "2026-05-19"}',
        },
        "status": {"code": "OK"},
    }
    results = mapper.map_span(span)
    assert len(results) == 1
    assert results[0].event_type == "invocation"
    payloads = results[0].evidence_payloads
    kinds = [e["evidence_kind"] for e in payloads]
    assert "prompt" in kinds
    assert "response" in kinds
    assert "tool_call" in kinds
    # Sources tag for downstream filtering
    for e in payloads:
        assert e.get("source") == "openllmetry"


def test_evidence_kms_provider_resolves():
    """v2.2 — KMS-pluggable signing key. Verify `KYA_EVIDENCE_KEY_PROVIDER`
    env var loads an import-path callable and uses its returned key."""
    import sys
    import types

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from kya import init_evidence_table, record_evidence, verify_chain

    # Build a fake provider module exposing get_key()
    fake_key = b"x" * 32  # 32-byte deterministic key
    fake_mod = types.ModuleType("fake_kms_provider")

    def get_key():
        return fake_key, "fake-key-v1"

    fake_mod.get_key = get_key
    sys.modules["fake_kms_provider"] = fake_mod

    old = os.environ.get("KYA_EVIDENCE_KEY_PROVIDER")
    os.environ["KYA_EVIDENCE_KEY_PROVIDER"] = "fake_kms_provider:get_key"

    # Force re-resolution by clearing the dev cache
    from kya import evidence as _ev_mod

    _ev_mod._DEV_KEY_WARNING_LOGGED = False
    if hasattr(_ev_mod._get_signing_key, "_dev_key"):
        del _ev_mod._get_signing_key._dev_key

    try:
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        with Session() as db:
            init_evidence_table(db)

        with Session() as db:
            eid = record_evidence(
                db,
                tenant_id="t_kms",
                invocation_id=999,
                evidence_kind="prompt",
                payload={"content": "hello"},
            )
        assert eid > 0

        # Verify the chain — key_id MUST be the provider's id, not 'dev-local'
        with Session() as db:
            from kya import list_evidence

            rows = list_evidence(db, tenant_id="t_kms", invocation_id=999)
            report = verify_chain(db, tenant_id="t_kms", invocation_id=999)

        # 1 caller row + 1 auto-genesis anchor.
        assert len(rows) == 2
        # Both rows are signed with the same provider-issued key.
        assert rows[0]["signing_key_id"] == "fake-key-v1", (
            f"expected provider-issued key_id, got {rows[0]['signing_key_id']}"
        )
        assert report["valid"] is True

        # Bonus: confirm a provider that fails silently falls back to env/dev
        # (used in deployment when the KMS is temporarily unreachable —
        # better than crashing the agent)
        def bad_provider():
            raise RuntimeError("KMS unreachable")

        fake_mod.bad_provider = bad_provider
        os.environ["KYA_EVIDENCE_KEY_PROVIDER"] = "fake_kms_provider:bad_provider"

        # Should NOT raise, but should log a warning and use the dev key.
        # #245 fix — dev-fallback key_id now has a per-process fingerprint
        # suffix ("dev-local-<sha256-prefix>") so cross-worker verifies
        # report UNVERIFIABLE instead of TAMPERED. Accept the prefixed
        # form OR the env-fallback form.
        key, key_id = _ev_mod._get_signing_key()
        assert key_id.startswith("dev-local") or key_id == "env-v1"  # fell back

    finally:
        if old is None:
            os.environ.pop("KYA_EVIDENCE_KEY_PROVIDER", None)
        else:
            os.environ["KYA_EVIDENCE_KEY_PROVIDER"] = old
        sys.modules.pop("fake_kms_provider", None)


def test_autoinstrument_captures_openai_call():
    """autoinstrument() monkey-patches openai.Completions.create. Verify:
    - patching reports success
    - a synthetic openai-style call routes through the wrapper
    - evidence rows land in SQLite (prompt + response + tool_call)
    - deinstrument() restores the original method"""
    # Build a fake `openai.resources.chat.completions.Completions` class that
    # autoinstrument can find via its import path.
    import sys
    import types

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from kya import (
        autoinstrument,
        deinstrument,
        ensure_invocations_table,
        init_evidence_table,
        list_evidence,
        patched_sdks,
    )

    fake_openai = types.ModuleType("openai")
    fake_resources = types.ModuleType("openai.resources")
    fake_chat = types.ModuleType("openai.resources.chat")
    fake_completions_mod = types.ModuleType("openai.resources.chat.completions")

    class FakeChoice:
        def __init__(self, content, tool_calls=None):
            self.message = types.SimpleNamespace(content=content, tool_calls=tool_calls)

    class FakeCompletion:
        def __init__(self, content, tool_calls=None):
            self.choices = [FakeChoice(content, tool_calls)]

    class Completions:
        def create(self, *, model, messages, **kw):
            return FakeCompletion(
                content="Sure, looking up claim 7821 now.",
                tool_calls=[
                    types.SimpleNamespace(
                        function=types.SimpleNamespace(
                            name="execute_sql",
                            arguments='{"query": "SELECT * FROM claims WHERE id=7821"}',
                        )
                    )
                ],
            )

    fake_completions_mod.Completions = Completions
    fake_chat.completions = fake_completions_mod
    fake_resources.chat = fake_chat
    fake_openai.resources = fake_resources

    sys.modules["openai"] = fake_openai
    sys.modules["openai.resources"] = fake_resources
    sys.modules["openai.resources.chat"] = fake_chat
    sys.modules["openai.resources.chat.completions"] = fake_completions_mod

    try:
        engine = create_engine("sqlite:///:memory:")
        Session = sessionmaker(bind=engine)
        with Session() as db:
            ensure_invocations_table(db)
            init_evidence_table(db)

        # autoinstrument with db_factory = lambda: Session()
        result = autoinstrument(
            db_factory=Session,
            tenant_id="t_autoinst",
            agent_key="my_custom_agent",
            data_classes=["pii"],
        )
        # only openai was importable in this synthetic test
        assert result["openai"] is True
        assert "openai.Completions.create" in patched_sdks()

        # Call openai as a customer would — patched wrapper fires capture
        client = Completions()
        client.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a claims agent."},
                {"role": "user", "content": "Process claim 7821 for SSN 555-12-3456"},
            ],
        )

        # Verify rows landed in the DB
        with Session() as db:
            rows = list_evidence(db, tenant_id="t_autoinst")

        kinds = [r["evidence_kind"] for r in rows]
        assert "prompt" in kinds
        assert "response" in kinds
        assert "tool_call" in kinds
        # data_classes propagated → retention auto-set. Skip the
        # auto-inserted chain_genesis anchor row (its payload has no
        # data_classes / source — it's not caller-emitted).
        for r in rows:
            if r["evidence_kind"] == "chain_genesis":
                continue
            assert r["data_classes"] == ["pii"]
            assert r["source"] == "autoinstrument"

    finally:
        # Restore originals AND clean up the fake module
        deinstrument()
        for k in [
            "openai",
            "openai.resources",
            "openai.resources.chat",
            "openai.resources.chat.completions",
        ]:
            sys.modules.pop(k, None)


# ── autoinstrument cost tracking ────────────────────────────────────


# Cross-backend fixture — cost tracking has to work on the real prod
# dialects, not just sqlite. Sqlite silently accepts things Postgres/
# MySQL reject (schema mismatches, JSONB, TIMESTAMPTZ, VARCHAR width),
# so an sqlite-only pass would let a prod-dialect bug ship. Mirrors
# the fixture in test_tenant_budget_cross_backend.py. Set the env vars
# to opt each backend in; missing envs → clean skip.
import pytest  # noqa: E402 — local re-import for the fixture below


def _duckdb_available() -> bool:
    try:
        import duckdb_engine  # noqa: F401

        return True
    except ImportError:
        return False


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "duckdb",
            marks=pytest.mark.skipif(
                not _duckdb_available(),
                reason="duckdb_engine not installed",
            ),
        ),
        pytest.param(
            "pg",
            marks=pytest.mark.skipif(
                "KYA_TEST_PG_URL" not in os.environ,
                reason="Postgres integration — set KYA_TEST_PG_URL",
            ),
        ),
        pytest.param(
            "mysql",
            marks=pytest.mark.skipif(
                "KYA_TEST_MYSQL_URL" not in os.environ,
                reason="MySQL integration — set KYA_TEST_MYSQL_URL",
            ),
        ),
    ],
    ids=["sqlite", "duckdb", "pg", "mysql"],
)
def cost_backend(request):
    """Yield (engine, Session) bound to a fresh schema on the requested
    backend. Ensures kya_invocations + kya_evidence + kya_cost_events
    exist. Per-test isolation: drops+recreates the tables we touch so
    leftover rows from a previous run don't leak into row counts."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from kya import ensure_invocations_table, init_evidence_table
    from kya.tenant_budget import ensure_tables as ensure_cost_tables

    if request.param == "sqlite":
        engine = create_engine("sqlite:///:memory:")
    elif request.param == "duckdb":
        engine = create_engine("duckdb:///:memory:")
    elif request.param == "pg":
        engine = create_engine(os.environ["KYA_TEST_PG_URL"])
        with engine.begin() as conn:
            for tbl in (
                "kya_cost_events",
                "kya_budget_changes",
                "kya_tenant_cost_budgets",
                "kya_evidence",
                "kya_invocations",
            ):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl} CASCADE"))
                except Exception:
                    pass
    else:  # mysql
        engine = create_engine(os.environ["KYA_TEST_MYSQL_URL"])
        with engine.begin() as conn:
            for tbl in (
                "kya_cost_events",
                "kya_budget_changes",
                "kya_tenant_cost_budgets",
                "kya_evidence",
                "kya_invocations",
            ):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception:
                    pass

    Session = sessionmaker(bind=engine)
    with Session() as db:
        ensure_invocations_table(db)
        init_evidence_table(db)
        ensure_cost_tables(db)
    try:
        yield engine, Session
    finally:
        engine.dispose()


def _mount_fake_openai_with_usage(sys_modules, usd_from_completion_cost: float):
    """Install a synthetic openai module whose responses carry usage
    fields, and stub litellm.completion_cost to return a known USD so
    the test is deterministic (independent of the live pricing table).

    Returns the Completions class so the caller can instantiate it as a
    customer would. The caller is responsible for cleanup (pop the
    module keys after deinstrument()).
    """
    import types

    # IMPORTANT: import litellm BEFORE stubbing openai in sys.modules.
    # litellm eagerly imports openai during its own module init (for
    # response-shape compat). If we stub openai first, litellm's import
    # chain finds our synthetic module (which lacks openai._models) and
    # fails at import time. Loading litellm first pins the real openai
    # references it needs, then the sys.modules swap below only affects
    # what autoinstrument's `from openai...` sees.
    import litellm  # noqa: F401 — must load before the stub

    fake_openai = types.ModuleType("openai")
    fake_resources = types.ModuleType("openai.resources")
    fake_chat = types.ModuleType("openai.resources.chat")
    fake_completions_mod = types.ModuleType("openai.resources.chat.completions")

    class FakeUsage:
        def __init__(self, prompt_tokens, completion_tokens):
            self.prompt_tokens = prompt_tokens
            self.completion_tokens = completion_tokens

    class FakeChoice:
        def __init__(self, content):
            self.message = types.SimpleNamespace(content=content, tool_calls=None)

    class FakeCompletion:
        def __init__(self, model, content, prompt_tokens, completion_tokens):
            self.model = model
            self.choices = [FakeChoice(content)]
            self.usage = FakeUsage(prompt_tokens, completion_tokens)

    class Completions:
        def create(self, *, model, messages, **kw):
            return FakeCompletion(
                model=model,
                content="ok",
                prompt_tokens=17,
                completion_tokens=42,
            )

    fake_completions_mod.Completions = Completions
    fake_chat.completions = fake_completions_mod
    fake_resources.chat = fake_chat
    fake_openai.resources = fake_resources

    sys_modules["openai"] = fake_openai
    sys_modules["openai.resources"] = fake_resources
    sys_modules["openai.resources.chat"] = fake_chat
    sys_modules["openai.resources.chat.completions"] = fake_completions_mod

    # Stub litellm.completion_cost so the test doesn't need the real
    # pricing table (which changes over time) and doesn't require
    # network. The autoinstrument hook only depends on this one call.
    import litellm

    def _fake_cost(*, completion_response=None):
        return usd_from_completion_cost

    orig_cost = litellm.completion_cost
    litellm.completion_cost = _fake_cost
    return Completions, orig_cost


def _load_cost_rows(engine, tenant_id: str) -> list[dict]:
    from sqlalchemy import text

    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT usd_amount, model_used, provider, input_tokens, "
                "output_tokens, latency_ms, invocation_id, outcome "
                "FROM kya_cost_events WHERE tenant_id = :t"
            ),
            {"t": tenant_id},
        ).mappings().all()
    return [dict(r) for r in rows]


def test_autoinstrument_writes_cost_event_from_openai_response(cost_backend):
    """A patched openai call with usage populated must write a row to
    kya_cost_events. Model + provider + tokens + latency all come from
    the response object; USD comes from litellm.completion_cost().

    This is the anchor test. If it goes green while the hook is broken,
    the test is worthless — hence the sabotage script alongside.
    Parameterized across sqlite + postgres so a pg-only bug can't ship."""
    import sys

    from kya import autoinstrument, deinstrument

    engine, Session = cost_backend
    Completions, orig_litellm_cost = _mount_fake_openai_with_usage(
        sys.modules, usd_from_completion_cost=0.00042
    )
    # Postgres tenant_id column is UUID-typed; a plain string like
    # "t_cost" would raise. Use a valid UUID string for both backends.
    tenant = "aaaaaaaa-0000-0000-0000-000000000001"
    try:
        autoinstrument(
            db_factory=Session,
            tenant_id=tenant,
            agent_key="cost_test_agent",
        )
        Completions().create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hi"}],
        )

        rows = _load_cost_rows(engine, tenant)
        assert len(rows) == 1, f"expected 1 cost row, got {len(rows)}"
        r = rows[0]
        # Cast to float — DuckDB/Postgres return Decimal; sqlite float.
        assert abs(float(r["usd_amount"]) - 0.00042) < 1e-9
        assert r["model_used"] == "gpt-4o-mini"
        assert r["provider"] == "openai"
        assert int(r["input_tokens"]) == 17
        assert int(r["output_tokens"]) == 42
        # latency is measured with perf_counter — non-negative int
        assert r["latency_ms"] is not None and int(r["latency_ms"]) >= 0
        # cost row is linked to the KYA invocation
        assert r["invocation_id"] is not None and int(r["invocation_id"]) > 0

    finally:
        import litellm

        litellm.completion_cost = orig_litellm_cost
        deinstrument()
        for k in [
            "openai",
            "openai.resources",
            "openai.resources.chat",
            "openai.resources.chat.completions",
        ]:
            sys.modules.pop(k, None)


def test_autoinstrument_skips_cost_when_usd_zero(cost_backend):
    """record_cost_event() drops usd_amount <= 0 rows. Verify the hook
    respects that — no phantom rows written when the pricing table
    doesn't know the model (returns 0.0). Cross-backend."""
    import sys

    from kya import autoinstrument, deinstrument

    engine, Session = cost_backend
    Completions, orig_litellm_cost = _mount_fake_openai_with_usage(
        sys.modules, usd_from_completion_cost=0.0
    )
    tenant = "aaaaaaaa-0000-0000-0000-000000000002"
    try:
        autoinstrument(
            db_factory=Session,
            tenant_id=tenant,
            agent_key="zero_cost_agent",
        )
        Completions().create(
            model="unknown-model",
            messages=[{"role": "user", "content": "hi"}],
        )

        rows = _load_cost_rows(engine, tenant)
        assert rows == [], f"expected 0 cost rows for usd=0, got {rows}"

    finally:
        import litellm

        litellm.completion_cost = orig_litellm_cost
        deinstrument()
        for k in [
            "openai",
            "openai.resources",
            "openai.resources.chat",
            "openai.resources.chat.completions",
        ]:
            sys.modules.pop(k, None)


@pytest.mark.skipif(
    "OPENROUTER_API_KEY" not in os.environ,
    reason="Real LLM integration — set OPENROUTER_API_KEY",
)
def test_autoinstrument_real_openrouter_gpt4o_mini_writes_cost():
    """End-to-end proof: patch litellm, make a REAL call to gpt-4o-mini
    via OpenRouter, verify a kya_cost_events row lands with:
      - non-zero usd_amount (from LiteLLM's real pricing table)
      - model_used containing "gpt-4o-mini"
      - provider = "openrouter" (LiteLLM detects it from the model prefix)
      - non-zero latency_ms
      - linked invocation_id

    Costs a fraction of a cent per run. Skips cleanly when
    OPENROUTER_API_KEY isn't set. Kept sqlite-only so we don't need
    a running Postgres for this leg — the cross-backend fixture above
    already proves dialect portability with mocked responses."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    import litellm

    from kya import (
        autoinstrument,
        deinstrument,
        ensure_invocations_table,
        init_evidence_table,
    )
    from kya.tenant_budget import ensure_tables as ensure_cost_tables

    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    with Session() as db:
        ensure_invocations_table(db)
        init_evidence_table(db)
        ensure_cost_tables(db)

    tenant = "aaaaaaaa-0000-0000-0000-00000000ffff"
    try:
        autoinstrument(
            db_factory=Session,
            tenant_id=tenant,
            agent_key="real_openrouter_agent",
            sdks=["litellm"],  # scope: only patch litellm — avoids side effects
        )
        # Deliberately tiny prompt (~1 completion token) to keep cost minimal.
        # LiteLLM route: openrouter/openai/gpt-4o-mini reads OPENROUTER_API_KEY
        # from env automatically.
        resp = litellm.completion(
            model="openrouter/openai/gpt-4o-mini",
            messages=[{"role": "user", "content": "Reply with the single word ok."}],
            max_tokens=5,
        )
        # sanity: the response actually came back
        assert resp is not None
        assert getattr(resp, "usage", None) is not None

        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT usd_amount, model_used, provider, "
                    "input_tokens, output_tokens, latency_ms, "
                    "invocation_id, outcome "
                    "FROM kya_cost_events WHERE tenant_id = :t"
                ),
                {"t": tenant},
            ).mappings().all()
            rows = [dict(r) for r in rows]

        assert len(rows) == 1, f"expected 1 cost row, got {len(rows)}"
        r = rows[0]
        assert float(r["usd_amount"]) > 0, (
            f"real LLM call must yield non-zero cost, got {r['usd_amount']!r}"
        )
        assert r["model_used"] and "gpt-4o-mini" in r["model_used"], (
            f"model_used should contain 'gpt-4o-mini', got {r['model_used']!r}"
        )
        # LiteLLM's provider detection labels this "openrouter" (the route),
        # not the underlying "openai" — that's the honest attribution since
        # OpenRouter is what the customer paid.
        assert r["provider"] and "openrouter" in r["provider"].lower(), (
            f"provider should include 'openrouter', got {r['provider']!r}"
        )
        assert int(r["input_tokens"]) > 0
        assert int(r["output_tokens"]) > 0
        assert int(r["latency_ms"]) > 0
        assert int(r["invocation_id"]) > 0

    finally:
        deinstrument()
        engine.dispose()


@pytest.mark.skipif(
    "OPENROUTER_API_KEY" not in os.environ,
    reason="Real LLM integration — set OPENROUTER_API_KEY",
)
def test_264_two_concurrent_agents_dont_leak_context_via_openrouter():
    """PROOF #264 fix works. Before ContextVar swap:
    two asyncio tasks calling autoinstrument() concurrently would clobber
    each other's _CONTEXT — the second call would overwrite the first's
    agent_key + invocation_id, so cost rows from Agent A could end up
    attributed to Agent B's tenant.

    After ContextVar swap: each asyncio task carries its own _CONTEXT
    copy, so isolation holds even under concurrent real LLM traffic.

    We run two REAL OpenRouter calls in parallel via asyncio.gather,
    each in its own autoinstrument() context with distinct tenant_ids
    and agent_keys. Then we inspect kya_cost_events and assert:
    - Exactly 2 cost rows landed (one per agent)
    - Tenant A's row belongs to Tenant A (no leak to Tenant B)
    - Same for Tenant B → A"""
    import asyncio

    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    import litellm

    from kya import (
        autoinstrument,
        deinstrument,
        ensure_invocations_table,
        init_evidence_table,
    )
    from kya.tenant_budget import ensure_tables as ensure_cost_tables

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Session = sessionmaker(bind=engine)
    with Session() as db:
        ensure_invocations_table(db)
        init_evidence_table(db)
        ensure_cost_tables(db)

    tenant_a = "aaaaaaaa-0000-0000-0000-00000000aaaa"
    tenant_b = "bbbbbbbb-0000-0000-0000-00000000bbbb"

    async def _agent_task(tenant_id: str, agent_key: str, prompt: str):
        # Each task runs autoinstrument() in its OWN context; the
        # ContextVar isolation means each task sees only its own
        # _CONTEXT, not the sibling's.
        autoinstrument(
            db_factory=Session,
            tenant_id=tenant_id,
            agent_key=agent_key,
            sdks=["litellm"],
        )
        # asyncio-compatible LiteLLM call
        return await litellm.acompletion(
            model="openrouter/openai/gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=5,
        )

    async def _run_both_concurrent():
        return await asyncio.gather(
            _agent_task(tenant_a, "agent_alpha", "Reply with the word alpha."),
            _agent_task(tenant_b, "agent_beta", "Reply with the word beta."),
        )

    try:
        results = asyncio.run(_run_both_concurrent())
        assert len(results) == 2
        # Both real LLM calls succeeded
        for r in results:
            assert r is not None
            assert getattr(r, "usage", None) is not None

        with engine.begin() as conn:
            # (1) Each tenant's OWN cost rows
            rows_a = conn.execute(
                text(
                    "SELECT usd_amount, agent_key, invocation_id FROM kya_cost_events "
                    "WHERE tenant_id = :t"
                ),
                {"t": tenant_a},
            ).mappings().all()
            rows_b = conn.execute(
                text(
                    "SELECT usd_amount, agent_key, invocation_id FROM kya_cost_events "
                    "WHERE tenant_id = :t"
                ),
                {"t": tenant_b},
            ).mappings().all()

            # (2) Cross-tenant leak probes: assert NO row belonging to
            # agent_alpha ever landed under tenant_b, and vice versa.
            leak_alpha_into_b = conn.execute(
                text(
                    "SELECT COUNT(*) AS n FROM kya_cost_events "
                    "WHERE tenant_id = :t AND agent_key = :a"
                ),
                {"t": tenant_b, "a": "agent_alpha"},
            ).scalar_one()
            leak_beta_into_a = conn.execute(
                text(
                    "SELECT COUNT(*) AS n FROM kya_cost_events "
                    "WHERE tenant_id = :t AND agent_key = :a"
                ),
                {"t": tenant_a, "a": "agent_beta"},
            ).scalar_one()

            # (3) Invocation table isolation — same probe on kya_invocations
            inv_a = conn.execute(
                text("SELECT agent_key FROM kya_invocations WHERE tenant_id = :t"),
                {"t": tenant_a},
            ).mappings().all()
            inv_b = conn.execute(
                text("SELECT agent_key FROM kya_invocations WHERE tenant_id = :t"),
                {"t": tenant_b},
            ).mappings().all()

            # (4) Evidence table isolation — prompt evidence rows too
            ev_a = conn.execute(
                text(
                    "SELECT invocation_id FROM kya_evidence "
                    "WHERE tenant_id = :t AND evidence_kind = 'prompt'"
                ),
                {"t": tenant_a},
            ).mappings().all()
            ev_b = conn.execute(
                text(
                    "SELECT invocation_id FROM kya_evidence "
                    "WHERE tenant_id = :t AND evidence_kind = 'prompt'"
                ),
                {"t": tenant_b},
            ).mappings().all()

        # ── ISOLATION ASSERTIONS ────────────────────────────────────

        # Positive: each tenant has its own row(s)
        assert len(rows_a) >= 1, f"tenant_a should have >=1 cost row, got {rows_a}"
        assert len(rows_b) >= 1, f"tenant_b should have >=1 cost row, got {rows_b}"

        # Positive: agent_key matches within tenant
        for r in rows_a:
            assert r["agent_key"] == "agent_alpha", (
                f"tenant_a cost row wrong agent_key: {dict(r)}"
            )
        for r in rows_b:
            assert r["agent_key"] == "agent_beta", (
                f"tenant_b cost row wrong agent_key: {dict(r)}"
            )

        # NEGATIVE (cross-tenant leak probes) — the load-bearing bit
        assert leak_alpha_into_b == 0, (
            f"LEAK: {leak_alpha_into_b} agent_alpha cost row(s) written under tenant_b"
        )
        assert leak_beta_into_a == 0, (
            f"LEAK: {leak_beta_into_a} agent_beta cost row(s) written under tenant_a"
        )

        # Invocation-table isolation (should also hold since ContextVar
        # is the identity source for record_invocation too)
        for r in inv_a:
            assert r["agent_key"] == "agent_alpha", (
                f"tenant_a invocation wrong agent_key: {dict(r)}"
            )
        for r in inv_b:
            assert r["agent_key"] == "agent_beta", (
                f"tenant_b invocation wrong agent_key: {dict(r)}"
            )

        # Evidence-table isolation — prompts must land under the tenant
        # whose autoinstrument() saw them. If ContextVar was leaking,
        # both prompts could pile up under one tenant.
        assert len(ev_a) >= 1, f"tenant_a should have >=1 prompt evidence, got {ev_a}"
        assert len(ev_b) >= 1, f"tenant_b should have >=1 prompt evidence, got {ev_b}"

        # Referential-integrity: cost row's invocation_id must point at
        # an invocation belonging to the SAME tenant. If tenant_a's
        # cost row had a tenant_b invocation_id, that's an isolation
        # break even if agent_key looks right.
        with engine.begin() as conn:
            for r in rows_a:
                own_inv = conn.execute(
                    text(
                        "SELECT tenant_id FROM kya_invocations WHERE id = :i"
                    ),
                    {"i": r["invocation_id"]},
                ).scalar_one_or_none()
                assert own_inv == tenant_a, (
                    f"tenant_a cost row invocation_id={r['invocation_id']} "
                    f"actually belongs to tenant {own_inv!r}"
                )
            for r in rows_b:
                own_inv = conn.execute(
                    text(
                        "SELECT tenant_id FROM kya_invocations WHERE id = :i"
                    ),
                    {"i": r["invocation_id"]},
                ).scalar_one_or_none()
                assert own_inv == tenant_b, (
                    f"tenant_b cost row invocation_id={r['invocation_id']} "
                    f"actually belongs to tenant {own_inv!r}"
                )

    finally:
        deinstrument()
        engine.dispose()


@pytest.mark.skipif(
    "OPENROUTER_API_KEY" not in os.environ,
    reason="Real LLM integration — set OPENROUTER_API_KEY",
)
def test_265_llm_error_is_captured_as_evidence_and_reraises():
    """PROOF #265 fix works. Before try/except wrap:
    when the LLM call raised (bad API key, unknown model, rate limit),
    the exception propagated but NO evidence was recorded. Silent tail —
    ops teams saw failures in prod logs with no matching KYA row.

    After the wrap: an 'error' evidence row lands linked to the
    invocation, AND the exception still propagates to the caller
    unchanged.

    We force a real error via a non-existent OpenRouter model and
    assert both the exception AND the evidence row."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    import litellm

    from kya import (
        autoinstrument,
        deinstrument,
        ensure_invocations_table,
        init_evidence_table,
    )
    from kya.tenant_budget import ensure_tables as ensure_cost_tables

    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    with Session() as db:
        ensure_invocations_table(db)
        init_evidence_table(db)
        ensure_cost_tables(db)

    tenant = "cccccccc-0000-0000-0000-00000000cccc"
    exc_type: type[BaseException] | None = None
    try:
        autoinstrument(
            db_factory=Session,
            tenant_id=tenant,
            agent_key="failing_agent",
            sdks=["litellm"],
        )
        try:
            # A model name that OpenRouter will reject → real error path
            litellm.completion(
                model="openrouter/nonexistent-provider/no-such-model-xyz",
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=1,
            )
            raise AssertionError("expected LLM call to raise, but it returned normally")
        except AssertionError:
            raise
        except Exception as e:
            exc_type = type(e)

        # Assertion 1: the exception DID propagate (not swallowed)
        assert exc_type is not None, "exception should have propagated, got None"

        # Assertion 2: an error evidence row was written by _capture_error.
        # Filter on payload marker (kya.evidence coerces unknown
        # evidence_kind → "system_message", so we tag the error inside
        # the payload as {"kind": "llm_error", ...}).
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT evidence_kind, payload FROM kya_evidence "
                    "WHERE tenant_id = :t AND evidence_kind = 'system_message'"
                ),
                {"t": tenant},
            ).mappings().all()
        error_rows = [
            r for r in rows
            if isinstance(r.get("payload"), dict)
            and r["payload"].get("kind") == "llm_error"
        ]
        # SQLite may return payload as a JSON string; handle both cases.
        if not error_rows:
            import json as _json
            error_rows = [
                r for r in rows
                if isinstance(r.get("payload"), str)
                and _json.loads(r["payload"]).get("kind") == "llm_error"
            ]
        assert len(error_rows) >= 1, (
            f"expected >=1 llm_error evidence row for tenant {tenant}, got {list(rows)}"
        )

        # Assertion 3: no cost row written (usd=0 on error → dropped)
        with engine.begin() as conn:
            cost_rows = conn.execute(
                text("SELECT * FROM kya_cost_events WHERE tenant_id = :t"),
                {"t": tenant},
            ).mappings().all()
        assert cost_rows == [], (
            f"error path should not write cost rows, got {cost_rows}"
        )

    finally:
        deinstrument()
        engine.dispose()


def test_no_veldt_runtime_leak():
    """Subprocess isolation: other tests in this file pre-load
    ``decisions.*`` modules into ``sys.modules`` (intentionally, to stub
    out the parent app for cross-backend table tests). We need a fresh
    interpreter to verify ``import kya`` alone does not pull them in.
    """
    import json
    import subprocess

    code = (
        "import sys, json\n"
        "import kya\n"
        "forbidden = ('fastapi','uvicorn','starlette','decisions','services','routes','agents.api','agents.registry')\n"
        "leaked = sorted(m for m in sys.modules if any(m == k or m.startswith(k + '.') for k in forbidden))\n"
        "print(json.dumps(leaked))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    leaked = json.loads(result.stdout.strip())
    assert not leaked, f"runtime leak after `import kya`: {leaked}"
