"""Unit tests for kya/delegation_overrides.py."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from kya import (
    DelegationPolicyError,
    InvalidOverrideError,
    delete_delegation_override,
    init_storage,
    list_delegation_overrides,
    record_invocation,
    resolve_effective_mode,
    set_delegation_override,
    snapshot_agent,
)


TENANT = "00000000-0000-0000-0000-0000000000bb"


def _backends_to_test():
    """Return (label, url) pairs for every backend the env exposes.
    sqlite always; postgresql/mysql if KYA_TEST_*_URL set; duckdb if
    duckdb_engine installed."""
    out = [("sqlite", "sqlite:///:memory:")]
    try:
        import duckdb_engine  # noqa: F401
        out.append(("duckdb", "duckdb:///:memory:"))
    except ImportError:
        pass
    pg = os.environ.get("KYA_TEST_PG_URL")
    if pg:
        out.append(("postgresql", pg))
    my = os.environ.get("KYA_TEST_MYSQL_URL")
    if my:
        out.append(("mysql", my))
    return out


@pytest.fixture(params=_backends_to_test(),
                 ids=lambda p: p[0])
def db(request):
    label, url = request.param
    if label == "postgresql":
        eng = create_engine(url)
        with eng.begin() as conn:
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            for tbl in ("kya_delegation_policy_overrides",
                        "kya_delegation_violations", "kya_invocations",
                        "agent_versions"):
                conn.execute(text(
                    f"DROP TABLE IF EXISTS prov_schema.{tbl}"))
    elif label == "mysql":
        eng = create_engine(url)
        with eng.begin() as conn:
            for tbl in ("kya_delegation_policy_overrides",
                        "kya_delegation_violations", "kya_invocations",
                        "agent_versions"):
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {tbl}"))
                except Exception:
                    pass
    else:
        eng = create_engine(url)
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


@pytest.fixture(autouse=True)
def clean_env():
    prev = os.environ.pop("KYA_DELEGATION_POLICY", None)
    yield
    if prev is not None:
        os.environ["KYA_DELEGATION_POLICY"] = prev
    else:
        os.environ.pop("KYA_DELEGATION_POLICY", None)


# ── CRUD ───────────────────────────────────────────────────────────


def test_set_returns_id_and_resolve_picks_it(db):
    oid = set_delegation_override(
        db, tenant_id=TENANT, mode="block",
        parent_agent_key="OrchA",
        reason="lock down OrchA delegations",
        changed_by="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )
    assert oid > 0
    mode, source = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="OrchA",
        sub_agent_key="SubB", violation_kind="access_escalation")
    assert mode == "block"
    assert "OrchA" in source


def test_unknown_mode_raises(db):
    with pytest.raises(InvalidOverrideError, match="Unknown mode"):
        set_delegation_override(
            db, tenant_id=TENANT, mode="frobozz",
            parent_agent_key="X")


def test_empty_tenant_raises(db):
    with pytest.raises(InvalidOverrideError, match="tenant_id is required"):
        set_delegation_override(db, tenant_id="", mode="observe")


def test_expires_before_effective_raises(db):
    now = datetime.now(timezone.utc)
    with pytest.raises(InvalidOverrideError, match="expires_at"):
        set_delegation_override(
            db, tenant_id=TENANT, mode="observe",
            effective_at=now,
            expires_at=now - timedelta(seconds=1))


def test_list_returns_active_only_by_default(db):
    set_delegation_override(db, tenant_id=TENANT, mode="block",
                              parent_agent_key="LiveOrch")
    # Insert expired override
    set_delegation_override(
        db, tenant_id=TENANT, mode="flag",
        parent_agent_key="ExpiredOrch",
        effective_at=datetime.now(timezone.utc) - timedelta(days=2),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    active = list_delegation_overrides(db, tenant_id=TENANT)
    parents = {a["parent_agent_key"] for a in active}
    assert "LiveOrch" in parents
    assert "ExpiredOrch" not in parents
    all_rows = list_delegation_overrides(
        db, tenant_id=TENANT, include_inactive=True)
    parents_all = {a["parent_agent_key"] for a in all_rows}
    assert {"LiveOrch", "ExpiredOrch"} <= parents_all


def test_soft_delete_expires_now(db):
    oid = set_delegation_override(
        db, tenant_id=TENANT, mode="block",
        parent_agent_key="DeletableOrch")
    ok = delete_delegation_override(db, override_id=oid,
                                       reason="rolled back")
    assert ok
    # Resolution no longer picks it
    mode, source = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="DeletableOrch",
        sub_agent_key="Sub", violation_kind="access_escalation")
    assert source == "global_env"


# ── Specificity ordering ──────────────────────────────────────────


def test_most_specific_wins_over_wildcard(db):
    # Tenant-wide observe
    set_delegation_override(db, tenant_id=TENANT, mode="observe")
    # Parent-specific flag
    set_delegation_override(db, tenant_id=TENANT, mode="flag",
                              parent_agent_key="OrchSpec")
    # Pair-specific block
    set_delegation_override(db, tenant_id=TENANT, mode="block",
                              parent_agent_key="OrchSpec",
                              sub_agent_key="SubSpec")
    # Full-3 (parent + sub + kind) — most specific
    set_delegation_override(db, tenant_id=TENANT, mode="observe",
                              parent_agent_key="OrchSpec",
                              sub_agent_key="SubSpec",
                              violation_kind="access_escalation")

    # Test full-3 wins
    mode, _ = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="OrchSpec",
        sub_agent_key="SubSpec", violation_kind="access_escalation")
    assert mode == "observe"

    # Different kind → falls back to pair-level override (block)
    mode2, _ = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="OrchSpec",
        sub_agent_key="SubSpec", violation_kind="tool_widening")
    assert mode2 == "block"

    # Different sub → falls back to parent-level (flag)
    mode3, _ = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="OrchSpec",
        sub_agent_key="DifferentSub",
        violation_kind="access_escalation")
    assert mode3 == "flag"

    # Different parent → falls back to tenant-level (observe)
    mode4, _ = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="OtherOrch",
        sub_agent_key="OtherSub",
        violation_kind="access_escalation")
    assert mode4 == "observe"


def test_tie_at_same_specificity_last_write_wins(db):
    # Two parent-only overrides for the same parent. Tie-break: the
    # one with the higher id (= second insert) wins.
    id1 = set_delegation_override(db, tenant_id=TENANT, mode="observe",
                                    parent_agent_key="P_tie")
    id2 = set_delegation_override(db, tenant_id=TENANT, mode="block",
                                    parent_agent_key="P_tie")
    mode, source = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="P_tie",
        sub_agent_key="Any", violation_kind="access_escalation")
    # Include id1/id2 in the failure message — when this test flakes
    # (rare PG sequence state issue), seeing the ids points at the
    # tie-break logic vs. an insert ordering issue.
    assert mode == "block", (
        f"expected block (id2={id2} wins over observe at id1={id1}); "
        f"got {mode} from {source}")
    assert "P_tie" in source


def test_no_match_falls_back_to_global_env(db, monkeypatch):
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "flag")
    mode, source = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="never_seen",
        sub_agent_key="never_seen", violation_kind="access_escalation")
    assert mode == "flag"
    assert source == "global_env"


# ── Effective-at / expires-at gating ──────────────────────────────


def test_future_effective_override_is_ignored(db):
    # Override that takes effect tomorrow
    set_delegation_override(
        db, tenant_id=TENANT, mode="block",
        parent_agent_key="FutureOrch",
        effective_at=datetime.now(timezone.utc) + timedelta(days=1))
    mode, source = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="FutureOrch",
        sub_agent_key="X", violation_kind="access_escalation")
    assert source == "global_env"


def test_expired_override_is_ignored(db):
    set_delegation_override(
        db, tenant_id=TENANT, mode="block",
        parent_agent_key="ExpOrch",
        effective_at=datetime.now(timezone.utc) - timedelta(days=2),
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    mode, source = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="ExpOrch",
        sub_agent_key="X", violation_kind="access_escalation")
    assert source == "global_env"


# ── Multi-tenant isolation ────────────────────────────────────────


def test_overrides_are_per_tenant(db):
    other = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    set_delegation_override(
        db, tenant_id=TENANT, mode="block",
        parent_agent_key="SharedKey")
    # Tenant TENANT sees block
    m1, _ = resolve_effective_mode(
        db, tenant_id=TENANT, parent_agent_key="SharedKey",
        sub_agent_key="S", violation_kind="access_escalation")
    assert m1 == "block"
    # Other tenant sees global env (no override)
    m2, src2 = resolve_effective_mode(
        db, tenant_id=other, parent_agent_key="SharedKey",
        sub_agent_key="S", violation_kind="access_escalation")
    assert src2 == "global_env"


# ── Integration with enforce_delegation_policy ───────────────────


def _snapshot_pair(db, parent_key, sub_key,
                    parent_access="read", sub_access="admin"):
    snapshot_agent(db, tenant_id=TENANT, agent_key=parent_key,
                   definition={"agent_key": parent_key,
                                "access_level": parent_access},
                   note="test")
    snapshot_agent(db, tenant_id=TENANT, agent_key=sub_key,
                   definition={"agent_key": sub_key,
                                "access_level": sub_access},
                   note="test")


def test_override_lets_one_pair_block_while_others_observe(db,
                                                              monkeypatch):
    """Global env = observe; an override pins specific orchestrator
    into block — only its delegations raise, others stay silent."""
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "observe")
    _snapshot_pair(db, "OrchBlocked", "SubBlocked")
    _snapshot_pair(db, "OrchSilent", "SubSilent")

    # Override: just OrchBlocked → block
    set_delegation_override(
        db, tenant_id=TENANT, mode="block",
        parent_agent_key="OrchBlocked")

    # OrchSilent → observe (no override, env default)
    record_invocation(
        db, tenant_id=TENANT, agent_key="SubSilent",
        principal_kind="agent", principal_id="OrchSilent")

    # OrchBlocked → raises
    with pytest.raises(DelegationPolicyError):
        record_invocation(
            db, tenant_id=TENANT, agent_key="SubBlocked",
            principal_kind="agent", principal_id="OrchBlocked")


def test_per_kind_override_routes_violations_to_different_modes(db,
                                                                    monkeypatch):
    """Two violation kinds from one delegation can land in different
    modes if a kind-specific override exists."""
    monkeypatch.setenv("KYA_DELEGATION_POLICY", "observe")
    # Parent + sub with two violations: access_escalation AND tool_widening
    snapshot_agent(db, tenant_id=TENANT, agent_key="ParentLooks",
                   definition={"agent_key": "ParentLooks",
                                "access_level": "read", "tools": []},
                   note="test")
    snapshot_agent(db, tenant_id=TENANT, agent_key="SubMisbehaves",
                   definition={"agent_key": "SubMisbehaves",
                                "access_level": "admin",
                                "tools": ["execute_sql"]},
                   note="test")
    # Per-kind override: only escalation → block; widening stays observe
    set_delegation_override(
        db, tenant_id=TENANT, mode="block",
        violation_kind="access_escalation")

    with pytest.raises(DelegationPolicyError):
        record_invocation(
            db, tenant_id=TENANT, agent_key="SubMisbehaves",
            principal_kind="agent", principal_id="ParentLooks")

    # Both violations should be persisted, but only access_escalation
    # in block mode; tool_widening in observe. Use the dialect-aware
    # schema prefix so this query works on PG (prov_schema.) AND on
    # sqlite/duckdb/mysql (default ns).
    _sp = ("prov_schema."
           if db.get_bind().dialect.name == "postgresql" else "")
    rows = db.execute(text(
        f"SELECT violation_kind, mode_active, blocked "
        f"FROM {_sp}kya_delegation_violations "
        f"WHERE sub_agent_key='SubMisbehaves' ORDER BY violation_kind"
    )).fetchall()
    by_kind = {r[0]: (r[1], r[2]) for r in rows}
    assert by_kind.get("access_escalation") is not None
    assert by_kind["access_escalation"][0] == "block"
    assert by_kind["access_escalation"][1] in (1, True)
    # The "tool_widening" kind isn't an admin/write tool by default,
    # but if present it should be observe
    if "tool_widening" in by_kind:
        assert by_kind["tool_widening"][0] == "observe"
        assert by_kind["tool_widening"][1] in (0, False)
