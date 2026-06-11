"""Tests for the runtime bridge: ingestion, principal binding, and
**live HMAC-evidence-chain attach against a real SQLite DB**.

Layer 3 of the runtime-bridge test stack. The HMAC-chain test is the
load-bearing assurance: it proves that a Falco alert genuinely lands
as a signed row in ``kya_evidence`` whose ``payload_hash`` matches
the canonical event we built. That's the "principal-bound evidence"
promise made concrete -- not a stub, an actual chain row that
``verify_chain`` accepts.

The live test uses SQLite-in-memory because:
* It's the cheap-infra end of the three-layer commitment.
* ``kya.evidence`` is dialect-aware and supports SQLite.
* CI can run it without docker.

A subsequent test file (``test_runtime_falco_live.py``, gated by
``KYA_RUNTIME_LIVE_FALCO=1``) will run against an actual Falco
container.
"""
from __future__ import annotations

import json

import pytest

from kya.runtime import (
    PrincipalHint,
    ProcessRef,
    RuntimeEvent,
    ingest,
    record_runtime_event,
    reset_principal_resolver_to_default,
    set_principal_resolver,
)

# ── Fixture: a canonical event ─────────────────────────────────


def _make_event(**overrides) -> RuntimeEvent:
    defaults = dict(
        source_tool="falco",
        source_rule_id="Terminal shell in container",
        occurred_at_ts=1748513025.0,
        severity="high",
        action="terminal_shell_in_container",
        message="A shell was spawned in a container",
        container_id="abcd1234",
        container_image="alpine",
        pod_name="checkout-7f8b9c-x2k",
        namespace="production",
        node="node-01",
        process=ProcessRef(
            name="sh", cmdline="sh -i", pid=12345, ppid=1234,
            user="root", uid=0,
        ),
        principal_hints=(
            PrincipalHint("container_label", "agent_42"),
            PrincipalHint("service_account", "production/checkout-runner"),
            PrincipalHint("process_user", "root"),
        ),
        tags=("container", "mitre_execution", "T1059"),
        raw={"rule": "Terminal shell in container", "priority": "Warning"},
    )
    defaults.update(overrides)
    return RuntimeEvent(**defaults)


# ── Principal binding (no resolver, no DB) ─────────────────────


@pytest.fixture(autouse=True)
def _reset_resolver():
    """Each test starts with the resolver disabled so we can assert
    on the bridge's unbound / explicit behavior without the default
    auto-chain interfering (it would otherwise try docker / naming /
    etc). Tests that need a specific resolver install it explicitly.
    Teardown resets to the production default chain so a later test
    file using import-time defaults isn't surprised."""
    set_principal_resolver(None)
    yield
    reset_principal_resolver_to_default()


def test_unbound_event_still_accepted_and_dispatched():
    """No resolver, no pre-bound tenant -- bridge still accepts the
    event so we never silently drop runtime evidence."""
    r = record_runtime_event(_make_event())
    assert r.accepted is True
    assert r.principal_binding_method == "unbound"
    assert r.tenant_id is None
    assert r.principal_id is None
    assert r.attack_chain_matches == []
    assert r.evidence_id is None


def test_explicit_tenant_principal_on_event_wins():
    """When the caller pre-binds the event (parsed from a richer
    payload), the bridge uses that without consulting hints."""
    ev = _make_event(tenant_id="t1", principal_id="agent_42")
    r = record_runtime_event(ev)
    assert r.principal_binding_method == "explicit"
    assert r.tenant_id == "t1"
    assert r.principal_id == "agent_42"


def test_custom_event_resolver_returns_tid_pid_and_method():
    """A custom resolver gets the whole event and returns
    (tenant_id, principal_id, method_label). The bridge surfaces the
    label in RuntimeIngestResult so operators can tell what bound it.
    """
    def resolver(ev):
        if ev.container_id == "abcd1234":
            return ("tenant_x", "principal_from_custom", "custom_db")
        return None

    set_principal_resolver(resolver)
    r = record_runtime_event(_make_event())
    assert r.principal_binding_method == "custom_db"
    assert r.tenant_id == "tenant_x"
    assert r.principal_id == "principal_from_custom"


def test_resolver_exception_is_swallowed_and_falls_through_to_unbound():
    """A buggy resolver must not crash the bridge -- exception
    logged + fall through to unbound. Crucial for production: one
    flaky lookup backend cannot stop runtime evidence flowing."""
    def resolver(ev):
        raise RuntimeError("boom")

    set_principal_resolver(resolver)
    r = record_runtime_event(_make_event())
    assert r.accepted is True
    assert r.principal_binding_method == "unbound"


def test_explicit_hint_kind_resolves_without_resolver():
    """An ``explicit`` hint carries the principal_id verbatim, so it
    binds even when no resolver is wired up. Useful for collectors
    that already know the principal."""
    ev = _make_event(
        tenant_id="t1",
        principal_hints=(PrincipalHint("explicit", "agent_x"),),
    )
    r = record_runtime_event(ev)
    assert r.principal_binding_method == "hint:explicit"
    assert r.principal_id == "agent_x"


# ── ingest() dispatch / autodetect ─────────────────────────────


def test_ingest_with_explicit_source_tool_uses_named_parser():
    falco_sample = {
        "time": "2026-05-29T10:23:45.000Z",
        "rule": "X", "priority": "Notice",
        "output": "x", "tags": [], "hostname": "h",
        "output_fields": {"proc.name": "sh"},
    }
    r = ingest(falco_sample, source_tool="falco")
    assert r.accepted is True
    assert r.source_tool == "falco"


def test_ingest_with_unregistered_source_tool_returns_clear_error():
    r = ingest({"x": 1}, source_tool="tetragon")  # not yet shipped
    assert r.accepted is False
    assert "no parser registered" in (r.error or "")


def test_ingest_autodetect_finds_falco_for_falco_shape():
    falco_sample = {
        "rule": "X", "priority": "Notice",
        "output_fields": {"proc.name": "sh"},
    }
    r = ingest(falco_sample)
    assert r.accepted is True
    assert r.source_tool == "falco"


def test_ingest_autodetect_returns_clear_error_on_unknown_shape():
    r = ingest({"alien_format": True})
    assert r.accepted is False
    assert "no registered parser" in (r.error or "")


# ── LIVE: HMAC evidence-chain attach against SQLite ────────────


def _make_sqlite_session():
    """Build a real SQLAlchemy session backed by SQLite-in-memory.

    kya.evidence is dialect-aware; SQLite is the cheapest backend
    that exercises the real schema path -- the table is created
    via ``init_evidence_table`` exactly the way it is in prod.
    """
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from sqlalchemy.orm import sessionmaker

    eng = sqlalchemy.create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=eng)
    return Session(), eng


def test_live_record_runtime_event_writes_signed_evidence_row():
    """**The load-bearing assurance.** A canonical event with a real
    DB session and an invocation_id anchor lands a signed row in
    kya_evidence with the right payload hash, evidence_kind, and
    principal binding. Without this test, "principal-bound evidence"
    would just be a slide."""
    session, _eng = _make_sqlite_session()
    try:
        ev = _make_event(tenant_id="t1", principal_id="agent_42")
        r = record_runtime_event(
            ev, db=session, invocation_id=1,
            correlation_id="corr_xyz",
        )

        assert r.accepted is True
        assert r.evidence_id is not None, "must attach to HMAC chain"
        assert r.principal_binding_method == "explicit"

        # Read the row back and verify it carries what we claimed.
        from kya.evidence import get_evidence
        row = get_evidence(session, tenant_id="t1", evidence_id=r.evidence_id)
        assert row is not None
        assert row["evidence_kind"] == "runtime_falco"
        assert row["correlation_id"] == "corr_xyz"
        assert row["source"] == "runtime.falco"
        # payload was the flattened canonical view -- spot-check
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        assert payload["source_rule_id"] == "Terminal shell in container"
        assert payload["container_id"] == "abcd1234"
        assert payload["proc.cmdline"] == "sh -i"
        # The HMAC chain fields must be populated.
        assert row["payload_hash"]
        assert row["signed_hash"]
    finally:
        session.close()


def test_live_evidence_chain_verifies_after_multiple_events():
    """Two consecutive runtime events in the same (tenant,
    invocation) anchor must chain: row 2's prev_hash equals row 1's
    signed_hash, and ``verify_chain`` confirms the chain is intact.

    This is the property regulated buyers will pay for. Test it
    against the real SQLite-backed implementation.
    """
    session, _eng = _make_sqlite_session()
    try:
        ev1 = _make_event(
            tenant_id="t1", principal_id="agent_42",
            occurred_at_ts=100.0,
            source_rule_id="rule_a",
        )
        ev2 = _make_event(
            tenant_id="t1", principal_id="agent_42",
            occurred_at_ts=101.0,
            source_rule_id="rule_b",
        )
        r1 = record_runtime_event(ev1, db=session, invocation_id=42)
        r2 = record_runtime_event(ev2, db=session, invocation_id=42)
        assert r1.evidence_id and r2.evidence_id

        from kya.evidence import verify_chain
        result = verify_chain(session, tenant_id="t1", invocation_id=42)
        assert result["valid"] is True, result
        assert result["broken_at"] is None, result
        assert result["checked"] == 2, result
    finally:
        session.close()


def test_live_no_invocation_id_skips_chain_but_still_dispatches():
    """When the collector doesn't have an anchor invocation_id,
    the bridge MUST still accept the event and run attack-chain
    dispatch -- only the chain attach is skipped. evidence_id=None
    surfaces the missed attach to the caller for logging."""
    session, _eng = _make_sqlite_session()
    try:
        ev = _make_event(tenant_id="t1", principal_id="agent_42")
        r = record_runtime_event(ev, db=session)  # no invocation_id
        assert r.accepted is True
        assert r.evidence_id is None
    finally:
        session.close()
