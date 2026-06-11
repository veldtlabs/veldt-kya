"""Phase 5g Part B — DID-to-KYA integration regression tests.

Covers integration points #3, #4, #5, #7, #9 from the design doc:

- #3 / #4 / #7: new event kinds in `_HARDENING_EVENT_KINDS` so the
  gateway / issuer-API can emit revocation_blocked / dpop_* /
  issuer_rotation_pending through the existing emit_security_event().
- #5: VC issuer DID → kya_principal_edges link when the issuer is a
  known KYA principal in the same tenant.
- #9: new evidence kinds in VALID_EVIDENCE_KINDS so callers don't
  silently fall back to system_message.

Integration points #1 (rate_limit) and #2 (Valkey JtiCache) landed
in Phase 5f and have their own tests in `veldt-kya-pro`.

Integration points #6 (VC scope → delegation_policy) and #8 (issuer
tenant_id UUID normalization) are deferred — they need design work
beyond the scope of this phase (#6 requires customer-authored scope
policies, #8 requires a schema migration).
"""
from __future__ import annotations

# ─── #9 — new evidence kinds are registered ────────────────────────


def test_phase5g_evidence_kinds_registered():
    from kya.evidence import VALID_EVIDENCE_KINDS
    new_kinds = {
        "issuer_vc_issued",
        "issuer_vc_revoked",
        "trust_registry_change",
        "gateway_verdict",
        "revocation_blocked",
        "dpop_replay",
        "dpop_forge_attempt",
        "dpop_expired",
        "issuer_rotation_pending",
    }
    missing = new_kinds - set(VALID_EVIDENCE_KINDS)
    assert not missing, f"missing evidence kinds: {sorted(missing)}"


# ─── #3 / #4 / #7 — new security event kinds emit correctly ─────────


def test_phase5g_security_event_kinds_registered():
    from kya._security_events import _HARDENING_EVENT_KINDS
    new_kinds = {
        "revocation_blocked",
        "dpop_replay",
        "dpop_forge_attempt",
        "dpop_expired",
        "issuer_rotation_pending",
    }
    missing = new_kinds - _HARDENING_EVENT_KINDS
    assert not missing, f"missing security-event kinds: {sorted(missing)}"


def test_hardening_event_kinds_match_realtime_and_signal_deltas():
    """5g-B-11 — every _HARDENING_EVENT_KIND must also appear in
    realtime.ALLOWED_SIGNAL_KINDS AND users.SIGNAL_DELTAS, or the
    realtime + DB persistence paths silently drop the signal."""
    from kya._security_events import _HARDENING_EVENT_KINDS
    from kya.realtime import ALLOWED_SIGNAL_KINDS
    from kya.users import SIGNAL_DELTAS
    missing_realtime = _HARDENING_EVENT_KINDS - ALLOWED_SIGNAL_KINDS
    assert not missing_realtime, (
        f"_HARDENING_EVENT_KINDS not in realtime.ALLOWED_SIGNAL_KINDS: "
        f"{sorted(missing_realtime)}"
    )
    missing_deltas = _HARDENING_EVENT_KINDS - set(SIGNAL_DELTAS)
    assert not missing_deltas, (
        f"_HARDENING_EVENT_KINDS not in users.SIGNAL_DELTAS: "
        f"{sorted(missing_deltas)}"
    )


def test_emit_security_event_revocation_blocked_does_not_drop_silently(monkeypatch, caplog):
    """Before 5g, emit_security_event('revocation_blocked', ...) would
    log DEBUG ('unknown event_kind') and skip persistence. After 5g it
    must log WARNING and attempt persistence."""
    import logging
    caplog.set_level(logging.WARNING, logger="kya._security_events")
    from kya._security_events import emit_security_event

    emit_security_event(
        "revocation_blocked",
        tenant_id="t1",
        primitive="gateway",
        principal_kind="agent",
        principal_id="agent-abc",
        detail={"reason": "status list bit set"},
    )
    # The WARNING log line is the universal-fail path; presence proves
    # the kind reached the persistence pipeline (not "skipping
    # persistence" at DEBUG).
    matched = [r for r in caplog.records
               if "revocation_blocked" in r.message
               and "agent-abc" in r.message]
    assert matched, "revocation_blocked event was silently dropped"


def test_emit_security_event_dpop_replay_warns(caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="kya._security_events")
    from kya._security_events import emit_security_event
    emit_security_event(
        "dpop_replay",
        tenant_id="t1",
        primitive="gateway",
        detail={"jti": "abc123"},
    )
    matched = [r for r in caplog.records
               if "dpop_replay" in r.message]
    assert matched


def test_emit_security_event_unknown_kind_still_skips_persistence(caplog):
    """Sanity check — the closed-set gate still rejects garbage."""
    import logging
    caplog.set_level(logging.DEBUG, logger="kya._security_events")
    from kya._security_events import emit_security_event
    emit_security_event(
        "totally_made_up_event",
        tenant_id="t1",
        primitive="x",
    )
    skipped = [r for r in caplog.records
               if "unknown event_kind" in r.message]
    assert skipped, "unknown kinds should hit the closed-set DEBUG path"


# ─── #5 — VC issuer DID becomes a principal_edges parent link ──────


def test_bind_did_principal_links_known_issuer_via_principal_edges(tmp_path):
    """When the VC's issuer DID matches an existing KYA principal in
    the same tenant, bind_did_principal must write an edge linking
    the issuer (parent) to the bound principal (child). Lets the
    delegation-graph queries traverse from "who issued this VC?" to
    "who is allowed to act under it?" without scanning attributes."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{tmp_path / 'kya.db'}")
    Session = sessionmaker(bind=engine)
    db = Session()

    # Ensure schemas exist.
    from kya.principal_edges import (
        ensure_principal_edges_table,
        list_children,
    )
    from kya.principals import ensure_principal_table as ensure_principal_tables
    ensure_principal_tables(db)
    ensure_principal_edges_table(db)

    # The gateway-bound principal exists.
    from kya.principals import record_principal_signal
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="child-agent", signal_kind="clean_invocation",
    )
    # The "issuer" exists as a known principal too.
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="issuer-agent", signal_kind="clean_invocation",
    )
    db.commit()

    # The hook we're adding to bind_did_principal needs to be exercised.
    # We call the public helper that consolidates the VC-issuer →
    # principal-edges link (Phase 5g #5). When kya/external_id.py
    # exposes it as a follow-up to bind_did_principal, callers may
    # invoke it directly too (e.g., from the gateway after a successful
    # bind).
    from kya.external_id import link_vc_issuer_to_child
    link_vc_issuer_to_child(
        db,
        tenant_id="t1",
        issuer_did="did:web:issuer.example",
        issuer_principal_id="issuer-agent",
        child_principal_kind="agent",
        child_principal_id="child-agent",
    )
    db.commit()

    children = list_children(
        db, tenant_id="t1",
        parent_kind="agent", parent_id="issuer-agent",
    )
    assert any(c.child_id == "child-agent" and c.edge_kind == "vc_issued"
               for c in children), (
        f"VC-issuer edge not recorded: {children}"
    )


def test_link_vc_issuer_no_op_when_issuer_unknown(tmp_path):
    """When the VC issuer is NOT a known KYA principal, the linker
    must no-op silently — issuers from unknown trust domains shouldn't
    spawn ghost edges. Returns False to signal no link was written."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(f"sqlite:///{tmp_path / 'kya2.db'}")
    Session = sessionmaker(bind=engine)
    db = Session()

    from kya.principal_edges import ensure_principal_edges_table
    from kya.principals import ensure_principal_table as ensure_principal_tables
    from kya.principals import record_principal_signal
    ensure_principal_tables(db)
    ensure_principal_edges_table(db)
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="orphan-child", signal_kind="clean_invocation",
    )
    db.commit()

    from kya.external_id import link_vc_issuer_to_child
    linked = link_vc_issuer_to_child(
        db,
        tenant_id="t1",
        issuer_did="did:web:unknown.example",
        issuer_principal_id=None,   # caller signals "no KYA principal"
        child_principal_kind="agent",
        child_principal_id="orphan-child",
    )
    assert linked is False
