"""Phase 5g Part B — security event emission + automatic VC issuer linkage.

Covers integration points #3 (revocation_blocked), #4 (dpop_* events),
and #5-wiring (link_vc_issuer_to_child fires from inside
bind_did_principal automatically).
"""
from __future__ import annotations

import json
import logging
import os

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"


# ─── #3 — revocation block emits a security event ──────────────────


def _stub_kya_for_gateway(monkeypatch, *, sec_sink=None):
    """Stub `kya` core + `kya._security_events` for gateway tests.

    Capture emit_security_event calls into `sec_sink` so tests can
    assert which event_kinds the gateway fired."""
    import sys
    import types
    fake = types.ModuleType("kya")

    class _Sess:
        def commit(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fake.default_session = lambda: _Sess()
    fake.record_invocation = lambda db, **kw: 1
    fake.record_evidence = lambda db, **kw: 1
    fake.record_principal_signal = lambda db, **kw: 1
    class _ADE(Exception): pass
    fake.AccessDeniedError = _ADE
    fake.require_action = lambda *a, **k: True

    # Fake _security_events submodule — the gateway imports
    # `from kya._security_events import emit_security_event`.
    captured = sec_sink if sec_sink is not None else []
    fake_se = types.ModuleType("kya._security_events")

    def fake_emit(event_kind, **kw):
        captured.append({"event_kind": event_kind, **kw})

    fake_se.emit_security_event = fake_emit
    fake._security_events = fake_se

    monkeypatch.setitem(sys.modules, "kya", fake)
    monkeypatch.setitem(sys.modules, "kya._security_events", fake_se)
    return captured


def test_revocation_blocked_emits_security_event(monkeypatch, caplog):
    """When a VC fails the status-list check, the gateway must emit a
    `revocation_blocked` security event so trust-score + attack-chain
    correlation see the signal."""
    caplog.set_level(logging.WARNING, logger="kya._security_events")
    sec_events = _stub_kya_for_gateway(monkeypatch)

    from fastapi.testclient import TestClient

    from kya_gateway.config import (
        AuditConfig,
        BackendConfig,
        DIDConfig,
        EnforcementConfig,
        GatewayBindConfig,
        GatewayConfig,
        IdentityConfig,
        JWTConfig,
        PolicyConfig,
    )
    from kya_gateway.errors import RevocationBlocked
    from kya_gateway.server import Gateway

    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t-rev"),
        identity=IdentityConfig(
            methods=["bearer_jwt"], jwt=JWTConfig(),
            did=DIDConfig(
                resolvers=["key"], trusted_issuers=[],
                allow_header_trust=True,
                pop_audience="http://testserver/mcp",
                dpop_audience="http://testserver",
                require_dpop_on_me=False,
            ),
        ),
        backends=[BackendConfig(name="default", url="http://localhost:1")],
        policy=PolicyConfig(),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode="audit_only"),
    )
    gw = Gateway(cfg)

    # Force identity to fail with the specific subclass.
    from kya_gateway import identity as _id_mod
    def fail(self, h):
        raise RevocationBlocked("VC was revoked")
    monkeypatch.setattr(_id_mod.IdentityResolver, "resolve", fail)

    from kya_gateway import forwarder as _fwd
    async def fake_forward(self, backend_name, payload, **_kw):
        return _fwd.ForwardResult(status_code=200, body=b'{}',
                                  headers={"content-type": "application/json"})
    monkeypatch.setattr(_fwd.Forwarder, "forward_json", fake_forward)

    client = TestClient(gw.app)
    client.post("/mcp", data=json.dumps({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"filesystem.read","arguments":{}},
    }), headers={"Content-Type":"application/json",
                 "Authorization":"Bearer revoked-token"})

    kinds = [e["event_kind"] for e in sec_events]
    assert "revocation_blocked" in kinds, (
        f"expected revocation_blocked event, got {kinds}"
    )


def test_revocation_blocked_passes_allow_create_false_to_signal_record(
    monkeypatch,
):
    """Phase 14a #147 — the gateway's identity-failure path MUST
    invoke ``record_principal_signal`` with ``allow_create=False`` so
    a VC signed by a cross-tenant federated trusted issuer can't
    create a phantom ``(gateway_tenant, that_other_tenant's_principal_id)``
    row. A future refactor that drops the kwarg would silently reopen
    the vulnerability, so we pin the contract here.

    Also asserts that the ``cross_tenant_signal_dropped`` metric
    increments when the OSS function returns ``-1`` (the sentinel for
    "skipped, no existing row"), since the metric is the only
    operator-visible signal that the defence fired.
    """
    sec_events = _stub_kya_for_gateway(monkeypatch)

    # Override the stubbed `record_principal_signal` to (a) capture
    # the kwargs it was called with and (b) return -1 so the metric
    # bump path fires.
    captured_signal_calls: list = []
    import sys

    def captured_record(db, **kw):
        captured_signal_calls.append(kw)
        return -1

    sys.modules["kya"].record_principal_signal = captured_record

    from fastapi.testclient import TestClient

    from kya_gateway.config import (
        AuditConfig, BackendConfig, DIDConfig, EnforcementConfig,
        GatewayBindConfig, GatewayConfig, IdentityConfig, JWTConfig,
        PolicyConfig,
    )
    from kya_gateway.errors import RevocationBlocked
    from kya_gateway.server import Gateway, _METRICS

    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0",
                                  tenant_id="t-147"),
        identity=IdentityConfig(
            methods=["bearer_jwt"], jwt=JWTConfig(),
            did=DIDConfig(
                resolvers=["key"], trusted_issuers=[],
                allow_header_trust=True,
                pop_audience="http://testserver/mcp",
                dpop_audience="http://testserver",
                require_dpop_on_me=False,
            ),
        ),
        backends=[BackendConfig(name="default",
                                url="http://localhost:1")],
        policy=PolicyConfig(),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode="audit_only"),
    )
    gw = Gateway(cfg)

    # Raise RevocationBlocked with principal info attached
    # (matches identity.py:_maybe_check_revocation post-#145).
    from kya_gateway import identity as _id_mod
    def fail(self, h):
        raise RevocationBlocked(
            "VC was revoked",
            principal_kind="agent",
            principal_id="did:key:zCROSSTENANT",
        )
    monkeypatch.setattr(_id_mod.IdentityResolver, "resolve", fail)

    from kya_gateway import forwarder as _fwd
    async def fake_forward(self, backend_name, payload, **_kw):
        return _fwd.ForwardResult(
            status_code=200, body=b'{}',
            headers={"content-type": "application/json"},
        )
    monkeypatch.setattr(_fwd.Forwarder, "forward_json", fake_forward)

    before = _METRICS["cross_tenant_signal_dropped"]
    client = TestClient(gw.app)
    client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {}},
    }), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer revoked-token",
    })

    # The contract: at least one principal_signal call landed AND it
    # carried allow_create=False.
    assert captured_signal_calls, (
        "_emit_identity_failure_event did not invoke "
        "record_principal_signal -- the #145 bridge regressed"
    )
    allow_create_kwargs = [
        c.get("allow_create") for c in captured_signal_calls
    ]
    assert False in allow_create_kwargs, (
        f"gateway identity-failure path MUST pass "
        f"allow_create=False to defend cross-tenant attribution. "
        f"Captured kwargs: {captured_signal_calls}"
    )
    # And: when the OSS function returns -1, the operator-visible
    # drop counter increments.
    after = _METRICS["cross_tenant_signal_dropped"]
    assert after == before + 1, (
        f"cross_tenant_signal_dropped expected {before + 1}, "
        f"got {after}"
    )


# ─── #4 — DPoP errors emit dpop_* events ──────────────────────────


def test_dpop_failure_on_me_emits_dpop_event(monkeypatch):
    """A failed DPoP proof on /v1/principals/me must emit a
    `dpop_forge_attempt` security event."""
    sec_events = _stub_kya_for_gateway(monkeypatch)

    from fastapi.testclient import TestClient

    from kya_gateway.config import (
        AuditConfig,
        BackendConfig,
        DIDConfig,
        EnforcementConfig,
        GatewayBindConfig,
        GatewayConfig,
        IdentityConfig,
        JWTConfig,
        PolicyConfig,
    )
    from kya_gateway.identity import BoundPrincipal
    from kya_gateway.server import Gateway

    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t-dp"),
        identity=IdentityConfig(
            methods=["bearer_jwt"], jwt=JWTConfig(),
            did=DIDConfig(
                resolvers=["key"], trusted_issuers=[],
                allow_header_trust=False,
                pop_audience="http://testserver/mcp",
                dpop_audience="http://testserver",
                require_dpop_on_me=True,
            ),
        ),
        backends=[BackendConfig(name="default", url="http://localhost:1")],
        policy=PolicyConfig(),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode="enforce"),
    )
    gw = Gateway(cfg)

    # Stub identity to return a DID-method principal (so DPoP runs).
    from kya_gateway import identity as _id_mod
    monkeypatch.setattr(_id_mod.IdentityResolver, "resolve",
                        lambda self, h: BoundPrincipal(
                            principal_kind="agent",
                            principal_id="did:key:z6Mk-x",
                            method="did",
                            external_subject="did:key:z6Mk-x",
                            external_issuer=None,
                        ))
    # Stub the DID resolver — the gateway lazy-imports `kya.did`
    # inside _verify_me_dpop, so we plant a fake module that returns
    # a doc on resolve_did().
    import sys
    import types
    fake_did = types.ModuleType("kya.did")
    class _FakeDoc:
        id = "did:key:z6Mk-x"
        def find_key(self, kid): return None
    fake_did.resolve_did = lambda d: _FakeDoc()
    monkeypatch.setitem(sys.modules, "kya.did", fake_did)

    client = TestClient(gw.app)
    r = client.get("/v1/principals/me",
                   headers={"Authorization": "Bearer x"})
    # 401 since enforce mode + DPoP fail.
    assert r.status_code == 401
    kinds = [e["event_kind"] for e in sec_events]
    assert any(k.startswith("dpop_") for k in kinds), (
        f"expected a dpop_* event, got {kinds}"
    )


# ─── #5 — bind_did_principal auto-links a known issuer ─────────────


def test_bind_did_principal_auto_links_known_issuer(tmp_path, monkeypatch):
    """When the VC's issuer DID maps to an existing KYA principal in
    the tenant, bind_did_principal must call link_vc_issuer_to_child
    automatically — so callers don't have to remember the second step."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(f"sqlite:///{tmp_path / 'kya.db'}")
    Session = sessionmaker(bind=engine)
    db = Session()

    from kya.principal_edges import (
        ensure_principal_edges_table,
        list_children,
    )
    from kya.principals import (
        ensure_principal_table as ensure_principal_tables,
    )
    from kya.principals import (
        record_principal_signal,
    )
    ensure_principal_tables(db)
    ensure_principal_edges_table(db)

    # Create the issuer principal so the auto-link finds it.
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="issuer-1", signal_kind="clean_invocation",
    )
    # Create the principal that will be bound.
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="child-1", signal_kind="clean_invocation",
    )
    db.commit()

    # Hook the lookup so bind_did_principal can find the issuer's
    # KYA principal_id from its DID. This lookup is the wiring under
    # test — when present, the linker runs; when absent, it no-ops.
    from kya import external_id as _ex
    monkeypatch.setattr(
        _ex, "_lookup_principal_by_did",
        lambda db, tenant_id, did:
            ("agent", "issuer-1") if did == "did:web:issuer.example" else None,
    )

    # Stub the DID resolver + VC verifier so we don't need real crypto.
    from kya import did as _did
    class _Doc:
        id = "did:key:z6Mk-child"
    monkeypatch.setattr(_did, "resolve_did", lambda d: _Doc())

    from kya import vc as _vc
    class _Verified:
        subject_did = "did:key:z6Mk-child"
        issuer_did = "did:web:issuer.example"
        claims = {"iss": "did:web:issuer.example",
                  "sub": "did:key:z6Mk-child"}
    monkeypatch.setattr(_vc, "verify_vc", lambda v, **kw: _Verified())

    from kya.external_id import bind_did_principal
    ok = bind_did_principal(
        db, tenant_id="t1",
        principal_kind="agent", principal_id="child-1",
        did="did:key:z6Mk-child",
        vc="fake-vc-jwt",   # bypassed by the verify_vc stub
    )
    assert ok is True
    db.commit()

    children = list_children(db, tenant_id="t1",
                              parent_kind="agent", parent_id="issuer-1")
    assert any(c.child_id == "child-1" and c.edge_kind == "vc_issued"
               for c in children), (
        f"auto-link did not fire: {children}"
    )


# ─── #6 — VC scope claims run through delegation policy ────────────


def test_vc_scope_check_detects_widening():
    """A VC whose `credentialSubject` claims an access_level higher
    than the issuer's must produce a delegation violation. The check
    is read-only (no DB) — the gateway / caller decides what to do
    with the violation."""
    from kya.external_id import check_vc_scope_against_issuer
    parent_def = {
        "access_level": "read",
        "data_classes": {"public"},
        "tools": ["fs.read"],
    }
    vc_claims = {
        "vc": {
            "credentialSubject": {
                "access_level": "admin",   # widens parent → violation
                "data_classes": ["public", "phi"],   # widens
            },
        },
    }
    violations = check_vc_scope_against_issuer(parent_def, vc_claims)
    kinds = {v["violation_kind"] for v in violations}
    assert "access_escalation" in kinds
    assert "data_class_widening" in kinds


def test_vc_scope_check_passes_when_within_ceiling():
    """Scope claims within the issuer's ceiling produce no violations."""
    from kya.external_id import check_vc_scope_against_issuer
    parent_def = {
        "access_level": "admin",
        "data_classes": {"public", "phi"},
        "tools": ["fs.read", "fs.write"],
    }
    vc_claims = {
        "vc": {
            "credentialSubject": {
                "access_level": "write",   # ≤ admin
                "data_classes": ["public"],   # ⊂ parent
            },
        },
    }
    assert check_vc_scope_against_issuer(parent_def, vc_claims) == []


# ─── #8 — Issuer API tenant_id configurable; UUID-derive helper ────


def test_issuer_tenant_id_uuid5_derive_helper():
    """Operators wanting multi-issuer separation can derive a stable
    UUID5 tenant_id from the issuer DID. Same input → same output;
    different DIDs → different UUIDs."""
    from kya.external_id import issuer_tenant_id_from_did
    a1 = issuer_tenant_id_from_did("did:web:issuer.example")
    a2 = issuer_tenant_id_from_did("did:web:issuer.example")
    b = issuer_tenant_id_from_did("did:web:other.example")
    assert a1 == a2
    assert a1 != b
    # UUID-shaped: 36 chars, 4 hyphens.
    assert len(a1) == 36 and a1.count("-") == 4


# ─── 5g-B-01 — DPoP classifier dispatches on typed code, not message ──


def test_dpop_classifier_immune_to_attacker_shaped_message():
    """The DPoP-error-to-event-kind dispatcher must read the typed
    `code` attribute, NOT the message text. An attacker who shapes
    the error message with the word 'replay' must not be able to
    force a forge attempt to be classified as a replay."""
    from kya_gateway._dpop import DPoPError
    from kya_gateway.server import _identity_failure_sec_event

    # forge attempt whose message contains 'replay' word (attacker
    # could put 'replay' inside their JWS kid/htu/iss)
    exc = DPoPError("DPoP kid='evil-replay' not in DID document",
                    code="kid_unknown")
    # Must classify as forge_attempt (per code), not replay (per message)
    assert _identity_failure_sec_event(exc) == "dpop_forge_attempt"

    # iat_too_old → dpop_expired
    exc2 = DPoPError("DPoP iat=12345 too old (max age 150s)",
                     code="iat_too_old")
    assert _identity_failure_sec_event(exc2) == "dpop_expired"

    # signature failure → forge_attempt
    exc3 = DPoPError("DPoP signature failed; kid='replay'",
                     code="signature")
    assert _identity_failure_sec_event(exc3) == "dpop_forge_attempt"


# ─── 5g-B-02 — VC scope check catches human_loop widening ──────────


def test_vc_scope_check_catches_human_loop_widening_via_either_key():
    """The most safety-critical dimension (human-in-loop requirement)
    must NOT be silently widenable through a VC scope claim, whether
    the claim uses `human_loop` or the VC-data-model `human_in_loop`."""
    from kya.external_id import check_vc_scope_against_issuer
    parent_def = {"human_loop": "in_the_loop"}
    # VC-data-model phrasing
    vc1 = {"vc": {"credentialSubject": {"human_in_loop": "out_of_loop"}}}
    v1 = check_vc_scope_against_issuer(parent_def, vc1)
    assert any(v["violation_kind"] == "human_loop_relax" for v in v1), (
        f"human_in_loop widen NOT caught: {v1}"
    )
    # KYA-native phrasing
    vc2 = {"vc": {"credentialSubject": {"human_loop": "out_of_loop"}}}
    v2 = check_vc_scope_against_issuer(parent_def, vc2)
    assert any(v["violation_kind"] == "human_loop_relax" for v in v2)


# ─── 5g-B-03 — auto-link uses real issuer kind, not hardcoded agent ──


def test_auto_link_uses_real_issuer_principal_kind(tmp_path, monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(f"sqlite:///{tmp_path / 'kya.db'}")
    db = sessionmaker(bind=engine)()

    from kya.principal_edges import (
        ensure_principal_edges_table,
        list_children,
    )
    from kya.principals import (
        ensure_principal_table as ensure_principal_tables,
    )
    from kya.principals import (
        record_principal_signal,
    )
    ensure_principal_tables(db)
    ensure_principal_edges_table(db)
    # Issuer is a service_account, not an agent.
    record_principal_signal(
        db, tenant_id="t1", principal_kind="service_account",
        principal_id="svc-issuer-1", signal_kind="clean_invocation",
    )
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="child-1", signal_kind="clean_invocation",
    )
    db.commit()

    from kya import external_id as _ex
    # Return real kind in the lookup.
    monkeypatch.setattr(
        _ex, "_lookup_principal_by_did",
        lambda db, tenant_id, did:
            ("service_account", "svc-issuer-1")
            if did == "did:web:svc.example" else None,
    )
    # Stub resolvers.
    from kya import did as _did_mod
    monkeypatch.setattr(_did_mod, "resolve_did", lambda d: type("D",(), {"id":d})())
    from kya import vc as _vc_mod
    class _V:
        subject_did = "did:key:child"
        issuer_did = "did:web:svc.example"
        claims = {"iss":"did:web:svc.example","sub":"did:key:child"}
    monkeypatch.setattr(_vc_mod, "verify_vc", lambda v, **kw: _V())

    from kya.external_id import bind_did_principal
    ok = bind_did_principal(
        db, tenant_id="t1",
        principal_kind="agent", principal_id="child-1",
        did="did:key:child", vc="fake-vc",
    )
    assert ok is True
    db.commit()
    # Edge must point at (service_account, svc-issuer-1), NOT at
    # (agent, svc-issuer-1).
    sa_children = list_children(
        db, tenant_id="t1",
        parent_kind="service_account", parent_id="svc-issuer-1",
    )
    assert any(c.child_id == "child-1" for c in sa_children), (
        f"edge not at service_account parent: {sa_children}"
    )


# ─── 5g-B-07 — auto-link respects trusted_issuers allowlist ────────


def test_auto_link_skipped_when_issuer_not_in_trusted_allowlist(
    tmp_path, monkeypatch,
):
    """A VC signed by an issuer NOT in the operator's trusted_issuers
    must not auto-create a delegation edge even if the DID coincides
    with a known principal."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(f"sqlite:///{tmp_path / 'kya2.db'}")
    db = sessionmaker(bind=engine)()
    from kya.principal_edges import (
        ensure_principal_edges_table,
        list_children,
    )
    from kya.principals import (
        ensure_principal_table as ensure_principal_tables,
    )
    from kya.principals import (
        record_principal_signal,
    )
    ensure_principal_tables(db)
    ensure_principal_edges_table(db)
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="suspicious-issuer", signal_kind="clean_invocation",
    )
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="child-1", signal_kind="clean_invocation",
    )
    db.commit()

    from kya import external_id as _ex
    monkeypatch.setattr(
        _ex, "_lookup_principal_by_did",
        lambda db, t, d: ("agent", "suspicious-issuer"),
    )
    from kya import did as _did_mod
    monkeypatch.setattr(_did_mod, "resolve_did",
                        lambda d: type("D",(), {"id":d})())
    from kya import vc as _vc_mod
    class _V:
        subject_did = "did:key:child"
        issuer_did = "did:web:untrusted.example"
        claims = {"iss":"did:web:untrusted.example","sub":"did:key:child"}
    monkeypatch.setattr(_vc_mod, "verify_vc", lambda v, **kw: _V())

    from kya.external_id import bind_did_principal
    ok = bind_did_principal(
        db, tenant_id="t1",
        principal_kind="agent", principal_id="child-1",
        did="did:key:child", vc="fake-vc",
        trusted_issuers={"did:web:trusted.example"},  # NOT the issuer
    )
    assert ok is True
    children = list_children(
        db, tenant_id="t1",
        parent_kind="agent", parent_id="suspicious-issuer",
    )
    assert not any(c.child_id == "child-1" for c in children), (
        f"edge created despite untrusted issuer: {children}"
    )


# ─── 5g-B-09 — UUID5 uses NAMESPACE_URL ────────────────────────────


def test_issuer_tenant_id_uses_namespace_url():
    """DIDs are URIs (DID Core §3.1); UUID5 must use NAMESPACE_URL so
    interoperating systems compute the same UUID for the same DID."""
    import uuid

    from kya.external_id import issuer_tenant_id_from_did
    did = "did:web:test.example"
    expected = str(uuid.uuid5(uuid.NAMESPACE_URL, did))
    assert issuer_tenant_id_from_did(did) == expected


# ─── N-2 — empty-set trusted_issuers means deny-all (not allow-all) ──


def test_auto_link_empty_set_means_deny_all(tmp_path, monkeypatch):
    """`trusted_issuers=set()` explicitly means trust nobody — auto-link
    must NOT fire even for a verified VC whose issuer is a known principal."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(f"sqlite:///{tmp_path / 'kya_n2.db'}")
    db = sessionmaker(bind=engine)()
    from kya.principal_edges import (
        ensure_principal_edges_table,
        list_children,
    )
    from kya.principals import (
        ensure_principal_table as ensure_principal_tables,
    )
    from kya.principals import (
        record_principal_signal,
    )
    ensure_principal_tables(db)
    ensure_principal_edges_table(db)
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="iss-1", signal_kind="clean_invocation",
    )
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="kid-1", signal_kind="clean_invocation",
    )
    db.commit()

    from kya import external_id as _ex
    monkeypatch.setattr(_ex, "_lookup_principal_by_did",
                        lambda db, t, d: ("agent", "iss-1"))
    from kya import did as _d
    monkeypatch.setattr(_d, "resolve_did",
                        lambda d: type("D",(), {"id":d})())
    from kya import vc as _v
    class _V:
        subject_did = "did:key:kid"
        issuer_did = "did:web:iss.example"
        claims = {"iss":"did:web:iss.example","sub":"did:key:kid"}
    monkeypatch.setattr(_v, "verify_vc", lambda v, **kw: _V())

    from kya.external_id import bind_did_principal
    ok = bind_did_principal(
        db, tenant_id="t1",
        principal_kind="agent", principal_id="kid-1",
        did="did:key:kid", vc="x",
        trusted_issuers=set(),   # explicit "trust nobody"
    )
    assert ok is True
    db.commit()
    assert not list_children(
        db, tenant_id="t1",
        parent_kind="agent", parent_id="iss-1",
    ), "empty-set should deny all auto-links"


# ─── N-3 — KYA_DID_TRUSTED_ISSUERS env-var fallback ─────────────────


def test_auto_link_honors_env_var_trusted_issuers(tmp_path, monkeypatch):
    """When the caller passes `trusted_issuers=None`, the env var
    `KYA_DID_TRUSTED_ISSUERS` (comma-separated) is consulted."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(f"sqlite:///{tmp_path / 'kya_n3.db'}")
    db = sessionmaker(bind=engine)()
    from kya.principal_edges import (
        ensure_principal_edges_table,
        list_children,
    )
    from kya.principals import (
        ensure_principal_table as ensure_principal_tables,
    )
    from kya.principals import (
        record_principal_signal,
    )
    ensure_principal_tables(db)
    ensure_principal_edges_table(db)
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="env-iss", signal_kind="clean_invocation",
    )
    record_principal_signal(
        db, tenant_id="t1", principal_kind="agent",
        principal_id="env-kid", signal_kind="clean_invocation",
    )
    db.commit()

    monkeypatch.setenv("KYA_DID_TRUSTED_ISSUERS",
                       "did:web:other.example,did:web:also-other.example")
    from kya import external_id as _ex
    monkeypatch.setattr(_ex, "_lookup_principal_by_did",
                        lambda db, t, d: ("agent", "env-iss"))
    from kya import did as _d
    monkeypatch.setattr(_d, "resolve_did",
                        lambda d: type("D",(), {"id":d})())
    from kya import vc as _v
    class _V:
        subject_did = "did:key:env-kid"
        issuer_did = "did:web:NOT-LISTED.example"
        claims = {"iss":"did:web:NOT-LISTED.example","sub":"did:key:env-kid"}
    monkeypatch.setattr(_v, "verify_vc", lambda v, **kw: _V())

    from kya.external_id import bind_did_principal
    ok = bind_did_principal(
        db, tenant_id="t1",
        principal_kind="agent", principal_id="env-kid",
        did="did:key:env-kid", vc="x",
        trusted_issuers=None,   # use env fallback
    )
    assert ok is True
    db.commit()
    # Env allowlist excludes the verified issuer → no edge.
    assert not list_children(
        db, tenant_id="t1",
        parent_kind="agent", parent_id="env-iss",
    ), "env-var allowlist not enforced"


# ─── N-6 — DPoP code dispatch is gated by isinstance(exc, DPoPError) ─


def test_dpop_code_dispatch_gated_by_isinstance():
    """A non-DPoP exception whose `.code` collides with a DPoP code
    must NOT be misclassified as a DPoP event."""
    from kya_gateway.errors import IdentityCredentialInvalid
    from kya_gateway.server import _identity_failure_sec_event

    class _FakeExc(IdentityCredentialInvalid):
        code = "signature"   # would map to dpop_forge_attempt

    # Falls through to the class-name map; no DPoP misclassification.
    assert _identity_failure_sec_event(_FakeExc("x")) is None


# ─── 5g-B-12 — VC scope check fails CLOSED on delegation_policy import ──


def test_vc_scope_check_fails_closed_when_delegation_policy_unavailable(monkeypatch):
    """If kya.delegation_policy can't be imported, scope check must
    return a violation (fail-CLOSED), not silently pass (fail-open)."""
    import sys
    monkeypatch.setitem(sys.modules, "kya.delegation_policy", None)
    from kya.external_id import check_vc_scope_against_issuer
    parent_def = {"access_level": "read"}
    vc_claims = {"vc": {"credentialSubject": {"access_level": "admin"}}}
    violations = check_vc_scope_against_issuer(parent_def, vc_claims)
    assert any(v["violation_kind"] == "scope_check_unavailable"
               for v in violations), (
        f"fail-open: {violations}"
    )
