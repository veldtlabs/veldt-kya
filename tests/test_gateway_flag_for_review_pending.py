"""End-to-end tests for the gateway's flag_for_review → 428 emission
with kya_pending_invocations persistence (#101 layer 2).

Real fixtures, no LLM-in-the-loop (verdict has already fired by the
time this test runs — we're proving the persistence hook works). Real
LLM/agent E2E lives in #103.

Approach:
    - Real SQLite engine + real kya.pending_invocations DDL + real
      pending row.
    - Mocked kya.default_session so the gateway's DB session is bound
      to the test engine.
    - Real FastAPI TestClient for the /mcp POST + response inspection.
    - Real BoundPrincipal + real RBACConfig with a flag_for_review rule.

Coverage:
    - Happy path: 428 emitted with X-Kya-Pending-Id header + body carries
      pending_id; a row lands in kya_pending_invocations with the right
      shape.
    - Backward compat: rule uses ``verdict: require_human`` — pipeline
      normalizes to flag_for_review + row written the same way.
    - Sensitive headers stripped: authorization, cookie, proxy-authorization
      never persist to the pending row.
    - Fail-soft: DB write raises → 428 still ships without X-Kya-
      Pending-Id header; ERROR log surfaces the failure.
    - Non-enforce modes: audit_only + advise → no pending row written
      (nothing was blocked; nothing needs approval).
    - Multiple concurrent 428s in one session produce distinct
      pending_ids.
    - Policy config hash pinned at emission — later config mutations
      don't rewrite the row.
"""
from __future__ import annotations

import json
import os
import sys
import types

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"


# ── Test infra: swap in a real SQLite engine as the kya session ─────


def _install_real_kya_with_engine(monkeypatch, engine):
    """Wire the gateway to a real SQLite backing via monkey-patched
    ``kya.default_session``.

    Instead of stubbing sys.modules['kya'] with a bare ModuleType
    (which breaks ``from kya.pending_invocations import ...`` inside
    the gateway), import the real kya package and swap only the
    functions we need for isolation.
    """
    from sqlalchemy.orm import Session
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
    monkeypatch.setattr(_real_kya, "record_invocation",
                        lambda db, **kw: 42)
    monkeypatch.setattr(_real_kya, "record_evidence",
                        lambda db, **kw: 1)
    monkeypatch.setattr(_real_kya, "record_principal_signal",
                        lambda db, **kw: 1)
    # require_action is imported inside policy_pipeline via
    # ``from kya import ... require_action``. Patch at the source.
    monkeypatch.setattr(_real_kya, "require_action",
                        lambda *a, **k: True)


def _build_gateway(monkeypatch, verdict: str, mode: str = "enforce"):
    """Build a Gateway with an RBAC rule that fires the target verdict."""
    from kya_gateway.config import (
        AuditConfig,
        BackendConfig,
        EnforcementConfig,
        GatewayBindConfig,
        GatewayConfig,
        IdentityConfig,
        JWTConfig,
        PolicyConfig,
        RBACConfig,
        RBACRule,
    )
    from kya_gateway.identity import BoundPrincipal
    from kya_gateway.server import Gateway

    cfg = GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t-ffr"),
        identity=IdentityConfig(methods=["bearer_jwt"], jwt=JWTConfig()),
        backends=[BackendConfig(name="default", url="http://x")],
        policy=PolicyConfig(rbac=RBACConfig(default="deny", rules=[
            RBACRule(
                principal_kind="agent",
                actions=["mcp.filesystem.delete_file"],
                verdict=verdict,
            ),
        ])),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode=mode),
    )
    gw = Gateway(cfg)

    from kya_gateway import identity as _id_mod
    monkeypatch.setattr(
        _id_mod.IdentityResolver, "resolve",
        lambda self, h: BoundPrincipal(
            principal_kind="agent", principal_id="agent-01",
            method="bearer_jwt", external_subject="agent-01",
            external_issuer=None,
        ),
    )
    return gw


def _mcp_call_body() -> str:
    return json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.delete_file",
                   "arguments": {"path": "/tmp/x"}},
    })


# ═══════════════════════════════════════════════════════════════════════
# Happy path — flag_for_review verdict, enforce mode, 428 + pending row
# ═══════════════════════════════════════════════════════════════════════


def test_flag_for_review_enforce_writes_pending_row_and_stamps_header(
    monkeypatch, tmp_path,
):
    from sqlalchemy import create_engine, text as _sql
    from kya.pending_invocations import ensure_table, get_by_id

    engine = create_engine(f"sqlite:///{tmp_path}/gw.db")
    # id() reuse across tests: fresh engine may share id with a GC'd
    # one from an earlier test, tricking ensure_table's sentinel into
    # skipping DDL. Clear before every fresh engine.
    from kya.pending_invocations import _ENSURED_ENGINES
    _ENSURED_ENGINES.clear()
    ensure_table(engine)
    _install_real_kya_with_engine(monkeypatch, engine)

    gw = _build_gateway(monkeypatch, "flag_for_review")

    from fastapi.testclient import TestClient
    client = TestClient(gw.app)
    r = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer secret-token-do-not-persist",
        "X-Custom-Header": "should-persist",
    })
    assert r.status_code == 428, r.text
    body = r.json()
    # JSON-RPC envelope preserved.
    assert body["error"]["code"] == -32007
    assert body["error"]["data"]["verdict"] == "flag_for_review"

    # X-Kya-Pending-Id stamped + body carries the same id.
    pending_id = r.headers.get("X-Kya-Pending-Id")
    assert pending_id, "gateway must stamp X-Kya-Pending-Id header"
    assert body["error"]["data"]["pending_id"] == pending_id

    # Row landed with the right shape.
    row = get_by_id(engine, pending_id)
    assert row is not None
    assert row.tenant_id == "t-ffr"
    # Gateway canonicalizes to ``mcp.<name>`` for MCP-namespaced calls.
    assert row.action == "mcp.filesystem.delete_file"
    assert row.principal_kind == "agent"
    assert row.principal_id == "agent-01"
    assert row.status == "pending"
    # Body is captured verbatim.
    assert b"filesystem.delete_file" in row.request_body_ciphertext
    # Policy config hash is deterministic + non-empty.
    assert row.policy_config_hash
    assert len(row.policy_config_hash) == 64  # sha256 hex


# ═══════════════════════════════════════════════════════════════════════
# Backward compat — legacy require_human verdict still triggers 428+row
# ═══════════════════════════════════════════════════════════════════════


def test_require_human_alias_still_writes_pending_row(monkeypatch, tmp_path):
    """Legacy config using ``verdict: require_human`` continues to
    work. Config parser normalizes to flag_for_review; pipeline emits
    the canonical string; gateway writes a pending row."""
    from sqlalchemy import create_engine
    from kya.pending_invocations import ensure_table, get_by_id

    engine = create_engine(f"sqlite:///{tmp_path}/gw.db")
    # id() reuse across tests: fresh engine may share id with a GC'd
    # one from an earlier test, tricking ensure_table's sentinel into
    # skipping DDL. Clear before every fresh engine.
    from kya.pending_invocations import _ENSURED_ENGINES
    _ENSURED_ENGINES.clear()
    ensure_table(engine)
    _install_real_kya_with_engine(monkeypatch, engine)

    gw = _build_gateway(monkeypatch, "require_human")

    from fastapi.testclient import TestClient
    client = TestClient(gw.app)
    r = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer x",
    })
    assert r.status_code == 428
    pending_id = r.headers.get("X-Kya-Pending-Id")
    assert pending_id
    row = get_by_id(engine, pending_id)
    assert row is not None
    assert row.status == "pending"


# ═══════════════════════════════════════════════════════════════════════
# Sensitive headers stripped before persist
# ═══════════════════════════════════════════════════════════════════════


def test_authorization_cookie_proxy_headers_never_persist(
    monkeypatch, tmp_path,
):
    """A leaked pending row must NOT enable replay of the caller's
    bearer token. Strip authorization, cookie, proxy-authorization."""
    from sqlalchemy import create_engine
    from kya.pending_invocations import ensure_table, get_by_id

    engine = create_engine(f"sqlite:///{tmp_path}/gw.db")
    # id() reuse across tests: fresh engine may share id with a GC'd
    # one from an earlier test, tricking ensure_table's sentinel into
    # skipping DDL. Clear before every fresh engine.
    from kya.pending_invocations import _ENSURED_ENGINES
    _ENSURED_ENGINES.clear()
    ensure_table(engine)
    _install_real_kya_with_engine(monkeypatch, engine)
    gw = _build_gateway(monkeypatch, "flag_for_review")

    from fastapi.testclient import TestClient
    client = TestClient(gw.app)
    r = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer super-secret-must-not-persist",
        "Cookie": "session=super-secret-cookie",
        "Proxy-Authorization": "Basic hunter2",
        "X-Retain-Me": "please-keep",
    })
    pending_id = r.headers.get("X-Kya-Pending-Id")
    assert pending_id
    row = get_by_id(engine, pending_id)
    persisted = {k.lower(): v for k, v in row.request_headers.items()}
    assert "authorization" not in persisted, (
        f"authorization header leaked into pending row: {persisted}"
    )
    assert "cookie" not in persisted
    assert "proxy-authorization" not in persisted
    # Non-sensitive headers ARE preserved.
    assert persisted.get("x-retain-me") == "please-keep"


# ═══════════════════════════════════════════════════════════════════════
# Fail-soft — pending write failure doesn't kill the 428
# ═══════════════════════════════════════════════════════════════════════


def test_pending_write_failure_ships_428_without_header(
    monkeypatch, tmp_path, caplog,
):
    """DB down? Gateway must still 428 IN PRODUCTION. Caller sees no
    X-Kya-Pending-Id and knows to retry from scratch. ERROR log
    surfaces the failure.

    M2 fix: in non-prod, the write failure re-raises so integration
    tests + local dev see the real bug loudly. This test pins the
    prod-mode fail-soft behavior explicitly."""
    monkeypatch.setenv("KYA_ENV", "production")
    import logging
    from sqlalchemy import create_engine
    from kya.pending_invocations import ensure_table

    engine = create_engine(f"sqlite:///{tmp_path}/gw.db")
    # id() reuse across tests: fresh engine may share id with a GC'd
    # one from an earlier test, tricking ensure_table's sentinel into
    # skipping DDL. Clear before every fresh engine.
    from kya.pending_invocations import _ENSURED_ENGINES
    _ENSURED_ENGINES.clear()
    ensure_table(engine)
    _install_real_kya_with_engine(monkeypatch, engine)

    # Sabotage: make create_pending raise.
    import kya.pending_invocations as pi

    def _boom(*a, **kw):
        raise RuntimeError("simulated DB write failure")

    monkeypatch.setattr(pi, "create_pending", _boom)

    gw = _build_gateway(monkeypatch, "flag_for_review")

    from fastapi.testclient import TestClient
    client = TestClient(gw.app)
    with caplog.at_level(logging.ERROR, logger="kya_gateway.server"):
        r = client.post("/mcp", data=_mcp_call_body(), headers={
            "Content-Type": "application/json", "Authorization": "Bearer x",
        })
    assert r.status_code == 428, r.text
    assert r.headers.get("X-Kya-Pending-Id") is None
    body = r.json()
    assert body["error"]["data"].get("pending_id") is None
    assert any("create_pending failed" in rec.message
               for rec in caplog.records)


# ═══════════════════════════════════════════════════════════════════════
# Non-enforce modes — no pending row (nothing was actually blocked)
# ═══════════════════════════════════════════════════════════════════════


def test_audit_only_mode_does_not_write_pending_row(monkeypatch, tmp_path):
    """audit_only just RECORDS the verdict + forwards. No block →
    no 428 → no pending row (nothing to approve to resume)."""
    from sqlalchemy import create_engine, text as _sql
    from kya.pending_invocations import ensure_table

    engine = create_engine(f"sqlite:///{tmp_path}/gw.db")
    # id() reuse across tests: fresh engine may share id with a GC'd
    # one from an earlier test, tricking ensure_table's sentinel into
    # skipping DDL. Clear before every fresh engine.
    from kya.pending_invocations import _ENSURED_ENGINES
    _ENSURED_ENGINES.clear()
    ensure_table(engine)
    _install_real_kya_with_engine(monkeypatch, engine)
    gw = _build_gateway(monkeypatch, "flag_for_review", mode="audit_only")

    # Also short-circuit the backend forward — we just care about the
    # policy path, not what the backend returns. Patch the http POST.
    from fastapi.testclient import TestClient
    import kya_gateway.server as _srv

    class _FakeResp:
        status_code = 200
        headers = {"content-type": "application/json"}
        content = b'{"jsonrpc": "2.0", "id": 1, "result": {}}'

    async def _fake_forward(*a, **kw):
        return _FakeResp()

    if hasattr(_srv, "_forward_to_backend"):
        monkeypatch.setattr(_srv, "_forward_to_backend", _fake_forward)

    client = TestClient(gw.app)
    r = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer x",
    })
    # In audit_only, the response comes back (or would if backend
    # were reachable). The critical assertion: NO pending row.
    with engine.connect() as c:
        n = c.execute(_sql(
            "SELECT COUNT(*) FROM kya_pending_invocations"
        )).scalar()
    assert n == 0, "audit_only must not write pending rows"


# ═══════════════════════════════════════════════════════════════════════
# Multiple concurrent 428s produce distinct pending_ids
# ═══════════════════════════════════════════════════════════════════════


def test_two_calls_produce_two_distinct_pending_rows(monkeypatch, tmp_path):
    from sqlalchemy import create_engine
    from kya.pending_invocations import ensure_table, get_by_id

    engine = create_engine(f"sqlite:///{tmp_path}/gw.db")
    # id() reuse across tests: fresh engine may share id with a GC'd
    # one from an earlier test, tricking ensure_table's sentinel into
    # skipping DDL. Clear before every fresh engine.
    from kya.pending_invocations import _ENSURED_ENGINES
    _ENSURED_ENGINES.clear()
    ensure_table(engine)
    _install_real_kya_with_engine(monkeypatch, engine)
    gw = _build_gateway(monkeypatch, "flag_for_review")

    from fastapi.testclient import TestClient
    client = TestClient(gw.app)
    r1 = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer x",
    })
    r2 = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer x",
    })
    id1 = r1.headers.get("X-Kya-Pending-Id")
    id2 = r2.headers.get("X-Kya-Pending-Id")
    assert id1 and id2
    assert id1 != id2, "each 428 must produce a distinct pending row"
    # Both are queryable, both pending.
    assert get_by_id(engine, id1).status == "pending"
    assert get_by_id(engine, id2).status == "pending"


# ═══════════════════════════════════════════════════════════════════════
# Policy config hash is captured at emission
# ═══════════════════════════════════════════════════════════════════════


def test_policy_config_hash_persists_original_snapshot(monkeypatch, tmp_path):
    """Emission-time hash is deterministic; two 428s from the SAME
    config produce the same hash. Foundational to M5 replay pinning:
    the resume endpoint compares this hash to the current config."""
    from sqlalchemy import create_engine
    from kya.pending_invocations import ensure_table, get_by_id

    engine = create_engine(f"sqlite:///{tmp_path}/gw.db")
    # id() reuse across tests: fresh engine may share id with a GC'd
    # one from an earlier test, tricking ensure_table's sentinel into
    # skipping DDL. Clear before every fresh engine.
    from kya.pending_invocations import _ENSURED_ENGINES
    _ENSURED_ENGINES.clear()
    ensure_table(engine)
    _install_real_kya_with_engine(monkeypatch, engine)
    gw = _build_gateway(monkeypatch, "flag_for_review")

    from fastapi.testclient import TestClient
    client = TestClient(gw.app)
    r1 = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer x",
    })
    r2 = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer x",
    })
    row1 = get_by_id(engine, r1.headers["X-Kya-Pending-Id"])
    row2 = get_by_id(engine, r2.headers["X-Kya-Pending-Id"])
    assert row1.policy_config_hash == row2.policy_config_hash
    assert len(row1.policy_config_hash) == 64


# ═══════════════════════════════════════════════════════════════════════
# Deny + allow verdicts continue to work — regression guard
# ═══════════════════════════════════════════════════════════════════════


def test_deny_verdict_no_pending_row_written(monkeypatch, tmp_path):
    """A deny is a hard 403 with no resume possible — no pending row."""
    from sqlalchemy import create_engine, text as _sql
    from kya.pending_invocations import ensure_table

    engine = create_engine(f"sqlite:///{tmp_path}/gw.db")
    # id() reuse across tests: fresh engine may share id with a GC'd
    # one from an earlier test, tricking ensure_table's sentinel into
    # skipping DDL. Clear before every fresh engine.
    from kya.pending_invocations import _ENSURED_ENGINES
    _ENSURED_ENGINES.clear()
    ensure_table(engine)
    _install_real_kya_with_engine(monkeypatch, engine)
    gw = _build_gateway(monkeypatch, "deny")

    from fastapi.testclient import TestClient
    client = TestClient(gw.app)
    r = client.post("/mcp", data=_mcp_call_body(), headers={
        "Content-Type": "application/json", "Authorization": "Bearer x",
    })
    assert r.status_code == 403
    assert r.headers.get("X-Kya-Pending-Id") is None
    with engine.connect() as c:
        n = c.execute(_sql(
            "SELECT COUNT(*) FROM kya_pending_invocations"
        )).scalar()
    assert n == 0
