"""Phase 4 (#S4-1) — E2E: evaluator_name flows from ``VerdictResult``
through ``policy_pipeline.evaluate()`` into ``kya_evidence.evaluator_name``.

Proves the wire-up end to end on the OSS gateway:

    1. Register a SabotageDenyEvaluator (reused from
       ``tests/test_gateway_policy_pipeline_evaluator.py`` — DO NOT
       create a parallel stub).
    2. Build a gateway PolicyConfig that names the sabotage evaluator.
    3. Drive ``evaluate()`` for N gateway-rule paths (default-allow,
       RBAC-deny, payload-too-large, rate-limit path skipped — needs
       primitive setup).
    4. Call ``record_evidence(..., evaluator_name=v.rich.get(
       "evaluator_name"))`` for each returned Verdict.
    5. Query kya_evidence back → assert every row carries
       ``evaluator_name == "sabotage-deny"`` AND the verdict flipped
       to deny.

Sabotage-verify: unregister the sabotage evaluator, re-run through the
default NativeEvaluator — assert ``evaluator_name == "native"``
(populated by the Phase 3 attribution helpers on the short-circuit
path). If either polarity fails, the wire-up is not real.

Reuse-first (per feedback_reusability_first + Kola directive
2026-08-08):

* ``SabotageDenyEvaluator`` — imported from
  ``tests/test_gateway_policy_pipeline_evaluator.py``. Its
  ``VerdictResult`` already carries ``evaluator_name=self.name`` from
  Phase 2; no re-plumb needed.
* ``init_storage`` / ``record_evidence`` / ``list_evidence`` — OSS
  public API. Extended by Phase 4 (kwarg + column).
* ``kya.register_evaluator`` / ``unregister_evaluator`` — copy-on-write
  registry. Sabotage tests use these; no monkey-patching.
* ``PolicyConfig`` + ``BoundPrincipal`` — reused from the existing
  gateway suite (same imports).

Evaluator-name literals in this file (``"sabotage-e2e"`` / ``"native"``)
mirror the evaluator's ``.name`` attribute and the Phase 3
attribution helper's ``rich.setdefault("evaluator_name", "native")``
respectively — not policy strings.
"""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from kya import (
    init_storage,
    list_evidence,
    record_evidence,
    record_invocation,
    register_evaluator,
    unregister_evaluator,
)
from kya_gateway.config import (
    PayloadCapsConfig,
    PolicyConfig,
    RBACConfig,
)
from kya_gateway.identity import BoundPrincipal
from kya_gateway.policy_pipeline import evaluate

# REUSE — SabotageDenyEvaluator already ships in the Phase 3 pipeline
# suite. Importing (not duplicating) keeps a single source of truth for
# the sabotage stub's behavior. pytest collects tests/ as a rootdir but
# doesn't add it to sys.path as a package — import by file location
# using the plain module name.
from test_gateway_policy_pipeline_evaluator import (  # type: ignore[import-not-found]
    SabotageDenyEvaluator,
)


# Registered name for the E2E sabotage evaluator. Distinct from the
# pipeline suite's ``"sabotage-deny"`` so parallel test runs (or a
# shared registry left over from a poisoned run) don't collide.
_SABOTAGE_REGISTERED_NAME = "sabotage-e2e"

# Canonical evaluator name emitted by the Phase 3 attribution helper
# ``_fallback_with_native_attribution`` when NativeEvaluator short-
# circuits. Named here so a rename of that literal breaks this test
# loudly rather than silently drifting.
_NATIVE_EVALUATOR_ATTRIBUTION_NAME = "native"

TENANT = "tenant-phase4-e2e"


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


@pytest.fixture
def sabotage_evaluator_fixture():
    """Register the SabotageDenyEvaluator instance under the E2E name
    for the duration of one test, then unregister. Uses the OSS
    ``register_evaluator`` registry seam (the intended path) rather
    than monkey-patching a private state — this is the same discipline
    the Phase 3 pipeline suite uses (its own ``registry_scoped``
    fixture).
    """
    # Reuse the shared SabotageDenyEvaluator class. Overwrite its
    # instance `.name` so verdict rows attribute to the E2E-scoped
    # registered name — the class-level default ``"sabotage-deny"``
    # would collide with the Phase 3 test suite when both suites'
    # registries live in the same process.
    stub = SabotageDenyEvaluator()
    stub.name = _SABOTAGE_REGISTERED_NAME
    register_evaluator(_SABOTAGE_REGISTERED_NAME, stub)
    try:
        yield stub
    finally:
        unregister_evaluator(_SABOTAGE_REGISTERED_NAME)


def _principal() -> BoundPrincipal:
    return BoundPrincipal(
        principal_kind="agent",
        principal_id="p-e2e",
        method="bearer_jwt",
        external_subject="p-e2e",
        external_issuer=None,
    )


def _record_verdict_evidence(
    db, tenant_id: str, invocation_id: int, action: str, verdict,
) -> int:
    """Small helper that mirrors what
    ``kya_gateway/server.py::_record_verdict_evidence`` does at the
    real HTTP boundary — pulls ``evaluator_name`` off ``Verdict.rich``
    (the single source of truth set by the Phase 3 attribution
    helpers) and passes it to ``record_evidence``.
    """
    rich = getattr(verdict, "rich", None) or {}
    return record_evidence(
        db=db,
        tenant_id=tenant_id,
        invocation_id=invocation_id,
        evidence_kind="gateway_verdict",
        payload={
            "action": action,
            "verdict": verdict.verdict,
            "reason_codes": list(verdict.reason_codes),
        },
        evaluator_name=rich.get("evaluator_name"),
    )


# ── Cohort A: sabotage-injected evaluator — flips outcome + attribution ─


def test_sabotage_evaluator_stamps_evaluator_name_on_default_allow_path(
    db, sabotage_evaluator_fixture,
):
    """Empty-policy request ordinarily allows. With the sabotage
    evaluator in play, verdict flips to deny AND the evidence row
    attributes to the sabotage evaluator's name."""
    cfg = PolicyConfig(
        min_trust=0, policy_evaluator_name=_SABOTAGE_REGISTERED_NAME,
    )
    inv = record_invocation(
        db, tenant_id=TENANT, agent_key="a1",
        principal_kind="agent", principal_id="p-e2e",
        mode="observed", outcome="success",
    )
    v = evaluate(
        db=db, tenant_id=TENANT, principal=_principal(),
        action="mcp.x.read", payload_bytes=100,
        invocation_id=inv, cfg=cfg,
    )
    assert v.verdict == "deny"
    assert v.rich.get("evaluator_name") == _SABOTAGE_REGISTERED_NAME

    _record_verdict_evidence(db, TENANT, inv, "mcp.x.read", v)
    rows = list_evidence(db, tenant_id=TENANT, invocation_id=inv)
    verdict_rows = [
        r for r in rows if r["evidence_kind"] == "gateway_verdict"
    ]
    assert len(verdict_rows) == 1
    assert verdict_rows[0]["evaluator_name"] == _SABOTAGE_REGISTERED_NAME


def test_sabotage_evaluator_stamps_evaluator_name_on_rbac_deny_path(
    db, sabotage_evaluator_fixture,
):
    """RBAC deny-by-default → dispatch goes through the RBAC branch of
    the pipeline. Evaluator returns deny → evidence row attributes
    to the sabotage evaluator."""
    cfg = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[]),
        policy_evaluator_name=_SABOTAGE_REGISTERED_NAME,
    )
    inv = record_invocation(
        db, tenant_id=TENANT, agent_key="a2",
        principal_kind="agent", principal_id="p-e2e",
        mode="observed", outcome="success",
    )
    v = evaluate(
        db=db, tenant_id=TENANT, principal=_principal(),
        action="mcp.x.read", payload_bytes=100,
        invocation_id=inv, cfg=cfg,
    )
    assert v.verdict == "deny"
    _record_verdict_evidence(db, TENANT, inv, "mcp.x.read", v)
    rows = list_evidence(db, tenant_id=TENANT, invocation_id=inv)
    verdict_rows = [
        r for r in rows if r["evidence_kind"] == "gateway_verdict"
    ]
    assert len(verdict_rows) == 1
    assert verdict_rows[0]["evaluator_name"] == _SABOTAGE_REGISTERED_NAME


def test_sabotage_evaluator_stamps_evaluator_name_on_payload_too_large_path(
    db, sabotage_evaluator_fixture,
):
    """Payload-caps deny path. Evaluator dispatch fires → attribution
    lands on the row."""
    cfg = PolicyConfig(
        min_trust=0,
        payload_caps=PayloadCapsConfig(max_bytes=1024),
        policy_evaluator_name=_SABOTAGE_REGISTERED_NAME,
    )
    inv = record_invocation(
        db, tenant_id=TENANT, agent_key="a3",
        principal_kind="agent", principal_id="p-e2e",
        mode="observed", outcome="success",
    )
    v = evaluate(
        db=db, tenant_id=TENANT, principal=_principal(),
        action="mcp.x.read", payload_bytes=4096,
        invocation_id=inv, cfg=cfg,
    )
    assert v.verdict == "deny"
    _record_verdict_evidence(db, TENANT, inv, "mcp.x.read", v)
    rows = list_evidence(db, tenant_id=TENANT, invocation_id=inv)
    verdict_rows = [
        r for r in rows if r["evidence_kind"] == "gateway_verdict"
    ]
    assert len(verdict_rows) == 1
    assert verdict_rows[0]["evaluator_name"] == _SABOTAGE_REGISTERED_NAME


# ── Cohort B: default NativeEvaluator — attribution still lands ────


def test_default_native_evaluator_stamps_native_attribution_on_allow(db):
    """No sabotage registered — the default NativeEvaluator serves.
    Its Phase 3 attribution helper enriches ``Verdict.rich`` with
    ``evaluator_name="native"`` even on the default-allow short-
    circuit path. The evidence row must carry that same value."""
    cfg = PolicyConfig(min_trust=0)
    inv = record_invocation(
        db, tenant_id=TENANT, agent_key="a4",
        principal_kind="agent", principal_id="p-e2e",
        mode="observed", outcome="success",
    )
    v = evaluate(
        db=db, tenant_id=TENANT, principal=_principal(),
        action="mcp.x.read", payload_bytes=100,
        invocation_id=inv, cfg=cfg,
    )
    assert v.verdict == "allow"
    assert v.rich.get("evaluator_name") == _NATIVE_EVALUATOR_ATTRIBUTION_NAME

    _record_verdict_evidence(db, TENANT, inv, "mcp.x.read", v)
    rows = list_evidence(db, tenant_id=TENANT, invocation_id=inv)
    verdict_rows = [
        r for r in rows if r["evidence_kind"] == "gateway_verdict"
    ]
    assert len(verdict_rows) == 1
    assert (
        verdict_rows[0]["evaluator_name"]
        == _NATIVE_EVALUATOR_ATTRIBUTION_NAME
    )


# ── Cohort C: sabotage-verify — RED under the inverse polarity ─────


def test_sabotage_verify_row_attribution_differs_between_evaluators(db):
    """Sabotage-verify (per feedback_sabotage_verify): the attribution
    the evidence row carries MUST differ based on which evaluator
    produced the verdict. If both polarities produced the same
    ``evaluator_name`` value, the wire-up would be a decorative
    string — not a real attribution signal.

    This test runs BOTH branches inline: first with sabotage
    registered (asserts sabotage attribution), then without it
    (asserts native attribution). If any regression makes the
    attribution collapse to a single hardcoded value, both branches
    would produce the same string and the final ``assert !=`` goes
    RED.
    """
    inv = record_invocation(
        db, tenant_id=TENANT, agent_key="a-sab",
        principal_kind="agent", principal_id="p-e2e",
        mode="observed", outcome="success",
    )
    # (1) With sabotage — attribution is sabotage's name.
    stub = SabotageDenyEvaluator()
    stub.name = _SABOTAGE_REGISTERED_NAME
    register_evaluator(_SABOTAGE_REGISTERED_NAME, stub)
    try:
        cfg = PolicyConfig(
            min_trust=0,
            policy_evaluator_name=_SABOTAGE_REGISTERED_NAME,
        )
        v_sab = evaluate(
            db=db, tenant_id=TENANT, principal=_principal(),
            action="mcp.x.read", payload_bytes=100,
            invocation_id=inv, cfg=cfg,
        )
        sab_attr = (v_sab.rich or {}).get("evaluator_name")
    finally:
        unregister_evaluator(_SABOTAGE_REGISTERED_NAME)

    # (2) Without sabotage — default NativeEvaluator serves.
    inv2 = record_invocation(
        db, tenant_id=TENANT, agent_key="a-nat",
        principal_kind="agent", principal_id="p-e2e",
        mode="observed", outcome="success",
    )
    cfg2 = PolicyConfig(min_trust=0)
    v_nat = evaluate(
        db=db, tenant_id=TENANT, principal=_principal(),
        action="mcp.x.read", payload_bytes=100,
        invocation_id=inv2, cfg=cfg2,
    )
    nat_attr = (v_nat.rich or {}).get("evaluator_name")

    assert sab_attr == _SABOTAGE_REGISTERED_NAME
    assert nat_attr == _NATIVE_EVALUATOR_ATTRIBUTION_NAME
    # The load-bearing sabotage check: if a regression collapsed
    # attribution to a single constant, this would go RED.
    assert sab_attr != nat_attr


# ═══════════════════════════════════════════════════════════════════════
# Cohort D — REAL gateway HTTP path (Phase 4 residual FIX-M2, 2026-08-08)
# ═══════════════════════════════════════════════════════════════════════
#
# Motivation (Round-1 review, task #343 Sabotage-B1):
#   Cohorts A/B/C exercise ``policy_pipeline.evaluate()`` and a private
#   ``_record_verdict_evidence`` helper that mirrors the shape of the
#   production ``server.py`` call site. That mirror is a load-bearing
#   assumption — if a fixer removed the ``evaluator_name=...`` kwarg
#   from ``kya_gateway/server.py:1487``, the mirror would still work
#   and all three cohorts would stay green. Cohort D closes that gap
#   by driving a real HTTP POST through the real gateway's real
#   ``_record_verdict_evidence`` path and asserting the resulting
#   ``kya_evidence.evaluator_name`` column carries the attribution.
#
# Reuse discipline (per feedback_reusability_first, Kola 2026-08-08):
#   * ``SabotageDenyEvaluator`` — imported at top of file, class-level
#     reuse.
#   * ``_SABOTAGE_REGISTERED_NAME`` + ``_NATIVE_EVALUATOR_ATTRIBUTION_NAME``
#     — reused module constants.
#   * ``TestClient`` — reused from the OSS gateway suite pattern
#     (``tests/test_gateway_server.py`` — no conftest fixture exists;
#     TestClient is instantiated inline in ~20 tests over there). The
#     ``_patch_identity_to`` + ``_patch_forwarder_to_echo`` helpers
#     are imported from ``test_gateway_server`` module rather than
#     re-implemented (verified 2026-08-08: same import trick used for
#     ``SabotageDenyEvaluator``).
#   * ``record_invocation`` / ``record_evidence`` / ``list_evidence``
#     — the real OSS public API, bound to a real in-memory sqlite via
#     ``_install_real_kya_shim``.
#
# No hardcoded literals: the two evaluator-name constants above are
# the ONLY string values compared against evidence columns.

# REUSE from tests/test_gateway_server.py — identity + forwarder
# monkey-patch helpers. Same import pattern used for
# ``SabotageDenyEvaluator`` above.
from test_gateway_server import (  # type: ignore[import-not-found]
    _patch_forwarder_to_echo,
    _patch_identity_to,
)
from kya_gateway.config import (
    AuditConfig,
    BackendConfig,
    EnforcementConfig,
    GatewayBindConfig,
    GatewayConfig,
    IdentityConfig,
    JWTConfig,
)
from kya_gateway.server import Gateway
from fastapi.testclient import TestClient
import json as _json
import sys as _sys
import types as _types

# Tenant used by the Cohort D gateway config — distinct from the
# top-of-file ``TENANT`` constant so the real evidence rows don't
# collide with the in-process ``db`` fixture's rows across tests.
_COHORT_D_TENANT = "tenant-cohort-d-http"
# Principal identifier used by all three Cohort D helpers (principal,
# seed_invocation, config). Named constant so a rename ripples cleanly
# and the same identity flows through record_invocation +
# BoundPrincipal + the gateway config's audit path.
_COHORT_D_PRINCIPAL_ID = "planner-cohort-d"


@pytest.fixture
def cohort_d_engine():
    """Thread-safe in-memory sqlite engine for Cohort D. TestClient
    runs handlers in a starlette threadpool worker; the default
    ``sqlite:///:memory:`` engine is single-thread only. StaticPool
    + ``check_same_thread=False`` shares one connection across all
    threads and preserves the in-memory dataset across sessions
    opened by the gateway."""
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    bootstrap = sessionmaker(bind=eng)()
    init_storage(bootstrap)
    bootstrap.commit()
    bootstrap.close()
    yield eng
    eng.dispose()


def _install_real_kya_shim(monkeypatch, engine):
    """Point ``kya.default_session`` at ``engine`` via monkey-patch —
    leaving every other ``kya`` symbol (EvaluationInput,
    get_evaluator, _native_evaluator, record_evidence, etc.) intact.

    Rationale (verified 2026-08-08 while wiring Cohort D): the sibling
    ``_patch_kya_core`` in ``tests/test_gateway_server.py`` installs a
    ``types.ModuleType('kya')`` stub in ``sys.modules['kya']``, which
    would erase ``kya.EvaluationInput``, ``kya.get_evaluator``, and the
    ``kya._native_evaluator`` submodule the pipeline imports lazily.
    Without those the pipeline's ``_build_eval_input`` returns None
    and ``_emit_via_evaluator`` short-circuits BEFORE the Phase 3
    attribution helper runs — ``evaluator_name`` would silently drop
    to ``None`` and Cohort D would false-fail. Patching just the one
    seam we need keeps the pipeline's attribution paths intact so
    Cohort D actually exercises FIX-M2.

    Fresh Session per ``with`` block matches the real ``kya.default_
    session`` contract (rows persisted across sessions). Thread-safe
    when ``engine`` is the StaticPool + ``check_same_thread=False``
    sqlite engine from ``cohort_d_engine``.
    """
    factory = sessionmaker(bind=engine)

    class _SessionCtx:
        """Context manager that yields a fresh Session bound to the
        shared engine. Real close on exit — the row is committed
        inside the gateway helper (``db.commit()``) so subsequent
        opens see it. Mirrors the real ``kya.default_session``
        contract."""
        def __init__(self):
            self._sess = factory()
        def __enter__(self):
            return self._sess
        def __exit__(self, *exc):
            try:
                self._sess.close()
            except Exception as exc_close:
                # Never let session-close teardown swallow a live
                # exception silently — log and continue.
                import logging
                logging.getLogger(__name__).debug(
                    "cohort_d session close raised: %s", exc_close,
                )
            return False

    import kya as _real_kya
    monkeypatch.setattr(
        _real_kya, "default_session", lambda: _SessionCtx(),
    )
    return _real_kya


def _cohort_d_gateway_config(tenant_id: str, evaluator_name: str | None):
    """Build a minimal GatewayConfig with the requested policy
    evaluator name. Distinct from test_gateway_server's ``_build_gateway``
    because we need the ``policy_evaluator_name`` slot exposed (that
    helper doesn't accept it)."""
    return GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id=tenant_id),
        identity=IdentityConfig(methods=["bearer_jwt"], jwt=JWTConfig()),
        backends=[BackendConfig(name="default", url="http://localhost:1")],
        policy=PolicyConfig(
            min_trust=0,
            policy_evaluator_name=(
                evaluator_name
                if evaluator_name
                else _NATIVE_EVALUATOR_ATTRIBUTION_NAME
            ),
        ),
        audit=AuditConfig(),
        enforcement=EnforcementConfig(mode="audit_only"),
    )


def _post_mcp_body():
    """A canonical tools/call payload — routes to backend ``default``
    with a filesystem read action. The policy pipeline treats this as
    a normal invocation and (given no RBAC rules configured) short-
    circuits to allow via the NativeEvaluator attribution path OR
    flips to deny under a registered SabotageDenyEvaluator."""
    return {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read_file", "arguments": {}},
    }


def _post_mcp(client, body):
    return client.post(
        "/mcp", data=_json.dumps(body),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer dummy",
        },
    )


def _cohort_d_principal():
    return BoundPrincipal(
        principal_kind="agent",
        principal_id=_COHORT_D_PRINCIPAL_ID,
        method="bearer_jwt",
        external_subject=_COHORT_D_PRINCIPAL_ID,
        external_issuer=None,
    )


def _list_verdict_rows(engine, tenant_id: str) -> list[dict]:
    """Open a fresh Session on the shared engine and query for
    ``gateway_verdict`` rows for ``tenant_id``. Kept as a helper so
    both cohort-D tests use the same read seam (a rework of the read
    path is a common regression vector — one seam = one place to
    fix)."""
    factory = sessionmaker(bind=engine)
    sess = factory()
    try:
        rows = list_evidence(sess, tenant_id=tenant_id)
        return [r for r in rows if r["evidence_kind"] == "gateway_verdict"]
    finally:
        sess.close()


def _seed_invocation(engine, tenant_id: str) -> int:
    """Insert one real invocation row via the OSS ``record_invocation``
    public API and return its id.

    Isolates Cohort D from any regression in
    ``_record_invocation_pre_policy``. Task #349 resolved the specific
    ``outcome='pending'`` bug (``pending`` is now a canonical
    ``VALID_OUTCOMES`` member), but this workaround is preserved as
    defense-in-depth per Kola directive 2026-08-08: the helper decouples
    Cohort D's evaluator-attribution assertions from any future bugs in
    pre-policy recording. Cohort D validates the evaluator_name plumbing
    (FIX-M2); it should not depend on the pre-policy audit-row happy
    path staying green. Keeping the seed + patch pattern means a
    regression in the pre-policy helper cannot mask an evaluator
    attribution regression."""
    from kya import record_invocation
    factory = sessionmaker(bind=engine)
    sess = factory()
    try:
        inv = record_invocation(
            sess, tenant_id=tenant_id, agent_key=_COHORT_D_PRINCIPAL_ID,
            principal_kind="agent", principal_id=_COHORT_D_PRINCIPAL_ID,
            mode="observed", outcome="in_progress",
        )
        sess.commit()
        return int(inv)
    finally:
        sess.close()


def _patch_pre_policy_to_return(monkeypatch, invocation_id: int):
    """Patch ``kya_gateway.server._record_invocation_pre_policy`` to
    return ``invocation_id`` unconditionally. Isolates Cohort D from
    any regression in that helper (see ``_seed_invocation`` — task #349
    resolved the historical ``outcome='pending'`` bug but the isolation
    is preserved as defense-in-depth)."""
    from kya_gateway import server as _server_mod
    monkeypatch.setattr(
        _server_mod,
        "_record_invocation_pre_policy",
        lambda **kw: invocation_id,
    )


def test_cohort_d_http_sabotage_evaluator_stamps_row_via_real_server(
    cohort_d_engine, monkeypatch, sabotage_evaluator_fixture,
):
    """Cohort D + sabotage-registered evaluator: driving a real HTTP
    POST through ``kya_gateway.server`` MUST result in a
    ``gateway_verdict`` evidence row whose ``evaluator_name`` column
    equals the sabotage evaluator's registered name.

    Load-bearing sabotage guarantee (FIX-M2): if a future edit drops
    the ``evaluator_name=_evaluator_name`` kwarg from
    ``server.py::_record_verdict_evidence``, this test goes RED — the
    column would come back ``None``. Cohorts A/B/C would stay green
    because they call a mirror helper, not ``server.py``.
    """
    _install_real_kya_shim(monkeypatch, engine=cohort_d_engine)
    inv_id = _seed_invocation(cohort_d_engine, _COHORT_D_TENANT)
    _patch_pre_policy_to_return(monkeypatch, inv_id)
    _patch_identity_to(monkeypatch, _cohort_d_principal())
    _patch_forwarder_to_echo(monkeypatch)

    cfg = _cohort_d_gateway_config(
        tenant_id=_COHORT_D_TENANT,
        evaluator_name=_SABOTAGE_REGISTERED_NAME,
    )
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    r = _post_mcp(client, _post_mcp_body())
    # audit_only mode + sabotage-deny → 200 from the gateway (audit
    # doesn't block) but the verdict row is still written. Assert on
    # the row, not the HTTP code.
    assert r.status_code in (200, 403), r.text

    verdict_rows = _list_verdict_rows(cohort_d_engine, _COHORT_D_TENANT)
    assert len(verdict_rows) >= 1, (
        "no gateway_verdict evidence row written via real server.py — "
        "shim wiring is broken"
    )
    latest = verdict_rows[-1]
    assert latest["evaluator_name"] == _SABOTAGE_REGISTERED_NAME, (
        "server.py did NOT forward evaluator_name through to "
        f"record_evidence; got {latest['evaluator_name']!r}, expected "
        f"{_SABOTAGE_REGISTERED_NAME!r}. FIX-M2 wire regressed."
    )


def test_cohort_d_http_default_native_evaluator_stamps_row_via_real_server(
    cohort_d_engine, monkeypatch,
):
    """Cohort D default-native cohort — with no sabotage registered,
    the default NativeEvaluator serves. The Phase 3 attribution
    helper enriches ``Verdict.rich`` with ``evaluator_name="native"``,
    and the real ``server.py`` MUST propagate that to
    ``kya_evidence.evaluator_name``.
    """
    _install_real_kya_shim(monkeypatch, engine=cohort_d_engine)
    inv_id = _seed_invocation(cohort_d_engine, _COHORT_D_TENANT)
    _patch_pre_policy_to_return(monkeypatch, inv_id)
    _patch_identity_to(monkeypatch, _cohort_d_principal())
    _patch_forwarder_to_echo(monkeypatch)

    cfg = _cohort_d_gateway_config(
        tenant_id=_COHORT_D_TENANT, evaluator_name=None,
    )
    gw = Gateway(cfg)
    client = TestClient(gw.app)
    r = _post_mcp(client, _post_mcp_body())
    assert r.status_code == 200, r.text

    verdict_rows = _list_verdict_rows(cohort_d_engine, _COHORT_D_TENANT)
    assert len(verdict_rows) >= 1, (
        "no gateway_verdict evidence row written via real server.py "
        "on default-native path"
    )
    latest = verdict_rows[-1]
    assert latest["evaluator_name"] == _NATIVE_EVALUATOR_ATTRIBUTION_NAME, (
        "default-native path did NOT stamp "
        f"{_NATIVE_EVALUATOR_ATTRIBUTION_NAME!r} on the real evidence "
        f"row; got {latest['evaluator_name']!r}. Attribution wire "
        "regressed on the default cohort."
    )
