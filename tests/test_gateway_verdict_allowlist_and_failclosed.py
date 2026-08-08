"""Task #318 FIX-3 + FIX-4 — verdict allowlist in adapter, fail-closed
else in ``server.py``.

FIX-3: ``_verdict_result_to_gateway_verdict`` MUST reject any
``VerdictResult.verdict`` not in the paper Figure-4 canonical vocabulary,
returning the gateway rule's fallback verdict (and logging WARN)
instead of silently propagating a typo / new-vocab string that would
slip past ``server.py``'s explicit verdict branches.

FIX-4: even if a bad verdict somehow reaches ``server.py`` (belt +
suspenders), the enforce-mode block MUST treat any non-allow /
non-deny / non-flag_for_review verdict as deny (403) rather than
falling through to the "forward to backend" happy path.

Sabotage-verify for FIX-3: registered evaluator returns
``verdict="denny"``. Assert the pipeline returns the fallback (deny
per gateway rule) NOT a Verdict with ``verdict="denny"``. Then
temporarily disable the allowlist and assert the typo propagates.

Sabotage-verify for FIX-4: mock the pipeline to return a
``Verdict(verdict="mystery")`` and assert the enforce-mode HTTP
response is 403. Without the fail-closed else the server would fall
through to the backend forwarder and return 200.
"""
from __future__ import annotations

import json
import os
import sys
import types
from unittest.mock import patch

import pytest

os.environ.setdefault("KYA_DID_RESOLVERS", "key,web,jwk")

from fastapi.testclient import TestClient

from kya.policy_evaluator import (
    EvaluationInput,
    VerdictResult,
    register_evaluator,
    unregister_evaluator,
)
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
    RBACConfig,
)
from kya_gateway.identity import BoundPrincipal
from kya_gateway.policy_pipeline import (
    Verdict,
    _verdict_result_to_gateway_verdict,
    evaluate,
)


def _principal(kind: str = "agent") -> BoundPrincipal:
    return BoundPrincipal(
        principal_kind=kind,
        principal_id="planner",
        method="bearer_jwt",
        external_subject="planner",
        external_issuer=None,
    )


# ── FIX-3: allowlist in adapter ────────────────────────────────────


def test_adapter_rejects_typo_verdict_and_returns_fallback(caplog):
    fallback = Verdict(
        verdict="deny", reason_codes=["FALLBACK_RBAC"], signal_kind="rbac_refusal",
    )
    vr = VerdictResult(
        verdict="denny",  # typo
        reasons=("typo_reason",),
        policy_hash="typo-hash",
        evaluator_name="typo-eval",
    )
    with caplog.at_level("WARNING"):
        out = _verdict_result_to_gateway_verdict(vr, fallback=fallback)
    # Fallback preserved verbatim — typo did NOT propagate
    assert out.verdict == "deny"
    assert out.reason_codes == ["FALLBACK_RBAC"]
    assert out.signal_kind == "rbac_refusal"
    # WARN log captured
    assert any(
        "unknown verdict" in rec.message and "denny" in rec.message
        for rec in caplog.records
    ), caplog.records


def test_adapter_accepts_known_vocabulary():
    """All Figure-4 canonical verdicts pass through unchanged.

    Note: after FIX-C (task #105 alias sunset), ``require_human`` is
    NOT in this list — it's normalized to ``flag_for_review`` at the
    adapter boundary (see ``test_require_human_verdict_normalizes_
    to_flag_for_review``). Only strings that pass through with the
    same string on the other side are asserted here.
    """
    from kya_gateway.policy_pipeline import (
        _LEGACY_VERDICT_ALIASES,
        _VALID_VERDICTS,
    )
    for good in _VALID_VERDICTS:
        # Sanity-check: no legacy alias should sneak into the allowlist
        # under FIX-C — normalization runs BEFORE the check.
        assert good not in _LEGACY_VERDICT_ALIASES
        fallback = Verdict(verdict="deny", reason_codes=["F"], signal_kind="sk")
        vr = VerdictResult(
            verdict=good, reasons=("r",), policy_hash="h", evaluator_name="e",
        )
        out = _verdict_result_to_gateway_verdict(vr, fallback=fallback)
        assert out.verdict == good, f"canonical verdict {good!r} rejected"


def test_adapter_end_to_end_pipeline_ignores_typo(caplog):
    """Sabotage via registered evaluator: pipeline routes through
    adapter, which must trap the typo and keep the gateway's rule
    verdict."""

    class _TypoEval:
        name = "typo-e2e-eval"

        def evaluate(self, inp):
            return VerdictResult(
                verdict="denny",
                reasons=("e2e_typo",),
                policy_hash="h",
                evaluator_name=self.name,
            )

    register_evaluator("typo-e2e-eval", _TypoEval())
    try:
        cfg = PolicyConfig(
            min_trust=0,
            rbac=RBACConfig(default="deny", rules=[]),  # rule fallback = deny
            policy_evaluator_name="typo-e2e-eval",
        )
        with caplog.at_level("WARNING"):
            v = evaluate(
                db=None, tenant_id="tenant-alpha", principal=_principal(),
                action="mcp.x.read", payload_bytes=100, invocation_id=None, cfg=cfg,
            )
        # Fallback used — typo did not propagate to gateway.
        assert v.verdict == "deny", (
            "typo verdict 'denny' propagated through pipeline — allowlist "
            "is not blocking unknown vocabulary"
        )
        assert "RBAC_DENY" in v.reason_codes
    finally:
        unregister_evaluator("typo-e2e-eval")


def test_adapter_sabotage_disabled_allowlist_lets_typo_propagate(monkeypatch):
    """POLARITY FLIP: patch ``_VALID_VERDICTS`` to include the typo, and
    assert it propagates. Confirms the allowlist (not some other
    mechanism) is what trapped it in the primary test above."""
    from kya_gateway import policy_pipeline
    monkeypatch.setattr(
        policy_pipeline, "_VALID_VERDICTS",
        frozenset(policy_pipeline._VALID_VERDICTS | {"denny"}),
    )
    fallback = Verdict(verdict="deny", reason_codes=["F"], signal_kind="sk")
    vr = VerdictResult(
        verdict="denny", reasons=("t",), policy_hash="h", evaluator_name="e",
    )
    out = _verdict_result_to_gateway_verdict(vr, fallback=fallback)
    assert out.verdict == "denny", (
        "with allowlist relaxed, typo verdict should propagate; if this "
        "still returns 'deny' the primary test wasn't proving the "
        "allowlist was load-bearing"
    )


# ── FIX-4: fail-closed else in server.py enforce mode ──────────────


def _patch_minimal(monkeypatch, principal=None):
    """Stub identity + KYA core + forwarder so we can exercise mode logic.
    Mirrors ``tests/test_gateway_enforcement_modes.py::_patch_minimal``."""
    fake_kya = types.ModuleType("kya")

    class _Sess:
        def commit(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False

    fake_kya.default_session = lambda: _Sess()
    fake_kya.record_invocation = lambda db, **kw: 1
    fake_kya.record_evidence = lambda db, **kw: 1
    fake_kya.record_principal_signal = lambda db, **kw: 1

    class _ADE(Exception):
        pass
    fake_kya.AccessDeniedError = _ADE
    fake_kya.require_action = lambda *a, **kw: True
    monkeypatch.setitem(sys.modules, "kya", fake_kya)

    from kya_gateway import identity as _id_mod
    monkeypatch.setattr(
        _id_mod.IdentityResolver, "resolve",
        lambda self, headers: principal or _principal(),
    )

    from kya_gateway import forwarder as _fwd

    async def fake_forward_json(self, backend_name, payload, **_kwargs):
        return _fwd.ForwardResult(
            status_code=200,
            body=b'{"result":"backend-forwarded"}',
            headers={"content-type": "application/json"},
        )
    monkeypatch.setattr(_fwd.Forwarder, "forward_json", fake_forward_json)


def _build_gateway(mode: str):
    return GatewayConfig(
        gateway=GatewayBindConfig(bind="127.0.0.1:0", tenant_id="t1"),
        identity=IdentityConfig(
            methods=["bearer_jwt"],
            jwt=JWTConfig(),
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
        enforcement=EnforcementConfig(mode=mode),
    )


def _post_tools_call(client):
    return client.post("/mcp", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read", "arguments": {}},
    }), headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer dummy",
    })


def test_enforce_mode_unknown_verdict_is_treated_as_deny(monkeypatch, caplog):
    """Sabotage: monkey-patch ``evaluate()`` in the server's namespace
    to return a mystery verdict. Assert 403 (fail-closed) not 200
    (silent forward)."""
    _patch_minimal(monkeypatch)
    from kya_gateway import server as srv

    def fake_evaluate(*args, **kwargs):
        return Verdict(
            verdict="mystery",
            reason_codes=["MYSTERY"],
            signal_kind="governance_block",
        )
    monkeypatch.setattr(srv, "evaluate_policy", fake_evaluate)

    gw = srv.Gateway(_build_gateway(mode="enforce"))
    client = TestClient(gw.app)
    with caplog.at_level("WARNING"):
        r = _post_tools_call(client)
    assert r.status_code == 403, (
        f"expected 403 fail-closed on unknown verdict, got {r.status_code}: "
        f"{r.text}"
    )
    body = r.json()
    assert body["error"]["data"]["verdict"] == "deny"
    assert body["error"]["data"]["original_verdict"] == "mystery"
    # WARN log captured
    assert any(
        "unknown verdict" in rec.message and "mystery" in rec.message
        for rec in caplog.records
    ), [rec.message for rec in caplog.records]


def test_enforce_mode_allow_still_forwards(monkeypatch):
    """Regression: allow verdicts in enforce mode still forward to the
    backend. FIX-4 else must not accidentally 403 the happy path."""
    _patch_minimal(monkeypatch)
    from kya_gateway import server as srv

    def fake_evaluate(*args, **kwargs):
        return Verdict(
            verdict="allow", reason_codes=[], signal_kind="clean_invocation",
        )
    monkeypatch.setattr(srv, "evaluate_policy", fake_evaluate)

    gw = srv.Gateway(_build_gateway(mode="enforce"))
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 200
    assert b"backend-forwarded" in r.content


def test_enforce_mode_deny_still_403(monkeypatch):
    """Regression: explicit deny still 403 via the original branch."""
    _patch_minimal(monkeypatch)
    from kya_gateway import server as srv

    def fake_evaluate(*args, **kwargs):
        return Verdict(
            verdict="deny", reason_codes=["EXPLICIT_DENY"],
            signal_kind="governance_block",
        )
    monkeypatch.setattr(srv, "evaluate_policy", fake_evaluate)

    gw = srv.Gateway(_build_gateway(mode="enforce"))
    client = TestClient(gw.app)
    r = _post_tools_call(client)
    assert r.status_code == 403
    body = r.json()
    assert body["error"]["data"]["verdict"] == "deny"
    # Original verdict key only added on the FIX-4 else branch — must
    # NOT be present here since this is the plain-deny branch.
    assert "original_verdict" not in body["error"]["data"]


# ── FIX-C (task #105): legacy `require_human` alias normalization ──
#
# Load-bearing promise: NO internal code path sees `require_human` as
# a live verdict. The alias is normalized to `flag_for_review` at
# every boundary (adapter, config parse, RBAC eval) with a WARN log
# that references the sunset version constant `_DEPRECATION_SUNSET`.
#
# All alias mapping + version references come from the source-of-
# truth constants in `kya_gateway.policy_pipeline`. No hardcoded
# alias strings or version numbers below — every literal is derived
# from the module constant so a bump-in-one-place ripples through.


def test_require_human_verdict_normalizes_to_flag_for_review(caplog):
    """Evaluator returns VerdictResult(verdict="require_human"). The
    adapter must (a) rewrite verdict to flag_for_review, (b) emit a
    WARN with 'deprecated' + the sunset version in the message.
    """
    from kya_gateway.policy_pipeline import (
        _DEPRECATION_SUNSET,
        _LEGACY_VERDICT_ALIASES,
    )
    legacy = next(iter(_LEGACY_VERDICT_ALIASES.keys()))
    canonical = _LEGACY_VERDICT_ALIASES[legacy]

    fallback = Verdict(
        verdict="deny", reason_codes=["FALLBACK"], signal_kind="rbac_refusal",
    )
    vr = VerdictResult(
        verdict=legacy, reasons=("legacy_reason",),
        policy_hash="h", evaluator_name="legacy-eval",
    )
    with caplog.at_level("WARNING"):
        out = _verdict_result_to_gateway_verdict(vr, fallback=fallback)
    # (a) verdict normalized
    assert out.verdict == canonical, (
        f"expected legacy alias {legacy!r} to normalize to {canonical!r}, "
        f"got {out.verdict!r}"
    )
    # (b) WARN captured referencing 'deprecated' + sunset version
    matching = [
        rec for rec in caplog.records
        if "deprecated" in rec.message.lower()
        and _DEPRECATION_SUNSET in rec.message
    ]
    assert matching, (
        f"no WARN log mentioning 'deprecated' + sunset "
        f"{_DEPRECATION_SUNSET!r}; got: "
        f"{[r.message for r in caplog.records]}"
    )


def test_require_human_normalization_sabotage(monkeypatch):
    """SABOTAGE polarity flip: neuter the alias map (make it empty) and
    confirm the adapter rejects the legacy verdict via the allowlist
    instead of normalizing (out.verdict != canonical). Proves the
    normalization step is the load-bearing mechanism in the primary
    test above.
    """
    from kya_gateway import policy_pipeline as pp
    monkeypatch.setattr(pp, "_LEGACY_VERDICT_ALIASES", {})

    legacy = "require_human"
    fallback = Verdict(
        verdict="deny", reason_codes=["FALLBACK"], signal_kind="rbac_refusal",
    )
    vr = VerdictResult(
        verdict=legacy, reasons=("legacy_reason",),
        policy_hash="h", evaluator_name="legacy-eval",
    )
    out = pp._verdict_result_to_gateway_verdict(vr, fallback=fallback)
    # With alias map empty AND require_human removed from _VALID_VERDICTS
    # by FIX-C, the adapter should now REJECT the legacy string via the
    # allowlist path → return fallback.
    assert out.verdict == "deny", (
        f"expected fallback (deny) when alias map is neutered; got "
        f"{out.verdict!r} — some code path is still normalizing outside "
        f"the FIX-C entry point"
    )


def test_require_human_in_config_normalizes_at_parse_time(caplog):
    """Parse a PolicyConfig with an RBAC rule verdict='require_human'.
    Assert:
      (a) parsed rule's verdict == canonical form (normalized),
      (b) WARN captured with 'deprecated' + sunset version,
      (c) config still loads (does not raise).
    """
    from kya_gateway.config import GatewayConfig
    from kya_gateway.policy_pipeline import (
        _DEPRECATION_SUNSET,
        _LEGACY_VERDICT_ALIASES,
    )
    legacy = next(iter(_LEGACY_VERDICT_ALIASES.keys()))
    canonical = _LEGACY_VERDICT_ALIASES[legacy]

    raw = {
        "gateway": {"bind": "127.0.0.1:0", "tenant_id": "t"},
        "identity": {
            "methods": ["bearer_jwt"],
            "jwt": {"jwks_url": "https://x/.well-known/jwks.json",
                    "issuer": "x"},
        },
        "backends": [{"name": "b", "url": "http://x"}],
        "policy": {
            "rbac": {
                "default": "deny",
                "rules": [
                    {"principal_kind": "agent",
                     "actions": ["mcp.x.write"],
                     "verdict": legacy},
                ],
            },
        },
        "audit": {},
    }
    with caplog.at_level("WARNING"):
        cfg = GatewayConfig.from_dict(raw)   # (c) — must NOT raise
    # (a) rule verdict normalized
    assert cfg.policy.rbac is not None
    assert cfg.policy.rbac.rules[0].verdict == canonical, (
        f"config-parse did NOT normalize legacy alias {legacy!r} → "
        f"{canonical!r}; got {cfg.policy.rbac.rules[0].verdict!r}"
    )
    # (b) WARN with 'deprecated' + sunset version
    matching = [
        rec for rec in caplog.records
        if "deprecated" in rec.message.lower()
        and _DEPRECATION_SUNSET in rec.message
    ]
    assert matching, (
        f"no config-parse WARN mentioning 'deprecated' + sunset "
        f"{_DEPRECATION_SUNSET!r}; got: "
        f"{[r.message for r in caplog.records]}"
    )


def test_config_parse_sabotage_removes_normalization(monkeypatch):
    """SABOTAGE: neuter alias map so _parse_rbac's normalization branch
    skips. Config parse must then REJECT the legacy verdict via the
    'allow/deny/flag_for_review' allowlist that follows. Proves the
    normalize-then-validate ordering is what makes the primary test
    accept the legacy value.
    """
    from kya_gateway import policy_pipeline as pp
    from kya_gateway.config import GatewayConfig
    from kya_gateway.errors import GatewayConfigError
    monkeypatch.setattr(pp, "_LEGACY_VERDICT_ALIASES", {})

    raw = {
        "gateway": {"bind": "127.0.0.1:0", "tenant_id": "t"},
        "identity": {
            "methods": ["bearer_jwt"],
            "jwt": {"jwks_url": "https://x/.well-known/jwks.json",
                    "issuer": "x"},
        },
        "backends": [{"name": "b", "url": "http://x"}],
        "policy": {
            "rbac": {
                "default": "deny",
                "rules": [
                    {"principal_kind": "agent",
                     "actions": ["mcp.x.write"],
                     "verdict": "require_human"},
                ],
            },
        },
        "audit": {},
    }
    with pytest.raises(GatewayConfigError, match="require_human"):
        GatewayConfig.from_dict(raw)


def test_no_internal_code_sees_legacy_string_after_boundary(caplog):
    """After parse-time normalization + adapter normalization, downstream
    code (e.g. evaluate() output) never contains 'require_human'.
    Enumerate the boundaries end-to-end.
    """
    from kya_gateway.config import GatewayConfig
    from kya_gateway.policy_pipeline import (
        _LEGACY_VERDICT_ALIASES,
        _VALID_VERDICTS,
    )
    # (1) _VALID_VERDICTS post-FIX-C should NOT contain any legacy alias.
    for legacy in _LEGACY_VERDICT_ALIASES:
        assert legacy not in _VALID_VERDICTS, (
            f"post-FIX-C, {legacy!r} must not be in _VALID_VERDICTS — "
            f"normalization runs BEFORE the allowlist check, so keeping "
            f"the alias in the allowlist would let it slip through"
        )

    # (2) config-parse: rule verdict is normalized in the parsed cfg
    raw = {
        "gateway": {"bind": "127.0.0.1:0", "tenant_id": "t"},
        "identity": {
            "methods": ["bearer_jwt"],
            "jwt": {"jwks_url": "https://x/.well-known/jwks.json",
                    "issuer": "x"},
        },
        "backends": [{"name": "b", "url": "http://x"}],
        "policy": {
            "rbac": {
                "default": "deny",
                "rules": [
                    {"principal_kind": "agent",
                     "actions": ["mcp.x.write"],
                     "verdict": "require_human"},
                ],
            },
        },
        "audit": {},
    }
    with caplog.at_level("WARNING"):
        cfg = GatewayConfig.from_dict(raw)
    for rule in cfg.policy.rbac.rules:
        for legacy in _LEGACY_VERDICT_ALIASES:
            assert rule.verdict != legacy, (
                f"parsed RBAC rule verdict is still legacy {legacy!r}"
            )

    # (3) full pipeline: evaluate() must return canonical verdict on a
    # rule that was CONSTRUCTED with the legacy alias directly (RBAC-
    # eval-time normalization boundary — bypasses config parse).
    from kya_gateway.config import RBACConfig, RBACRule
    cfg2 = PolicyConfig(
        min_trust=0,
        rbac=RBACConfig(default="deny", rules=[
            RBACRule(principal_kind="agent",
                     actions=["mcp.x.write"],
                     verdict="require_human"),  # direct legacy input
        ]),
    )
    v = evaluate(
        db=None, tenant_id="t", principal=_principal(),
        action="mcp.x.write", payload_bytes=100,
        invocation_id=None, cfg=cfg2,
    )
    for legacy in _LEGACY_VERDICT_ALIASES:
        assert v.verdict != legacy, (
            f"pipeline output verdict is still legacy {legacy!r}; "
            f"internal code path leaked the alias past the boundary"
        )
    # And critically: it's the canonical form.
    assert v.verdict == "flag_for_review"
