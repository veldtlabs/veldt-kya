"""A chain that fires must decay the trust of a REAL principal.

What was shipping
-----------------
``_emit`` derived the principal from ``rule.correlate_by`` via
``dict(zip(rule.correlate_by, correlate_key))``. Cross-agent rules
declare ``correlate_by: [tenant_id, correlation_id]`` -- no
``principal_id`` -- so the lookup defaulted to ``""``. Every one of the
five shipped rules is cross-agent or DAG-shaped, so in practice the
detection fired, the trust decay landed on an empty principal, and the
agent that actually exfiltrated kept full trust and was never blocked.

``default_signal_emitter`` additionally hardcoded
``principal_kind="user"`` while ``get_principal_trust`` keys its lookup
on ``(tenant_id, principal_kind, principal_id)`` and every agent reader
passes ``"agent"`` -- so even a correct principal_id was written under a
kind nothing reads back.

Both are the same defect class: a detection that fires but is
enforcement-inert. These tests assert the OUTCOME (whose trust moved),
never the column, because a signal row that no reader queries is
documentation rather than enforcement.
"""
from __future__ import annotations

import functools
from unittest.mock import MagicMock, Mock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import kya
from kya.attack_chains import (
    AttackChainEngine,
    InMemoryStateStore,
    bundled_rules_dir,
    load_rule,
)
from kya.attack_chains._engine import default_signal_emitter
from kya.users import SEVERITY_DELTAS, STARTING_TRUST

TENANT = "11111111-2222-3333-4444-attribution1"
RECON = {"tool": "file_read", "path": "/etc/shadow"}
EXFIL = {"tool": "http_post", "url": "https://evil.example.com"}


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=eng)()
    kya.init_storage(session)
    yield session
    session.close()
    eng.dispose()


def _rule(severity="high", correlate_by=None, rule_id="cross_agent",
          emits_signal=None):
    return load_rule(
        {
            "version": 1,
            "id": rule_id,
            "severity": severity,
            "emits_signal": emits_signal or f"rogue_{rule_id}",
            "correlate_by": correlate_by or ["tenant_id", "correlation_id"],
            "steps": [
                {"id": "recon", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "file_read"}},
                {"id": "exfil", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "http_post"},
                 "after": "recon", "within_seconds": 300},
            ],
        },
        source_label="<test>",
    )


def _run_chain(db, engine, recon_by="agent-recon", exfil_by="agent-exfil",
               kind="agent", corr="req-1", recon_tenant=TENANT,
               exfil_tenant=TENANT):
    engine.process_evidence(
        db, tenant_id=recon_tenant, principal_id=recon_by,
        principal_kind=kind, evidence_kind="tool_call",
        payload=RECON, correlation_id=corr)
    return engine.process_evidence(
        db, tenant_id=exfil_tenant, principal_id=exfil_by,
        principal_kind=kind, evidence_kind="tool_call",
        payload=EXFIL, correlation_id=corr)


def test_the_offending_agent_loses_trust(db):
    """The bug: this agent's trust was never touched, at any threshold."""
    engine = AttackChainEngine(
        rules=[_rule()], state_store=InMemoryStateStore())

    assert _run_chain(db, engine) == ["cross_agent"]
    db.commit()

    trust = kya.get_principal_trust(
        db, tenant_id=TENANT, principal_kind="agent",
        principal_id="agent-exfil")
    assert trust is not None, (
        "the chain fired but no trust row exists for the exfiltrating "
        "agent -- the signal went to an empty principal and nothing "
        "downstream can act on it"
    )
    assert trust.trust_score < STARTING_TRUST


def test_the_signal_is_not_written_to_an_empty_principal(db):
    engine = AttackChainEngine(
        rules=[_rule()], state_store=InMemoryStateStore())
    _run_chain(db, engine)
    db.commit()

    # get_principal_trust synthesizes a default row rather than
    # returning None, so assert nothing was RECORDED against it.
    phantom = kya.get_principal_trust(
        db, tenant_id=TENANT, principal_kind="agent", principal_id="")
    assert not phantom.signal_counts, (
        f"a signal was recorded against the empty principal: {phantom}"
    )
    assert phantom.trust_score == STARTING_TRUST


def test_severity_drives_the_trust_cost(db):
    """A critical chain must cost more than a low one.

    Rules name their own signal kinds, so none appear in
    SIGNAL_DELTAS and every chain used to take the same default.
    """
    scores = {}
    for severity in ("low", "critical"):
        engine = AttackChainEngine(
            rules=[_rule(severity=severity, rule_id=f"chain_{severity}")],
            state_store=InMemoryStateStore())
        agent = f"agent-{severity}"
        _run_chain(db, engine, exfil_by=agent, corr=f"req-{severity}")
        db.commit()
        scores[severity] = kya.get_principal_trust(
            db, tenant_id=TENANT, principal_kind="agent",
            principal_id=agent).trust_score

    assert scores["critical"] < scores["low"], (
        f"severity did not change the trust cost: {scores}"
    )
    assert scores["critical"] == STARTING_TRUST + SEVERITY_DELTAS["critical"]


def test_the_runtime_bridge_attributes_to_agents():
    """The only production caller of process_evidence.

    Without this, the principal_kind parameter exists but nothing
    passes it, agent trust is written under kind "user", and every
    reader -- which queries "agent" -- misses it.
    """
    import inspect

    from kya.runtime import _bridge
    from kya.runtime._bridge import RUNTIME_PRINCIPAL_KIND

    src = inspect.getsource(_bridge._dispatch_attack_chains)
    assert "principal_kind=" in src, (
        "the bridge does not pass principal_kind, so chain signals land "
        "under the default kind and no agent reader will see them"
    )
    assert RUNTIME_PRINCIPAL_KIND == "agent"


def test_a_rule_without_tenant_id_never_attributes_cross_tenant(db):
    """Falling back to the live event's tenant would let a chain
    correlated only by correlation_id decay a principal in whichever
    tenant happened to complete it."""
    seen: list[tuple[str, str]] = []
    engine = AttackChainEngine(
        rules=[_rule(correlate_by=["correlation_id"], rule_id="no_tenant")],
        state_store=InMemoryStateStore(),
        signal_emitter=lambda _db, t, p, _s, _e, _r: seen.append((t, p)))

    _run_chain(db, engine, recon_by="tenant-a-agent", exfil_by="tenant-b-agent",
               recon_tenant="tenant-a", exfil_tenant="tenant-b")

    principals = [p for _, p in seen]
    assert "tenant-a-agent" not in principals, (
        f"a tenant-a principal was penalised by tenant-b traffic: {seen}"
    )
    assert [t for t, _ in seen] == [""] * len(seen)


@pytest.mark.parametrize("emitter", [
    Mock(spec=default_signal_emitter),
    MagicMock(spec=default_signal_emitter),
    max,
    str,
    functools.reduce,
])
def test_uninspectable_emitters_survive_a_real_emit(db, emitter):
    """Builtins, Mocks and lazy proxies raise from inspect.signature.

    The probe runs at emit time, so building an engine proves nothing --
    the chain has to actually complete. A probe failure must degrade to
    the legacy call, never drop the detection.
    """
    engine = AttackChainEngine(
        rules=[_rule()], state_store=InMemoryStateStore(),
        signal_emitter=emitter)
    assert _run_chain(db, engine) == ["cross_agent"]


def test_a_legacy_emitter_assigned_after_construction_still_fires(db):
    """signal_emitter is a public attribute. Caching the capability
    probe at construction made a later legacy assignment raise
    TypeError inside the fail-soft handler, dropping the signal
    entirely -- worse than attributing it wrongly."""
    called: list[str] = []
    engine = AttackChainEngine(
        rules=[_rule()], state_store=InMemoryStateStore())
    engine.signal_emitter = (
        lambda _db, _t, p, _s, _e, _r: called.append(p))

    _run_chain(db, engine)
    assert called == ["agent-recon", "agent-exfil"]


def test_an_emitter_that_binds_the_kind_keeps_its_choice():
    from kya.attack_chains._engine import _emitter_accepts_kind

    bound = functools.partial(default_signal_emitter, principal_kind="agent")
    assert _emitter_accepts_kind(bound) is False


def test_bundled_rules_ship_with_the_package():
    """They were absent from the built wheel entirely."""
    import pathlib

    rules = list(pathlib.Path(bundled_rules_dir()).glob("*.yml"))
    assert len(rules) >= 5


def test_every_participant_in_the_chain_loses_trust(db):
    """Penalising only the principal that completed the chain lets the
    orchestrating parent keep full authority and spawn a fresh
    sub-agent to run the same attack again.

    The recon agent read /etc/shadow. That is half of an exfiltration
    and it must cost the agent that did it.
    """
    engine = AttackChainEngine(
        rules=[_rule()], state_store=InMemoryStateStore())
    _run_chain(db, engine)
    db.commit()

    for agent in ("agent-recon", "agent-exfil"):
        trust = kya.get_principal_trust(
            db, tenant_id=TENANT, principal_kind="agent",
            principal_id=agent)
        assert trust.trust_score < STARTING_TRUST, (
            f"{agent} participated in the chain but kept full trust"
        )


def test_a_repeated_principal_is_penalised_once_per_chain(db):
    """One agent performing every step is one attack, not N."""
    engine = AttackChainEngine(
        rules=[_rule()], state_store=InMemoryStateStore())
    _run_chain(db, engine, recon_by="solo", exfil_by="solo")
    db.commit()

    trust = kya.get_principal_trust(
        db, tenant_id=TENANT, principal_kind="agent", principal_id="solo")
    assert trust.trust_score == STARTING_TRUST + SEVERITY_DELTAS["high"]


def test_a_per_principal_rule_still_penalises_only_that_principal(db):
    """correlate_by [tenant_id, principal_id] already names the
    principal; participant tracking must not widen the blast radius."""
    seen: list[str] = []
    engine = AttackChainEngine(
        rules=[_rule(correlate_by=["tenant_id", "principal_id"],
                     rule_id="per_principal")],
        state_store=InMemoryStateStore(),
        signal_emitter=lambda _db, _t, p, _s, _e, _r: seen.append(p))

    _run_chain(db, engine, recon_by="solo", exfil_by="solo")
    assert seen == ["solo"]


def test_the_dag_diamond_penalises_the_whole_delegation_tree(db):
    """The shipped 4-step diamond, run with four distinct principals.

    Before participant tracking only the http_post leaf was decayed:
    the parent that spawned the tree and both recon sub-agents kept
    full authority, so the parent could spawn a replacement leaf and
    repeat the exfiltration immediately.
    """
    import pathlib

    import yaml

    raw = yaml.safe_load(
        (pathlib.Path(bundled_rules_dir())
         / "delegated_credential_exfil_diamond.yml").read_text(
             encoding="utf-8"))
    engine = AttackChainEngine(
        rules=[load_rule(raw)], state_store=InMemoryStateStore())

    tree = [
        ("parent", {"tool": "agent_spawn"}),
        ("sub-a", {"tool": "file_read", "path": "/etc/shadow"}),
        ("sub-b", {"tool": "env_read", "key": "AWS_SECRET_KEY"}),
        ("leaf", {"tool": "http_post", "url": "https://evil.example.com"}),
    ]
    fired = []
    for principal, payload in tree:
        fired = engine.process_evidence(
            db, tenant_id=TENANT, principal_id=principal,
            principal_kind="agent", evidence_kind="tool_call",
            payload=payload, correlation_id="req-diamond")
    db.commit()

    assert fired == ["delegated_credential_exfil_diamond"]
    for principal, _ in tree:
        trust = kya.get_principal_trust(
            db, tenant_id=TENANT, principal_kind="agent",
            principal_id=principal)
        assert trust.trust_score < STARTING_TRUST, (
            f"{principal} took part in the diamond but kept full trust"
        )


def test_a_chain_with_no_attributable_principal_emits_nothing(db):
    """The runtime bridge dispatches unbound events with principal_id
    "" (see _resolve_principal's "unbound" path), and cross-agent rules
    match without a principal. Falling back to the completing principal
    unconditionally re-creates the original bug: a phantom row at
    principal_id="" that is provisioned and decayed forever while
    nothing downstream can act on it.
    """
    seen: list[str] = []
    engine = AttackChainEngine(
        rules=[_rule()], state_store=InMemoryStateStore(),
        signal_emitter=lambda _db, _t, p, _s, _e, _r: seen.append(p))

    engine.process_evidence(
        db, tenant_id=TENANT, principal_id="", principal_kind="agent",
        evidence_kind="tool_call", payload=RECON, correlation_id="unbound")
    engine.process_evidence(
        db, tenant_id=TENANT, principal_id="", principal_kind="agent",
        evidence_kind="tool_call", payload=EXFIL, correlation_id="unbound")
    db.commit()

    assert seen == [], f"signal emitted for an empty principal: {seen}"
    phantom = kya.get_principal_trust(
        db, tenant_id=TENANT, principal_kind="agent", principal_id="")
    assert not phantom.signal_counts


def test_severity_never_overrides_a_canonical_signal_kind(db):
    """SIGNAL_DELTAS entries are calibrated per kind. A rule that emits
    one must not get a LIGHTER penalty just because it declared a low
    severity.
    """
    from kya.users import SIGNAL_DELTAS

    engine = AttackChainEngine(
        rules=[_rule(severity="low", rule_id="canonical",
                     emits_signal="cross_tenant")],
        state_store=InMemoryStateStore())

    _run_chain(db, engine, exfil_by="agent-canonical")
    db.commit()

    trust = kya.get_principal_trust(
        db, tenant_id=TENANT, principal_kind="agent",
        principal_id="agent-canonical")
    assert trust.trust_score == STARTING_TRUST + SIGNAL_DELTAS["cross_tenant"]


def test_a_rogue_signal_can_never_raise_trust(db):
    """record_principal_signal is public API and SEVERITY_DELTAS is a
    mutable dict. Clamping bounds the score, not the sign."""
    kya.record_principal_signal(
        db, tenant_id=TENANT, principal_kind="agent",
        principal_id="agent-credit", signal_kind="rogue_x", trust_delta=+40)
    db.commit()

    trust = kya.get_principal_trust(
        db, tenant_id=TENANT, principal_kind="agent",
        principal_id="agent-credit")
    assert trust.trust_score <= STARTING_TRUST


def test_the_recon_step_does_not_match_routine_config_reads(db):
    """A /etc/* glob matches hosts, resolv.conf and CA bundles. With
    every participant penalised, that would decay any benign service
    that shares a request tree."""
    import pathlib

    import yaml

    from kya.attack_chains._matchers import match_value

    raw = yaml.safe_load(
        (pathlib.Path(bundled_rules_dir())
         / "cross_agent_data_exfiltration.yml").read_text(encoding="utf-8"))
    spec = raw["steps"][0]["match"]["payload.path"]

    for benign in ("/etc/hosts", "/etc/resolv.conf", "/etc/timezone",
                   "/etc/ssl/certs/ca-bundle.crt", "/etc/mime.types"):
        assert not match_value(benign, spec), f"{benign} matches {spec!r}"
    for sensitive in ("/etc/shadow", "/etc/passwd", "/etc/sudoers"):
        assert match_value(sensitive, spec), f"{sensitive} missed by {spec!r}"


def test_the_bridge_actually_dispatches_under_the_agent_kind(monkeypatch):
    """Behavioural companion to the source-string guard above.

    That guard passes on `principal_kind="user"` too, so it cannot tell
    a correct fix from a wrong one. This drives the real dispatch and
    asserts what reached the engine.
    """
    from kya.runtime import _bridge

    seen: dict = {}

    class _Recorder:
        rules = [object()]

        def process_evidence(self, _db, **kwargs):
            seen.update(kwargs)
            return []

    monkeypatch.setattr(
        "kya.attack_chains.get_default_engine", lambda: _Recorder())
    # Payload shaping is not under test; isolate the dispatch itself.
    monkeypatch.setattr(_bridge, "_evidence_kind", lambda _ev: "tool_call")
    monkeypatch.setattr(
        _bridge, "_event_to_payload", lambda _ev: {"tool": "file_read"})

    ev = _bridge.BoundEvent.__new__(_bridge.BoundEvent)
    object.__setattr__(ev, "occurred_at_ts", 0.0)

    _bridge._dispatch_attack_chains(
        None, ev, tenant_id="acme", principal_id="agent-1")

    assert seen.get("principal_kind") == "agent", (
        f"the bridge dispatched under kind {seen.get('principal_kind')!r}; "
        f"agent trust is read back under 'agent'"
    )


def test_pyproject_ships_the_bundled_rules():
    """The rule files were absent from the published wheel entirely.

    Structural guard: it catches the key being removed or renamed, which
    is how the regression happened. It cannot see a broken build.
    """
    import pathlib

    import tomllib

    root = pathlib.Path(__file__).resolve().parents[1]
    cfg = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    data = cfg["tool"]["setuptools"]["package-data"]
    assert any("rules/*.yml" in v for v in data.get("kya.attack_chains", [])), (
        f"bundled attack-chain rules are not declared as package data: {data}"
    )


def test_an_unsatisfiable_min_trust_is_flagged_at_config_load(caplog):
    """A threshold above the starting score denies every new principal,
    which reads as a broken gateway rather than a policy choice."""
    import logging

    from kya.users import STARTING_TRUST
    from kya_gateway.config import _warn_if_min_trust_denies_new_agents

    with caplog.at_level(logging.WARNING):
        _warn_if_min_trust_denies_new_agents(STARTING_TRUST)
    assert not caplog.records, "warned on a threshold a new agent can meet"

    with caplog.at_level(logging.WARNING):
        _warn_if_min_trust_denies_new_agents(STARTING_TRUST + 1)
    assert any("starting" in r.getMessage() for r in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        _warn_if_min_trust_denies_new_agents(1000)
    assert any("maximum" in r.getMessage() for r in caplog.records)
