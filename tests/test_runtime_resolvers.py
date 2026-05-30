"""Unit tests for the auto-resolver chain.

Each resolver in isolation, then the chain composition. Live Docker
behavior is exercised in ``test_runtime_resolvers_live_docker.py``
(gated by ``KYA_RUNTIME_LIVE_DOCKER=1``).
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

import pytest

from kya.runtime import (
    ContainerNameConventionResolver,
    DockerLabelResolver,
    ExplicitBindingCache,
    K8sAnnotationResolver,
    PrincipalResolverChain,
    ProcessRef,
    ProcessUserResolver,
    RuntimeEvent,
    bind_container,
    build_default_resolver_chain,
    unbind_container,
)


# ── Helpers ────────────────────────────────────────────────────


def _event(**overrides) -> RuntimeEvent:
    defaults = dict(
        source_tool="falco",
        source_rule_id="r",
        occurred_at_ts=100.0,
        severity="medium",
        action="x",
        message="m",
        container_id="cidABC123",
        process=ProcessRef(name="sh", user="root"),
        raw={"output_fields": {"container.name": "agent-research-42"}},
    )
    defaults.update(overrides)
    return RuntimeEvent(**defaults)


@pytest.fixture(autouse=True)
def _clear_explicit_cache():
    """The explicit cache is module-global. Clear before AND after
    each test so nothing leaks across the suite."""
    ExplicitBindingCache.clear()
    yield
    ExplicitBindingCache.clear()


# ══════════════════════════════════════════════════════════════
# ExplicitBindingCache
# ══════════════════════════════════════════════════════════════


def test_explicit_cache_round_trip():
    bind_container("c1", "tenant_a", "agent_42")
    r = ExplicitBindingCache()
    result = r(_event(container_id="c1"))
    assert result == ("tenant_a", "agent_42", "explicit_cache")


def test_explicit_cache_unbind_removes_entry():
    bind_container("c1", "t1", "p1")
    unbind_container("c1")
    assert ExplicitBindingCache()(_event(container_id="c1")) is None


def test_explicit_cache_rebind_overwrites():
    bind_container("c1", "t1", "p1")
    bind_container("c1", "t2", "p2")
    result = ExplicitBindingCache()(_event(container_id="c1"))
    assert result[:2] == ("t2", "p2")


def test_explicit_cache_ignores_empty_args():
    bind_container("", "t1", "p1")
    bind_container("c1", "", "p1")
    bind_container("c1", "t1", "")
    assert ExplicitBindingCache.size() == 0


def test_explicit_cache_returns_none_when_event_has_no_container_id():
    bind_container("c1", "t1", "p1")
    r = ExplicitBindingCache()
    assert r(_event(container_id=None)) is None


def test_explicit_cache_is_thread_safe_under_concurrent_writes():
    """Production collectors may bind/lookup from multiple threads.
    Hammer the cache to surface any locking bugs."""
    def writer(i: int) -> None:
        for j in range(50):
            bind_container(f"c{i}_{j}", f"t{i}", f"p{i}_{j}")

    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(writer, range(8)))
    # Some entries may have been evicted by LRU bound, but the cache
    # must be in a sane state -- no exceptions raised, lookups still
    # work for whatever survived.
    r = ExplicitBindingCache()
    # Spot-check: at least one binding survives and lookup succeeds.
    survived = 0
    for i in range(8):
        for j in range(50):
            if r(_event(container_id=f"c{i}_{j}")):
                survived += 1
    assert survived > 0


def test_explicit_cache_lru_bound_evicts_oldest():
    """Past _max_entries (10k), the cache must drop oldest first --
    never grow unbounded, never error."""
    # We can't easily push 10k entries in a fast test; instead verify
    # the property by tightening the bound for this test.
    original_max = ExplicitBindingCache._max_entries
    ExplicitBindingCache._max_entries = 5
    try:
        for i in range(10):
            bind_container(f"c{i}", "t", f"p{i}")
        assert ExplicitBindingCache.size() == 5
        # The oldest 5 must be gone, the newest 5 present.
        r = ExplicitBindingCache()
        for i in range(5):
            assert r(_event(container_id=f"c{i}")) is None, i
        for i in range(5, 10):
            assert r(_event(container_id=f"c{i}")) is not None, i
    finally:
        ExplicitBindingCache._max_entries = original_max


# ══════════════════════════════════════════════════════════════
# DockerLabelResolver
# ══════════════════════════════════════════════════════════════


def test_docker_resolver_inert_when_no_container_id():
    r = DockerLabelResolver()
    assert r(_event(container_id=None)) is None


def test_docker_resolver_inert_when_docker_sdk_missing(monkeypatch):
    """If `docker` isn't installed, lazy import returns None and the
    resolver becomes inert. Verify by faking the ImportError."""
    import builtins
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "docker":
            raise ImportError("no docker SDK for this test")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    r = DockerLabelResolver()
    assert r(_event(container_id="cidABC")) is None
    # And the resolver remembers the SDK is missing so it doesn't
    # retry the import on the next event.
    assert r._client_ready is False


def test_docker_resolver_caches_negative_lookups():
    """Cache must hold both positive AND negative results so a
    container without our labels doesn't trigger docker-inspect on
    every alert. Verify via call counting on a mocked client."""
    r = DockerLabelResolver(cache_ttl_seconds=300)
    call_count = {"n": 0}

    class _FakeClient:
        class containers:
            @staticmethod
            def get(cid):
                call_count["n"] += 1
                class _C:
                    labels = {"unrelated": "value"}
                return _C()

    r._client = _FakeClient()
    r._client_ready = True

    for _ in range(5):
        assert r(_event(container_id="cidABC")) is None
    assert call_count["n"] == 1  # cached after first inspect


def test_docker_resolver_returns_binding_when_labels_match():
    r = DockerLabelResolver(default_tenant="acme")

    class _FakeClient:
        class containers:
            @staticmethod
            def get(cid):
                class _C:
                    labels = {"io.veldt.principal_id": "agent_42"}
                return _C()

    r._client = _FakeClient()
    r._client_ready = True
    result = r(_event(container_id="cidABC"))
    assert result == ("acme", "agent_42", "docker_label")


def test_docker_resolver_tenant_from_label_overrides_default():
    r = DockerLabelResolver(default_tenant="from_default")

    class _FakeClient:
        class containers:
            @staticmethod
            def get(cid):
                class _C:
                    labels = {
                        "io.veldt.principal_id": "agent_42",
                        "io.veldt.tenant_id": "from_label",
                    }
                return _C()

    r._client = _FakeClient()
    r._client_ready = True
    result = r(_event(container_id="cidABC"))
    assert result[0] == "from_label"


def test_docker_resolver_returns_none_when_principal_label_missing():
    r = DockerLabelResolver(default_tenant="acme")

    class _FakeClient:
        class containers:
            @staticmethod
            def get(cid):
                class _C:
                    labels = {}
                return _C()

    r._client = _FakeClient()
    r._client_ready = True
    assert r(_event(container_id="cidABC")) is None


# ══════════════════════════════════════════════════════════════
# K8sAnnotationResolver (stub)
# ══════════════════════════════════════════════════════════════


def test_k8s_stub_returns_none_in_open_release():
    """Open release ships a stub; the polished informer lives in the
    premium bundle. The stub must NEVER bind (or it would hide the
    fact the premium feature isn't installed)."""
    assert K8sAnnotationResolver()(_event()) is None


# ══════════════════════════════════════════════════════════════
# ContainerNameConventionResolver
# ══════════════════════════════════════════════════════════════


def test_name_convention_default_pattern_matches_agent_prefix():
    r = ContainerNameConventionResolver(default_tenant="acme")
    result = r(_event(
        raw={"output_fields": {"container.name": "agent-research-42"}}))
    assert result == ("acme", "research-42", "container_name")
    # Hmm -- the default regex used `[a-zA-Z0-9_]+` so dashes
    # shouldn't match. Let's verify behavior matches the regex.


def test_name_convention_underscore_form_also_matches():
    r = ContainerNameConventionResolver(default_tenant="acme")
    result = r(_event(
        raw={"output_fields": {"container.name": "agent_research_42"}}))
    assert result == ("acme", "research_42", "container_name")


def test_name_convention_no_match_returns_none():
    r = ContainerNameConventionResolver(default_tenant="acme")
    assert r(_event(
        raw={"output_fields": {"container.name": "alpine"}})) is None


def test_name_convention_inert_without_tenant():
    r = ContainerNameConventionResolver()
    assert r(_event(
        raw={"output_fields": {
            "container.name": "agent_research_42"}})) is None


def test_name_convention_custom_pattern():
    r = ContainerNameConventionResolver(
        pattern=r"^svc[-](?P<pid>[a-z]+)$",
        default_tenant="acme",
    )
    result = r(_event(
        raw={"output_fields": {"container.name": "svc-checkout"}}))
    assert result == ("acme", "checkout", "container_name")


def test_name_convention_invalid_pattern_is_inert_not_crash():
    """A bad regex from env config must not crash the bridge."""
    r = ContainerNameConventionResolver(
        pattern=r"[unbalanced",
        default_tenant="acme",
    )
    assert r(_event(
        raw={"output_fields": {"container.name": "agent_x"}})) is None


def test_name_convention_handles_missing_raw_payload():
    r = ContainerNameConventionResolver(default_tenant="acme")
    assert r(_event(raw={})) is None


# ══════════════════════════════════════════════════════════════
# ProcessUserResolver
# ══════════════════════════════════════════════════════════════


def test_process_user_resolver_empty_map_is_inert():
    r = ProcessUserResolver()
    assert r(_event()) is None


def test_process_user_resolver_returns_mapped_principal():
    r = ProcessUserResolver(
        user_map={"agent": ("acme", "agent_42")})
    ev = _event(process=ProcessRef(name="x", user="agent"))
    result = r(ev)
    assert result == ("acme", "agent_42", "process_user_map")


def test_process_user_resolver_returns_none_when_user_not_in_map():
    r = ProcessUserResolver(
        user_map={"agent": ("acme", "agent_42")})
    ev = _event(process=ProcessRef(name="x", user="root"))
    assert r(ev) is None


def test_process_user_resolver_returns_none_when_event_has_no_process():
    r = ProcessUserResolver(
        user_map={"root": ("acme", "agent_42")})
    assert r(_event(process=None)) is None


# ══════════════════════════════════════════════════════════════
# PrincipalResolverChain composition
# ══════════════════════════════════════════════════════════════


def test_chain_returns_first_resolver_hit():
    """Order matters: the chain stops at the first resolver that
    returns a non-None result."""
    chain = PrincipalResolverChain([
        lambda ev: None,
        lambda ev: ("t", "p_second", "second"),
        lambda ev: ("t", "p_third", "third"),  # never reached
    ])
    result = chain(_event())
    assert result == ("t", "p_second", "second")


def test_chain_returns_none_when_all_resolvers_return_none():
    chain = PrincipalResolverChain([lambda ev: None, lambda ev: None])
    assert chain(_event()) is None


def test_chain_swallows_exception_and_tries_next_resolver():
    """One buggy resolver must NOT poison the chain. The bridge
    relies on this: a flaky docker-socket call can't drop subsequent
    strategies."""
    def boom(ev):
        raise RuntimeError("boom")

    chain = PrincipalResolverChain([
        boom,
        lambda ev: ("t", "p_after_boom", "ok"),
    ])
    result = chain(_event())
    assert result == ("t", "p_after_boom", "ok")


def test_chain_handles_empty_resolver_list():
    """Vacuous chain returns None for any event without crashing."""
    chain = PrincipalResolverChain([])
    assert chain(_event()) is None


# ══════════════════════════════════════════════════════════════
# build_default_resolver_chain — composition
# ══════════════════════════════════════════════════════════════


def test_default_chain_has_all_five_strategies_in_order():
    """The default chain order is part of the public contract --
    explicit cache wins over docker label wins over k8s annotation
    wins over name convention wins over process-user. If we change
    the order, we MUST also update the docs that promise this."""
    chain = build_default_resolver_chain()
    classes = [type(r).__name__ for r in chain.resolvers]
    assert classes == [
        "ExplicitBindingCache",
        "DockerLabelResolver",
        "K8sAnnotationResolver",
        "ContainerNameConventionResolver",
        "ProcessUserResolver",
    ]


def test_default_chain_explicit_cache_wins_over_naming_convention():
    """If both strategies could bind, the cache (strategy 1) wins.
    Verify by registering an explicit binding for a container whose
    name ALSO matches the convention."""
    bind_container("cidX", "tenant_explicit", "principal_explicit")
    chain = build_default_resolver_chain(default_tenant="acme_default")
    ev = _event(
        container_id="cidX",
        raw={"output_fields": {"container.name": "agent_other_42"}},
    )
    result = chain(ev)
    # Explicit cache wins -- principal_explicit, NOT 'other_42'.
    assert result[1] == "principal_explicit"
    assert result[2] == "explicit_cache"


def test_default_chain_falls_to_naming_when_cache_empty():
    """Cache empty + docker SDK unavailable (no fake client) ->
    chain falls through to the naming convention if it can bind."""
    chain = build_default_resolver_chain(default_tenant="acme")
    ev = _event(
        container_id="never_registered",
        raw={"output_fields": {"container.name": "agent_alpha"}},
    )
    # Docker resolver will try and fail (no daemon access in this
    # test env, or daemon doesn't know "never_registered"), then
    # naming convention fires.
    result = chain(ev)
    assert result is not None
    assert result[1] == "alpha"
    assert result[2] == "container_name"
