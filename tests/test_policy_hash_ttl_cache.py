"""Task #318 FIX-2 — TTL cache in front of ``get_effective_policy_hash``.

Load-bearing promises:
    1. Repeated calls with the same ``tenant_id`` hit the cache and
       don't re-run the underlying (DB-fanout) compute.
    2. ``invalidate_policy_hash_cache(tenant_id)`` drops the entry so
       the next call re-computes.
    3. Disabling the cache (TTL=0 in this test's monkey-patch) restores
       the un-cached behaviour — proving the cache IS what's absorbing
       the calls, not some other mechanism.
    4. ``tenant_id=None`` (platform default) is a distinct cache key
       from any concrete tenant.

Sabotage-verify: this test explicitly disables the cache and asserts
compute count == N. If disabling the cache DOESN'T flip the assertion
from 1 to N, the cache was never load-bearing to begin with.
"""
from __future__ import annotations

import kya.policy_hash as ph


class _CountingCompute:
    """Wraps the underlying uncached compute with a call counter."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, db, tenant_id):
        self.calls += 1
        return f"policy-hash-sha256-v1:fake-{tenant_id}"


def _install_counter(monkeypatch) -> _CountingCompute:
    counter = _CountingCompute()
    monkeypatch.setattr(
        ph, "_compute_effective_policy_hash_uncached", counter,
    )
    # Reset cache so previous tests don't leak
    ph.invalidate_policy_hash_cache()
    return counter


def test_cache_absorbs_repeated_calls(monkeypatch):
    """1000 calls in a tight loop must produce exactly ONE compute."""
    counter = _install_counter(monkeypatch)
    for _ in range(1000):
        ph.get_effective_policy_hash(db=None, tenant_id="tenant-A")
    assert counter.calls == 1, (
        f"expected exactly 1 uncached compute for 1000 cached calls, "
        f"got {counter.calls}"
    )


def test_cache_disabled_produces_n_computes(monkeypatch):
    """SABOTAGE: set TTL=0 so every call misses. 100 calls → 100 computes.

    This is the load-bearing polarity flip: if this test's expectation
    of 100 doesn't hold, the cache in the primary test wasn't proving
    anything.
    """
    counter = _install_counter(monkeypatch)
    monkeypatch.setattr(ph, "_POLICY_HASH_CACHE_TTL_SECONDS", 0.0)
    ph.invalidate_policy_hash_cache()  # ensure a clean slate
    for _ in range(100):
        ph.get_effective_policy_hash(db=None, tenant_id="tenant-A")
    assert counter.calls == 100, (
        f"expected 100 uncached computes with cache disabled, got "
        f"{counter.calls} — the cache is still doing work when it "
        f"shouldn't be"
    )


def test_invalidate_forces_recompute(monkeypatch):
    counter = _install_counter(monkeypatch)
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-B")
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-B")
    assert counter.calls == 1

    ph.invalidate_policy_hash_cache("tenant-B")
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-B")
    assert counter.calls == 2, (
        "invalidate_policy_hash_cache('tenant-B') did NOT drop the "
        "cached entry — a policy mutation would return a stale hash"
    )


def test_invalidate_all_drops_every_entry(monkeypatch):
    counter = _install_counter(monkeypatch)
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-A")
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-B")
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-C")
    assert counter.calls == 3

    ph.invalidate_policy_hash_cache()  # no-arg = nuke all
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-A")
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-B")
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-C")
    assert counter.calls == 6


def test_none_and_empty_string_are_distinct_keys(monkeypatch):
    """Platform default (``None``) must be cached separately from any
    concrete tenant. Otherwise a call for tenant '' would return the
    platform-default hash — which is a real cross-tenant leak."""
    counter = _install_counter(monkeypatch)
    ph.get_effective_policy_hash(db=None, tenant_id=None)
    ph.get_effective_policy_hash(db=None, tenant_id="")
    assert counter.calls == 2, (
        "None (platform default) and '' (empty-string tenant) collapsed "
        "into a single cache key — cross-tenant hash contamination risk"
    )


def test_register_scope_invalidates_cache(monkeypatch):
    """Task #318 FIX-B — registering a NEW weight scope must invalidate
    the policy-hash cache so the next lookup reflects the new registry
    (via ``known_scopes()``).

    Sabotage-verify: this test proves the invalidation-on-register.
    Removing the invalidate_policy_hash_cache() call from register_scope
    flips the second assertion RED (compute count does NOT increment).
    """
    from kya import tenant_weights as tw

    counter = _install_counter(monkeypatch)
    # Prime cache for tenant "T1"
    ph.get_effective_policy_hash(db=None, tenant_id="T1")
    assert counter.calls == 1
    # Repeat call → cached
    ph.get_effective_policy_hash(db=None, tenant_id="T1")
    assert counter.calls == 1

    # Register a NEW scope. This must invalidate the cache. Use a name
    # that does not collide with any real scope; clean up in teardown.
    _test_scope_name = "test_fix_b_scope"
    try:
        tw.register_scope(_test_scope_name, {"k": 1})
        # Post-register: next call for T1 MUST recompute (was 1 → now 2)
        ph.get_effective_policy_hash(db=None, tenant_id="T1")
        assert counter.calls == 2, (
            f"register_scope did NOT invalidate policy_hash cache — "
            f"expected compute count 2 after register, got {counter.calls}. "
            f"A late-registering scope would produce a stale hash for the "
            f"cache TTL window."
        )
    finally:
        tw._SCOPE_REGISTRY.pop(_test_scope_name, None)


def test_register_scope_invalidation_sabotage(monkeypatch):
    """SABOTAGE polarity flip: stub out invalidate_policy_hash_cache
    so register_scope's invalidation call is a no-op. Confirm the cache
    stays warm (compute count stays at 1). If this test ALSO fails to
    keep the cache warm under sabotage, some other seam is invalidating
    the cache and FIX-B's added call isn't load-bearing.
    """
    from kya import policy_hash as _ph_mod
    from kya import tenant_weights as tw

    counter = _install_counter(monkeypatch)
    ph.get_effective_policy_hash(db=None, tenant_id="T1")
    assert counter.calls == 1

    # Neuter the invalidation entry-point that register_scope calls.
    monkeypatch.setattr(
        _ph_mod, "invalidate_policy_hash_cache", lambda *a, **kw: None,
    )
    _test_scope_name = "test_fix_b_sabotage_scope"
    try:
        tw.register_scope(_test_scope_name, {"k": 1})
        ph.get_effective_policy_hash(db=None, tenant_id="T1")
        # With invalidation neutered, cache must still be warm.
        assert counter.calls == 1, (
            f"cache was invalidated even though invalidate_policy_hash_cache "
            f"was stubbed to a no-op — some other seam is nuking the cache; "
            f"FIX-B's register_scope invalidation wasn't the load-bearing "
            f"mechanism. Compute count={counter.calls}"
        )
    finally:
        tw._SCOPE_REGISTRY.pop(_test_scope_name, None)


def test_expiration_forces_recompute(monkeypatch):
    """After TTL elapses, next call re-computes. Uses a tiny TTL +
    a fake clock to keep the test fast."""
    counter = _install_counter(monkeypatch)
    fake_time = [1000.0]

    def _now():
        return fake_time[0]

    monkeypatch.setattr(ph.time, "monotonic", _now)
    monkeypatch.setattr(ph, "_POLICY_HASH_CACHE_TTL_SECONDS", 10.0)
    ph.invalidate_policy_hash_cache()

    ph.get_effective_policy_hash(db=None, tenant_id="tenant-Z")
    assert counter.calls == 1
    fake_time[0] = 1005.0  # inside window
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-Z")
    assert counter.calls == 1
    fake_time[0] = 1011.0  # past TTL
    ph.get_effective_policy_hash(db=None, tenant_id="tenant-Z")
    assert counter.calls == 2, (
        "past-TTL call did not re-compute — cache never expires which "
        "means policy mutations could stick around forever"
    )
