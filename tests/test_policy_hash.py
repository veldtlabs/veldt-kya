"""Real tests for the policy-hash primitive (task #157 §3).

Each test proves a specific promise the primitive makes. Where a
promise is critical to the "policy operators see == policy runtime
applies" guarantee, the test is designed to be non-gameable —
sabotage the primitive and the test must go RED.
"""
from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import create_engine, text as _sql
from sqlalchemy.orm import Session

from kya.policy_hash import (
    POLICY_HASH_VERSION_PREFIX,
    canonicalize_policy,
    get_effective_policy,
    get_effective_policy_hash,
    hash_policy,
    hash_policy_hex,
    parse_policy_hash,
    verify_policy_hash,
)


# ── Pure-function tests (no DB) ─────────────────────────────────────


def test_canonicalize_is_deterministic_and_order_insensitive():
    """Same content, different insertion order → identical bytes."""
    a = {"b": 1, "a": 2, "c": {"y": 10, "x": 20}}
    b = {"c": {"x": 20, "y": 10}, "a": 2, "b": 1}
    assert canonicalize_policy(a) == canonicalize_policy(b)


def test_canonicalize_uses_tight_separators():
    """Regulator/Watchtower verifiers rely on the exact byte shape.

    Whitespace drift between environments (e.g. someone imports
    json.dumps with default separators) would silently invalidate
    every downstream hash.
    """
    out = canonicalize_policy({"a": 1, "b": 2})
    assert b" " not in out, (
        f"canonical form contains whitespace: {out!r}. "
        f"That means someone dropped `separators=(',', ':')` and "
        f"the hash promise is now cross-environment-broken."
    )


def test_canonicalize_rejects_non_dict():
    """A caller who accidentally passes a list of weight rows should
    get a loud error, not a silently-hashed different shape."""
    with pytest.raises(TypeError, match="expects a dict"):
        canonicalize_policy(["not", "a", "dict"])  # type: ignore[arg-type]


def test_hash_policy_hex_is_pure_sha256():
    """Bind hash_policy_hex to the exact sha256 promise so a future
    refactor that quietly switched to md5 (or truncated the digest)
    turns this test red before it ships."""
    policy = {"capability_weights": {"code_execution": 45}}
    expected = hashlib.sha256(canonicalize_policy(policy)).hexdigest()
    assert hash_policy_hex(policy) == expected


def test_hash_policy_carries_versioned_prefix():
    """Consumers store the prefixed form so an algorithm swap in
    hash_policy is a loud mismatch, not a silent collision."""
    policy = {"x": 1}
    stamped = hash_policy(policy)
    assert stamped.startswith(POLICY_HASH_VERSION_PREFIX)
    assert stamped[len(POLICY_HASH_VERSION_PREFIX):] == hash_policy_hex(policy)


def test_hash_policy_changes_when_a_single_weight_changes():
    """The core §3 promise. If ANY weight changes, the hash must
    change. Sabotage-verified: change one integer, verify the hash
    diverges."""
    before = {"capability_weights": {"code_execution": 30, "network_egress": 30}}
    after = {"capability_weights": {"code_execution": 45, "network_egress": 30}}
    assert hash_policy(before) != hash_policy(after)


def test_canonicalize_treats_bool_and_int_as_equal():
    """Guard against silent bool-vs-int drift.

    Regression from delegated review: `json.dumps(True)` is `"true"`
    but `json.dumps(1)` is `"1"`. A DB driver quirk that returned
    True/False for a weight (or a manual override script) would
    silently produce a different hash from the equivalent int, and
    Watchtower's cross-check would report a false-positive
    tampering event.
    """
    with_bool = {"scope": {"key": True, "other": False}}
    with_int = {"scope": {"key": 1, "other": 0}}
    assert hash_policy(with_bool) == hash_policy(with_int)


def test_canonicalize_rejects_nan_and_infinity():
    """Guard against silent float drift.

    Weights are always integers by contract. A stray float that
    happens to be NaN or ±inf would serialise to non-standard JSON
    (`NaN`, `Infinity`) which two hosts may format identically OR
    fail on identically, but the promise here is "loud on unexpected
    types". allow_nan=False upstream turns this into ValueError.
    """
    with pytest.raises(ValueError):
        canonicalize_policy({"scope": {"k": float("nan")}})
    with pytest.raises(ValueError):
        canonicalize_policy({"scope": {"k": float("inf")}})


def test_canonicalize_normalises_unicode_to_nfc():
    """Guard against Windows/Linux/macOS NFC-vs-NFD drift.

    'café' can be composed (NFC: 4 codepoints) or decomposed
    (NFD: 5 codepoints, an 'e' + combining acute). Two hosts that
    both faithfully preserve their input would produce different
    JSON bytes for the same logical key. NFC-normalising both keys
    AND string values before serialising makes the hash stable
    across OSes.
    """
    nfc_key = "café"          # é as single codepoint
    nfd_key = "café"         # e + combining acute
    assert nfc_key != nfd_key
    a = canonicalize_policy({"scope": {nfc_key: 1}})
    b = canonicalize_policy({"scope": {nfd_key: 1}})
    assert a == b, (
        f"canonicalize did not normalise Unicode — bytes diverged:\n"
        f"  NFC input: {a!r}\n  NFD input: {b!r}"
    )


def test_hash_policy_hex_matches_known_value():
    """Regression pin: sha256 of a canonical known policy is exactly
    this hex.

    Any future change to canonicalisation — even a subtle one like
    adding a space after colons, or changing the sort order — would
    silently break every stored hash unless we notice via this
    assertion. Pin the byte contract to a value computed once.
    """
    policy = {"a": {"x": 1, "y": 2}, "b": {"z": 3}}
    # Computed from canonicalize_policy({"a":{"x":1,"y":2},"b":{"z":3}}):
    #   b'{"a":{"x":1,"y":2},"b":{"z":3}}'
    expected = hashlib.sha256(
        b'{"a":{"x":1,"y":2},"b":{"z":3}}'
    ).hexdigest()
    assert hash_policy_hex(policy) == expected, (
        f"hash_policy_hex drifted from the pinned byte contract.\n"
        f"  Expected: {expected}\n  Got:      {hash_policy_hex(policy)}\n"
        f"  Canonical form now: {canonicalize_policy(policy)!r}\n"
        f"If canonicalisation changed intentionally, bump "
        f"POLICY_HASH_VERSION_PREFIX to sha256-v2 rather than "
        f"silently changing v1's meaning."
    )


def test_verify_policy_hash_matches_stamped_output():
    """The Watchtower use case: verify a stored stamped hash."""
    policy = {"capability_weights": {"code_execution": 45}}
    stamped = hash_policy(policy)
    assert verify_policy_hash(policy, stamped) is True
    # Tampering — flip one bit in the policy → verification fails.
    tampered = {"capability_weights": {"code_execution": 46}}
    assert verify_policy_hash(tampered, stamped) is False


def test_parse_policy_hash_returns_version_and_hex():
    """parse_policy_hash splits the versioned string cleanly."""
    policy = {"x": 1}
    stamped = hash_policy(policy)
    version, hex_part = parse_policy_hash(stamped)
    assert version == POLICY_HASH_VERSION_PREFIX
    assert hex_part == hash_policy_hex(policy)


def test_parse_policy_hash_rejects_unknown_prefix():
    """A Watchtower running v1 that sees a v2 stamped hash must
    refuse politely, not silently coerce."""
    with pytest.raises(ValueError, match="not a policy hash we recognise"):
        parse_policy_hash("policy-hash-sha256-v2:deadbeef")
    with pytest.raises(ValueError):
        parse_policy_hash("just-a-plain-hex-string")


def test_hash_policy_is_stable_across_repeated_calls():
    """Idempotency — same input, same output, forever. If this test
    ever goes red, we've introduced non-determinism (usually a
    process-id, wall-clock, or weakref leak). This is the exact
    class of bug that would let a compromised evaluator hash the
    policy 'fresh' each time and never diverge from what the
    /controls page shows even after tampering."""
    policy = {
        "capability_weights": {"code_execution": 45},
        "sensitivity_weights": {"pii": 60},
    }
    hashes = {hash_policy(policy) for _ in range(50)}
    assert len(hashes) == 1, (
        f"hash_policy returned {len(hashes)} distinct values across "
        f"50 identical calls: {hashes}. That's non-determinism, which "
        f"breaks the policy→outcome integrity promise at the root."
    )


# ── DB-backed tests (sqlite in-memory) ──────────────────────────────


def _sqlite_engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    from kya.tenant_weights import ensure_tables

    with Session(engine) as sess:
        ensure_tables(sess)
        sess.commit()
    return engine


def test_get_effective_policy_covers_every_registered_scope():
    """A partial policy hash (missing scopes) is exactly the shape a
    compromised evaluator would emit to hide a tightening. Force the
    assembly to include EVERY known scope so 'the hash is over the
    whole policy' is enforced by construction."""
    from kya.tenant_weights import known_scopes

    engine = _sqlite_engine()
    with Session(engine) as db:
        policy = get_effective_policy(db, tenant_id=None)

    scopes = set(known_scopes())
    assert scopes, (
        "kya.tenant_weights registered zero scopes at import time. "
        "Either the ensure_tables call didn't run, or the OSS package "
        "changed its scope-registration mechanism — either way the "
        "policy hash is over an empty policy which is silently wrong."
    )
    assert set(policy.keys()) == scopes, (
        f"get_effective_policy returned scopes {set(policy.keys())} but "
        f"the registry knows about {scopes}. A subset would let a "
        f"compromised layer hash 'part of the policy' and still emit "
        f"a stable-looking hash."
    )


def test_effective_policy_hash_changes_when_a_tenant_override_lands():
    """The end-to-end promise, DB-side. Insert a tenant override,
    confirm the hash actually diverges from platform-baseline. If it
    doesn't diverge, either the override didn't take OR the hash
    didn't observe the change — both mean §3 is broken."""
    from kya.tenant_weights import known_scopes, set_override

    engine = _sqlite_engine()
    tenant = "test-tenant-alpha"

    with Session(engine) as db:
        baseline = get_effective_policy_hash(db, tenant_id=tenant)

    # Find a real key we can tighten. Pick the first scope with any
    # keys — bounces off the actual scope registry so a future scope
    # rename doesn't silently skip this test.
    scope, key, current_value = None, None, None
    with Session(engine) as db:
        for candidate in known_scopes():
            defaults = get_effective_policy(db, tenant_id=None)[candidate]
            if defaults:
                scope = candidate
                key, current_value = next(iter(defaults.items()))
                break
    assert scope and key, "no populated scopes to test against"

    # Tighten (only-tighten invariant): move UP.
    new_value = min(100, current_value + 10)
    with Session(engine) as db:
        set_override(
            db,
            scope=scope,
            key=key,
            value=new_value,
            tenant_id=tenant,
            changed_by="test-actor",
        )
        db.commit()

    with Session(engine) as db:
        after = get_effective_policy_hash(db, tenant_id=tenant)

    assert baseline != after, (
        f"Set a real tenant override on {scope}.{key} "
        f"({current_value} → {new_value}), but the effective policy "
        f"hash did not change:\n  baseline: {baseline}\n  after:    "
        f"{after}\nThis is the exact 'policy operators see is NOT "
        f"the policy the runtime applies' failure mode #157 §3 was "
        f"built to prevent. Either set_override didn't persist, or "
        f"get_effective_policy is caching / short-circuiting."
    )


def test_scope_list_is_tenant_invariant():
    """Same scope set for every tenant.

    ``get_effective_policy`` iterates ``known_scopes()`` — which is
    global — so tenant A and tenant B always hash over the same set
    of scopes. If a future feature ever adds per-tenant scope
    registration, this test breaks loudly and forces the design to
    reckon with cross-tenant hash comparability.
    """
    engine = _sqlite_engine()
    with Session(engine) as db:
        alpha = set(get_effective_policy(db, tenant_id="alpha").keys())
        beta = set(get_effective_policy(db, tenant_id="beta").keys())
        plat = set(get_effective_policy(db, tenant_id=None).keys())
    assert alpha == beta == plat, (
        f"Scope coverage diverged across the tenant + platform views:\n"
        f"  alpha:    {sorted(alpha)}\n"
        f"  beta:     {sorted(beta)}\n"
        f"  platform: {sorted(plat)}"
    )


def test_get_effective_policy_hash_is_fast_enough_for_hot_path():
    """SLA: hash assembly must be cheap enough to call on every verdict.

    The verdict recorder embeds a policy hash in every recorded
    invocation. If assembly ever gets slow (unnoticed scope-count
    growth, an O(n²) merge, a cross-schema JOIN sneaking in), the
    verdict ingest path silently gets slower and cost-per-request
    creeps up. Assert <50ms at standard scope count so a regression
    trips CI, not production."""
    import time as _time

    engine = _sqlite_engine()
    with Session(engine) as db:
        # Warm the module import + prepared statement cache.
        _ = get_effective_policy_hash(db, tenant_id=None)
        t0 = _time.perf_counter()
        for _ in range(20):
            get_effective_policy_hash(db, tenant_id=None)
        elapsed_ms = ((_time.perf_counter() - t0) / 20) * 1000
    # 50 ms per call is generous — SQLite in-memory hits ms range.
    # Postgres in a Docker network hits 5-15 ms. A regression that
    # blows past 50 ms is a design bug, not a hardware variance.
    assert elapsed_ms < 50, (
        f"get_effective_policy_hash averaged {elapsed_ms:.2f} ms per "
        f"call — exceeds the 50 ms verdict-hot-path SLA. Something has "
        f"introduced O(scope²) or a cold DB lookup on the fast path."
    )


def test_get_effective_policy_raises_when_scope_registry_is_empty(monkeypatch):
    """Empty scope registry must be loud, not silent.

    Hashing an empty policy would silently produce a stable-looking
    but wrong hash. A caller booted before weight modules imported
    (test setup that doesn't ``import kya``, or a monkey-patched
    subpackage) would compute a "policy hash" that matches nothing
    real. Force RuntimeError so the bug surfaces at first call."""
    import kya.tenant_weights as tw

    engine = _sqlite_engine()
    # Simulate the "no modules registered" condition without
    # trashing real state.
    monkeypatch.setattr(tw, "known_scopes", lambda: [])
    with Session(engine) as db:
        with pytest.raises(RuntimeError, match="zero registered scopes"):
            get_effective_policy(db, tenant_id=None)


def test_two_tenants_produce_distinct_hashes_when_configs_differ():
    """Multi-tenant isolation. Tenant A tightens, tenant B doesn't.
    Their hashes must diverge — otherwise a compromised layer could
    serve tenant B tenant A's more-permissive hash without anyone
    noticing."""
    from kya.tenant_weights import known_scopes, set_override

    engine = _sqlite_engine()

    scope, key, current_value = None, None, None
    with Session(engine) as db:
        for candidate in known_scopes():
            defaults = get_effective_policy(db, tenant_id=None)[candidate]
            if defaults:
                scope = candidate
                key, current_value = next(iter(defaults.items()))
                break
    assert scope and key

    with Session(engine) as db:
        set_override(
            db,
            scope=scope,
            key=key,
            value=min(100, current_value + 15),
            tenant_id="tenant-alpha",
            changed_by="alice",
        )
        db.commit()

    with Session(engine) as db:
        alpha = get_effective_policy_hash(db, tenant_id="tenant-alpha")
        beta = get_effective_policy_hash(db, tenant_id="tenant-beta")

    assert alpha != beta, (
        "Tenant alpha has a tightening override; tenant beta does not. "
        f"Both hashes came back identical ({alpha}) — the hash is "
        "leaking cross-tenant OR ignoring tenant_id entirely. Both "
        "failure modes are catastrophic for multi-tenant governance."
    )
