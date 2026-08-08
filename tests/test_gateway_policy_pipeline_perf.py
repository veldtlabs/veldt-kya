"""Task #318 PERF-BENCHMARK — latency + compute-count guardrails for
the gateway policy pipeline hot path.

Load-bearing promise: after FIX-1 (short-circuit) + FIX-2 (TTL cache)
+ FIX-6 (attribution enrichment), the pipeline should:

    1. Absorb 995+ of every 1000 ``get_effective_policy_hash`` calls
       via the TTL cache. The compute-count assertion is the load-
       bearing one — if it fails, the cache/short-circuit combo is
       not working end-to-end.
    2. Meet a conservative wall-clock budget on a machine with a
       simulated ~1ms DB SELECT. Per ``feedback_latency_budget``, the
       gateway pipeline target is p50 <10 ms / p99 <50 ms. This test
       asserts p50 <5 ms / p99 <20 ms for headroom.

The timing assertion is intentionally slack; the compute-count
assertion is the primary correctness signal.
"""
from __future__ import annotations

import statistics
import time

import pytest

import kya.policy_hash as ph
from kya.policy_evaluator import register_evaluator, unregister_evaluator
from kya._native_evaluator import NativeEvaluator
from kya_gateway.config import PolicyConfig
from kya_gateway.identity import BoundPrincipal
from kya_gateway.policy_pipeline import evaluate


def _principal(kind: str = "agent") -> BoundPrincipal:
    return BoundPrincipal(
        principal_kind=kind,
        principal_id="planner",
        method="bearer_jwt",
        external_subject="planner",
        external_issuer=None,
    )


class _CountingCompute:
    """Instrumented replacement for ``_compute_effective_policy_hash_uncached``.

    Counts calls + simulates ~1ms DB latency so the perf assertion has
    something to measure. If the pipeline hasn't short-circuited AND
    the cache hasn't absorbed the call, this hits N times × 1ms and
    the latency assertion loudly fails.
    """

    def __init__(self, sleep_seconds: float = 0.001):
        self.calls = 0
        self.sleep_seconds = sleep_seconds

    def __call__(self, db, tenant_id):
        self.calls += 1
        if self.sleep_seconds > 0:
            time.sleep(self.sleep_seconds)
        return f"policy-hash-sha256-v1:perf-{tenant_id}"


def test_perf_compute_count_and_latency_budget(monkeypatch):
    counter = _CountingCompute(sleep_seconds=0.001)
    monkeypatch.setattr(
        ph, "_compute_effective_policy_hash_uncached", counter,
    )
    ph.invalidate_policy_hash_cache()

    # Register a plain NativeEvaluator so short-circuit fires
    ev = NativeEvaluator()
    register_evaluator("perf-native", ev)

    try:
        cfg = PolicyConfig(min_trust=0, policy_evaluator_name="perf-native")

        # Warm-up (primes the TTL cache with a real compute for tenant-perf)
        for _ in range(3):
            evaluate(
                db=None, tenant_id="tenant-perf", principal=_principal(),
                action="mcp.x.read", payload_bytes=100, invocation_id=None,
                cfg=cfg,
            )

        # Timed loop
        N = 1000
        durations_us: list[float] = []
        for _ in range(N):
            t0 = time.perf_counter()
            v = evaluate(
                db=None, tenant_id="tenant-perf", principal=_principal(),
                action="mcp.x.read", payload_bytes=100, invocation_id=None,
                cfg=cfg,
            )
            durations_us.append((time.perf_counter() - t0) * 1_000_000.0)
            assert v.verdict == "allow"

        durations_us.sort()
        p50 = durations_us[N // 2]
        p99 = durations_us[int(N * 0.99)]

        # Compute-count is the LOAD-BEARING assertion. After warm-up
        # the cache should absorb every call to
        # ``_compute_effective_policy_hash_uncached``. Threshold set at
        # 5 to leave room for a stray TTL expiry on a slow CI runner.
        assert counter.calls <= 5, (
            f"expected <=5 uncached compute calls across {N} pipeline "
            f"iterations (post-warm-up), got {counter.calls}. TTL cache "
            f"and/or short-circuit are not absorbing hot-path calls."
        )

        # Latency guardrail. Deliberately generous: real numbers should
        # be well under these thresholds. If we blow past them the DB
        # fan-out is happening on the hot path.
        assert p50 < 5_000, (
            f"p50 latency {p50:.1f}us > 5000us — hot path is slow "
            f"despite short-circuit + cache. Check "
            f"_fallback_with_native_attribution for unexpected work."
        )
        assert p99 < 20_000, f"p99 latency {p99:.1f}us > 20000us"

        # Emit numbers so the test log doubles as a benchmark report
        print(
            f"\n[perf] N={N} p50={p50:.1f}us p99={p99:.1f}us "
            f"compute_calls={counter.calls}"
        )
    finally:
        unregister_evaluator("perf-native")


def test_perf_sabotage_cache_off_produces_n_computes(monkeypatch):
    """POLARITY FLIP: with the TTL cache disabled (TTL=0), the
    short-circuit path's ``_fallback_with_native_attribution`` call to
    ``get_effective_policy_hash`` fans out on every request. compute-
    count MUST equal N. Confirms the cache is the load-bearing
    mechanism absorbing the calls in the primary test.

    Note: NativeEvaluator's own ``_compute_policy_hash`` skips
    ``get_effective_policy_hash`` when ``db is None`` (falls back to
    hashing ``{}``). We're specifically probing the FIX-6 attribution
    path in ``_fallback_with_native_attribution``, which DOES call
    ``get_effective_policy_hash(db=None, ...)`` unconditionally — the
    hash helper itself decides to raise on ``db=None``. Patch it to
    return a valid hash so the compute is counted."""
    counter = _CountingCompute(sleep_seconds=0.0)
    monkeypatch.setattr(
        ph, "_compute_effective_policy_hash_uncached", counter,
    )
    monkeypatch.setattr(ph, "_POLICY_HASH_CACHE_TTL_SECONDS", 0.0)
    ph.invalidate_policy_hash_cache()

    ev = NativeEvaluator()
    register_evaluator("perf-native-sabotage", ev)
    try:
        cfg = PolicyConfig(
            min_trust=0, policy_evaluator_name="perf-native-sabotage",
        )
        N = 50
        for _ in range(N):
            evaluate(
                db=None, tenant_id="tenant-perf-sabotage",
                principal=_principal(),
                action="mcp.x.read", payload_bytes=100, invocation_id=None,
                cfg=cfg,
            )
        # Every short-circuit fires FIX-6's attribution enrichment,
        # which calls get_effective_policy_hash. With TTL=0 that
        # ALWAYS fans out. Assert every request produced one compute.
        assert counter.calls >= N, (
            f"expected >={N} uncached compute calls with cache disabled, "
            f"got {counter.calls}. The TTL cache is not the mechanism "
            f"absorbing the calls in the primary test — some other "
            f"caching or bypass path exists."
        )
    finally:
        unregister_evaluator("perf-native-sabotage")
