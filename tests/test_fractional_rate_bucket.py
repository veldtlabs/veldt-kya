"""The throttle multiplier is continuous; the bucket must be too.

``check_rate_token`` derives its allowance with::

    cap = max(1, int(rate_limit_rps))

Truncating a continuous value to an integer destroys precision exactly
where a throttle needs it, and it fails in BOTH directions:

* **inert** -- 1.5 rps at 0.7x is 1.05 rps; ``int()`` returns it to 1,
  the same allowance as un-throttled. The verdict is recorded, the row
  is written, and nothing changes.
* **overshoot** -- 2.0 rps at 0.9x is 1.8 rps; ``int()`` gives 1, a 50%
  cut for a policy that asked for 10%. A rule intending a gentle
  slowdown halves the agent's throughput.

Widening the bucket window would only shrink the quantisation error
while adding burst semantics. ``check_rate_token_precise`` removes it
instead: float tokens, refilled continuously::

    tokens = min(capacity, tokens + elapsed * rate)

These tests run against a REAL Valkey. The refill-and-consume is a Lua
script precisely because it has to be atomic, so a Python fake would
test a reimplementation rather than the thing that ships.
"""
from __future__ import annotations

import os
import time
import uuid

import pytest

VALKEY_URL = os.environ.get(
    "KYA_TEST_VALKEY_URL",
    "redis://:veldt_valkey_2026@localhost:18379/0",
)


def _valkey_reachable() -> bool:
    try:
        import redis
        redis.from_url(VALKEY_URL, socket_connect_timeout=2).ping()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _valkey_reachable(),
    reason=(
        "no reachable Valkey -- set KYA_TEST_VALKEY_URL. The bucket's "
        "refill/consume is an atomic Lua script; faking it would test a "
        "reimplementation, not the shipped code."
    ),
)


@pytest.fixture()
def rt(monkeypatch):
    """runtime module bound to the real Valkey."""
    import redis
    import kya_redteam.runtime as _rt

    client = redis.from_url(VALKEY_URL)
    monkeypatch.setattr(_rt, "_get_valkey", lambda: client)
    return _rt


def _target():
    return f"frac-test-{uuid.uuid4().hex[:12]}"


def _admitted(rt, rps, n, target=None, capacity=None):
    """Admitted calls in an immediate burst (no refill time)."""
    tgt = target or _target()
    return sum(
        rt.check_rate_token_precise(tgt, rps, capacity=capacity)
        for _ in range(n)
    )


# -- the two failure modes of the integer bucket -----------------------

def test_the_inert_case_now_tightens(rt):
    """1.5 rps at 0.7x = 1.05 rps -- the integer bucket saw no change.

    Capacity must exceed 1 token, or capacity rather than rate is what
    bounds the burst and every rate looks identical. Both buckets are
    drained, then refilled for the same wall-clock window, so the only
    variable is the refill rate.
    """
    CAP, WINDOW = 4.0, 2.0
    fast_t, slow_t = _target(), _target()
    _admitted(rt, 1.5, 8, target=fast_t, capacity=CAP)    # drain
    _admitted(rt, 1.05, 8, target=slow_t, capacity=CAP)   # drain
    time.sleep(WINDOW)

    fast = _admitted(rt, 1.5, 8, target=fast_t, capacity=CAP)
    slow = _admitted(rt, 1.05, 8, target=slow_t, capacity=CAP)

    assert fast > slow, (
        f"1.5 rps admitted {fast} and 1.05 rps admitted {slow} over the "
        "same window -- a 0.7x throttle is still being truncated away, "
        "which is exactly the inert case this bucket exists to fix"
    )


def test_a_fractional_rate_is_not_rounded_down_to_one(rt):
    """A rate between two integers must behave as itself.

    Under ``int()`` every rate in [1.0, 2.0) collapsed to 1.
    """
    CAP, WINDOW = 4.0, 2.0
    a, b = _target(), _target()
    _admitted(rt, 1.9, 8, target=a, capacity=CAP)
    _admitted(rt, 1.0, 8, target=b, capacity=CAP)
    time.sleep(WINDOW)

    faster = _admitted(rt, 1.9, 8, target=a, capacity=CAP)
    slower = _admitted(rt, 1.0, 8, target=b, capacity=CAP)
    assert faster > slower, (
        f"1.9 rps admitted {faster}, 1.0 rps admitted {slower} -- both "
        "were collapsed to the same integer allowance"
    )


def test_capacity_bounds_the_burst(rt):
    """Tokens accrue only up to capacity, so idle time is not banked."""
    tgt = _target()
    assert _admitted(rt, 5.0, 10, target=tgt, capacity=3.0) == 3, (
        "burst exceeded capacity -- an idle agent could bank an "
        "unbounded allowance and spend it at once"
    )


def test_tokens_refill_continuously(rt):
    """A drained bucket recovers in proportion to elapsed time."""
    tgt = _target()
    _admitted(rt, 2.0, 5, target=tgt, capacity=2.0)   # drain
    assert rt.check_rate_token_precise(tgt, 2.0, capacity=2.0) is False

    time.sleep(1.1)   # 2 rps -> ~2 tokens back
    assert rt.check_rate_token_precise(tgt, 2.0, capacity=2.0) is True


def test_a_slower_rate_refills_more_slowly(rt):
    """Refill tracks the rate, which is what makes 0.7x mean 0.7x."""
    fast, slow = _target(), _target()
    _admitted(rt, 2.0, 4, target=fast, capacity=1.0)
    _admitted(rt, 0.5, 4, target=slow, capacity=1.0)

    time.sleep(0.75)
    assert rt.check_rate_token_precise(fast, 2.0, capacity=1.0) is True
    assert rt.check_rate_token_precise(slow, 0.5, capacity=1.0) is False, (
        "a 0.5 rps bucket refilled within 0.75s -- refill is not "
        "proportional to the rate"
    )


# -- isolation and safety ---------------------------------------------

def test_buckets_are_per_target(rt):
    a, b = _target(), _target()
    _admitted(rt, 1.0, 5, target=a, capacity=1.0)
    assert rt.check_rate_token_precise(b, 1.0, capacity=1.0) is True, (
        "one principal's spend drained another's bucket"
    )


def test_a_non_positive_rate_is_treated_as_no_limit(rt):
    assert rt.check_rate_token_precise(_target(), 0) is True
    assert rt.check_rate_token_precise(_target(), -1) is True


def test_it_fails_open_when_the_store_is_gone(rt, monkeypatch):
    """Rate limiting must never be the reason a request dies."""
    monkeypatch.setattr(rt, "_get_valkey", lambda: None)
    assert rt.check_rate_token_precise(_target(), 1.05) is True


def test_it_falls_back_to_the_integer_bucket_if_lua_is_unavailable(
    rt, monkeypatch,
):
    """Managed Redis variants may refuse EVAL.

    Falling back to the coarser bucket is worse than the fractional one
    but far better than failing the request or silently allowing all.
    """
    class NoEval:
        def eval(self, *a, **k):
            raise RuntimeError("EVAL disabled")

    monkeypatch.setattr(rt, "_get_valkey", lambda: NoEval())
    called = {}

    def _fallback(target_id, rps):
        called["hit"] = rps
        return True

    monkeypatch.setattr(rt, "check_rate_token", _fallback)
    assert rt.check_rate_token_precise(_target(), 1.05) is True
    assert called.get("hit") == pytest.approx(1.05)


# -- quantitative accuracy (ordering alone is too weak) ---------------

def test_admitted_count_tracks_rate_times_time(rt):
    """Sabotage-hardening: ordering tests miss fractional loss.

    A bucket that floors its token count still admits more at a higher
    rate, so "faster > slower" stays green while sub-token accrual is
    discarded on every call and the effective rate silently drops.
    Pin the actual number instead: over WINDOW seconds at RATE, a
    drained bucket must hand back about RATE*WINDOW tokens.
    """
    RATE, WINDOW, CAP = 1.05, 4.0, 10.0
    tgt = _target()
    _admitted(rt, RATE, 15, target=tgt, capacity=CAP)   # drain
    time.sleep(WINDOW)

    got = _admitted(rt, RATE, 15, target=tgt, capacity=CAP)
    expected = RATE * WINDOW          # ~4.2
    assert abs(got - expected) <= 1.0, (
        f"admitted {got} over {WINDOW}s at {RATE} rps; expected about "
        f"{expected:.1f}. Fractional tokens are being lost, so the "
        "effective rate is not the configured one"
    )


def test_capacity_clamps_accrual_over_a_long_idle(rt):
    """The clamp only shows up after real idle time, and under the TTL.

    Two traps this test walked into before:
      * a fresh bucket starts full with ~0 elapsed, so a burst against
        it is bounded by the initial fill whether or not a clamp exists;
      * sleeping for the key's TTL expires it, and the bucket
        reinitialises to capacity -- which looks exactly like a working
        clamp.

    So: drain, then idle LONGER than it takes to accrue past capacity
    but SHORTER than the TTL (max(2, int(cap/rate)+2) = 2s here).
    """
    RATE, CAP, IDLE = 8.0, 4.0, 1.5      # accrual 12 tokens, cap 4, ttl 2s
    tgt = _target()
    _admitted(rt, RATE, 12, target=tgt, capacity=CAP)   # drain
    time.sleep(IDLE)

    got = _admitted(rt, RATE, 15, target=tgt, capacity=CAP)
    assert got <= CAP + 1, (
        f"admitted {got} after idling {IDLE}s at {RATE} rps with "
        f"capacity {CAP} -- accrual is not clamped, so an idle agent "
        "banks an unbounded allowance and spends it in one burst"
    )


def test_sub_token_accrual_carries_over(rt):
    """Fractional carry-over is the whole point of a float bucket.

    Rounding tokens down on each write destroys it: at 0.6 rps a
    one-second wait accrues 0.6 tokens, which floors to 0 and is
    written back as 0 -- so the next second accrues another 0.6 from
    zero and the caller is NEVER admitted, at any rate below 1.

    Ordering tests ("faster admits more") stay green through that,
    which is why this asserts the carry directly.
    """
    RATE, CAP = 0.6, 2.0
    tgt = _target()
    _admitted(rt, RATE, 5, target=tgt, capacity=CAP)     # drain

    time.sleep(1.0)   # 0.6 tokens -- not yet enough
    assert rt.check_rate_token_precise(tgt, RATE, capacity=CAP) is False

    time.sleep(1.2)   # +0.72 -> ~1.32 total, enough IF the 0.6 carried
    assert rt.check_rate_token_precise(tgt, RATE, capacity=CAP) is True, (
        "two sub-token refills did not add up -- fractional accrual is "
        "being discarded, so any rate below 1/s admits nothing at all"
    )


# -- the clock must come from the server ------------------------------

def test_skewed_replica_clocks_cannot_mint_tokens(rt, monkeypatch):
    """A caller-supplied clock let skew refill the bucket.

    The script originally took `now` from the caller and wrote it back
    unconditionally, so two gateway replicas with different clocks
    pushed the stored timestamp back and forth and every backwards step
    read as elapsed time to the next caller. Measured with 50ms of
    skew -- ordinary NTP spread between pods -- 21 calls were admitted
    where 10 is correct.

    Every call below is issued at ONE instant, so an honest limiter
    admits `capacity` and then denies no matter whose clock is used.
    """
    import time as _time

    real = _time.time
    frozen = real()
    tgt = _target()
    CAP, RATE, N, SKEW = 10.0, 10.0, 50, 0.05

    admitted = 0
    try:
        for i in range(N):
            offset = 0.0 if i % 2 == 0 else -SKEW
            monkeypatch.setattr(
                rt.time, "time", lambda o=offset: frozen + o)
            if rt.check_rate_token_precise(tgt, RATE, capacity=CAP):
                admitted += 1
    finally:
        monkeypatch.setattr(rt.time, "time", real)

    assert admitted <= CAP, (
        f"{admitted} calls admitted against a capacity of {CAP:.0f} at a "
        f"single instant with {SKEW*1000:.0f}ms of clock skew -- the "
        "bucket is refilling from skew rather than elapsed time, so "
        "every throttled principal gets a higher rate than configured "
        "simply by being served from replicas with unsynced clocks"
    )


def test_a_backwards_clock_step_never_refills(rt, monkeypatch):
    """An NTP step backwards must not hand out tokens either."""
    import time as _time

    real = _time.time
    frozen = real()
    tgt = _target()
    try:
        monkeypatch.setattr(rt.time, "time", lambda: frozen)
        _admitted(rt, 1.0, 5, target=tgt, capacity=1.0)   # drain
        monkeypatch.setattr(rt.time, "time", lambda: frozen - 3600)
        after = _admitted(rt, 1.0, 5, target=tgt, capacity=1.0)
    finally:
        monkeypatch.setattr(rt.time, "time", real)
    assert after == 0, (
        f"{after} admitted after the clock stepped backwards an hour; "
        "no real time has passed, so no tokens should have accrued"
    )
