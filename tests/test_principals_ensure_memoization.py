"""``ensure_principal_table`` memoization — keyed on engine identity.

``ensure_principal_table`` is reached from six call sites, two of them
on the ingest WRITE path (``record_principal_signal``,
``record_principal_clean``), so it previously ran ``create_all`` plus
the additive IdP migrations on every request. Measured at ~4ms, but
the real cost is lock contention: the DDL takes table locks and a
concurrent session sitting ``idle in transaction`` makes it wait with
no ``lock_timeout``. That showed up as two Pro ``[postgres]`` wave
tests stalling indefinitely while passing in isolation.

The memoization must be keyed on ENGINE IDENTITY, never on the URL
string. Two sibling caches in this package already say so in a
comment — ``kya/agent_aliases.py`` and ``kya/pending_invocations.py``
— and also record that ``id()`` was tried and found unsound because
CPython recycles ids. ``weakref.WeakSet`` is the established pattern.

A URL key is wrong because every ``sqlite:///:memory:`` engine is a
distinct, empty database behind an identical URL — so the second
engine is marked "already ensured" and never gets its table. When
this was first written that way it turned 11 trust tests red.
"""
from __future__ import annotations

import pytest

sa = pytest.importorskip("sqlalchemy")
from sqlalchemy import create_engine, inspect  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

import kya.principals as P  # noqa: E402
from kya.principals import ensure_principal_table  # noqa: E402


def test_two_in_memory_engines_sharing_a_url_each_get_the_table():
    """The defect a URL key reintroduces. Both engines are separate
    empty databases behind the identical URL ``sqlite:///:memory:``."""
    seen = []
    for _ in range(3):
        engine = create_engine("sqlite:///:memory:")
        with Session(engine) as db:
            ensure_principal_table(db)
            db.commit()
            seen.append(
                inspect(engine).has_table("kya_principal_trust"),
            )
    assert seen == [True, True, True], (
        f"an engine was skipped as 'already ensured' and never got its "
        f"table: {seen}. The cache is keyed on something shared "
        f"between distinct databases — almost certainly str(url)."
    )


def test_ddl_runs_once_per_engine_not_once_per_call():
    """The latency/lock fix itself: repeat calls on the SAME engine
    must not re-run the additive migrations."""
    calls = {"n": 0}
    real = P._apply_idp_binding_migrations

    def _counting(db):
        calls["n"] += 1
        return real(db)

    P._apply_idp_binding_migrations = _counting
    try:
        engine = create_engine("sqlite:///:memory:")
        with Session(engine) as db:
            for _ in range(25):
                ensure_principal_table(db)
            db.commit()
    finally:
        P._apply_idp_binding_migrations = real

    assert calls["n"] == 1, (
        f"the additive migrations ran {calls['n']} times for one "
        f"engine — the memoization is not active, so this DDL is back "
        f"on the request path where it blocks on table locks"
    )


def test_distinct_engines_each_run_the_ddl_once():
    """Per-engine granularity: three engines, three DDL runs, not one
    (which would skip two databases) and not twenty-five."""
    calls = {"n": 0}
    real = P._apply_idp_binding_migrations

    def _counting(db):
        calls["n"] += 1
        return real(db)

    P._apply_idp_binding_migrations = _counting
    try:
        held = []          # keep engines alive so the WeakSet retains them
        for _ in range(3):
            engine = create_engine("sqlite:///:memory:")
            held.append(engine)
            with Session(engine) as db:
                ensure_principal_table(db)
                ensure_principal_table(db)
                db.commit()
    finally:
        P._apply_idp_binding_migrations = real

    assert calls["n"] == 3, (
        f"expected one DDL run per distinct engine (3), got "
        f"{calls['n']}"
    )


def test_gate_is_checked_before_the_cache():
    """``schema_init_enabled()`` must still win. If the cache were
    consulted first, a saas deployment could populate it and the gate
    would stop being the authority on whether DDL may run."""
    import kya.principals as mod

    calls = {"n": 0}
    real = mod._apply_idp_binding_migrations

    def _counting(db):
        calls["n"] += 1
        return real(db)

    gate_real = mod.schema_init_enabled
    mod.schema_init_enabled = lambda: False
    mod._apply_idp_binding_migrations = _counting
    try:
        engine = create_engine("sqlite:///:memory:")
        with Session(engine) as db:
            ensure_principal_table(db)
        assert calls["n"] == 0, "DDL ran with the schema gate OFF"
        assert not inspect(engine).has_table("kya_principal_trust")
    finally:
        mod.schema_init_enabled = gate_real
        mod._apply_idp_binding_migrations = real
