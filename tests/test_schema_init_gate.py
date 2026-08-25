"""``KYA_SKIP_SCHEMA_INIT`` must gate every runtime DDL entry point.

``ensure_invocations_table`` issues ``ALTER TABLE kya_invocations ADD
COLUMN`` for two columns. ``kya_invocations`` is the hottest table in
the schema, and an ``ALTER TABLE`` waiting for ``ACCESS EXCLUSIVE``
blocks every subsequent read on that table behind it — so on a shared
database, one queued migration can stall a process indefinitely.

Self-healing DDL stays the default; it is right for a single instance
managing its own database. It is now switchable.

The parametrized cases enumerate the gated entry points from a single
list, so a NEW ``ensure_*`` added without a gate is caught by
``test_no_ungated_ddl_entry_points_exist`` rather than discovered in
production.
"""
from __future__ import annotations

import importlib
import os

import pytest

from kya._schema_gate import (
    SKIP_SCHEMA_INIT_ENV,
    schema_init_enabled,
    skip_schema_init,
)

pytest.importorskip("sqlalchemy")

#: Every runtime DDL entry point. (module, function, arg_kind).
#: arg_kind distinguishes the ones taking a Session from the one taking
#: an Engine — both must be gated before they touch it.
ENTRY_POINTS = [
    ("agent_aliases", "ensure_table", "db"),
    ("compliance_shim", "ensure_table", "db"),
    ("delegation_overrides", "ensure_delegation_overrides_table", "db"),
    ("delegation_policy", "ensure_delegation_violations_table", "db"),
    ("feedback", "ensure_suggestions_table", "db"),
    ("inbound", "ensure_inbound_table", "db"),
    ("invocations", "ensure_invocations_table", "db"),
    ("pending_invocations", "ensure_table", "engine"),
    ("principal_edges", "ensure_principal_edges_table", "db"),
    ("principals", "ensure_principal_table", "db"),
    ("rbac", "ensure_rbac_table", "db"),
    ("tenant_budget", "ensure_tables", "db"),
    ("tenant_weights", "ensure_tables", "db"),
    ("users", "ensure_user_trust_table", "db"),
    ("versioning", "ensure_table", "db"),
]

DDL_VERBS = ("CREATE TABLE", "ALTER TABLE", "CREATE INDEX", "DROP ")


class ExplodingBind:
    """Any attribute access is a failed assertion.

    A gate placed BELOW the first ``db.connection()`` / ``get_bind()``
    has already cost a database round-trip, which on a hot path is the
    cost this gate exists to avoid. Passing this proves the check comes
    first.
    """

    def __getattr__(self, name: str):
        raise AssertionError(
            f"gated call touched the database (accessed .{name}) — the "
            f"{SKIP_SCHEMA_INIT_ENV} check must come BEFORE any bind, "
            "connection, or inspect() call"
        )


def _fn(module: str, func: str):
    return getattr(importlib.import_module(f"kya.{module}"), func)


# ── the gate itself ──────────────────────────────────────────────────

def test_default_is_enabled_so_upgrades_change_nothing(monkeypatch) -> None:
    """The compatibility guarantee.

    An existing install that upgrades and sets nothing must keep
    self-healing. If this default ever flips, such installs silently
    stop maintaining their schema and fail on the first write against
    a missing column.
    """
    monkeypatch.delenv(SKIP_SCHEMA_INIT_ENV, raising=False)
    assert schema_init_enabled() is True
    assert skip_schema_init() is False


@pytest.mark.parametrize(
    "value,enabled",
    [("1", False), ("0", True), ("", True), ("true", True), ("yes", True)],
)
def test_only_exactly_1_disables_ddl(monkeypatch, value, enabled) -> None:
    """Strict ``== "1"``, and the loose direction fails SAFE.

    A typo like ``KYA_SKIP_SCHEMA_INIT=true`` leaves DDL ENABLED. The
    alternative — a deployment that silently stops maintaining schema
    because of a typo — is the worse failure.
    """
    monkeypatch.setenv(SKIP_SCHEMA_INIT_ENV, value)
    assert schema_init_enabled() is enabled


def test_gate_is_read_at_call_time_not_import_time(monkeypatch) -> None:
    """A module-level constant would freeze whatever the first import saw."""
    monkeypatch.setenv(SKIP_SCHEMA_INIT_ENV, "1")
    assert schema_init_enabled() is False
    monkeypatch.setenv(SKIP_SCHEMA_INIT_ENV, "0")
    assert schema_init_enabled() is True


# ── every entry point, both directions ───────────────────────────────

@pytest.mark.parametrize(
    "module,func,argkind", ENTRY_POINTS,
    ids=[f"{m}.{f}" for m, f, _ in ENTRY_POINTS],
)
def test_entry_point_costs_zero_roundtrips_when_gated(
    monkeypatch, module, func, argkind
) -> None:
    monkeypatch.setenv(SKIP_SCHEMA_INIT_ENV, "1")
    _fn(module, func)(ExplodingBind())  # must not raise


@pytest.mark.parametrize(
    "module,func,argkind", ENTRY_POINTS,
    ids=[f"{m}.{f}" for m, f, _ in ENTRY_POINTS],
)
def test_entry_point_DOES_touch_db_when_ungated(
    monkeypatch, module, func, argkind
) -> None:
    """Control — proves ExplodingBind can actually detect the access.

    Without this, the tests above would pass just as happily against a
    function whose body had been deleted entirely.
    """
    monkeypatch.setenv(SKIP_SCHEMA_INIT_ENV, "0")
    with pytest.raises(AssertionError, match="gated call touched the database"):
        _fn(module, func)(ExplodingBind())


# ── the anti-regression guard: no ungated entry point may exist ──────

def test_no_ungated_ddl_entry_points_exist() -> None:
    """The load-bearing case.

    Ungated DDL has shipped before because nothing made "is this
    gated?" a checkable question. This walks the package for
    ``ensure_*`` /
    ``_reconcile_*`` / ``_migrate_*`` functions that emit DDL and
    asserts each is either gated itself or listed as reached through a
    gated caller.

    A new ungated entry point fails HERE, at authoring time, rather
    than surfacing as a stalled cluster.
    """
    import ast
    import pathlib

    pkg = pathlib.Path(__file__).resolve().parents[1] / "kya"
    gated = {f"{m}.{f}" for m, f, _ in ENTRY_POINTS}

    # Reached only via a gated caller above; gating them again would be
    # redundant. Each must be called from a gated entry point only.
    REACHED_VIA_GATED_CALLER = {
        "invocations._migrate_agent_key_width",
        "invocations._reconcile_evidence_row_count_column",
        "invocations._reconcile_evidence_row_count_signature_column",
    }

    offenders = []
    for path in sorted(pkg.glob("*.py")):
        if path.name.startswith("_test") or path.name == "_schema_gate.py":
            continue
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for fn in tree.body:
            if not isinstance(fn, ast.FunctionDef):
                continue
            if not fn.name.startswith(("ensure_", "_reconcile_", "_migrate_")):
                continue
            body_src = ast.get_source_segment(src, fn) or ""
            if not any(v in body_src.upper() for v in DDL_VERBS):
                if "create_all" not in body_src:
                    continue
            qual = f"{path.stem}.{fn.name}"
            if qual in gated or qual in REACHED_VIA_GATED_CALLER:
                continue
            if "schema_init_enabled()" in body_src:
                continue
            offenders.append(qual)

    assert not offenders, (
        "ungated DDL entry point(s) found — each will issue CREATE/ALTER "
        "at runtime with no way to switch it off:\n  "
        + "\n  ".join(sorted(offenders))
        + "\n\nAdd `if not schema_init_enabled(): return` at the TOP of "
        "each, and register it in ENTRY_POINTS in this file."
    )


def test_entry_point_list_is_complete() -> None:
    """Guard the guard: every listed entry point must actually exist.

    A renamed function would otherwise silently drop out of every
    parametrized case above while the suite stayed green.
    """
    for module, func, _ in ENTRY_POINTS:
        fn = _fn(module, func)
        assert callable(fn), f"kya.{module}.{func} is not callable"
