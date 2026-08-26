"""``KYA_SKIP_SCHEMA_INIT`` must gate every runtime DDL entry point.

``ensure_invocations_table`` issues ``ALTER TABLE kya_invocations ADD
COLUMN`` for two columns, and ``init_evidence_table`` runs
``create_all`` plus an ``ALTER TABLE kya_evidence`` on every evidence
write. Those are the two hottest tables in the schema, and an
``ALTER TABLE`` waiting for ACCESS EXCLUSIVE blocks every subsequent
read on that table behind it — so on a shared database, one queued
migration can stall a process indefinitely.

Self-healing DDL stays the default; it is right for a single instance
managing its own database. It is now switchable.

``test_no_ungated_ddl_entry_points_exist`` is the load-bearing case: it
detects DDL by EMISSION rather than by function name, so a new emitter
cannot slip through by being called something unexpected.
"""
from __future__ import annotations

import importlib

import pytest

from kya._schema_gate import (
    SKIP_SCHEMA_INIT_ENV,
    schema_init_enabled,
    skip_schema_init,
)

pytest.importorskip("sqlalchemy")

#: Public entry points, gated individually. Each takes a Session or an
#: Engine and must check the gate before touching it.
ENTRY_POINTS = [
    ("agent_aliases", "ensure_table"),
    ("compliance_shim", "ensure_table"),
    ("delegation_overrides", "ensure_delegation_overrides_table"),
    ("delegation_policy", "ensure_delegation_violations_table"),
    ("evidence", "init_evidence_table"),
    ("feedback", "ensure_suggestions_table"),
    ("inbound", "ensure_inbound_table"),
    ("invocations", "ensure_invocations_table"),
    ("pending_invocations", "ensure_table"),
    ("principal_edges", "ensure_principal_edges_table"),
    ("principals", "ensure_principal_table"),
    ("rbac", "ensure_rbac_table"),
    ("tenant_budget", "ensure_tables"),
    ("tenant_weights", "ensure_tables"),
    ("users", "ensure_user_trust_table"),
    ("versioning", "ensure_table"),
]

DDL_VERBS = (
    "CREATE TABLE", "ALTER TABLE", "CREATE INDEX", "CREATE SCHEMA",
    "DROP TABLE", "DROP INDEX",
)

#: The shared executors. The dominant pattern here keeps the SQL in a
#: module-level constant and runs it through one of these, so searching
#: a function body for DDL text alone misses most real DDL.
DDL_EXECUTORS = ("create_all", "create_legacy_tables", "apply_migrations")

#: Every package shipped in the wheel. A subpackage, or a sibling
#: distribution installed by the same ``pip install``, is not exempt.
WHEEL_PACKAGES = ("kya", "kya_redteam")

#: DDL emitters reached ONLY through an already-gated caller. Gating
#: them again would be redundant; listing them makes the reasoning
#: explicit and forces a decision when a new one appears.
REACHED_VIA_GATED_CALLER = {
    # via kya/evidence.py::init_evidence_table
    "kya/evidence.py::_ensure_evaluator_name_column",
    # via kya/invocations.py::ensure_invocations_table
    "kya/invocations.py::_migrate_agent_key_width",
    "kya/invocations.py::_reconcile_evidence_row_count_column",
    "kya/invocations.py::_reconcile_evidence_row_count_signature_column",
    # via kya/pending_invocations.py::ensure_table
    "kya/pending_invocations.py::_create_index_if_missing",
    "kya/pending_invocations.py::_add_tool_arguments_column_if_missing",
    # via kya/principals.py::ensure_principal_table
    "kya/principals.py::_apply_idp_binding_migrations",
}


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


# -- the gate itself -------------------------------------------------

def test_default_is_enabled_so_upgrades_change_nothing(monkeypatch) -> None:
    """The compatibility guarantee.

    An existing install that upgrades and sets nothing must keep
    self-healing. If this default ever flips, such installs silently
    stop maintaining their schema and fail on the first write against a
    missing column.
    """
    monkeypatch.delenv(SKIP_SCHEMA_INIT_ENV, raising=False)
    assert schema_init_enabled() is True
    assert skip_schema_init() is False


@pytest.mark.parametrize(
    "value,enabled",
    [
        ("1", False), ("0", True), ("", True), ("true", True),
        ("yes", True), (" 1 ", True), ("1 ", True), ("01", True),
    ],
)
def test_only_exactly_1_disables_ddl(monkeypatch, value, enabled) -> None:
    """Strict ``== "1"``, and the loose direction fails SAFE.

    A typo like ``KYA_SKIP_SCHEMA_INIT=true`` leaves DDL ENABLED. The
    alternative — an install that silently stops maintaining its schema
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


# -- every entry point, both directions ------------------------------

@pytest.mark.parametrize(
    "module,func", ENTRY_POINTS, ids=[f"{m}.{f}" for m, f in ENTRY_POINTS],
)
def test_entry_point_costs_zero_roundtrips_when_gated(
    monkeypatch, module, func
) -> None:
    monkeypatch.setenv(SKIP_SCHEMA_INIT_ENV, "1")
    _fn(module, func)(ExplodingBind())  # must not raise


@pytest.mark.parametrize(
    "module,func", ENTRY_POINTS, ids=[f"{m}.{f}" for m, f in ENTRY_POINTS],
)
def test_entry_point_DOES_touch_db_when_ungated(
    monkeypatch, module, func
) -> None:
    """Control — proves ExplodingBind can actually detect the access.

    Without this, the tests above would pass just as happily against a
    function whose body had been deleted entirely.
    """
    monkeypatch.setenv(SKIP_SCHEMA_INIT_ENV, "0")
    with pytest.raises(AssertionError, match="gated call touched the database"):
        _fn(module, func)(ExplodingBind())


# -- the anti-regression guard ---------------------------------------

def test_no_ungated_ddl_entry_points_exist() -> None:
    """Every DDL emitter is gated, or explicitly justified.

    Detection is by EMISSION, not by name. An earlier version matched
    ``ensure_*``/``_reconcile_*``/``_migrate_*`` prefixes and therefore
    could not see ``init_evidence_table`` — which runs ``create_all`` on
    every evidence write plus an ``ALTER TABLE kya_evidence``. A guard
    that shares the blind spot of the inventory it checks reports
    nothing and stays green.

    So this looks at what a function DOES:
      * DDL verbs in executable source (comments stripped first, or
        prose about DDL would count), and
      * calls to the shared executors, since the dominant pattern here
        puts the SQL in a module-level constant.

    ``rglob`` across every wheel package — subpackages and sibling
    distributions included. ``ast.walk`` rather than ``tree.body``, so
    ``async def``, nested functions and methods are covered too.
    """
    import ast
    import pathlib

    repo = pathlib.Path(__file__).resolve().parents[1]
    offenders = []

    for pkg_name in WHEEL_PACKAGES:
        pkg = repo / pkg_name
        if not pkg.is_dir():
            continue
        for path in sorted(pkg.rglob("*.py")):
            if "test" in path.name or path.name == "_schema_gate.py":
                continue
            src = path.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(src)
            except SyntaxError:  # pragma: no cover
                continue
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                qual = f"{path.relative_to(repo).as_posix()}::{fn.name}"
                seg = ast.get_source_segment(src, fn)
                if seg is None:
                    # Fail CLOSED — an unreadable segment must never be
                    # silently treated as DDL-free.
                    offenders.append(f"{qual} (source unreadable)")
                    continue
                executable = "\n".join(
                    line.split("#")[0] for line in seg.splitlines()
                )
                emits = (
                    any(v in executable.upper() for v in DDL_VERBS)
                    or any(f"{e}(" in executable for e in DDL_EXECUTORS)
                )
                if not emits or "schema_init_enabled()" in seg:
                    continue
                if qual not in REACHED_VIA_GATED_CALLER:
                    offenders.append(qual)

    assert not offenders, (
        "ungated DDL emitter(s) — each will issue CREATE/ALTER at runtime "
        "with no way to switch it off:\n  "
        + "\n  ".join(sorted(offenders))
        + "\n\nAdd `if not schema_init_enabled(): return` at the TOP of the "
        "function (before any connection is taken), or — if it is genuinely "
        "only reachable through an already-gated caller — add it to "
        "REACHED_VIA_GATED_CALLER with the caller named."
    )


def test_allowlist_has_no_stale_entries() -> None:
    """A justified-by-caller entry that no longer exists hides a gap.

    If the function is renamed or deleted, the allowlist silently keeps
    excusing a name that is gone while the real emitter goes unchecked.
    """
    import pathlib

    repo = pathlib.Path(__file__).resolve().parents[1]
    for qual in sorted(REACHED_VIA_GATED_CALLER):
        relpath, funcname = qual.split("::")
        src = (repo / relpath).read_text(encoding="utf-8", errors="replace")
        assert f"def {funcname}(" in src, (
            f"{qual} is in REACHED_VIA_GATED_CALLER but no longer exists — "
            "remove it, or the allowlist is excusing a name that is gone"
        )


def test_entry_point_list_is_complete() -> None:
    """Guard the guard: every listed entry point must actually exist.

    A renamed function would otherwise silently drop out of every
    parametrized case above while the suite stayed green.
    """
    for module, func in ENTRY_POINTS:
        assert callable(_fn(module, func)), f"kya.{module}.{func} not callable"
