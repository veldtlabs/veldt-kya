"""
Unified storage setup for KYA.

KYA's persistent state spans multiple tables — each owned by a module
(versioning, aliases, principals, invocations, etc.). Historically callers
had to remember which `ensure_*_table()` to call before using each feature.
`init_storage(db)` collapses that to one idempotent call.

Backend portability
-------------------
- ORM-modeled (portable across PostgreSQL, SQLite, DuckDB, MySQL):
    * `agent_versions`        (versioning.py)
    * `kya_invocations`       (invocations.py)
    * `kya_principal_trust`   (principals.py)
- Still PG-only (raw DDL):
    * `kya_agent_aliases`, `kya_compliance_attestations`,
      `kya_tenant_weights`, `kya_user_trust`, `kya_feedback_suggestions`
  These report `skipped` (with reason) on non-PG backends — not raised.
  Veldt production runs on PG so every table succeeds; SDK consumers
  evaluating on SQLite/DuckDB/MySQL get the three portable tables and
  the rest activates when they move to PG.

Return shape
------------
    {
        "dialect": "postgresql" | "sqlite" | "duckdb" | ...,
        "succeeded": ["agent_versions", ...],
        "skipped":   [{"table": "kya_agent_aliases", "reason": "..."}],
        "all_ok":    bool,
    }
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


# Order matters only loosely — every ensure is idempotent and has no
# cross-table FKs. Listed here in approximate value-tier order so partial
# success on non-PG backends still gives consumers the most-useful tables.
# Each tuple: (label, module-suffix, function-name).
# The module suffix is resolved to either `kya.<x>` or
# `kya_redteam.<x>` depending on prefix — keeps the plan flat.
_TABLE_SETUP_PLAN = [
    # ── Core ORM-modeled (4 SDK-portable tables) ──
    ("agent_versions", "kya.versioning", "ensure_table"),
    ("kya_invocations", "kya.invocations", "ensure_invocations_table"),
    ("kya_principal_trust", "kya.principals", "ensure_principal_table"),
    ("kya_evidence", "kya.evidence", "init_evidence_table"),
    # ── Legacy tables — now portable via _legacy_tables.py ──
    ("kya_agent_aliases", "kya.agent_aliases", "ensure_table"),
    ("kya_user_trust", "kya.users", "ensure_user_trust_table"),
    ("kya_breach_notifications", "kya.compliance_shim", "ensure_table"),
    ("kya_weight_overrides+changes", "kya.tenant_weights", "ensure_tables"),
    ("kya_weight_suggestions", "kya.feedback", "ensure_suggestions_table"),
    # ── Red-team campaign storage (3 modules, 6 tables) ──
    ("kya_redteam_campaigns+findings+policy", "kya_redteam.campaigns", "ensure_tables"),
    ("kya_redteam_runs", "kya_redteam.runs", "ensure_table"),
    ("kya_redteam_targets+secrets", "kya_redteam.targets", "ensure_tables"),
    # ── Inbound recommendations (cross-tenant feedback loop) ──
    ("kya_inbound_recommendations", "kya.inbound", "ensure_inbound_table"),
    # ── Economic governance: per-tenant cost budgets + cost-event ledger ──
    ("kya_tenant_cost_budgets+events", "kya.tenant_budget", "ensure_tables"),
    # ── Delegation-policy enforcement (sub-agent capability ceiling) ──
    ("kya_delegation_violations", "kya.delegation_policy",
     "ensure_delegation_violations_table"),
    # ── Per-scope delegation-policy mode overrides ──
    ("kya_delegation_policy_overrides", "kya.delegation_overrides",
     "ensure_delegation_overrides_table"),
    # ── Phase 5b RBAC — per-tenant principal→action grants ──
    ("kya_role_grants", "kya.rbac", "ensure_rbac_table"),
]


def init_storage(db) -> dict[str, Any]:
    """Idempotently create every KYA-owned table. Safe to call on startup.

    Returns a structured report of per-table outcomes so callers can
    surface partial-success states (e.g. SDK eval on SQLite where only
    the ORM-modeled tables come up cleanly).

    Verification is post-hoc — we inspect the schema after each ensure_*
    runs. Several KYA modules swallow their own DDL exceptions (logging +
    rollback) and return normally, so trusting the return value would be a
    lie. Asking the catalog is the only honest signal.
    """
    try:
        from sqlalchemy import inspect as sa_inspect
    except ImportError:
        sa_inspect = None

    try:
        bind = db.get_bind()
        dialect = bind.dialect.name
    except Exception:
        bind = None
        dialect = "unknown"

    # PG-only: when the operator configures a non-default schema
    # (KYA_PG_SCHEMA or legacy KYA_VERSIONS_SCHEMA), CREATE it if
    # missing so a standalone ``pip install veldt-kya`` against a
    # fresh PG works out of the box without the operator remembering
    # to run CREATE SCHEMA manually. No-op when schema resolves to
    # None (= default ``public`` schema, always present on PG).
    if dialect == "postgresql" and bind is not None:
        try:
            from ._portable import dialect_schema_qualifier
            _schema = dialect_schema_qualifier()
        except Exception:  # noqa: BLE001
            _schema = None
        if _schema:
            # Validate identifier shape -- env-controlled, but a
            # mistyped value could still craft a SQL injection if it
            # contained quoting characters. Reject anything that isn't
            # a PG-legal unquoted identifier (letters / digits /
            # underscores, not starting with a digit).
            import re as _re
            if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", _schema):
                import logging
                logging.getLogger(__name__).error(
                    "[KYA-STORAGE] KYA_VERSIONS_SCHEMA=%r is not a "
                    "valid SQL identifier (letters, digits, "
                    "underscores; no leading digit). Refusing to "
                    "issue CREATE SCHEMA.", _schema,
                )
                _schema = None
        if _schema:
            try:
                from sqlalchemy import text as _sa_text
                with bind.begin() as _conn:
                    _conn.execute(_sa_text(
                        f"CREATE SCHEMA IF NOT EXISTS {_schema}"))
            except Exception as _exc:  # noqa: BLE001
                # If CREATE fails (RBAC denies CREATE on the database,
                # name has SQL-illegal characters, ...) downstream
                # ensure_* calls will also fail and report via the
                # structured ``skipped`` list. Log loudly so operators
                # see it even if ensure_* swallows the resulting error.
                import logging
                logging.getLogger(__name__).warning(
                    "[KYA-STORAGE] CREATE SCHEMA %s failed: %s "
                    "-- subsequent table creation will likely fail "
                    "with 'schema does not exist'.", _schema, _exc,
                )

    def _table_exists(name: str) -> bool:
        """Check the live catalog via the session's own connection — fresh
        engine connections may not see uncommitted DDL (DuckDB enforces
        connection-isolated catalog visibility before commit)."""
        if sa_inspect is None:
            return False
        try:
            insp = sa_inspect(db.connection())
            return insp.has_table(name)
        except Exception:
            # Fallback to engine-level inspect (sufficient for SQLite/PG
            # where DDL is visible across connections immediately).
            if bind is None:
                return False
            try:
                return sa_inspect(bind).has_table(name)
            except Exception:
                return False

    succeeded: list[str] = []
    skipped: list[dict[str, str]] = []

    def _try_import(mod_suffix: str, fn_name: str):
        """Resolve `kya.X` and `kya_redteam.X` against agents.* / kya.* /
        kya_redteam.* import paths (whichever is importable in this env)."""
        for parent in ("agents", "", None):
            try:
                full = (
                    f"agents.{mod_suffix}" if parent == "agents"
                    else mod_suffix if parent == ""
                    else None
                )
                if full is None:
                    continue
                return __import__(full, fromlist=[fn_name])
            except ImportError:
                continue
        return None

    for table_name, module_name, fn_name in _TABLE_SETUP_PLAN:
        module = _try_import(module_name, fn_name)
        if module is None:
            skipped.append({"table": table_name, "reason": "module unavailable"})
            continue

        fn = getattr(module, fn_name, None)
        if fn is None:
            skipped.append({"table": table_name, "reason": f"{module_name}.{fn_name} missing"})
            continue

        ensure_exc: str | None = None
        try:
            fn(db)
        except Exception as exc:
            try:
                db.rollback()
            except Exception:
                pass
            ensure_exc = str(exc).split("\n", 1)[0][:200]

        # Post-hoc verification — the catalog is the source of truth.
        # For compound labels ("kya_redteam_campaigns+findings+policy"),
        # check the FIRST listed table; others share the same fate.
        probe_name = table_name.split("+", 1)[0]
        if _table_exists(probe_name):
            succeeded.append(table_name)
        else:
            reason = (
                ensure_exc
                or "ensure_* returned but table not in catalog (likely swallowed DDL error)"
            )
            skipped.append({"table": table_name, "reason": reason})
            logger.info("[KYA-INIT] %s skipped on %s: %s", table_name, dialect, reason)

    report = {
        "dialect": dialect,
        "succeeded": succeeded,
        "skipped": skipped,
        "all_ok": len(skipped) == 0,
    }
    logger.info(
        "[KYA-INIT] dialect=%s succeeded=%d skipped=%d",
        dialect,
        len(succeeded),
        len(skipped),
    )
    return report
