"""Inspect every supported backend and report which KYA tables exist.

Highlights the 3 NEW budget tables (kya_tenant_cost_budgets,
kya_budget_changes, kya_cost_events) and confirms each table also
came up on every backend.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Reuse the same .env loader the e2e script uses so the keys flow
def _load_dotenv_if_present() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip().strip('"').strip("'")


_load_dotenv_if_present()

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from kya.storage import init_storage


# Expected tables. Three groups:
#   1. CORE_ORM         — 4 cross-backend ORM tables (always portable)
#   2. LEGACY_NON_BUDGET — 12 legacy tables (now also cross-backend)
#   3. BUDGET_NEW       — 3 NEW tables we added in v0.1.1
CORE_ORM = [
    "agent_versions",
    "kya_invocations",
    "kya_principal_trust",
    "kya_evidence",
]

LEGACY_NON_BUDGET = [
    "kya_agent_aliases",
    "kya_user_trust",
    "kya_weight_overrides",
    "kya_weight_changes",
    "kya_weight_suggestions",
    "kya_breach_notifications",
    "kya_redteam_campaigns",
    "kya_redteam_findings",
    "kya_redteam_tenant_policy",
    "kya_redteam_runs",
    "kya_redteam_targets",
    "kya_redteam_target_secrets",
    "kya_inbound_recommendations",
]

BUDGET_NEW = [
    "kya_tenant_cost_budgets",
    "kya_budget_changes",
    "kya_cost_events",
]


def _backends():
    out = [("sqlite", "sqlite:///:memory:")]
    try:
        import duckdb_engine  # noqa: F401
        out.append(("duckdb", "duckdb:///:memory:"))
    except ImportError:
        pass
    if "KYA_TEST_PG_URL" in os.environ:
        out.append(("postgresql", os.environ["KYA_TEST_PG_URL"]))
    if "KYA_TEST_MYSQL_URL" in os.environ:
        out.append(("mysql", os.environ["KYA_TEST_MYSQL_URL"]))
    return out


def _setup_backend(label: str, url: str):
    """Return a (session, dispose) pair. PG and MySQL get cleaned
    state; SQLite/DuckDB are in-memory and always fresh."""
    if label == "postgresql":
        eng = create_engine(url)
        with eng.begin() as conn:
            conn.execute(text("CREATE SCHEMA IF NOT EXISTS prov_schema"))
            for t in CORE_ORM + LEGACY_NON_BUDGET + BUDGET_NEW:
                conn.execute(text(f"DROP TABLE IF EXISTS prov_schema.{t}"))
    elif label == "mysql":
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
        with eng.begin() as conn:
            for t in CORE_ORM + LEGACY_NON_BUDGET + BUDGET_NEW:
                try:
                    conn.execute(text(f"DROP TABLE IF EXISTS {t}"))
                except Exception:
                    pass
    else:
        eng = create_engine(url).execution_options(
            schema_translate_map={"prov_schema": None})
    Session = sessionmaker(bind=eng)
    return Session(), eng.dispose


def _existing_tables(db, dialect: str) -> set[str]:
    """Return every KYA-prefixed table visible on the bound dialect."""
    insp = inspect(db.connection())
    schema = "prov_schema" if dialect == "postgresql" else None
    names = set(insp.get_table_names(schema=schema))
    # Anything starting with kya_, or agent_versions
    return {n for n in names if n.startswith("kya_") or n == "agent_versions"}


def _row(label: str, value) -> None:
    print(f"    {label:34s} {value}")


def main() -> int:
    backends = _backends()
    print(f"Inspecting {len(backends)} backend(s): "
          f"{', '.join(b[0] for b in backends)}\n")

    overall_ok = True
    per_backend: dict[str, dict] = {}

    for label, url in backends:
        print("=" * 78)
        print(f"  Backend: {label.upper()}")
        print("=" * 78)
        db, dispose = _setup_backend(label, url)
        try:
            init_storage(db)
            existing = _existing_tables(db, label)

            core_present = [t for t in CORE_ORM if t in existing]
            legacy_present = [t for t in LEGACY_NON_BUDGET if t in existing]
            budget_present = [t for t in BUDGET_NEW if t in existing]
            missing_budget = [t for t in BUDGET_NEW if t not in existing]

            ok_budget = (len(budget_present) == 3)

            _row("Core ORM tables (4 expected)",
                 f"{len(core_present)}/{len(CORE_ORM)} present")
            _row("Legacy tables (13 expected)",
                 f"{len(legacy_present)}/{len(LEGACY_NON_BUDGET)} present")
            _row("Budget tables (3 expected)",
                 f"{len(budget_present)}/{len(BUDGET_NEW)} present "
                 f"{'✓' if ok_budget else '✗ MISSING: ' + ','.join(missing_budget)}")
            _row("Total KYA tables", f"{len(existing)} on this backend")

            if budget_present:
                print()
                print("    BUDGET-SPECIFIC tables:")
                for t in budget_present:
                    insp = inspect(db.connection())
                    schema = "prov_schema" if label == "postgresql" else None
                    cols = insp.get_columns(t, schema=schema)
                    _row(f"      • {t}", f"{len(cols)} columns")

            per_backend[label] = {
                "core": len(core_present),
                "legacy": len(legacy_present),
                "budget": len(budget_present),
                "total": len(existing),
                "missing_budget": missing_budget,
            }
            if not ok_budget:
                overall_ok = False
        except Exception as exc:
            print(f"    [ERROR] {exc}")
            overall_ok = False
            per_backend[label] = {"error": str(exc)}
        finally:
            try:
                db.close()
            except Exception:
                pass
            dispose()
        print()

    # Final summary
    print("=" * 78)
    print("  CROSS-BACKEND SUMMARY")
    print("=" * 78)
    print(f"    {'backend':12s} {'core':>5s} {'legacy':>7s} {'budget':>7s} {'total':>6s}  status")
    for label, stats in per_backend.items():
        if "error" in stats:
            print(f"    {label:12s} ERROR — {stats['error'][:60]}")
            continue
        status = "OK" if stats["budget"] == 3 else f"MISSING: {','.join(stats['missing_budget'])}"
        print(f"    {label:12s} {stats['core']:>5d} {stats['legacy']:>7d} "
              f"{stats['budget']:>7d} {stats['total']:>6d}  {status}")

    print()
    print(f"Overall: {'PASS — all 3 budget tables present on every backend' if overall_ok else 'FAIL'}")
    return 0 if overall_ok else 2


if __name__ == "__main__":
    sys.exit(main())
