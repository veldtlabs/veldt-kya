"""
Shared migration helper for KYA tables.

KYA uses CREATE TABLE IF NOT EXISTS for fresh installs. When schema
evolves later (new column, new index), we need additive ALTER statements
that are safe to re-run forever. This helper centralizes that pattern so
every table follows the same idempotent shape.

Usage in any ensure_*_table helper:

    from ._migrations import apply_migrations

    _MIGRATIONS = [
        "ALTER TABLE prov_schema.my_table "
        "  ADD COLUMN IF NOT EXISTS new_col TEXT;",
        "CREATE INDEX IF NOT EXISTS idx_my_table_new "
        "  ON prov_schema.my_table (new_col);",
    ]

    def ensure_my_table(db):
        db.execute(text(_TABLE_DDL))
        apply_migrations(db, "my_table", _MIGRATIONS)
        db.commit()

Every statement in `migrations` MUST be safely re-runnable (IF NOT
EXISTS / IF EXISTS guards or naturally idempotent). The helper logs and
swallows individual failures so one bad migration doesn't break the rest.
"""

import logging
from collections.abc import Iterable

try:
    from sqlalchemy import text as _sa_text
except ImportError:

    def _sa_text(s):
        raise RuntimeError("kya._migrations requires SQLAlchemy")


text = _sa_text

logger = logging.getLogger(__name__)


def apply_migrations(db, table_name: str, migrations: Iterable[str]) -> None:
    """Run additive migrations idempotently. Each statement should be
    safe to execute multiple times (use IF NOT EXISTS / IF EXISTS guards).
    Individual failures are logged at debug and don't stop the rest."""
    for sql in migrations:
        try:
            db.execute(text(sql))
        except Exception as exc:
            logger.debug("[KYA-MIG] %s migration skipped: %s", table_name, exc)
