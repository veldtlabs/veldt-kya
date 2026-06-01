"""
Shared migration helper for KYA tables.

KYA uses CREATE TABLE IF NOT EXISTS for fresh installs. When schema
evolves later (new column, new index), we need additive ALTER statements
that are safe to re-run forever. This helper centralizes that pattern so
every table follows the same idempotent shape.

Usage in any ensure_*_table helper:

    from ._migrations import apply_migrations
    from ._portable import qual_for_raw_sql

    def ensure_my_table(db):
        db.execute(text(_TABLE_DDL))
        qual = qual_for_raw_sql(db)
        migrations = [
            f"ALTER TABLE {qual}my_table "
            f"  ADD COLUMN IF NOT EXISTS new_col TEXT;",
            f"CREATE INDEX IF NOT EXISTS idx_my_table_new "
            f"  ON {qual}my_table (new_col);",
        ]
        apply_migrations(db, "my_table", migrations)
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
