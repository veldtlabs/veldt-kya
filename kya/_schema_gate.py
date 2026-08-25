"""Whether the SDK may mutate database schema at runtime.

Every ``ensure_*`` function in this package is self-healing: it issues
``CREATE TABLE IF NOT EXISTS`` and, in places, ``ALTER TABLE ADD
COLUMN`` against live tables. That is the right default for a single
instance managing its own database — a missing column otherwise means
an error on the first write.

It is the wrong default when several processes share one database and
boot together. They race the same ``ALTER TABLE`` for an
``ACCESS EXCLUSIVE`` lock on a hot table, and while that ALTER waits,
every subsequent read on the table queues behind it.

So the DDL stays — it is correct for most installs — but it becomes
switchable.

Set ``KYA_SKIP_SCHEMA_INIT=1`` to disable all runtime DDL in this
package. Any other value, or unset, leaves the current self-healing
behaviour unchanged.

With it set, schema becomes the deployer's responsibility: apply your
migrations before the process starts, or the first write fails on a
missing table or column.
"""
from __future__ import annotations

import os

#: Set to "1" to disable all runtime DDL in this package.
SKIP_SCHEMA_INIT_ENV = "KYA_SKIP_SCHEMA_INIT"


def schema_init_enabled() -> bool:
    """True when ``ensure_*`` functions may issue DDL.

    Read at call time rather than cached at import, so a value changed
    between calls is honoured.

    Strict ``== "1"``. A truthy-looking typo such as ``true`` leaves
    DDL ENABLED, which is the safe direction to fail — the alternative
    is an install that silently stops maintaining its own schema.
    """
    return os.environ.get(SKIP_SCHEMA_INIT_ENV, "0") != "1"


def skip_schema_init() -> bool:
    """Inverse of :func:`schema_init_enabled`, for guard clauses."""
    return not schema_init_enabled()


__all__ = ["SKIP_SCHEMA_INIT_ENV", "schema_init_enabled", "skip_schema_init"]
