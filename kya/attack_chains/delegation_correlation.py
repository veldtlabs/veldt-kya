"""Resolve a request-scoped correlation_id from an invocation.

Attack chains that span a delegation graph need every event in the
graph to map to the same correlate key. KYA's convention is that
callers propagate ``correlation_id`` from parent to child invocation,
so the natural correlate key for cross-agent rules is
``[tenant_id, correlation_id]``.

This helper exists for callers that didn't follow the convention --
e.g., a sub-agent that generated a fresh correlation_id of its own.
By walking ``parent_invocation_id`` up to ``max_hops`` times, we find
the nearest ancestor with a non-null correlation_id and return that.
The engine never has to query the DB itself -- the caller does the
resolve once (typically inside record_evidence) and passes the result
into ``AttackChainEngine.process_evidence(correlation_id=...)``.

Pure SQL, dialect-portable via the existing
``kya._portable.qual_for_raw_sql`` helper. Fail-soft: any DB or
schema-translation error returns None, which the engine treats as
"no cross-agent correlation possible for this event" (the rule is
skipped, not silently misapplied).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Reasonable bound for any real delegation tree. 20 hops is huge in
# practice (a CrewAI / LangGraph fan-out is typically 2-5 deep). Capped
# to avoid pathological loops and runaway cost when invocation data is
# bad.
DEFAULT_MAX_HOPS = 20


def correlation_id_for_invocation(
    db,
    tenant_id: str,
    invocation_id: int,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> str | None:
    """Walk up ``parent_invocation_id`` and return the first non-null
    ``correlation_id`` found.

    Returns:
        - The invocation's own ``correlation_id`` when it has one
          (the common, correct case).
        - The nearest ancestor's ``correlation_id`` when this row's
          column is null but a parent set one (recovers from sub-agents
          that forgot to propagate).
        - ``None`` on DB error, when no ancestor has a correlation_id,
          when the walk hits a null parent before a hit, or when
          ``max_hops`` is exhausted.

    Args:
        db: SQLAlchemy Session.
        tenant_id: tenant scope. The walk never crosses tenant
            boundaries, even if some upstream row has the wrong parent
            pointer.
        invocation_id: starting invocation row id.
        max_hops: safety cap on chain depth.
    """
    # ── Input validation (fail-soft, return None on bad input) ──
    # Caller may have a row with NULL invocation_id, a non-numeric
    # value, or an empty tenant -- none of those are an exception
    # condition for us; we just have nothing to resolve.
    if not tenant_id or invocation_id is None:
        return None
    try:
        current_id: int | None = int(invocation_id)
    except (TypeError, ValueError):
        logger.debug(
            "[KYA-CHAINS] correlation_id_for_invocation: invocation_id "
            "is not numeric (%r); returning None", invocation_id)
        return None
    if current_id <= 0:
        return None
    if not isinstance(max_hops, int) or max_hops <= 0:
        return None

    # ── Imports (lazy + fail-soft if optional deps missing) ──
    try:
        from sqlalchemy import text

        from kya._portable import qual_for_raw_sql
    except Exception as exc:
        # SQLAlchemy missing -- the engine is fail-soft, so are we.
        logger.debug(
            "[KYA-CHAINS] correlation_id_for_invocation: "
            "SQLAlchemy import failed: %s", exc)
        return None

    try:
        qual = qual_for_raw_sql(db)
    except Exception as exc:
        logger.debug(
            "[KYA-CHAINS] correlation_id_for_invocation: "
            "schema qualifier resolution failed: %s", exc)
        return None

    stmt = text(
        f"SELECT correlation_id, parent_invocation_id "
        f"FROM {qual}kya_invocations "
        f"WHERE tenant_id = :t AND id = :i LIMIT 1"
    )

    for _hop in range(max_hops):
        if current_id is None:
            return None
        try:
            row = db.execute(
                stmt, {"t": str(tenant_id), "i": current_id},
            ).fetchone()
        except Exception as exc:
            logger.debug(
                "[KYA-CHAINS] correlation_id_for_invocation: "
                "DB lookup failed at id=%s: %s", current_id, exc)
            return None
        if row is None:
            return None
        corr = row[0]
        if corr:
            return str(corr)
        parent = row[1]
        if parent is None:
            return None
        current_id = int(parent)
    logger.debug(
        "[KYA-CHAINS] correlation_id_for_invocation: max_hops=%d "
        "exhausted from id=%s without finding a correlation_id",
        max_hops, invocation_id)
    return None
