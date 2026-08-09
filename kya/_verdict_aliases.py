"""Single source of truth for legacy verdict aliases + their sunset.

The ``require_human`` verdict was renamed to ``flag_for_review`` (the
canonical Layer-2 vocabulary). Rather than break existing configs, SDK
clients, and downstream payloads, we accept the legacy alias at every
BOUNDARY (config parse, evaluator adapter, RBAC evaluate, wire-input
validators) and NORMALIZE it to the canonical form so no internal code
path ever sees the legacy string as a live verdict.

Why this module exists
----------------------
No hardcoded alias strings or sunset versions duplicated across files.
Both the gateway (``kya_gateway.policy_pipeline``) and the handler
registry (``kya.policy_verdicts``) reference the same alias mapping and
the same sunset release string from here.

This module ships ZERO behaviour beyond the constants. The alias handler
lives in ``kya.policy_verdicts.GatewayRequireHumanAliasHandler`` (which
delegates on the wire for SDK back-compat); the boundary-normalization
helper lives in ``kya_gateway.policy_pipeline._normalize_legacy_verdict``
(which converts to canonical + WARN-logs). Both read from here.

Import discipline
-----------------
This module MUST NOT import from any other ``kya.*`` submodule — it is
the foundation. Consumers reach it via
``from kya._verdict_aliases import ...``. Circular-import risk is zero
by construction.
"""
from __future__ import annotations

# Legacy alias mapping — normalize at every boundary.
# Key is the legacy wire string; value is the canonical form.
# Add new legacy aliases here (do not scatter dicts across files).
_LEGACY_VERDICT_ALIASES: dict[str, str] = {
    "require_human": "flag_for_review",
}


# Release at which ``_LEGACY_VERDICT_ALIASES`` entries are removed.
# Referenced in every deprecation WARN message so callers grepping for
# a specific sunset version find the single source of truth for when
# the alias goes away. Bumped in tandem with the release note.
_DEPRECATION_SUNSET: str = "0.6.0"


# The canonical verdict a human-approval workflow lands on after alias
# normalization. Referenced by the gateway server's 428-response body +
# the gateway's handler default so a single edit ripples everywhere
# (e.g. if the canonical vocabulary ever shifts to
# ``needs_human_approval`` we change ONE constant, not N sites).
_CANONICAL_HUMAN_APPROVAL_VERDICT: str = "flag_for_review"


__all__ = [
    "_LEGACY_VERDICT_ALIASES",
    "_DEPRECATION_SUNSET",
    "_CANONICAL_HUMAN_APPROVAL_VERDICT",
]
