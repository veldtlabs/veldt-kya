"""
Definition integrity + lineage — cybersecurity primitives for KYA.

Integrity
---------
SHA256 hash of the canonical agent definition is computed at every
version-snapshot and on every dispatch read. A mismatch between the
two means somebody mutated the running agent without going through
KYA's versioning — which is either an attack or a process violation.

Hash is computed over a CANONICAL JSON serialization (sorted keys, no
whitespace) so semantically equivalent definitions produce the same
hash regardless of dict ordering.

Lineage
-------
Each agent can carry `parent_agent_key` (the agent it was forked from)
and `lineage` (list of ancestor keys, most-recent first). Risk inherits
from the parent with decay — a child of a critical agent starts with
heightened scrutiny that decays per generation.

Marketplace agents should carry a `signature` field with the publisher's
Ed25519 signature over the definition hash. KYA doesn't verify the
signature today (that requires a key registry); it surfaces the field
to operators who can verify externally.

Public API
----------
    canonical_hash(agent_def) -> str               # SHA256 hex
    detect_drift(declared_hash, definition) -> bool
    lineage_chain(agent_def) -> list[str]
    lineage_risk_inheritance(parent_score) -> int  # decayed bump for child
    verify_signature(agent_def, public_key=None) -> dict  # status report
"""

import hashlib
import json
import os

# Fields that are part of the "what this agent does" identity. Mutable
# operational fields (counters, timestamps) are excluded so the hash is
# stable across runs.
_HASHED_FIELDS = (
    "agent_key",
    "name",
    "description",
    "system_prompt",
    "model",
    "tools",
    "denied_tools",
    "human_loop",
    "access_level",
    "can_override",
    "can_revert",
    "can_delegate_to",
    "required_roles",
    "extends",
    "data_classes",
    "security_caps",
    "provenance",
    "model_trust",
    "compliance_scope",
)

# Ownership / accountability metadata. NOT in the identity hash by
# default -- changing the owner does not change what the agent does.
# Customers in strict-audit regimes can opt in by passing
# include_ownership=True to canonical_hash() or by setting the env
# var KYA_HASH_OWNER_FIELDS=true. In that mode, an ownership change
# triggers a new definition_hash + new fleet_fingerprint, which
# customers may want to treat as a new approval boundary.
_OWNERSHIP_FIELDS = (
    "owner",
    "on_call",
    "escalation",
    "review_status",
)


def _ownership_enabled(explicit: bool | None) -> bool:
    """Resolve the ``include_ownership`` flag: explicit kwarg wins;
    falls back to the ``KYA_HASH_OWNER_FIELDS`` env var; default False.
    """
    if explicit is not None:
        return bool(explicit)
    raw = os.environ.get("KYA_HASH_OWNER_FIELDS", "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def canonical_hash(
    agent_def: dict,
    *,
    include_ownership: bool | None = None,
) -> str:
    """SHA256 over a canonical JSON serialization of the identity fields.

    Two semantically-equal definitions hash identically. Mutating any
    identity field (or adding a new tool) changes the hash.

    By default the hash covers only "what this agent does" -- prompt,
    tools, data classes, governance mode, delegation permissions,
    model, etc. Ownership / accountability metadata (``owner``,
    ``on_call``, ``escalation``, ``review_status``) is NOT in the hash;
    a re-org that reassigns an owner does not, by default, count as
    "the agent changed."

    Customers in strict-audit regimes can opt in to ownership-as-identity
    by either:
        * ``canonical_hash(defn, include_ownership=True)``
        * setting the env var ``KYA_HASH_OWNER_FIELDS=true``
            (the explicit kwarg overrides the env var)

    In that mode, an ownership change treats the agent as a new
    approval boundary -- ``definition_hash`` changes, downstream
    ``fleet_fingerprint`` changes, drift detection fires.
    """
    fields = _HASHED_FIELDS
    if _ownership_enabled(include_ownership):
        fields = fields + _OWNERSHIP_FIELDS
    snapshot = {k: agent_def.get(k) for k in fields if k in agent_def}
    payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def detect_drift(
    declared_hash: str,
    agent_def: dict,
    *,
    include_ownership: bool | None = None,
) -> bool:
    """Return True if the declared hash doesn't match the current
    definition's canonical hash. Caller logs + alerts on True.

    ``include_ownership`` is passed through to ``canonical_hash`` --
    callers that opted into ownership-as-identity at sign-time MUST
    also opt in here, otherwise drift detection would compare
    incompatible hashes.
    """
    if not declared_hash:
        return False
    return canonical_hash(
        agent_def, include_ownership=include_ownership) != declared_hash


def lineage_chain(agent_def: dict) -> list[str]:
    """Return the lineage chain — current agent first, then ancestors.

    Reads `lineage` if present (preferred — full chain pre-computed),
    else `parent_agent_key` (single hop).
    """
    lineage = agent_def.get("lineage")
    if isinstance(lineage, list) and lineage:
        return list(lineage)
    parent = agent_def.get("parent_agent_key")
    if parent:
        return [agent_def.get("agent_key", "self"), parent]
    return [agent_def.get("agent_key", "self")] if agent_def.get("agent_key") else []


# Heuristic: each generation decays the inherited contribution.
# A child of a critical agent starts +8; grandchild +4; great-grandchild +2.
_INHERITANCE_PER_GEN = {0: 0, 1: 8, 2: 4, 3: 2}
_INHERITANCE_DEFAULT = 1  # for generations >= 4


def lineage_risk_inheritance(parent_score: int, generation: int = 1) -> int:
    """Decayed contribution from a parent's risk score to its child.

    `parent_score` is the parent's static risk score (0..100).
    `generation` is the number of hops between this agent and the parent
    being weighted (1 = direct parent). Critical (>=85) parents always
    contribute the per-generation amount; lower-risk parents contribute
    half as much. Returns 0 for clean lineage.
    """
    if parent_score <= 0 or generation <= 0:
        return 0
    base = _INHERITANCE_PER_GEN.get(generation, _INHERITANCE_DEFAULT)
    if parent_score >= 85:
        return base
    if parent_score >= 60:
        return max(1, base // 2)
    return 0


def verify_signature(agent_def: dict, public_key: bytes | None = None) -> dict:
    """Report whether the agent carries a publisher signature.

    KYA doesn't yet operate a public-key registry, so verification is
    optional. Returns a status dict the UI can render:
        {present: bool, algorithm: "ed25519"|..., verified: bool|None}
    """
    sig = agent_def.get("signature")
    if not sig or not isinstance(sig, dict):
        return {"present": False, "algorithm": None, "verified": None}
    algo = sig.get("algorithm", "unknown")
    if public_key is None:
        return {"present": True, "algorithm": algo, "verified": None}
    # ``verified`` is None when the caller has not supplied a public
    # key to check against; pass ``public_key=...`` for verification.
    return {"present": True, "algorithm": algo, "verified": None}
