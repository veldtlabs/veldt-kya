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


def canonical_hash(agent_def: dict) -> str:
    """SHA256 over a canonical JSON serialization of the identity fields.

    Two semantically-equal definitions hash identically. Mutating any
    identity field (or adding a new tool) changes the hash.
    """
    snapshot = {k: agent_def.get(k) for k in _HASHED_FIELDS if k in agent_def}
    payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def detect_drift(declared_hash: str, agent_def: dict) -> bool:
    """Return True if the declared hash doesn't match the current
    definition's canonical hash. Caller logs + alerts on True."""
    if not declared_hash:
        return False
    return canonical_hash(agent_def) != declared_hash


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
    # Real verification deferred until key registry is operational.
    return {"present": True, "algorithm": algo, "verified": None}
