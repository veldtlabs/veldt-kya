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

# Identity field sets per principal kind.
#
# ``canonical_hash`` projects only the keys present in the kind's
# field set (extra keys in the definition are ignored). Two
# definitions that agree on every identity field hash identically,
# even if they differ on operational metadata (timestamps, counters,
# call history) -- that's the contract that makes drift detection
# robust against benign telemetry churn.
#
# Adding a new field is an additive, backward-compatible change AS
# LONG AS existing definitions don't already use that key. The
# rule of thumb: when a new identity field appears, every definition
# implicitly opts in -- its hash will change for the FIRST recompute
# after the upgrade. Document the upgrade as a one-time fingerprint
# rotation, then move on.

# Agent identity (v0.1.0). Kept as a top-level constant for
# back-compat: callers reading ``kya.integrity._HASHED_FIELDS``
# continue to see the agent vocabulary they expect.
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

# Autonomy-asset identity fields. Common across drones / robots /
# vehicles -- firmware revision, kinematic envelope, parameter
# bundle, geofence, and security caps. A drone firmware bump or a
# geofence change MUST flip the fingerprint, otherwise an audit
# trail can't tell two materially-different drones apart.
_AUTONOMY_ASSET_FIELDS = (
    "firmware_version",   # firmware build / git SHA
    "firmware_hash",      # signed binary digest if available
    "airframe",           # "quad", "hex", "fixed_wing", "rover"
    "platform",           # vendor / autopilot ("ardupilot", "px4")
    "model",              # vendor model code ("CubeOrange", "DJI M300")
    "sensor_set",         # canonical sensor list (sorted)
    "actuator_set",       # canonical actuator list (sorted)
    "kinematic_envelope", # max speed / max alt / max payload / etc.
    "parameter_set_hash", # hash of the full MAVLink param dump
    "geofence_id",        # active geofence document id
    "mission_profile",    # named profile in use (e.g. "survey_v3")
    "approved_modes",     # flight modes the operator has authorised
    "data_classes",       # what data the asset handles (shared w/ agents)
    "compliance_scope",   # regulatory regime tags (shared w/ agents)
)

# PLC / industrial-controller identity fields. The "program" is the
# IEC 61131-3 logic; firmware + IO map are the operational envelope.
_PLC_FIELDS = (
    "firmware_version",
    "firmware_hash",
    "model",              # vendor PLC model
    "platform",           # vendor name
    "program_hash",       # IEC 61131-3 program digest
    "io_map_hash",        # tag database hash
    "approved_modes",     # RUN / PROG / REMOTE
    "compliance_scope",
)

# Service-account / machine-identity fields. Lightweight today;
# extend additively as IdP integration matures.
_MACHINE_IDENTITY_FIELDS = (
    "client_id",
    "issuer",
    "scopes",
    "approved_audiences",
    "compliance_scope",
)

# Composed-system identity. Identity = the MEMBERS, by reference.
# The composer's own metadata is mostly governance (owner, on_call)
# rather than capability, so the meaningful identity hash for an
# autonomous_system row is its membership manifest.
_AUTONOMOUS_SYSTEM_FIELDS = (
    "name",
    "description",
    "mission_profile",
    "approved_members",   # sorted list of {kind, id} members
    "compliance_scope",
)

# Per-kind registry. Lookup fallback is ``_HASHED_FIELDS`` (the
# agent vocabulary) so every kind hashes against something
# deterministic -- a typo'd kind degrades to "compute the hash like
# an agent" rather than raising.
_HASHED_FIELDS_BY_KIND: dict[str, tuple[str, ...]] = {
    "agent":             _HASHED_FIELDS,
    "user":              _HASHED_FIELDS,
    "service_account":   _MACHINE_IDENTITY_FIELDS,
    "machine_identity":  _MACHINE_IDENTITY_FIELDS,
    "drone":             _AUTONOMY_ASSET_FIELDS,
    "robot":             _AUTONOMY_ASSET_FIELDS,
    "vehicle":           _AUTONOMY_ASSET_FIELDS,
    "controller":        _AUTONOMY_ASSET_FIELDS,
    "sensor":            _AUTONOMY_ASSET_FIELDS,
    "actuator":          _AUTONOMY_ASSET_FIELDS,
    "plc":               _PLC_FIELDS,
    "lakehouse_job":     _HASHED_FIELDS,
    "autonomous_system": _AUTONOMOUS_SYSTEM_FIELDS,
}


def hashed_fields_for(principal_kind: str | None) -> tuple[str, ...]:
    """Look up the identity field set for a principal kind.

    Unknown / None kind falls back to the agent vocabulary so a
    miscategorised definition still hashes deterministically. Used
    by :func:`canonical_hash` when a caller passes
    ``principal_kind=``.
    """
    if not principal_kind:
        return _HASHED_FIELDS
    return _HASHED_FIELDS_BY_KIND.get(principal_kind, _HASHED_FIELDS)


def register_hashed_fields(
    principal_kind: str, fields: tuple[str, ...],
) -> None:
    """Override or extend the identity field set for a principal
    kind. Idempotent (last write wins). Useful for vendors who
    register new kinds via ``register_principal_kind`` and need
    matching identity hashing.

    Fields are validated as a tuple of non-empty strings. The
    registry mutation is process-local.
    """
    if not isinstance(fields, tuple):
        raise TypeError("fields must be a tuple of strings")
    for f in fields:
        if not isinstance(f, str) or not f:
            raise ValueError(
                f"every field must be a non-empty string; got {f!r}")
    _HASHED_FIELDS_BY_KIND[principal_kind] = fields


# Ownership / accountability metadata. NOT in the identity hash by
# default -- changing the owner does not change what the principal
# does. Customers in strict-audit regimes can opt in by passing
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
    definition: dict,
    *,
    include_ownership: bool | None = None,
    principal_kind: str | None = None,
) -> str:
    """SHA256 over a canonical JSON serialization of the identity fields.

    Two semantically-equal definitions hash identically. Mutating any
    identity field (or adding a new tool, or bumping firmware) changes
    the hash.

    By default the hash covers only "what this thing does":
        * Agents: prompt, tools, data classes, governance mode,
          delegation permissions, model, etc.
        * Drones / robots / vehicles: firmware, airframe, sensor set,
          parameter bundle, geofence, mission profile, approved modes.
        * PLCs: firmware, program digest, IO map, approved modes.
        * Service accounts: client_id, issuer, scopes, audiences.

    The field set is selected via ``principal_kind`` against the
    ``_HASHED_FIELDS_BY_KIND`` registry (extensible at runtime via
    :func:`register_hashed_fields`). Unknown / None kind falls back
    to the agent vocabulary, so existing v0.1.7 callers that don't
    pass ``principal_kind`` get IDENTICAL hashes to v0.1.7.

    Ownership / accountability metadata (``owner``, ``on_call``,
    ``escalation``, ``review_status``) is NOT in the hash by default;
    a re-org that reassigns an owner does not, by default, count as
    "the principal changed." Customers in strict-audit regimes opt
    in via:
        * ``canonical_hash(defn, include_ownership=True)``
        * env var ``KYA_HASH_OWNER_FIELDS=true``
          (the explicit kwarg overrides the env var)

    Args:
        definition: The principal definition dict. Historically called
            ``agent_def``; both kwarg names work for back-compat.
        include_ownership: Fold ownership fields into the hash.
        principal_kind: Pick the identity field set for this kind.
            ``None`` (default) uses the agent vocabulary, preserving
            v0.1.7 hashes exactly.

    Returns:
        Hex SHA-256 over the canonical-JSON projection.
    """
    fields = hashed_fields_for(principal_kind)
    if _ownership_enabled(include_ownership):
        fields = fields + _OWNERSHIP_FIELDS
    snapshot = {k: definition.get(k) for k in fields if k in definition}
    payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def detect_drift(
    declared_hash: str,
    definition: dict,
    *,
    include_ownership: bool | None = None,
    principal_kind: str | None = None,
) -> bool:
    """Return True if the declared hash doesn't match the current
    definition's canonical hash. Caller logs + alerts on True.

    ``include_ownership`` and ``principal_kind`` are passed through
    to :func:`canonical_hash` -- callers that opted into a non-default
    field set at sign-time MUST also opt in here, otherwise drift
    detection would compare incompatible hashes.
    """
    if not declared_hash:
        return False
    return canonical_hash(
        definition,
        include_ownership=include_ownership,
        principal_kind=principal_kind,
    ) != declared_hash


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
