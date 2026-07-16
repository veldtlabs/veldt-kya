"""Canonical policy hashing — the load-bearing primitive for
task #157 §3 (Policy → outcome integrity).

The goal: give operators, auditors, and Watchtower a cryptographic
handle on "the policy that was in force when this verdict was made,"
so the runtime CANNOT diverge from what the /controls page shows
without turning a hash comparison red.

Design invariants
-----------------
1. **Deterministic bytes.** Two hashes match iff the underlying
   policy is byte-equal after canonicalisation. No wall-clock, no
   process-id, no dict-iteration-order surprises.
2. **Cross-runtime stable.** A Python 3.10 process must produce
   the same hash as a Python 3.13 process, and dashboard-api must
   produce the same hash as Watchtower. Canonical JSON with sorted
   keys + tight separators is the well-trodden path here.
3. **OSS-only.** Every KYA layer (OSS evaluator, Pro dashboard-api,
   the future Watchtower) computes hashes via THIS module. No
   layer re-implements canonicalisation — that's how you get
   "same policy, two hashes" bugs that a compromised layer could
   exploit.
4. **No DB side effects.** ``hash_policy`` is a pure function of
   its input dict. ``get_effective_policy`` reads via the existing
   ``get_effective_weights`` API which is already read-only.

Semantic scope
--------------
The "policy" hashed here is the paper §08 effective weight table —
the 2-channel platform ⊕ tenant merge that ``get_effective_weights``
returns, spanning EVERY registered scope. Signed-rec applications
(3rd channel per §08) are persisted as tenant overrides at approval
time, so they already appear in the 2-channel result — no separate
merge needed here.

If a future release adds runtime-effective policy state that lives
OUTSIDE the weight table (e.g. per-tenant rule-DSL overlays), that
state MUST also feed into ``get_effective_policy`` or the hash
promise breaks. Extending here is intentional — you have to touch
this file to change the promise.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any


# Version prefix so a future canonicalisation change (unlikely but
# conceivable — e.g. Unicode normalisation form) can be rolled without
# a silent collision. Consumers that store the hash SHOULD store the
# full ``policy-hash-sha256-v1:<hex>`` form; the ``hash_policy_hex``
# helper returns just the hex if a caller wants the raw digest.
POLICY_HASH_VERSION_PREFIX = "policy-hash-sha256-v1:"


def _normalize_for_hash(value: Any) -> Any:
    """Recursively coerce a policy value into strict, cross-platform-
    stable JSON primitives before serialisation.

    Three loud coercions, each guarding a real determinism failure
    mode a reviewer flagged before we shipped:

    * ``bool`` → ``int`` — ``json.dumps(True)`` is ``"true"`` while
      ``json.dumps(1)`` is ``"1"``. A weight value that sneaks in as
      ``True`` (DB driver quirk, override script typo) would hash
      differently from the integer ``1`` even though the two compare
      equal in Python. Force ``bool``s to ``int`` so both paths agree.
    * ``float`` → ``TypeError`` at ``json.dumps`` time — weights are
      supposed to be integers. A float sneaking in via a bug would
      pass through ``json.dumps`` and produce platform-dependent
      output for edge values (NaN, infinities). ``allow_nan=False``
      catches NaN / inf loud; integer weights never touch this path.
    * Unicode keys → NFC — Windows filesystems emit NFC, macOS emits
      NFD, either can round-trip through Python source. Two hosts
      that both faithfully preserve their input produce different
      bytes for the SAME logical key. Normalise to NFC so
      dashboard-api on Windows and Watchtower on Linux agree.

    Values inside nested dicts and lists are recursed into so a
    tenant that adds a Unicode scope key deep in a policy sub-tree
    doesn't slip past the top-level normalisation.
    """
    if isinstance(value, bool):
        # bool is a subclass of int — narrow explicitly so True/False
        # serialise as 1/0. Order matters: check bool BEFORE int.
        return int(value)
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(k)): _normalize_for_hash(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_normalize_for_hash(v) for v in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    return value


def canonicalize_policy(policy: dict[str, Any]) -> bytes:
    """Deterministic byte encoding for hashing.

    Sorted keys, tight separators, UTF-8, NFC-normalised Unicode,
    strict int/str primitives (bools coerced to int, floats
    forbidden via ``allow_nan=False``). Same shape as the pack
    signer's canonical form so external verifiers who already
    integrated against that don't have to learn a second one.

    Rejects non-dict input rather than silently coercing so that a
    typo passing e.g. a list of weight rows produces a loud error
    instead of a hash that happens to match nothing.
    """
    if not isinstance(policy, dict):
        raise TypeError(
            f"canonicalize_policy expects a dict, got {type(policy).__name__}"
        )
    normalised = _normalize_for_hash(policy)
    # allow_nan=False turns a stray float('nan') / float('inf') from
    # a bugged upstream into a loud ValueError at hash time rather
    # than a platform-dependent byte string that would silently
    # cross-verify against nothing.
    return json.dumps(
        normalised,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=False,
    ).encode("utf-8")


def hash_policy_hex(policy: dict[str, Any]) -> str:
    """Return the raw sha256 hex digest of the canonicalised policy."""
    return hashlib.sha256(canonicalize_policy(policy)).hexdigest()


def hash_policy(policy: dict[str, Any]) -> str:
    """Return the versioned policy hash string.

    Format: ``policy-hash-sha256-v1:<64 hex chars>``. Consumers
    (verdict recorder, /v1/policies/hash endpoint, Watchtower)
    should store + compare this full string, not the bare hex, so
    a future algorithm swap is a loud comparison mismatch rather
    than a silent collision.
    """
    return POLICY_HASH_VERSION_PREFIX + hash_policy_hex(policy)


def parse_policy_hash(stamped: str) -> tuple[str, str]:
    """Split a versioned hash string into ``(version_prefix, hex)``.

    Useful for the future Watchtower use case where the verifier
    wants to gate on version before running the comparison — a v2
    hash coming in against a v1 verifier should fail with a
    ``version_mismatch`` message, not a silent-collision comparison.

    Raises ``ValueError`` when the string doesn't start with a
    known version prefix. Callers should treat that as "this string
    isn't a policy hash we know how to verify" rather than as a
    verification failure.
    """
    if not stamped.startswith(POLICY_HASH_VERSION_PREFIX):
        raise ValueError(
            f"not a policy hash we recognise: {stamped!r} — expected "
            f"prefix {POLICY_HASH_VERSION_PREFIX!r}"
        )
    return POLICY_HASH_VERSION_PREFIX, stamped[len(POLICY_HASH_VERSION_PREFIX):]


def verify_policy_hash(policy: dict[str, Any], expected_stamped: str) -> bool:
    """Return True iff ``policy`` hashes to ``expected_stamped``.

    The Watchtower use case: given an evidence row carrying a
    stamped policy hash and the effective policy at that moment,
    confirm the two match. Wraps ``hash_policy`` + string equality
    so a caller can't accidentally compare a raw hex string against
    a stamped one and miss the version prefix.
    """
    return hash_policy(policy) == expected_stamped


def get_effective_policy(db, tenant_id: str | None) -> dict[str, dict[str, int]]:
    """Assemble the full effective policy for a tenant across every
    registered weight scope.

    Structure: ``{scope: {key: value, ...}, ...}`` with scopes and
    keys BOTH sorted implicitly by the canonicaliser downstream.
    ``tenant_id=None`` returns the platform-effective view (no
    tenant overrides applied) — matches ``get_effective_weights``'s
    None semantics so Watchtower can spot-check platform-default
    hashes against dashboard-api's.

    This function is deliberately a thin wrapper over
    ``get_effective_weights`` so there is exactly ONE code path
    that assembles "the effective policy" across the whole KYA
    codebase. If we ever need to add a new channel to the merge,
    the change lands here.

    Empty scope registry raises ``RuntimeError`` rather than
    quietly returning ``{}``. A caller that hashes an empty policy
    would get a stable "zero-scope hash" that would silently pass
    verification against another caller with the same
    misconfiguration — exactly the drift #157 §3 exists to prevent.

    Cross-replica consistency note: when #157 §4's Watchtower reads
    from a Postgres logical replica it may momentarily lag the
    primary. A hash mismatch between "verdict recorder at time T"
    and "Watchtower at time T+lag" is expected during that window
    and should be resolved by re-reading at a coherent LSN, not by
    weakening the comparison. See docs/WHAT_GOVERNS_THE_GOVERNOR.md
    §4 acceptance criteria.
    """
    from .tenant_weights import known_scopes, get_effective_weights

    scopes = known_scopes()
    if not scopes:
        raise RuntimeError(
            "policy_hash.get_effective_policy: kya.tenant_weights has "
            "zero registered scopes. This usually means weight modules "
            "haven't finished importing yet — hashing an empty policy "
            "would silently produce a stable-looking-but-wrong hash. "
            "Ensure `kya` is imported (not just kya.policy_hash) and "
            "that ensure_tables() has run on this engine."
        )
    return {
        scope: get_effective_weights(db, scope, tenant_id=tenant_id)
        for scope in scopes
    }


def get_effective_policy_hash(db, tenant_id: str | None) -> str:
    """Convenience: assemble + hash in one call.

    Runtime hot-path helper. The verdict recorder calls this on
    every verdict; keeping the composition here means a compromised
    caller can't hash a subset of scopes and pretend it was the
    whole policy.
    """
    return hash_policy(get_effective_policy(db, tenant_id=tenant_id))


__all__ = [
    "POLICY_HASH_VERSION_PREFIX",
    "canonicalize_policy",
    "hash_policy_hex",
    "hash_policy",
    "parse_policy_hash",
    "verify_policy_hash",
    "get_effective_policy",
    "get_effective_policy_hash",
]
