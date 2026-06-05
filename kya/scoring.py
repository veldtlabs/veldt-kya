"""KYA trust-score composition with primitive-level explanations.

`score_with_why()` is the OSS scoring entrypoint. It takes the optional
results of KYA primitive checks (judge consensus, evidence chain
verification, delegation graph walks, authority/RBAC checks) and
produces:

  - a numeric `score` (0-100)
  - a `verdict` ("OK" / "SPLIT" / "BREACH")
  - a `why` list of REGULATION-AGNOSTIC primitive-state strings
    (human-readable)
  - a `why_codes` list of STABLE enum-style identifiers parallel to
    `why` — these are the join key Pro's regulator_pack YAML maps to
    clauses. Wording changes to `why` strings never break Pro's
    mappings because Pro keys on `why_codes`, not the English text.
  - an `evidence_links` list of evidence-record IDs the caller can
    cite when surfacing the score to an auditor

The `why` strings are drawn from a **closed vocabulary** defined by
``WHY_VOCABULARY`` below. This is the entire surface area that the Pro
``regulator_pack.annotate()`` layer translates into regulator-clause
mappings. Three architectural enforcement properties hold (and are
mechanically tested):

  1. **Closed vocabulary** — every string emitted by `score_with_why`
     belongs to ``WHY_VOCABULARY``. A future contributor introducing a
     new `why` string MUST add it to the vocabulary first.
  2. **No regulator names** — no `why` string contains the name of any
     regulator, regulation, statute, or jurisdiction. The OSS layer
     never mentions GDPR / NIST / HIPAA / ITAR / FedRAMP / EU AI Act /
     SOX / PCI / DORA / etc. The forbidden-term list is derived
     dynamically from `kya.compliance.REGIMES` so adding a new regime
     to the REGIMES set automatically extends the check.
  3. **Stable codes** — `why_codes` parallel `why` 1:1. Pro's YAML
     mappings join on codes, so wording changes are safe (rename a
     `why` string, keep its code, and every Pro mapping still works).

Together these properties guarantee that **adding a new regulation
NEVER requires changing this code** — only Pro's YAML mapping table.

Score arithmetic
----------------
Start at 100. Each negative finding subtracts 20. Each indeterminate
finding subtracts 5. Each error finding subtracts 3. Positive findings
do not increase the score (they are the baseline). Score is floored
at 0 and ceilinged at 100.

Verdict thresholds
------------------
  >= 80 → "OK"
  >= 50 → "SPLIT"
  <  50 → "BREACH"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ── Closed vocabulary of `why` strings + stable codes ─────────────


# Each vocabulary entry has TWO identifiers:
#   - the human-readable `why` string (subject to wording changes)
#   - the stable `_CODE` enum-style identifier (NEVER changes — this
#     is the join key Pro's regulator_pack YAML maps to clauses)
#
# Convention: the constant name without the `WHY_` prefix IS the
# stable code (e.g. WHY_EVIDENCE_VERIFIED → code `EVIDENCE_VERIFIED`).
# This eliminates "magic string" duplication: the code is mechanically
# derivable from the Python constant name.


# Positive primitive findings — score is unaffected (baseline 100).
WHY_EVIDENCE_VERIFIED = "signed evidence chain verified"
WHY_DELEGATION_VERIFIED = "delegation chain verified"
WHY_AUTHORITY_APPROVED = "authority scope approved"
WHY_INPUT_SAFETY_OK = "no input-safety threats detected"
WHY_RESPONSE_SAFETY_OK = "agent response passed safety checks"
WHY_FAITHFULNESS_OK = "agent grounded in context"

# Negative primitive findings — each subtracts 20 from score.
WHY_EVIDENCE_TAMPERED = "signed evidence chain tampered"
WHY_DELEGATION_BROKEN = "delegation chain broken"
WHY_AUTHORITY_MISSING = "authority scope missing"
WHY_INPUT_SAFETY_BREACH = "input-safety threat detected"
WHY_RESPONSE_SAFETY_BREACH = "agent response failed safety checks"
WHY_FAITHFULNESS_BREACH = "agent hallucination detected"

# Indeterminate findings — each subtracts 5 from score.
WHY_INPUT_SAFETY_UNCLEAR = "input-safety check inconclusive"
WHY_RESPONSE_SAFETY_UNCLEAR = "agent response safety check inconclusive"
WHY_FAITHFULNESS_UNCLEAR = "agent faithfulness check inconclusive"
WHY_INPUT_SAFETY_SPLIT = "input-safety judges disagreed"
WHY_RESPONSE_SAFETY_SPLIT = "agent response safety judges disagreed"
WHY_FAITHFULNESS_SPLIT = "agent faithfulness judges disagreed"

# Error findings — each subtracts 3 from score.
WHY_INPUT_SAFETY_ERROR = "input-safety check errored"
WHY_RESPONSE_SAFETY_ERROR = "agent response safety check errored"
WHY_FAITHFULNESS_ERROR = "agent faithfulness check errored"


# Stable code <-> human string mapping. Pro's regulator_pack YAML
# keys on the code (e.g. `EVIDENCE_VERIFIED`), so the human wording
# can change in OSS without breaking any Pro compliance pack.
WHY_CODE_TO_STRING: dict[str, str] = {
    "EVIDENCE_VERIFIED": WHY_EVIDENCE_VERIFIED,
    "DELEGATION_VERIFIED": WHY_DELEGATION_VERIFIED,
    "AUTHORITY_APPROVED": WHY_AUTHORITY_APPROVED,
    "INPUT_SAFETY_OK": WHY_INPUT_SAFETY_OK,
    "RESPONSE_SAFETY_OK": WHY_RESPONSE_SAFETY_OK,
    "FAITHFULNESS_OK": WHY_FAITHFULNESS_OK,
    "EVIDENCE_TAMPERED": WHY_EVIDENCE_TAMPERED,
    "DELEGATION_BROKEN": WHY_DELEGATION_BROKEN,
    "AUTHORITY_MISSING": WHY_AUTHORITY_MISSING,
    "INPUT_SAFETY_BREACH": WHY_INPUT_SAFETY_BREACH,
    "RESPONSE_SAFETY_BREACH": WHY_RESPONSE_SAFETY_BREACH,
    "FAITHFULNESS_BREACH": WHY_FAITHFULNESS_BREACH,
    "INPUT_SAFETY_UNCLEAR": WHY_INPUT_SAFETY_UNCLEAR,
    "RESPONSE_SAFETY_UNCLEAR": WHY_RESPONSE_SAFETY_UNCLEAR,
    "FAITHFULNESS_UNCLEAR": WHY_FAITHFULNESS_UNCLEAR,
    "INPUT_SAFETY_SPLIT": WHY_INPUT_SAFETY_SPLIT,
    "RESPONSE_SAFETY_SPLIT": WHY_RESPONSE_SAFETY_SPLIT,
    "FAITHFULNESS_SPLIT": WHY_FAITHFULNESS_SPLIT,
    "INPUT_SAFETY_ERROR": WHY_INPUT_SAFETY_ERROR,
    "RESPONSE_SAFETY_ERROR": WHY_RESPONSE_SAFETY_ERROR,
    "FAITHFULNESS_ERROR": WHY_FAITHFULNESS_ERROR,
}

# Reverse map for fast lookup during emission.
_WHY_STRING_TO_CODE: dict[str, str] = {
    v: k for k, v in WHY_CODE_TO_STRING.items()
}


# ── Vocabulary buckets ─────────────────────────────────────────────


_POSITIVE_WHY = frozenset({
    WHY_EVIDENCE_VERIFIED,
    WHY_DELEGATION_VERIFIED,
    WHY_AUTHORITY_APPROVED,
    WHY_INPUT_SAFETY_OK,
    WHY_RESPONSE_SAFETY_OK,
    WHY_FAITHFULNESS_OK,
})

_NEGATIVE_WHY = frozenset({
    WHY_EVIDENCE_TAMPERED,
    WHY_DELEGATION_BROKEN,
    WHY_AUTHORITY_MISSING,
    WHY_INPUT_SAFETY_BREACH,
    WHY_RESPONSE_SAFETY_BREACH,
    WHY_FAITHFULNESS_BREACH,
})

_INDETERMINATE_WHY = frozenset({
    WHY_INPUT_SAFETY_UNCLEAR,
    WHY_RESPONSE_SAFETY_UNCLEAR,
    WHY_FAITHFULNESS_UNCLEAR,
    WHY_INPUT_SAFETY_SPLIT,
    WHY_RESPONSE_SAFETY_SPLIT,
    WHY_FAITHFULNESS_SPLIT,
})

_ERROR_WHY = frozenset({
    WHY_INPUT_SAFETY_ERROR,
    WHY_RESPONSE_SAFETY_ERROR,
    WHY_FAITHFULNESS_ERROR,
})

# The full vocabulary — every `why` string emitted by score_with_why()
# MUST belong to this set. Mechanically enforced in
# tests/test_scoring_why.py.
WHY_VOCABULARY: frozenset[str] = (
    _POSITIVE_WHY | _NEGATIVE_WHY | _INDETERMINATE_WHY | _ERROR_WHY
)


# ── Score weights ──────────────────────────────────────────────────


_BASELINE_SCORE = 100
_NEGATIVE_PENALTY = 20
_INDETERMINATE_PENALTY = 5
_ERROR_PENALTY = 3
_SCORE_FLOOR = 0
_SCORE_CEILING = 100

_VERDICT_OK_THRESHOLD = 80
_VERDICT_SPLIT_THRESHOLD = 50


# ── Result dataclass ───────────────────────────────────────────────


@dataclass
class ScoreWithWhy:
    """The output of score_with_why().

    `why` and `why_codes` are PARALLEL ARRAYS — `why_codes[i]` is the
    stable enum-style identifier for the human-readable `why[i]`.
    Downstream layers (Pro's regulator_pack.annotate()) MUST join on
    `why_codes` so wording changes to `why` are safe.

    All three arrays (`why`, `why_codes`, `evidence_links`) are
    deterministically ordered (stable sort) so the same inputs always
    produce the same output.

    The `consumed_inputs` field records which optional primitives the
    caller supplied — useful when downstream layers (Pro) want to
    distinguish "primitive was checked and passed" from "primitive was
    never checked".
    """
    score: int
    verdict: str
    why: list[str] = field(default_factory=list)
    why_codes: list[str] = field(default_factory=list)
    evidence_links: list[str] = field(default_factory=list)
    consumed_inputs: list[str] = field(default_factory=list)


# ── Public API ─────────────────────────────────────────────────────


def score_with_why(
    *,
    consensus: Any = None,
    chain_status: dict | None = None,
    delegation_status: dict | None = None,
    authority_status: dict | None = None,
) -> ScoreWithWhy:
    """Compose a regulation-agnostic score + why from KYA primitive checks.

    Every argument is optional — callers pass only the primitives they
    have available. A primitive that isn't passed produces NO `why`
    entry (not even a "not checked" placeholder).

    Parameters
    ----------
    consensus : ConsensusResult | None
        Result from `kya.scorer_orchestrator.check_consensus`. The
        function inspects ``consensus.per_dimension`` to emit
        per-dimension `why` entries.
    chain_status : dict | None
        Result from `kya.evidence.verify_chain` — at minimum
        ``{"valid": bool}``. May include ``"checked"`` (count of rows
        verified) — used to populate `evidence_links` with the chain's
        rows when valid.
    delegation_status : dict | None
        Caller-computed delegation-graph state. At minimum
        ``{"valid": bool}``. Optional ``"edge_ids": [...]`` populates
        `evidence_links`.
    authority_status : dict | None
        Caller-computed RBAC / scope-grant state. At minimum
        ``{"approved": bool}``.

    Returns
    -------
    ScoreWithWhy
    """
    why: list[str] = []
    evidence_links: list[str] = []
    consumed: list[str] = []

    # ── Evidence primitive ──
    if chain_status is not None:
        consumed.append("chain_status")
        if chain_status.get("valid") is True:
            why.append(WHY_EVIDENCE_VERIFIED)
            # Surface evidence IDs if caller supplied them. The
            # standard `verify_chain` doesn't return per-row ids, so
            # this is purely additive when present.
            for eid in chain_status.get("evidence_ids", []) or []:
                evidence_links.append(f"evidence_id={eid}")
        elif chain_status.get("valid") is False:
            why.append(WHY_EVIDENCE_TAMPERED)
            # When tampered, the broken row id (if surfaced) is the
            # single most important evidence link.
            broken = chain_status.get("broken_at")
            if broken is not None:
                evidence_links.append(f"evidence_id={broken}")

    # ── Delegation primitive ──
    if delegation_status is not None:
        consumed.append("delegation_status")
        if delegation_status.get("valid") is True:
            why.append(WHY_DELEGATION_VERIFIED)
            for eid in delegation_status.get("edge_ids", []) or []:
                evidence_links.append(f"edge_id={eid}")
        elif delegation_status.get("valid") is False:
            why.append(WHY_DELEGATION_BROKEN)

    # ── Authority primitive ──
    if authority_status is not None:
        consumed.append("authority_status")
        if authority_status.get("approved") is True:
            why.append(WHY_AUTHORITY_APPROVED)
        elif authority_status.get("approved") is False:
            why.append(WHY_AUTHORITY_MISSING)

    # ── Verification primitive (judge consensus) ──
    if consensus is not None:
        consumed.append("consensus")
        # Validate shape rather than silently swallowing
        # malformed objects (e.g. consensus=42 would have produced
        # `per_dim={}` under the old `getattr(...) or {}` pattern).
        if not hasattr(consensus, "per_dimension"):
            raise TypeError(
                f"score_with_why: `consensus` must have a "
                f"`per_dimension` attribute (got {type(consensus).__name__}). "
                f"Pass kya.scorer_orchestrator.ConsensusResult or a "
                f"compatible object."
            )
        per_dim = consensus.per_dimension or {}
        why.extend(_consensus_why_entries(per_dim))

    # Deterministic ordering: sort by the position the string holds in
    # the vocabulary's canonical order. Using a literal alphabetical
    # sort would surface "agent ..." before "delegation ..." which
    # reads less naturally; the vocabulary order below puts the
    # 6 primitives in their natural reading order (evidence,
    # delegation, authority, input-safety, response-safety,
    # faithfulness).
    why_ordered = _sort_why(why)
    evidence_ordered = sorted(set(evidence_links))

    # ── Score arithmetic ──
    score = _BASELINE_SCORE
    for entry in why_ordered:
        if entry in _NEGATIVE_WHY:
            score -= _NEGATIVE_PENALTY
        elif entry in _INDETERMINATE_WHY:
            score -= _INDETERMINATE_PENALTY
        elif entry in _ERROR_WHY:
            score -= _ERROR_PENALTY
        # positive findings are baseline; no change
    score = max(_SCORE_FLOOR, min(_SCORE_CEILING, score))

    # ── Verdict ──
    if score >= _VERDICT_OK_THRESHOLD:
        verdict = "OK"
    elif score >= _VERDICT_SPLIT_THRESHOLD:
        verdict = "SPLIT"
    else:
        verdict = "BREACH"

    # Parallel `why_codes` array — same order, stable enum-style
    # identifiers. Pro's YAML keys on these, not on `why`.
    why_codes_ordered = [_WHY_STRING_TO_CODE[w] for w in why_ordered]

    return ScoreWithWhy(
        score=score,
        verdict=verdict,
        why=why_ordered,
        why_codes=why_codes_ordered,
        evidence_links=evidence_ordered,
        consumed_inputs=sorted(consumed),
    )


# ── Internal helpers ───────────────────────────────────────────────


def _consensus_why_entries(per_dim: dict) -> list[str]:
    """Translate per-dimension judge consensus into `why` entries.

    `per_dim` maps dimension name → DimensionConsensus (or any object
    with a `.consensus` attribute). Only the three canonical
    dimensions (input_safety / safety / faithfulness) produce `why`
    entries; the "any" pseudo-dimension is intentionally ignored
    because its judges already vote in every other dimension.
    """
    table = {
        "input_safety": {
            "OK": WHY_INPUT_SAFETY_OK,
            "BREACH": WHY_INPUT_SAFETY_BREACH,
            "UNCLEAR": WHY_INPUT_SAFETY_UNCLEAR,
            "SPLIT": WHY_INPUT_SAFETY_SPLIT,
            "ERROR": WHY_INPUT_SAFETY_ERROR,
        },
        "safety": {
            "OK": WHY_RESPONSE_SAFETY_OK,
            "BREACH": WHY_RESPONSE_SAFETY_BREACH,
            "UNCLEAR": WHY_RESPONSE_SAFETY_UNCLEAR,
            "SPLIT": WHY_RESPONSE_SAFETY_SPLIT,
            "ERROR": WHY_RESPONSE_SAFETY_ERROR,
        },
        "faithfulness": {
            "OK": WHY_FAITHFULNESS_OK,
            "BREACH": WHY_FAITHFULNESS_BREACH,
            "UNCLEAR": WHY_FAITHFULNESS_UNCLEAR,
            "SPLIT": WHY_FAITHFULNESS_SPLIT,
            "ERROR": WHY_FAITHFULNESS_ERROR,
        },
    }
    out: list[str] = []
    for dim, mapping in table.items():
        dc = per_dim.get(dim)
        if dc is None:
            continue
        verdict = getattr(dc, "consensus", None)
        entry = mapping.get(verdict)
        if entry is not None:
            out.append(entry)
    return out


# Canonical reading order for `why` entries. The order matches the
# six KYA primitives (evidence, delegation, authority, input safety,
# response safety, faithfulness) and within each primitive the order
# is positive → negative → indeterminate-flavors → error.
_WHY_ORDER: tuple[str, ...] = (
    WHY_EVIDENCE_VERIFIED, WHY_EVIDENCE_TAMPERED,
    WHY_DELEGATION_VERIFIED, WHY_DELEGATION_BROKEN,
    WHY_AUTHORITY_APPROVED, WHY_AUTHORITY_MISSING,
    WHY_INPUT_SAFETY_OK, WHY_INPUT_SAFETY_BREACH,
    WHY_INPUT_SAFETY_UNCLEAR, WHY_INPUT_SAFETY_SPLIT,
    WHY_INPUT_SAFETY_ERROR,
    WHY_RESPONSE_SAFETY_OK, WHY_RESPONSE_SAFETY_BREACH,
    WHY_RESPONSE_SAFETY_UNCLEAR, WHY_RESPONSE_SAFETY_SPLIT,
    WHY_RESPONSE_SAFETY_ERROR,
    WHY_FAITHFULNESS_OK, WHY_FAITHFULNESS_BREACH,
    WHY_FAITHFULNESS_UNCLEAR, WHY_FAITHFULNESS_SPLIT,
    WHY_FAITHFULNESS_ERROR,
)

# Static assertion: the canonical order MUST cover every vocabulary
# entry. If a new vocabulary string is added without updating the
# order, a `KeyError` at import time surfaces the omission
# immediately rather than letting it slip into sort_with_why output.
_WHY_INDEX: dict[str, int] = {w: i for i, w in enumerate(_WHY_ORDER)}
assert set(_WHY_INDEX) == set(WHY_VOCABULARY), (
    "kya/scoring.py: _WHY_ORDER missing entries from WHY_VOCABULARY"
)
# Static assertion: codes bijection covers the full vocabulary.
assert set(WHY_CODE_TO_STRING.values()) == set(WHY_VOCABULARY), (
    "kya/scoring.py: WHY_CODE_TO_STRING is not a bijection over the "
    "vocabulary"
)


def _sort_why(entries: list[str]) -> list[str]:
    """Deterministic ordering for the `why` list, using the canonical
    reading order. Duplicates are dropped (first occurrence wins; the
    canonical order resolves ties)."""
    seen: set[str] = set()
    dedup: list[str] = []
    for e in entries:
        if e in seen:
            continue
        seen.add(e)
        dedup.append(e)
    return sorted(dedup, key=lambda e: _WHY_INDEX.get(e, len(_WHY_ORDER)))
