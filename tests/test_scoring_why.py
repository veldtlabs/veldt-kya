"""Tests for kya/scoring.py — `score_with_why()` and the closed `why`
vocabulary.

These tests serve TWO architectural purposes beyond regression:

  1. **Vocabulary closure** — every `why` string emitted by
     `score_with_why()` must belong to `WHY_VOCABULARY`. A future
     contributor who adds a new `why` string without registering it
     fails CI.

  2. **No regulator names** — no `why` string ever contains a
     regulator/regulation/statute name. This enforces the
     architectural property that "adding a new regulation never
     requires changing OSS code" — all regulator awareness lives in
     the Pro YAML mapping layer, not in OSS code paths.

The other tests verify:
  - Each primitive (evidence / delegation / authority / consensus)
    correctly surfaces both positive and negative findings
  - Optional primitives that aren't passed produce NO entry
  - Multiple negative findings ALL appear (no swallowing)
  - Deterministic ordering across repeated calls
  - Score arithmetic matches the documented weights
  - Verdict thresholds (OK ≥ 80 > SPLIT ≥ 50 > BREACH)
  - Evidence links are deduplicated + collected from all sources
  - Two different inputs produce different `why` lists
"""
from __future__ import annotations

import re as _re
from dataclasses import dataclass

import pytest

from kya.scoring import (
    WHY_AUTHORITY_APPROVED,
    WHY_AUTHORITY_MISSING,
    WHY_CODE_TO_STRING,
    WHY_DELEGATION_BROKEN,
    WHY_DELEGATION_VERIFIED,
    WHY_EVIDENCE_TAMPERED,
    WHY_EVIDENCE_VERIFIED,
    WHY_FAITHFULNESS_ERROR,
    WHY_FAITHFULNESS_OK,
    WHY_INPUT_SAFETY_BREACH,
    WHY_INPUT_SAFETY_OK,
    WHY_INPUT_SAFETY_UNCLEAR,
    WHY_RESPONSE_SAFETY_OK,
    WHY_RESPONSE_SAFETY_SPLIT,
    WHY_VOCABULARY,
    score_with_why,
)

# ── Test fixtures ──────────────────────────────────────────────────


@dataclass
class FakeDimensionConsensus:
    consensus: str  # "BREACH" | "OK" | "SPLIT" | "UNCLEAR" | "ERROR"


@dataclass
class FakeConsensus:
    per_dimension: dict


# ── Architectural property #1: vocabulary closure ──────────────────


def test_vocabulary_closure_across_all_dimension_states():
    """Every `why` string emitted by score_with_why must belong to
    WHY_VOCABULARY. Iterates every primitive × every per-dim state
    and asserts every produced string is registered.

    Catches: a future contributor changing a string like
    "signed evidence chain verified" → "evidence chain verified"
    without updating the vocabulary set.
    """
    primitive_inputs = [
        {"chain_status": {"valid": True}},
        {"chain_status": {"valid": False, "broken_at": 42}},
        {"delegation_status": {"valid": True}},
        {"delegation_status": {"valid": False}},
        {"authority_status": {"approved": True}},
        {"authority_status": {"approved": False}},
    ]
    for verdict in ("OK", "BREACH", "UNCLEAR", "SPLIT", "ERROR"):
        for dim in ("input_safety", "safety", "faithfulness"):
            primitive_inputs.append({
                "consensus": FakeConsensus(per_dimension={
                    dim: FakeDimensionConsensus(consensus=verdict),
                }),
            })

    for kwargs in primitive_inputs:
        result = score_with_why(**kwargs)
        for entry in result.why:
            assert entry in WHY_VOCABULARY, (
                f"score_with_why emitted unregistered `why` entry "
                f"{entry!r} for inputs {kwargs}. Either add it to "
                f"WHY_VOCABULARY or fix the emitter."
            )


# ── Architectural property #2: no regulator names ──────────────────


# Forbidden regulator/regulation/statute terms that MUST NOT appear
# in OSS `why` strings. Derived dynamically from
# `kya.compliance.REGIMES` so adding a new regime automatically
# extends this check — the hand-curated list is purely additive,
# covering citation words and well-known aliases not captured by the
# raw regime short-codes.
def _build_forbidden_regulator_terms() -> list[str]:
    from kya.compliance import REGIMES
    terms: set[str] = set()
    for r in REGIMES:
        # Both raw short-code and uppercase variant, since YAML
        # regime keys are lowercase but customer-visible names tend
        # to be uppercase.
        terms.add(r)
        terms.add(r.upper())
    # Common aliases / spelled-out forms not in the raw short codes.
    terms.update({
        "GDPR", "HIPAA", "ITAR", "FedRAMP", "DORA", "NYDFS",
        "EU AI Act", "AI Act", "EO 14110", "Sarbanes",
        "AI Bill of Rights", "SR 11-7", "SR 11/7",
        "CMMC", "DFARS",
        # Generic regulator-citation words. We use match-as-token
        # patterns at assertion time so a primitive sentence
        # containing the word "section" in normal English isn't
        # caught — only strings citing a numbered article/section.
        # See `_contains_citation_token` below.
    })
    return sorted(terms)


_FORBIDDEN_REGULATOR_TERMS = _build_forbidden_regulator_terms()

# Citation-pattern tokens — match only when followed by punctuation
# or a digit so legitimate English words don't collide. (The
# vocabulary today doesn't include any of these but we guard
# against future contributors writing "Art. 30" or "§5(2)".)
_CITATION_PATTERNS = [
    _re.compile(r"\bArt\.?\b"),
    _re.compile(r"\b§"),
    _re.compile(r"\bReg\.\b"),
]


def test_no_regulator_names_appear_in_vocabulary():
    """No `why` string in the vocabulary contains any regulator name
    or regulator-citation word. This is the architectural enforcement
    that proves OSS is regulator-agnostic.

    The forbidden list is derived from `kya.compliance.REGIMES` so
    adding a new regime (e.g. UK AI Act) to that set automatically
    extends this check. Belt-and-braces: we also check
    citation-pattern tokens (`Art.`, `§`, `Reg.`) via regex.

    Catches: someone hardcoding "GDPR Art. 30 compliant" into a
    `why` string instead of adding it to the Pro YAML mapping.
    """
    leaks: list[tuple[str, str]] = []
    for entry in WHY_VOCABULARY:
        for term in _FORBIDDEN_REGULATOR_TERMS:
            if _term_appears_in(term, entry):
                leaks.append((entry, term))
        for pat in _CITATION_PATTERNS:
            if pat.search(entry):
                leaks.append((entry, pat.pattern))
    assert leaks == [], (
        f"Regulator-name leak into OSS `why` vocabulary: {leaks}. "
        "Move the wording to the Pro regulator_pack YAML mapping "
        "instead of putting it in OSS."
    )


def _term_appears_in(term: str, entry: str) -> bool:
    """Substring match for long terms, word-boundary match for short
    ones. Without the boundary, short regime codes like `ear`, `c5`,
    `sox`, `pci`, `il5`, `il6`, `dora` collide with innocent English
    ("unclear", "cleared", "search", "appeared"). The vocabulary
    today dodges this by writing "inconclusive" instead of "unclear",
    but a future contributor who writes "appeared tampered" would
    otherwise get a baffling test failure citing `ear`.
    """
    if len(term) <= 4:
        return _re.search(rf"\b{_re.escape(term)}\b",
                          entry, _re.IGNORECASE) is not None
    return term.lower() in entry.lower()


def test_no_regulator_names_in_any_emitted_why_under_all_inputs():
    """Belt-and-braces: not only must the vocabulary be clean, no
    runtime path must construct strings that ARE regulator names
    (e.g. via f-strings). Emit every possible `why` and assert none
    leak."""
    seen: set[str] = set()
    for verdict in ("OK", "BREACH", "UNCLEAR", "SPLIT", "ERROR"):
        for dim in ("input_safety", "safety", "faithfulness"):
            r = score_with_why(consensus=FakeConsensus(
                per_dimension={dim: FakeDimensionConsensus(
                    consensus=verdict)}))
            seen.update(r.why)
    for status_pair in (
        ({"valid": True}, {"valid": False, "broken_at": 1}),
        ({"approved": True}, {"approved": False}),
    ):
        for s in status_pair:
            r1 = score_with_why(chain_status=s if "valid" in s else None,
                                authority_status=s if "approved" in s else None)
            seen.update(r1.why)
    for entry in seen:
        for term in _FORBIDDEN_REGULATOR_TERMS:
            assert not _term_appears_in(term, entry), (
                f"Runtime-emitted `why` leaked regulator term "
                f"{term!r} in {entry!r}"
            )
        for pat in _CITATION_PATTERNS:
            assert not pat.search(entry), (
                f"Runtime-emitted `why` matched citation pattern "
                f"{pat.pattern!r} in {entry!r}"
            )


# ── Primitive behavior tests ───────────────────────────────────────


def test_chain_valid_surfaces_signed_evidence():
    r = score_with_why(chain_status={"valid": True})
    assert WHY_EVIDENCE_VERIFIED in r.why
    assert WHY_EVIDENCE_TAMPERED not in r.why


def test_chain_tampered_surfaces_tampered():
    r = score_with_why(chain_status={"valid": False, "broken_at": 99})
    assert WHY_EVIDENCE_TAMPERED in r.why
    assert WHY_EVIDENCE_VERIFIED not in r.why
    assert "evidence_id=99" in r.evidence_links


def test_no_chain_status_means_no_evidence_entry():
    """A primitive that wasn't checked must NOT produce a `why` entry."""
    r = score_with_why(chain_status=None)
    assert WHY_EVIDENCE_VERIFIED not in r.why
    assert WHY_EVIDENCE_TAMPERED not in r.why
    assert "chain_status" not in r.consumed_inputs


def test_delegation_valid_surfaces_verified():
    r = score_with_why(delegation_status={"valid": True,
                                            "edge_ids": [45, 46]})
    assert WHY_DELEGATION_VERIFIED in r.why
    assert "edge_id=45" in r.evidence_links
    assert "edge_id=46" in r.evidence_links


def test_delegation_broken_surfaces_broken():
    r = score_with_why(delegation_status={"valid": False})
    assert WHY_DELEGATION_BROKEN in r.why


def test_authority_approved_vs_missing():
    r_ok = score_with_why(authority_status={"approved": True})
    r_no = score_with_why(authority_status={"approved": False})
    assert WHY_AUTHORITY_APPROVED in r_ok.why
    assert WHY_AUTHORITY_MISSING in r_no.why
    assert WHY_AUTHORITY_APPROVED not in r_no.why


def test_consensus_breach_surfaces_input_safety_breach():
    r = score_with_why(consensus=FakeConsensus(per_dimension={
        "input_safety": FakeDimensionConsensus(consensus="BREACH"),
    }))
    assert WHY_INPUT_SAFETY_BREACH in r.why
    assert WHY_INPUT_SAFETY_OK not in r.why


def test_consensus_all_three_dimensions_ok():
    r = score_with_why(consensus=FakeConsensus(per_dimension={
        "input_safety": FakeDimensionConsensus(consensus="OK"),
        "safety": FakeDimensionConsensus(consensus="OK"),
        "faithfulness": FakeDimensionConsensus(consensus="OK"),
    }))
    assert WHY_INPUT_SAFETY_OK in r.why
    assert WHY_RESPONSE_SAFETY_OK in r.why
    assert WHY_FAITHFULNESS_OK in r.why
    assert r.score == 100
    assert r.verdict == "OK"


def test_consensus_intermediate_states():
    """UNCLEAR / SPLIT / ERROR per dimension all produce distinct
    `why` entries — caller can tell apart "judge abstained" vs
    "judges disagreed" vs "judge crashed"."""
    r = score_with_why(consensus=FakeConsensus(per_dimension={
        "input_safety": FakeDimensionConsensus(consensus="UNCLEAR"),
        "safety": FakeDimensionConsensus(consensus="SPLIT"),
        "faithfulness": FakeDimensionConsensus(consensus="ERROR"),
    }))
    assert WHY_INPUT_SAFETY_UNCLEAR in r.why
    assert WHY_RESPONSE_SAFETY_SPLIT in r.why
    assert WHY_FAITHFULNESS_ERROR in r.why


# ── Composition / non-swallowing ───────────────────────────────────


def test_multiple_negative_findings_all_appear():
    """When multiple primitives report negative findings, every one
    must appear in `why`. Catches accidental short-circuit logic."""
    r = score_with_why(
        chain_status={"valid": False, "broken_at": 1},
        delegation_status={"valid": False},
        authority_status={"approved": False},
        consensus=FakeConsensus(per_dimension={
            "input_safety": FakeDimensionConsensus(consensus="BREACH"),
        }),
    )
    assert WHY_EVIDENCE_TAMPERED in r.why
    assert WHY_DELEGATION_BROKEN in r.why
    assert WHY_AUTHORITY_MISSING in r.why
    assert WHY_INPUT_SAFETY_BREACH in r.why


def test_mixed_positives_and_negatives_both_surface():
    """Chain valid + delegation broken: both must appear; one doesn't
    suppress the other."""
    r = score_with_why(
        chain_status={"valid": True},
        delegation_status={"valid": False},
    )
    assert WHY_EVIDENCE_VERIFIED in r.why
    assert WHY_DELEGATION_BROKEN in r.why


# ── Determinism + idempotence ──────────────────────────────────────


def test_deterministic_ordering_across_repeat_calls():
    """Same inputs produce byte-identical `why` lists across N calls."""
    kwargs = dict(
        chain_status={"valid": True},
        delegation_status={"valid": True},
        consensus=FakeConsensus(per_dimension={
            "input_safety": FakeDimensionConsensus(consensus="OK"),
            "safety": FakeDimensionConsensus(consensus="OK"),
        }),
    )
    first = score_with_why(**kwargs)
    for _ in range(10):
        repeat = score_with_why(**kwargs)
        assert repeat.why == first.why
        assert repeat.evidence_links == first.evidence_links
        assert repeat.score == first.score
        assert repeat.verdict == first.verdict


def test_consumed_inputs_correctly_lists_only_passed_primitives():
    r = score_with_why(
        chain_status={"valid": True},
        consensus=FakeConsensus(per_dimension={
            "safety": FakeDimensionConsensus(consensus="OK")}),
    )
    assert set(r.consumed_inputs) == {"chain_status", "consensus"}
    assert "delegation_status" not in r.consumed_inputs
    assert "authority_status" not in r.consumed_inputs


def test_consumed_inputs_records_empty_per_dimension_consensus():
    """Pro layer relies on `consumed_inputs` to tell "checked but no
    findings" from "never checked." A consensus with empty
    per_dimension dict MUST still register as consumed, otherwise
    Pro can't distinguish "judges ran, nothing to report" from
    "judges never ran"."""
    r = score_with_why(consensus=FakeConsensus(per_dimension={}))
    assert "consensus" in r.consumed_inputs
    assert r.why == []  # nothing to say, but consensus WAS checked
    assert r.score == 100


# ── Edge cases ─────────────────────────────────────────────────────


def test_empty_inputs_returns_empty_why_not_crash():
    """All primitives unset → score 100, empty why, OK verdict."""
    r = score_with_why()
    assert r.why == []
    assert r.evidence_links == []
    assert r.consumed_inputs == []
    assert r.score == 100
    assert r.verdict == "OK"


def test_two_different_inputs_produce_different_why():
    """Trivial discrimination — proves the function actually reads
    its inputs (catches a `return ConstantResult` regression)."""
    r1 = score_with_why(chain_status={"valid": True})
    r2 = score_with_why(chain_status={"valid": False})
    assert r1.why != r2.why
    # Categorical outcome differs even though both happen to land in
    # the "OK" verdict band (100 and 80 are both ≥ 80).
    assert WHY_EVIDENCE_VERIFIED in r1.why
    assert WHY_EVIDENCE_TAMPERED in r2.why
    assert r1.score > r2.score


# ── Score arithmetic + verdict thresholds ──────────────────────────


def test_score_arithmetic_negative_penalties():
    """1 negative → 80, 2 negatives → 60, 3 negatives → 40,
    4 negatives → 20."""
    r1 = score_with_why(chain_status={"valid": False, "broken_at": 1})
    assert r1.score == 80
    r2 = score_with_why(
        chain_status={"valid": False, "broken_at": 1},
        delegation_status={"valid": False},
    )
    assert r2.score == 60
    r3 = score_with_why(
        chain_status={"valid": False, "broken_at": 1},
        delegation_status={"valid": False},
        authority_status={"approved": False},
    )
    assert r3.score == 40
    r4 = score_with_why(
        chain_status={"valid": False, "broken_at": 1},
        delegation_status={"valid": False},
        authority_status={"approved": False},
        consensus=FakeConsensus(per_dimension={
            "input_safety": FakeDimensionConsensus(consensus="BREACH"),
        }),
    )
    assert r4.score == 20


def test_score_arithmetic_floor_at_zero():
    """Many negatives shouldn't go below 0."""
    r = score_with_why(
        chain_status={"valid": False, "broken_at": 1},
        delegation_status={"valid": False},
        authority_status={"approved": False},
        consensus=FakeConsensus(per_dimension={
            "input_safety": FakeDimensionConsensus(consensus="BREACH"),
            "safety": FakeDimensionConsensus(consensus="BREACH"),
            "faithfulness": FakeDimensionConsensus(consensus="BREACH"),
        }),
    )
    # 6 negatives × -20 = -120; floored at 0
    assert r.score == 0
    assert r.verdict == "BREACH"


def test_score_arithmetic_indeterminate_smaller_penalty():
    """UNCLEAR / SPLIT are -5 each, not -20."""
    r = score_with_why(consensus=FakeConsensus(per_dimension={
        "input_safety": FakeDimensionConsensus(consensus="UNCLEAR"),
        "safety": FakeDimensionConsensus(consensus="SPLIT"),
    }))
    # 2 indeterminate × -5 = -10; final 90
    assert r.score == 90
    assert r.verdict == "OK"


def test_score_arithmetic_error_smallest_penalty():
    """ERROR is -3 each (smallest)."""
    r = score_with_why(consensus=FakeConsensus(per_dimension={
        "input_safety": FakeDimensionConsensus(consensus="ERROR"),
    }))
    assert r.score == 97
    assert r.verdict == "OK"


def test_verdict_thresholds():
    """Verify the OK/SPLIT/BREACH boundaries."""
    # score 100 → OK
    r_100 = score_with_why()
    assert r_100.score == 100 and r_100.verdict == "OK"
    # score 80 → OK (boundary inclusive)
    r_80 = score_with_why(chain_status={"valid": False, "broken_at": 1})
    assert r_80.score == 80 and r_80.verdict == "OK"
    # score 60 → SPLIT
    r_60 = score_with_why(
        chain_status={"valid": False, "broken_at": 1},
        delegation_status={"valid": False},
    )
    assert r_60.score == 60 and r_60.verdict == "SPLIT"
    # score 40 → BREACH
    r_40 = score_with_why(
        chain_status={"valid": False, "broken_at": 1},
        delegation_status={"valid": False},
        authority_status={"approved": False},
    )
    assert r_40.score == 40 and r_40.verdict == "BREACH"


def test_positive_findings_do_not_increase_score_above_100():
    """Score caps at 100 even when all primitives report positive."""
    r = score_with_why(
        chain_status={"valid": True},
        delegation_status={"valid": True},
        authority_status={"approved": True},
        consensus=FakeConsensus(per_dimension={
            "input_safety": FakeDimensionConsensus(consensus="OK"),
            "safety": FakeDimensionConsensus(consensus="OK"),
            "faithfulness": FakeDimensionConsensus(consensus="OK"),
        }),
    )
    assert r.score == 100


# ── Evidence links collection ──────────────────────────────────────


def test_evidence_links_deduplicated_across_sources():
    """A row id mentioned by both chain_status and delegation_status
    appears only once in evidence_links."""
    r = score_with_why(
        chain_status={"valid": True, "evidence_ids": [42, 42, 100]},
        delegation_status={"valid": True, "edge_ids": [42]},
    )
    # evidence_id=42 only once (from chain_status). edge_id=42 is a
    # separate identifier kind. Both should appear deduplicated.
    assert r.evidence_links.count("evidence_id=42") == 1
    assert "evidence_id=100" in r.evidence_links
    assert "edge_id=42" in r.evidence_links


def test_evidence_links_sorted_lexically_with_known_caveat():
    """Evidence-link ordering is string-lexical (not numeric). This
    test pins the actual order so a future change to use numeric
    sort surfaces immediately — and so callers know what to expect.

    Note: lex sort means `evidence_id=100` < `evidence_id=42` < `=7`
    in the ID number sense, but `=1` < `=4` < `=7` in the string
    sense. This is a documented behavior, not a bug; auditors
    typically display the full list rather than relying on order.
    If we ever want numeric sort, this test pins down what we'd
    have to change.
    """
    r = score_with_why(
        chain_status={"valid": True, "evidence_ids": [100, 42, 7]},
    )
    assert r.evidence_links == [
        "evidence_id=100",  # lex: "1" < "4" < "7"
        "evidence_id=42",
        "evidence_id=7",
    ]


# ── `why` ordering ─────────────────────────────────────────────────


def test_why_ordered_evidence_before_delegation_before_authority_before_consensus():
    """Canonical reading order: evidence → delegation → authority →
    input_safety → response_safety → faithfulness."""
    r = score_with_why(
        chain_status={"valid": True},
        delegation_status={"valid": True},
        authority_status={"approved": True},
        consensus=FakeConsensus(per_dimension={
            "input_safety": FakeDimensionConsensus(consensus="OK"),
            "safety": FakeDimensionConsensus(consensus="OK"),
            "faithfulness": FakeDimensionConsensus(consensus="OK"),
        }),
    )
    assert r.why == [
        WHY_EVIDENCE_VERIFIED,
        WHY_DELEGATION_VERIFIED,
        WHY_AUTHORITY_APPROVED,
        WHY_INPUT_SAFETY_OK,
        WHY_RESPONSE_SAFETY_OK,
        WHY_FAITHFULNESS_OK,
    ]


# ── ConsensusResult compatibility (real upstream object) ───────────


# ── Stable codes parallel `why` ─────────────────────────────────────


def test_why_codes_parallel_to_why_in_every_emission():
    """`why_codes[i]` MUST be the stable identifier for `why[i]`.
    This is the join key Pro's regulator_pack YAML maps to clauses;
    if the parallel-array contract breaks, every Pro mapping
    silently mis-attributes."""
    r = score_with_why(
        chain_status={"valid": True},
        delegation_status={"valid": False},
        authority_status={"approved": True},
        consensus=FakeConsensus(per_dimension={
            "input_safety": FakeDimensionConsensus(consensus="BREACH"),
            "faithfulness": FakeDimensionConsensus(consensus="OK"),
        }),
    )
    assert len(r.why) == len(r.why_codes)
    for human, code in zip(r.why, r.why_codes):
        assert WHY_CODE_TO_STRING[code] == human, (
            f"why_codes[i] does not key into the same wording as "
            f"why[i]: code={code!r} maps to "
            f"{WHY_CODE_TO_STRING.get(code)!r}, but why entry is "
            f"{human!r}"
        )


def test_why_codes_are_stable_identifiers_not_english():
    """`why_codes` are UPPER_SNAKE_CASE identifiers, NOT human
    English. Pro's YAML keys on these codes."""
    r = score_with_why(
        chain_status={"valid": True},
        consensus=FakeConsensus(per_dimension={
            "input_safety": FakeDimensionConsensus(consensus="BREACH"),
        }),
    )
    for code in r.why_codes:
        # Codes are UPPER_SNAKE — must be upper AND contain
        # underscore (catches a regression to lowercase or to a
        # single-word identifier without the underscore separator).
        assert code.isupper() and "_" in code, (
            f"why_code {code!r} is not UPPER_SNAKE_CASE"
        )
        assert " " not in code
        # And every code is registered
        assert code in WHY_CODE_TO_STRING


def test_why_codes_vocabulary_is_complete():
    """WHY_CODE_TO_STRING must be a bijection over the vocabulary.
    Catches: a contributor adds a vocabulary entry but forgets to
    register its stable code, breaking Pro's join."""
    assert set(WHY_CODE_TO_STRING.values()) == set(WHY_VOCABULARY), (
        "WHY_CODE_TO_STRING is not a bijection over WHY_VOCABULARY. "
        "Every vocabulary entry MUST have a stable code; every "
        "stable code MUST be in the vocabulary."
    )
    # Also: every code is unique (no duplicate keys in the dict —
    # Python would have deduped, but assert for clarity).
    assert len(WHY_CODE_TO_STRING) == len(set(WHY_CODE_TO_STRING))


# ── Duck-typing failure mode ────────────────────────────────────────


def test_malformed_consensus_raises_typeerror_not_silently_returns_ok():
    """Passing `consensus=42` (or any object without a
    `per_dimension` attribute) MUST raise TypeError. Pre-fix the
    `getattr(...) or {}` pattern silently returned score 100, masking
    integration bugs."""
    for bad in (42, "not a consensus", object(), [1, 2, 3]):
        with pytest.raises(TypeError) as ei:
            score_with_why(consensus=bad)
        assert "per_dimension" in str(ei.value)


def test_malformed_consensus_message_points_at_fix():
    """The TypeError message must tell the operator how to fix
    (point at ConsensusResult). A bare 'invalid input' is no use to
    a customer."""
    with pytest.raises(TypeError) as ei:
        score_with_why(consensus="oops")
    assert "ConsensusResult" in str(ei.value)


# ── Real upstream object compatibility ──────────────────────────────


def test_real_consensus_result_object_works():
    """score_with_why must accept the actual ConsensusResult from
    check_consensus, not just our test fakes. Ensures we don't ship
    code that only works against duck-typed mocks."""
    from kya.scorer_orchestrator import (
        ConsensusResult,
        DimensionConsensus,
    )
    real = ConsensusResult(
        consensus="OK", breach_votes=0, ok_votes=1,
        unclear_votes=0, error_votes=0, agreement_pct=1.0,
        judges=[], total_latency_ms=0,
        per_dimension={
            "input_safety": DimensionConsensus(
                dimension="input_safety", consensus="OK",
                breach_votes=0, ok_votes=1, unclear_votes=0,
                error_votes=0, agreement_pct=1.0,
                participating_judges=["test"]),
        },
    )
    r = score_with_why(consensus=real)
    assert WHY_INPUT_SAFETY_OK in r.why
    assert r.score == 100
