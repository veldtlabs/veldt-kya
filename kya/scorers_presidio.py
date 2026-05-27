"""Microsoft Presidio PII detector as a KYA judge -- OPT-IN ADAPTER.

This module is NOT part of the core KYA SDK runtime. Presidio is an
OPTIONAL dependency. KYA only adds Presidio to the judge panel when
the consumer explicitly calls `register_presidio_adapter()`.

Install:
    pip install kya[presidio]

or equivalently:
    pip install presidio-analyzer

Usage (default = strict, scans for all 10 structured PII types):

    from kya.scorers_presidio import register_presidio_adapter
    register_presidio_adapter()
    # check_consensus() now includes kya_presidio.

Tuning the noise vs coverage tradeoff
-------------------------------------
PII detection is INDUSTRY-DEPENDENT. Corporate SaaS traffic is full
of internal emails -- if EMAIL_ADDRESS findings BREACH, every
benign message flags. Healthcare and finance see emails as PHI/PII
and want them flagged. Different policies for different operators.

Knobs (all kwargs on `register_presidio_adapter()`):

    entities         List of Presidio entity types to scan for.
                     Default = all 10 supported types. Override to
                     reduce scope: `entities=["US_SSN", "CREDIT_CARD"]`.

    ignore_entities  Entity types to DETECT and record (in audit
                     trail) but NOT count toward BREACH. Useful for
                     SaaS where emails are everywhere:
                     `ignore_entities=["EMAIL_ADDRESS"]`.

    threshold        Minimum recognizer score required to BREACH.
                     Default 0.5. Presidio recognizers report 0.0-1.0;
                     SSN typically 0.5 (regex-only), Luhn-valid CC
                     ~0.85, email 1.0 (unambiguous regex). Raising
                     to 0.7 ignores SSN-shape false positives.

    min_findings     Number of distinct PII findings required to
                     BREACH. Default 1 (any PII triggers). Raising
                     to 2 means "single PII is recorded but doesn't
                     block -- a combination of two does."

    scan_response    Whether to scan the AGENT'S response for output-
                     side PII leak. Default False (matches the
                     dimension="input_safety" we register under).
                     Set True to ALSO check whether the agent
                     echoed PII into its reply -- but consider
                     registering a SEPARATE adapter with
                     dimension="safety" instead for cleaner audit.

Examples:

    # SaaS company: ignore corporate-email noise, flag SSN/CC/etc.
    register_presidio_adapter(
        ignore_entities=["EMAIL_ADDRESS"])

    # Strict HIPAA: every PII type matters
    register_presidio_adapter()    # all defaults

    # Combination-only: any single PII OK, two together = exfil
    register_presidio_adapter(
        ignore_entities=["EMAIL_ADDRESS"],
        min_findings=2)

    # Custom narrow scope: only financial PII
    register_presidio_adapter(
        entities=["CREDIT_CARD", "US_BANK_NUMBER", "IBAN_CODE"])

Lightweight design
------------------
We use Presidio's PATTERN-BASED recognizers directly, NOT the
`AnalyzerEngine` with spaCy NLP. This avoids the ~50MB spaCy model
dependency. The tradeoff: we catch STRUCTURED PII (SSN, CC, IBAN,
email, phone, passport, medical license, bank account, IP, ITIN)
but not free-text names/locations.

For free-text PERSON/LOCATION detection, customers can register a
separate adapter on top of Presidio's full AnalyzerEngine.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


# All 10 supported pattern-only recognizers. Listed so customers can
# see what's available for the `entities=` filter.
_SUPPORTED_ENTITIES = (
    "CREDIT_CARD",
    "US_SSN",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_BANK_NUMBER",
    "US_ITIN",
    "US_PASSPORT",
    "MEDICAL_LICENSE",
)


# Lazy-instantiated recognizer registry keyed by frozenset of
# requested entity types. Most deployments register once and stick
# with one config.
_RECOGNIZER_CACHE: dict[frozenset[str], list[Any]] = {}


def _build_recognizers(entities: tuple[str, ...]) -> list[Any]:
    """Instantiate the requested pattern recognizers. Raises a
    helpful error if presidio-analyzer is missing."""
    key = frozenset(entities)
    if key in _RECOGNIZER_CACHE:
        return _RECOGNIZER_CACHE[key]

    try:
        from presidio_analyzer.predefined_recognizers import (
            CreditCardRecognizer,
            EmailRecognizer,
            IbanRecognizer,
            IpRecognizer,
            MedicalLicenseRecognizer,
            PhoneRecognizer,
            UsBankRecognizer,
            UsItinRecognizer,
            UsPassportRecognizer,
            UsSsnRecognizer,
        )
    except ImportError as exc:
        raise RuntimeError(
            "presidio-analyzer is not installed. The kya_presidio "
            "judge is an OPTIONAL adapter; install it with:\n"
            "    pip install kya[presidio]\n"
            "or:\n"
            "    pip install presidio-analyzer"
        ) from exc

    factory_by_entity = {
        "CREDIT_CARD": CreditCardRecognizer,
        "US_SSN": UsSsnRecognizer,
        "EMAIL_ADDRESS": EmailRecognizer,
        "PHONE_NUMBER": PhoneRecognizer,
        "IBAN_CODE": IbanRecognizer,
        "IP_ADDRESS": IpRecognizer,
        "US_BANK_NUMBER": UsBankRecognizer,
        "US_ITIN": UsItinRecognizer,
        "US_PASSPORT": UsPassportRecognizer,
        "MEDICAL_LICENSE": MedicalLicenseRecognizer,
    }
    recognizers = []
    for ent in entities:
        factory = factory_by_entity.get(ent)
        if factory is None:
            raise ValueError(
                f"Unknown Presidio entity type: {ent!r}. "
                f"Supported: {_SUPPORTED_ENTITIES}")
        recognizers.append(factory())

    _RECOGNIZER_CACHE[key] = recognizers
    return recognizers


def _scan(text: str | None, recognizers: list[Any]) -> list[dict]:
    """Run the recognizers over `text`. Returns one dict per finding."""
    if not text:
        return []
    findings: list[dict] = []
    for recognizer in recognizers:
        try:
            # `nlp_artifacts=None` skips the NLP step.
            results = recognizer.analyze(
                text=text,
                entities=recognizer.supported_entities,
                nlp_artifacts=None,
            )
        except Exception as exc:
            logger.debug(
                "[KYA-PRESIDIO] recognizer %s raised: %s",
                recognizer.__class__.__name__, exc)
            continue
        for r in results:
            findings.append({
                "entity_type": r.entity_type,
                "score": float(r.score),
                "start": r.start,
                "end": r.end,
            })
    return findings


def register_presidio_adapter(
    *,
    entities: list[str] | tuple[str, ...] | None = None,
    ignore_entities: list[str] | tuple[str, ...] | None = None,
    threshold: float = 0.5,
    min_findings: int = 1,
    scan_response: bool = False,
) -> None:
    """Register Presidio as the `kya_presidio` judge.

    Default = strict: scans for all 10 structured PII types,
    BREACHes on any single high-confidence (>=0.5) finding.
    Customers tune via kwargs (see module docstring for examples).

    Parameters
    ----------
    entities : iterable[str], optional
        Which PII entity types to scan. Default = all 10
        (see `_SUPPORTED_ENTITIES`). Unknown names raise ValueError.
    ignore_entities : iterable[str], optional
        Detected and recorded in audit trail, but NOT counted toward
        BREACH. Use to suppress noise (e.g. EMAIL_ADDRESS in SaaS).
    threshold : float
        Minimum Presidio score required to count toward BREACH.
        Default 0.5.
    min_findings : int
        Number of qualifying findings (after `ignore_entities` and
        `threshold` filters) required to BREACH. Default 1.
    scan_response : bool
        Whether to also scan the agent's response. Default False --
        the judge is registered with dimension="input_safety" so it
        scans input + context only. Customers wanting output-side
        PII leak detection should register a separate adapter with
        a different name and dimension="safety".
    """
    from kya.scorer_orchestrator import JudgeResult, register_judge

    # Normalize + validate entity lists
    if entities is None:
        entities_tuple = _SUPPORTED_ENTITIES
    else:
        entities_tuple = tuple(entities)
        unknown = set(entities_tuple) - set(_SUPPORTED_ENTITIES)
        if unknown:
            raise ValueError(
                f"Unknown Presidio entity types: {sorted(unknown)}. "
                f"Supported: {_SUPPORTED_ENTITIES}")

    ignore_set = set(ignore_entities or ())
    unknown_ignore = ignore_set - set(_SUPPORTED_ENTITIES)
    if unknown_ignore:
        raise ValueError(
            f"Unknown entity types in ignore_entities: "
            f"{sorted(unknown_ignore)}. "
            f"Supported: {_SUPPORTED_ENTITIES}")
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(
            f"threshold must be in [0.0, 1.0]; got {threshold}")
    if min_findings < 1:
        raise ValueError(
            f"min_findings must be >= 1; got {min_findings}")

    # Pre-instantiate recognizers (and verify Presidio is installed)
    recognizers = _build_recognizers(entities_tuple)

    config_summary = {
        "entities": list(entities_tuple),
        "ignore_entities": sorted(ignore_set),
        "threshold": threshold,
        "min_findings": min_findings,
        "scan_response": scan_response,
    }

    def _judge_kya_presidio(
        input_text: str | None,
        response: str | None,
        context: str | None,
    ) -> JudgeResult:
        t0 = time.time()
        # Scan input + context (the surfaces an attacker controls)
        surfaces: list[tuple[str | None, str]] = [
            (input_text, "input"),
            (context, "context"),
        ]
        if scan_response:
            surfaces.append((response, "response"))

        all_findings: list[dict] = []
        for text, surface in surfaces:
            for f in _scan(text, recognizers):
                f["surface"] = surface
                all_findings.append(f)

        # Apply ignore_entities + threshold filters to decide BREACH.
        # Detected-but-ignored findings still appear in detail for
        # the audit trail.
        qualifying = [
            f for f in all_findings
            if f["entity_type"] not in ignore_set
            and f["score"] >= threshold
        ]
        breached = len(qualifying) >= min_findings
        max_score = max(
            (f["score"] for f in qualifying), default=0.0)

        # Audit summary
        entity_counts: dict[str, int] = {}
        ignored_counts: dict[str, int] = {}
        for f in all_findings:
            ent = f["entity_type"]
            if ent in ignore_set or f["score"] < threshold:
                ignored_counts[ent] = ignored_counts.get(ent, 0) + 1
            else:
                entity_counts[ent] = entity_counts.get(ent, 0) + 1

        # Narrow detector: absence of PII is NOT a positive assertion
        # that the input is safe across other dimensions. When we
        # find nothing, we ABSTAIN (UNCLEAR) -- this prevents Presidio
        # from diluting another input_safety judge's positive BREACH.
        # Only when we positively find qualifying PII do we vote.
        if breached:
            verdict = "BREACH"
        elif len(all_findings) > 0:
            # Detected PII but it didn't meet BREACH criteria
            # (below threshold, in ignore_entities, or min_findings
            # not met) -- positive "looks fine on PII" assertion.
            verdict = "OK"
        else:
            # Nothing scanned matched. Narrow detector abstains.
            verdict = "UNCLEAR"

        return JudgeResult(
            judge_name="kya_presidio",
            verdict=verdict,
            raw_score=max_score,
            threshold=threshold,
            latency_ms=int((time.time() - t0) * 1000),
            detail={
                "qualifying_entities": entity_counts,
                "ignored_entities": ignored_counts,
                "total_findings": len(all_findings),
                "qualifying_findings": len(qualifying),
                "findings_preview": all_findings[:5],
                "config": config_summary,
                "library": "presidio-analyzer (pattern-only)",
            },
            dimension="input_safety",
        )

    register_judge("kya_presidio", _judge_kya_presidio)
    logger.info(
        "[KYA-PRESIDIO] kya_presidio registered "
        "(entities=%d, ignored=%d, threshold=%.2f, "
        "min_findings=%d, scan_response=%s)",
        len(entities_tuple), len(ignore_set),
        threshold, min_findings, scan_response)


__all__ = ["register_presidio_adapter", "_SUPPORTED_ENTITIES"]
