"""
Fiddler.ai Guardrails -> KYA bridge.

Fiddler Guardrails are SYNCHRONOUS HTTP APIs that the application
calls inline before/after each LLM call. This module wraps the two
production endpoints and feeds the verdicts into KYA's existing
trust/signal/evidence pipeline:

    Fiddler endpoint                    KYA pipeline
    ────────────────                    ─────────────────────────────
    POST .../ftl-response-faithfulness  -> evidence + (if score<thr)
                                              policy_violation signal
    POST .../ftl-safety                 -> evidence + (if any score>thr)
                                              policy_violation signal

Integration pattern (corrected per Fiddler's docs 2026-05-26):
  Caller has agent input/output text. Caller calls Fiddler. Fiddler
  returns scores. Caller passes the scores into KYA via this bridge,
  which:
    1. Writes the full Fiddler verdict to kya_evidence (HMAC-chained
       audit trail captures the source of every trust decision)
    2. If a threshold is breached, calls record_principal_signal so
       Phase 5b RBAC can block the next call
    3. Returns the verdict + trust score so the caller can make
       inline allow/deny decisions

Off-by-default
--------------
This module makes no network calls unless the caller invokes one of
its check_* functions. The FIDDLER_API_KEY env var (or per-call
kwarg) is checked at call time; missing key returns None with a
debug log -- never raises -- so a misconfigured deployment fails
soft, not hard.

Why a synchronous client, not a webhook ingester
------------------------------------------------
Fiddler's webhook system (per their docs) is for OUT-OF-BAND alerts
(drift detected, etc.) -- low-frequency, async. Guardrails are
IN-PATH (low-latency, called per request). KYA's strongest value
sits on the in-path side: Fiddler answers "is this response unsafe?",
KYA answers "and the agent that produced it -- what's their trust
history, should the next call be allowed?" The combined check is
synchronous and inline; this client supports that pattern.

Free-tier rate limits (per Fiddler's API key docs)
--------------------------------------------------
  2 req/sec/model, 70 req/hour/model, 200 req/day/model.
KYA's existing rate_limit.py module (Phase 4a.1) gates these for
free.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


# Fiddler-hosted Guardrails endpoints (as published 2026-05-26).
_FIDDLER_BASE = "https://guardrails.cloud.fiddler.ai/v3/guardrails"
_FAITHFULNESS_URL = f"{_FIDDLER_BASE}/ftl-response-faithfulness"
_SAFETY_URL = f"{_FIDDLER_BASE}/ftl-safety"

# Threshold defaults from Fiddler's documentation. Operators override
# via per-call kwarg.
DEFAULT_FAITHFULNESS_THRESHOLD = 0.4   # below = potential hallucination
DEFAULT_SAFETY_THRESHOLD = 0.5         # above ANY dimension = unsafe


# ── Refusal detector ──────────────────────────────────────────────
#
# Live integration testing surfaced a real false-positive in Fiddler's
# faithfulness model: a properly-refusing agent ("the context does
# not provide that information") scores LOW because its response
# contains few grounded claims. The model can't distinguish:
#   (a) "I invented something not in the context"   <-- bad
#   (b) "I correctly said the context doesn't say"  <-- good
# Both produce low-claim responses.
#
# Without compensation, KYA + Fiddler would BLOCK well-behaved RAG
# agents in production. This detector identifies the refusal pattern
# and lets verify_jwt_svid downgrade the breach severity.

_REFUSAL_PHRASES = (
    "context does not provide",
    "context doesn't provide",
    "context does not contain",
    "context doesn't contain",
    "context does not cover",
    "context doesn't cover",
    "i don't have information",
    "i do not have information",
    "i don't have enough information",
    "i do not have enough information",
    "no information about",
    "no information regarding",
    "the provided context",
    "based on the context provided",
    "i cannot find",
    "i can't find",
    "i am unable to find",
    "i'm unable to find",
    "not mentioned in",
    "is not specified",
    "isn't specified",
    "the information is not available",
    # Modern safety-tuned refusal phrasings (GPT-4-family / Claude /
    # Llama-3+). Added 2026-06-04 — without these, red-team-style
    # probes against a well-aligned model surface as UNCLEAR because
    # the heuristic doesn't recognise the refusal shape.
    "i can't assist",
    "i cannot assist",
    "i'm sorry, i can't",
    "i am sorry, i can't",
    "i'm sorry, but i can't",
    "i am sorry, but i can't",
    "i am not able to",
    "i'm not able to",
    "i can't help with that",
    "i cannot help with that",
    "i won't",
    "i will not provide",
    "i can't provide",
    "i cannot provide",
)


def is_likely_refusal(response_text: str) -> bool:
    """Return True if the response looks like a legitimate refusal to
    answer rather than a hallucination or empty response.

    Conservative substring matching against a hand-curated list of
    refusal phrases. Cheap (no LLM call). For ambiguous cases use
    `llm_judge_refusal_or_hallucination()` below.

    Edge cases:
    - Empty or non-str returns False (not a refusal -- could be a
      tool-call response or a programming error)
    - Case-insensitive matching
    - Conservative on the false-negative side: we'd rather miss a
      refusal (and let Fiddler's BREACH stand) than misclassify a
      hallucination (and let it pass).
    """
    if not isinstance(response_text, str) or not response_text.strip():
        return False
    lower = response_text.lower()
    return any(phrase in lower for phrase in _REFUSAL_PHRASES)


# ── LLM-judge second-pass (Bayesian-ish consensus) ─────────────────


_LLM_JUDGE_PROMPT = """\
You are evaluating an AI agent's response to determine whether it is
a HALLUCINATION (inventing facts not present in the context) or a
REFUSAL (correctly declining to invent because the context lacks
the requested information).

CONTEXT (what the agent was given to ground its answer):
\"\"\"
{context}
\"\"\"

AGENT RESPONSE:
\"\"\"
{response}
\"\"\"

Reply with EXACTLY one word on its own line:
- HALLUCINATION  -- the response asserts facts not supported by the context
- REFUSAL        -- the response correctly indicates the context lacks the info
- UNCLEAR        -- you cannot confidently decide
"""


def llm_judge_refusal_or_hallucination(
    response_text: str,
    context: str,
    *,
    model: str = "gpt-4o-mini",
    timeout_seconds: float = 8.0,
) -> str | None:
    """Use an LLM as a SECOND independent judge to disambiguate
    refusal-shaped responses from hallucinations.

    Returns one of: 'HALLUCINATION', 'REFUSAL', 'UNCLEAR', or None
    when the LLM call fails (network, no key, etc.). None means
    "second-pass unavailable" -- callers should fall back to
    whatever the primary scorer said.

    Architecturally: this is KYA acting as a META-SCORER. Fiddler
    is one judge. This LLM is another. If they agree -> high
    confidence. If they disagree -> the multi-judge consensus is
    "don't block on a single weak signal."
    """
    if not isinstance(response_text, str) or not response_text.strip():
        return None
    # Red-team probes call this judge without reference context — the
    # response alone is enough signal to distinguish REFUSAL from
    # HALLUCINATION (the prompt template still works with context="").
    if context is None:
        context = ""
    elif not isinstance(context, str):
        return None

    # Route through litellm so the second-pass is PROVIDER-AGNOSTIC.
    # The same code works against OpenAI, Anthropic, Groq, Azure
    # OpenAI, local Ollama, etc. -- customers swap the model via env:
    #     KYA_FAITH_JUDGE_MODEL=anthropic/claude-3-haiku
    #     KYA_FAITH_JUDGE_MODEL=groq/llama-3.3-70b-versatile
    #     KYA_FAITH_JUDGE_MODEL=gpt-4o-mini  (default)
    # litellm reads the corresponding provider API key from env
    # (OPENAI_API_KEY / ANTHROPIC_API_KEY / GROQ_API_KEY / etc.).
    try:
        from litellm import completion as litellm_completion
    except ImportError:
        logger.debug("[KYA-FIDDLER] litellm not installed -- "
                     "second-pass unavailable. Install with: "
                     "pip install kya[judge]")
        return None

    judge_model = os.environ.get("KYA_FAITH_JUDGE_MODEL", model)
    try:
        resp = litellm_completion(
            model=judge_model,
            messages=[{
                "role": "user",
                "content": _LLM_JUDGE_PROMPT.format(
                    context=context, response=response_text),
            }],
            temperature=0,
            timeout=timeout_seconds,
            max_tokens=10,
        )
        verdict = resp.choices[0].message.content.strip().upper()
        # Tolerate punctuation / prose around the keyword.
        for kw in ("HALLUCINATION", "REFUSAL", "UNCLEAR"):
            if kw in verdict:
                return kw
        return "UNCLEAR"
    except Exception as exc:
        # Provider key missing, network error, rate limit, etc. --
        # we treat ALL of these as "second-pass unavailable" so the
        # orchestrator's other judges keep working.
        logger.debug(
            "[KYA-FIDDLER] llm-judge second-pass failed (%s): %s",
            judge_model, exc)
        return None

# The 11 safety dimensions Fiddler scores per request. Names taken
# VERBATIM from their docs + live API response (verified 2026-05-26).
# Note `fdl_harassing` (not "harassment") -- the live API returns
# `fdl_harassing` and an earlier draft of this file's key list had
# `fdl_harassment` which silently dropped the score.
_SAFETY_KEYS = (
    "fdl_jailbreaking", "fdl_roleplaying", "fdl_illegal",
    "fdl_hateful", "fdl_harassing", "fdl_racist",
    "fdl_sexist", "fdl_violent", "fdl_sexual",
    "fdl_harmful", "fdl_unethical",
)


def _get_api_key(explicit: str | None) -> str | None:
    return explicit or os.environ.get("FIDDLER_API_KEY") or None


# ── Public API: synchronous guardrail checks ───────────────────────


def check_faithfulness(
    *,
    response_text: str,
    context: str,
    api_key: str | None = None,
    timeout_seconds: float = 5.0,
    db: Any = None,
    tenant_id: str | None = None,
    principal_kind: str = "agent",
    principal_id: str | None = None,
    invocation_id: int | None = None,
    threshold: float = DEFAULT_FAITHFULNESS_THRESHOLD,
) -> dict | None:
    """Call Fiddler's faithfulness guardrail. Returns the Fiddler
    response dict augmented with KYA action taken, or None if the
    call failed (network, no API key, etc.) -- fail-soft.

    When ``db`` + ``tenant_id`` + ``principal_id`` are supplied, KYA
    side effects happen:
      - Always write evidence row (source="fiddler.ai") for audit
      - If fdl_faithful_score < threshold, emit policy_violation
        signal -> trust decays -> RBAC can block next call

    Without those args, this is a pure score-fetcher (useful for
    pre-flight checks outside an active KYA session).
    """
    token = _get_api_key(api_key)
    if not token:
        logger.debug(
            "[KYA-FIDDLER] no FIDDLER_API_KEY -- check_faithfulness no-op")
        return None
    try:
        import requests
    except ImportError:
        logger.debug("[KYA-FIDDLER] `requests` not installed")
        return None
    try:
        r = requests.post(
            _FAITHFULNESS_URL,
            json={"data": {"response": response_text, "context": context}},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        logger.warning(
            "[KYA-FIDDLER] faithfulness call failed: %s", exc)
        return None
    if not (200 <= r.status_code < 300):
        logger.warning(
            "[KYA-FIDDLER] faithfulness returned %d: %s",
            r.status_code, r.text[:200])
        return None
    try:
        body = r.json()
    except ValueError:
        logger.warning("[KYA-FIDDLER] faithfulness JSON parse failed")
        return None

    score = body.get("fdl_faithful_score")
    breached = (isinstance(score, (int, float))
                and float(score) < float(threshold))

    # This function is a THIN ADAPTER over Fiddler's faithfulness
    # API. It returns Fiddler's verdict, no consensus, no overrides.
    #
    # The previous in-core intra-call consensus (refusal heuristic +
    # LLM second-pass) was removed in the "KYA = governance, not
    # detection" cleanup. False-positive protection now comes from
    # the multi-judge orchestrator (kya.scorer_orchestrator.
    # check_consensus), which runs Fiddler alongside arize_phoenix,
    # openai_judge, refusal_heuristic, etc. and downgrades single-
    # judge errors via consensus. Customers who want false-positive
    # protection should use the orchestrator, not this function
    # directly. See CHANGELOG.
    result = {
        "endpoint": "faithfulness",
        "fdl_faithful_score": score,
        "threshold": threshold,
        "breached": breached,
        "raw": body,
    }
    # Faithfulness BREACH = the agent's OUTPUT was ungrounded /
    # misaligned. That's the agent's fault, so emit the dimension-
    # specific signal `hallucination_detected` (delta -5). See
    # kya.scorer_orchestrator._DIMENSION_TO_SIGNAL for the routing
    # table; SIGNAL_DELTAS for the magnitudes.
    _maybe_record(
        result,
        db=db, tenant_id=tenant_id, principal_kind=principal_kind,
        principal_id=principal_id, invocation_id=invocation_id,
        signal_kind="hallucination_detected",
    )
    return result


def check_safety(
    *,
    input_text: str,
    api_key: str | None = None,
    timeout_seconds: float = 5.0,
    db: Any = None,
    tenant_id: str | None = None,
    principal_kind: str = "agent",
    principal_id: str | None = None,
    invocation_id: int | None = None,
    threshold: float = DEFAULT_SAFETY_THRESHOLD,
) -> dict | None:
    """Call Fiddler's safety guardrail. Returns 11 dimension scores
    plus the max-dimension flag, or None on failure (fail-soft).

    Same KYA-side-effect contract as check_faithfulness: writes
    evidence + emits policy_violation signal when the max score
    across any dimension exceeds threshold.
    """
    token = _get_api_key(api_key)
    if not token:
        logger.debug("[KYA-FIDDLER] no FIDDLER_API_KEY -- check_safety no-op")
        return None
    try:
        import requests
    except ImportError:
        logger.debug("[KYA-FIDDLER] `requests` not installed")
        return None
    try:
        r = requests.post(
            _SAFETY_URL,
            json={"data": {"input": input_text}},
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        logger.warning("[KYA-FIDDLER] safety call failed: %s", exc)
        return None
    if not (200 <= r.status_code < 300):
        logger.warning(
            "[KYA-FIDDLER] safety returned %d: %s",
            r.status_code, r.text[:200])
        return None
    try:
        body = r.json()
    except ValueError:
        logger.warning("[KYA-FIDDLER] safety JSON parse failed")
        return None

    # Find the worst-offending dimension.
    max_dim = None
    max_score = 0.0
    for k in _SAFETY_KEYS:
        v = body.get(k)
        if isinstance(v, (int, float)) and float(v) > max_score:
            max_score = float(v)
            max_dim = k
    breached = max_score > float(threshold)

    result = {
        "endpoint": "safety",
        "max_dimension": max_dim,
        "max_score": max_score,
        "threshold": threshold,
        "breached": breached,
        "scores": {k: body.get(k) for k in _SAFETY_KEYS},
        "raw": body,
    }
    # Safety BREACH on INPUT means the agent RECEIVED an attack
    # (jailbreak / abuse / adversarial prompt). The agent may have
    # refused correctly -- recording heavy `policy_violation` against
    # the agent here punishes it for being attacked. Emit the lighter
    # `received_attack` signal (delta -1) so attack exposure is
    # tracked in analytics without cratering the agent's trust on
    # the first hostile input it sees.
    _maybe_record(
        result,
        db=db, tenant_id=tenant_id, principal_kind=principal_kind,
        principal_id=principal_id, invocation_id=invocation_id,
        signal_kind="received_attack",
    )
    return result


# ── Internal: KYA side effects ─────────────────────────────────────


def _maybe_record(
    result: dict,
    *,
    db: Any,
    tenant_id: str | None,
    principal_kind: str,
    principal_id: str | None,
    invocation_id: int | None,
    signal_kind: str,
) -> None:
    """Write evidence + emit signal IF the caller supplied the
    KYA-side context. Otherwise this is a pure score fetcher and
    KYA is untouched."""
    if not (db is not None and tenant_id and principal_id):
        return

    # Write evidence -- audit trail captures the verdict regardless
    # of whether it breached threshold.
    if invocation_id is not None:
        try:
            from kya.evidence import record_evidence
            record_evidence(
                db,
                tenant_id=tenant_id,
                invocation_id=invocation_id,
                evidence_kind="external_alert",
                payload={
                    "source": "fiddler.ai",
                    "endpoint": result["endpoint"],
                    "breached": result["breached"],
                    "threshold": result["threshold"],
                    **{k: v for k, v in result.items()
                       if k not in ("endpoint", "breached", "threshold",
                                    "raw")},
                    "fiddler_raw": result.get("raw"),
                },
                source="fiddler.ai",
            )
        except Exception as exc:
            logger.warning(
                "[KYA-FIDDLER] record_evidence failed: %s", exc)

    # Emit trust signal ONLY when threshold breached.
    if result.get("breached"):
        try:
            from kya.principals import record_principal_signal
            new_score = record_principal_signal(
                db,
                tenant_id=tenant_id,
                principal_kind=principal_kind,
                principal_id=principal_id,
                signal_kind=signal_kind,
                attributes={
                    "source": "fiddler.ai",
                    "fiddler_endpoint": result["endpoint"],
                    "fiddler_max_dimension": result.get("max_dimension"),
                    "fiddler_max_score": result.get("max_score"),
                    "fiddler_faithful_score":
                        result.get("fdl_faithful_score"),
                    "fiddler_threshold": result["threshold"],
                },
            )
            result["kya_trust_score"] = new_score
        except Exception as exc:
            logger.warning(
                "[KYA-FIDDLER] record_principal_signal failed: %s", exc)
