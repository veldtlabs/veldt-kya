"""
Multi-judge scorer orchestration for KYA.

ONE call -> N independent judges run in PARALLEL -> single aggregated
verdict + per-judge breakdown. Each judge is a pluggable adapter;
operators register their own with `register_judge()`.

The whole point of this module is to NOT depend on any single judge
being right. Live integration testing surfaced that Fiddler's
faithfulness model penalizes legitimate refusals; that's the kind of
single-judge failure mode that an orchestration layer compensates
for. Two judges must agree to BREACH (default); a single judge being
wrong gets out-voted.

Bundled adapters (in this file)
-------------------------------
  - "fiddler_safety"        -> Fiddler ftl-safety
  - "fiddler_faithfulness"  -> Fiddler ftl-response-faithfulness
  - "openai_judge"          -> direct gpt-4o-mini "refusal vs
                               hallucination" prompt
  - "refusal_heuristic"     -> substring match (no API call)

Optional external adapters (register via register_*_adapter())
--------------------------------------------------------------
  - "lakera_guard"          -> Lakera Guard API (needs LAKERA_API_KEY)
  - "nemo_guardrails"       -> NeMo Guardrails (needs pip install +
                               local config)
  - "arize_phoenix"         -> Phoenix evals (needs pip install
                               arize-phoenix-evals)

Operators add their own:

    from kya.scorer_orchestrator import register_judge, JudgeResult
    def my_custom_judge(input_text, response, context):
        # ... call any API, run any model, return a JudgeResult
        return JudgeResult(...)
    register_judge("my_custom", my_custom_judge)
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ── Result dataclass ───────────────────────────────────────────────


@dataclass
class JudgeResult:
    """One judge's verdict. Aggregator votes over these."""
    judge_name: str
    verdict: str             # "BREACH" | "OK" | "UNCLEAR" | "ERROR"
    raw_score: float | None  # 0-1 if the judge produced a numeric score
    threshold: float | None  # the threshold used
    latency_ms: int
    detail: dict = field(default_factory=dict)
    error: str | None = None
    # Which dimension is this judge scoring? Determines which
    # consensus pool the verdict votes in. Dimensions:
    #   "input_safety"  -- the USER INPUT (jailbreak / abuse /
    #                      adversarial prompt). A BREACH here means
    #                      the agent RECEIVED an attack -- not that
    #                      the agent did anything wrong.
    #   "safety"        -- the AGENT RESPONSE (data leak / unsafe
    #                      content emitted by the agent). A BREACH
    #                      here means the agent COMMITTED a violation.
    #   "faithfulness"  -- the response grounded in the context /
    #                      aligned to the user's intent. A BREACH
    #                      here means hallucination or misalignment.
    #   "any"           -- judge participates in every pool. Use
    #                      sparingly -- it conflates orthogonal
    #                      signals.
    dimension: str = "any"


# Adapter signature -- callable that returns a JudgeResult.
JudgeAdapter = Callable[[str | None, str | None, str | None], JudgeResult]


# Process-wide registry. Adapters register at import time.
_JUDGES: dict[str, JudgeAdapter] = {}


def register_judge(name: str, adapter: JudgeAdapter) -> None:
    """Add a custom judge. Replaces any prior judge with the same name."""
    _JUDGES[name] = adapter
    logger.debug("[KYA-SCORER] registered judge: %s", name)


def list_judges() -> list[str]:
    """Names of all currently-registered judges."""
    return sorted(_JUDGES.keys())


# ── Bundled adapter: Fiddler safety ────────────────────────────────


def _judge_fiddler_safety(
    input_text: str | None,
    response: str | None,
    context: str | None,
) -> JudgeResult:
    """Score the USER INPUT against Fiddler's safety model."""
    from kya.fiddler_bridge import check_safety
    t0 = time.time()
    if not input_text:
        return JudgeResult("fiddler_safety", "UNCLEAR", None, None,
                           int((time.time() - t0) * 1000),
                           detail={"reason": "no input_text"})
    r = check_safety(input_text=input_text)
    latency = int((time.time() - t0) * 1000)
    if r is None:
        return JudgeResult("fiddler_safety", "ERROR", None, None,
                           latency,
                           error="fiddler API unavailable")
    verdict = "BREACH" if r["breached"] else "OK"
    # Fiddler ftl-safety scores the USER INPUT, so this judge votes
    # in the "input_safety" pool, NOT the "safety" pool. A BREACH
    # here means the agent RECEIVED an attack -- the agent itself may
    # still have refused correctly. Conflating these caused live
    # tests to outvote a real input-attack signal with judges that
    # scored the agent's clean refusal as OK.
    return JudgeResult(
        "fiddler_safety", verdict,
        raw_score=r["max_score"], threshold=r["threshold"],
        latency_ms=latency,
        detail={"max_dimension": r["max_dimension"]},
        dimension="input_safety")


register_judge("fiddler_safety", _judge_fiddler_safety)


# ── Bundled adapter: Fiddler faithfulness ──────────────────────────


def _judge_fiddler_faithfulness(
    input_text: str | None,
    response: str | None,
    context: str | None,
) -> JudgeResult:
    """Score response against context with Fiddler's faithfulness model.

    Already includes the refusal-detector + LLM-judge second-pass
    consensus internally (see fiddler_bridge.check_faithfulness)."""
    from kya.fiddler_bridge import check_faithfulness
    t0 = time.time()
    if not response or not context:
        return JudgeResult("fiddler_faithfulness", "UNCLEAR", None,
                           None, int((time.time() - t0) * 1000),
                           detail={"reason": "no response/context"})
    r = check_faithfulness(response_text=response, context=context)
    latency = int((time.time() - t0) * 1000)
    if r is None:
        return JudgeResult("fiddler_faithfulness", "ERROR", None, None,
                           latency,
                           error="fiddler API unavailable")
    verdict = "BREACH" if r["breached"] else "OK"
    return JudgeResult(
        "fiddler_faithfulness", verdict,
        raw_score=r["fdl_faithful_score"], threshold=r["threshold"],
        latency_ms=latency,
        detail={
            "refusal_detected": r.get("refusal_detected"),
            "llm_judge_verdict": r.get("llm_judge_verdict"),
            "breached_raw": r.get("breached_raw"),
        },
        dimension="faithfulness")


register_judge("fiddler_faithfulness", _judge_fiddler_faithfulness)


# ── Bundled adapter: OpenAI direct judge ───────────────────────────


def _judge_openai_direct(
    input_text: str | None,
    response: str | None,
    context: str | None,
) -> JudgeResult:
    """Independent LLM judge using gpt-4o-mini directly."""
    from kya.fiddler_bridge import llm_judge_refusal_or_hallucination
    t0 = time.time()
    if not response:
        return JudgeResult("openai_judge", "UNCLEAR", None, None,
                           int((time.time() - t0) * 1000),
                           detail={"reason": "no response"})
    # Red-team probes pass response without reference context — the judge
    # can still distinguish refusal-shaped output from compliant output
    # using the response alone. fiddler_bridge tolerates context="".
    verdict_word = llm_judge_refusal_or_hallucination(response, context or "")
    latency = int((time.time() - t0) * 1000)
    if verdict_word is None:
        return JudgeResult("openai_judge", "ERROR", None, None,
                           latency, error="openai unavailable")
    # Map LLM judge verdicts to OK/BREACH.
    if verdict_word == "HALLUCINATION":
        verdict = "BREACH"
    elif verdict_word == "REFUSAL":
        verdict = "OK"
    else:  # UNCLEAR
        verdict = "UNCLEAR"
    return JudgeResult(
        "openai_judge", verdict, raw_score=None, threshold=None,
        latency_ms=latency,
        detail={"llm_verdict": verdict_word, "model": "gpt-4o-mini"},
        dimension="faithfulness")


register_judge("openai_judge", _judge_openai_direct)


# ── Bundled adapter: Refusal heuristic (zero-cost) ─────────────────


def _judge_refusal_heuristic(
    input_text: str | None,
    response: str | None,
    context: str | None,
) -> JudgeResult:
    """Substring-based refusal detector. Cheap, fast, no API call."""
    from kya.fiddler_bridge import is_likely_refusal
    t0 = time.time()
    if not response:
        return JudgeResult("refusal_heuristic", "UNCLEAR", None, None,
                           int((time.time() - t0) * 1000))
    is_refusal = is_likely_refusal(response)
    # Refusal heuristic only votes when it RECOGNIZES a refusal.
    # When it can't tell, it abstains (UNCLEAR) rather than voting OK.
    verdict = "OK" if is_refusal else "UNCLEAR"
    return JudgeResult(
        "refusal_heuristic", verdict, None, None,
        int((time.time() - t0) * 1000),
        detail={"matched": is_refusal},
        dimension="faithfulness")


register_judge("refusal_heuristic", _judge_refusal_heuristic)


# Note: the in-core kya_llm_judge adapter was removed in the
# "KYA = governance, not detection" cleanup. Customers wanting a
# generic LLM-as-judge for faithfulness should use the orchestrator's
# arize_phoenix or openai_judge adapters (both via litellm), or
# plug in their own judge via register_judge(). See CHANGELOG.


# ── Bundled adapter: KYA PyRIT scorer (Microsoft PyRIT) ────────────


def _judge_kya_pyrit(
    input_text: str | None,
    response: str | None,
    context: str | None,
) -> JudgeResult:
    """Use the bundled kya_redteam PyRIT scorers.

    PyRIT is Microsoft's Python Risk Identification Toolkit. The
    bundled `kya_redteam.pyrit_scorer` exposes a `build_scorer(kind)`
    factory returning a callable scorer. We instantiate the
    DataLeakScannerScorer + RefusalFailureScorer composite -- both
    work LLM-free (regex/substring heuristics) so the adapter has no
    runtime dependencies and no LLM call.

    More sophisticated PyRIT scorers (self_ask_true_false) require an
    attacker_model + objective; configure those via PyRIT directly and
    register the resulting scorer through ``register_judge``.
    """
    t0 = time.time()
    if not response:
        return JudgeResult("kya_pyrit", "UNCLEAR", None, None,
                           int((time.time() - t0) * 1000),
                           detail={"reason": "no response to score"})
    try:
        from kya_redteam.pyrit_scorer import DataLeakScannerScorer
    except ImportError as exc:
        return JudgeResult("kya_pyrit", "ERROR", None, None,
                           int((time.time() - t0) * 1000),
                           error=f"pyrit_scorer import: {exc}")
    try:
        # PyRIT scorers operate on `.score(prompt, TargetResponse)`.
        # We use DataLeakScannerScorer (PII / secrets / financial /
        # PHI detection) because it's CONTENT-NEUTRAL -- it scores
        # the response on its own, regardless of whether the prompt
        # was hostile. RefusalFailureScorer is INTENTIONALLY excluded
        # here because it assumes the prompt is an attack and treats
        # any non-refusal as a finding -- which is right for red-team
        # campaigns but wrong for general traffic (live testing showed
        # it BREACHES every benign response).
        from kya_redteam.pyrit_target import TargetResponse
        prompt = input_text or ""
        resp = TargetResponse(
            output=response,
            tools_used=[],
            events=[])
        leak_v = DataLeakScannerScorer().score(prompt, resp)
        breached = bool(leak_v.is_finding)
        max_score = leak_v.score
        details = {
            "is_finding": leak_v.is_finding,
            "score": leak_v.score,
            "severity": leak_v.severity,
            "finding_class": leak_v.finding_class,
            "attack_category": leak_v.attack_category,
        }
        return JudgeResult(
            "kya_pyrit",
            "BREACH" if breached else "OK",
            raw_score=max_score, threshold=None,
            latency_ms=int((time.time() - t0) * 1000),
            detail=details,
            dimension="safety")
    except Exception as exc:
        return JudgeResult("kya_pyrit", "ERROR", None, None,
                           int((time.time() - t0) * 1000),
                           error=str(exc))


# Register PyRIT by default -- it has no external API requirements
# (the bundled scorers are heuristic / regex / substring, not
# LLM-based). Caller can unregister or replace if they want.
register_judge("kya_pyrit", _judge_kya_pyrit)


# ── Bundled adapter: KYA input attack pattern detector ─────────────


def _judge_kya_attack_patterns(
    input_text: str | None,
    response: str | None,
    context: str | None,
) -> JudgeResult:
    """High-precision regex/heuristic input_safety judge that
    catches the attack classes Fiddler misses.

    Live testing showed Fiddler's safety model has specific phrasing
    blind spots: it scored 0.007-0.041 on textbook exfiltration,
    PII smuggling, URL exfil, and indirect injection (false
    negatives), while correctly flagging overt jailbreaks at 0.9+.
    This judge fills those gaps with content-neutral pattern matching
    over 7 attack categories: encoded payloads, exfiltration paths,
    action-following directives, external redirects, authority
    claims + urgency, PII smuggling, role hijack, indirect injection
    markers.

    Implementation lives in `kya/input_attack_patterns.py`. No LLM
    call, no API key, no external dependency -- runs in microseconds.
    Dimension is "input_safety" so this judge votes in the same pool
    as `fiddler_safety` -- two judges must agree to BREACH on the
    input, but EITHER can flag a real attack the other missed.
    """
    from kya.input_attack_patterns import scan
    t0 = time.time()
    if not input_text and not context:
        return JudgeResult("kya_attack_patterns", "UNCLEAR",
                           None, None,
                           int((time.time() - t0) * 1000),
                           detail={"reason": "no input or context"})
    try:
        result = scan(input_text, context)
    except Exception as exc:
        return JudgeResult("kya_attack_patterns", "ERROR",
                           None, None,
                           int((time.time() - t0) * 1000),
                           error=str(exc))
    # Narrow detector: absence of attack-pattern hits is NOT a
    # positive assertion that the input is safe. When no category
    # fires at all, we ABSTAIN (UNCLEAR) so this judge doesn't
    # dilute another input_safety judge's positive BREACH. When at
    # least one category fires but below threshold, we vote OK
    # (positive "patterns checked, none qualifying").
    if result.breached:
        verdict = "BREACH"
    elif result.categories:
        verdict = "OK"  # patterns found, below threshold
    else:
        verdict = "UNCLEAR"  # nothing matched; narrow detector abstains
    return JudgeResult(
        "kya_attack_patterns",
        verdict,
        raw_score=result.max_weight,
        threshold=result.breach_threshold,
        latency_ms=int((time.time() - t0) * 1000),
        detail={
            "categories": result.category_names,
            "findings": result.categories[:5],  # top 5 for size cap
        },
        dimension="input_safety")


register_judge("kya_attack_patterns", _judge_kya_attack_patterns)


# NOT auto-registered: PyRIT requires explicit setup. Caller invokes
# `register_judge("kya_pyrit", _judge_kya_pyrit)` after configuring
# their PyRIT target. The function itself is available so customers
# can register it conditionally.


# ── Optional external-framework adapters ───────────────────────────


def register_lakera_adapter(api_key: str | None = None) -> None:
    """Lakera Guard adapter (https://www.lakera.ai/lakera-guard).

    Requires LAKERA_API_KEY env (or kwarg). Adds a "lakera_guard"
    judge that calls Lakera's screen endpoint. The API surface is
    similar shape to Fiddler -- POST JSON, get back per-category
    scores -- so the adapter wires straight into the orchestrator.

    NOT registered by default -- caller invokes this once at startup
    after confirming they have a Lakera contract.
    """
    key = api_key or os.environ.get("LAKERA_API_KEY")
    if not key:
        raise RuntimeError(
            "LAKERA_API_KEY not set -- can't register lakera_guard")
    # Lakera endpoint shape per their docs (placeholder URL --
    # operators verify with their account):
    LAKERA_URL = "https://api.lakera.ai/v1/guard"

    def _lakera(input_text, response, context):
        import requests
        t0 = time.time()
        if not input_text:
            return JudgeResult("lakera_guard", "UNCLEAR", None, None,
                               int((time.time() - t0) * 1000))
        try:
            r = requests.post(
                LAKERA_URL,
                headers={"Authorization": f"Bearer {key}"},
                json={"input": input_text},
                timeout=5.0)
            r.raise_for_status()
            body = r.json()
            # Lakera-specific aggregation -- placeholder shape:
            # operators adapt to their account's actual response.
            categories = body.get("categories", {})
            scores = [v for v in categories.values()
                      if isinstance(v, (int, float))]
            max_score = max(scores) if scores else 0.0
            verdict = "BREACH" if max_score > 0.5 else "OK"
            return JudgeResult(
                "lakera_guard", verdict, max_score, 0.5,
                int((time.time() - t0) * 1000),
                detail={"categories": categories})
        except Exception as exc:
            return JudgeResult(
                "lakera_guard", "ERROR", None, None,
                int((time.time() - t0) * 1000), error=str(exc))

    register_judge("lakera_guard", _lakera)


def register_nemo_adapter() -> None:
    """NeMo Guardrails adapter.

    Requires `pip install nemoguardrails` and a config file. The
    adapter calls `LLMRails.generate()` and inspects whether the
    response was rewritten or blocked.

    NOT registered by default -- caller invokes after install + config.
    """
    try:
        from nemoguardrails import LLMRails, RailsConfig
    except ImportError as exc:
        raise RuntimeError(
            "nemoguardrails not installed -- "
            "pip install nemoguardrails") from exc

    config_path = os.environ.get("NEMO_GUARDRAILS_CONFIG", "./config")
    config = RailsConfig.from_path(config_path)
    rails = LLMRails(config)

    def _nemo(input_text, response, context):
        t0 = time.time()
        if not input_text:
            return JudgeResult("nemo_guardrails", "UNCLEAR", None, None,
                               int((time.time() - t0) * 1000))
        try:
            result = rails.generate(messages=[
                {"role": "user", "content": input_text}])
            # NeMo signals blocking by returning a refusal-shaped message.
            # Heuristic: if rails rewrote the input, it caught something.
            blocked = "i cannot" in (result or "").lower() or \
                      "policy" in (result or "").lower()
            verdict = "BREACH" if blocked else "OK"
            return JudgeResult(
                "nemo_guardrails", verdict, None, None,
                int((time.time() - t0) * 1000),
                detail={"nemo_response": (result or "")[:200]})
        except Exception as exc:
            return JudgeResult(
                "nemo_guardrails", "ERROR", None, None,
                int((time.time() - t0) * 1000), error=str(exc))

    register_judge("nemo_guardrails", _nemo)


def register_langkit_adapter() -> None:
    """LangKit (WhyLabs) adapter -- bundled metric extractors for
    LLM monitoring.

    Requires `pip install langkit[all]` and (optionally) WhyLabs
    credentials. Uses langkit's prompt-injection and toxicity
    extractors as a safety judge.

    NOT registered by default."""
    try:
        # response_consistency + sentiment imports are availability
        # probes -- importing them triggers langkit's extractor
        # registration as a side effect. ruff would flag them as
        # unused; the import IS the use.
        from langkit import extract, response_consistency, sentiment  # noqa: F401
        from langkit.injections import init as injections_init
        injections_init()
    except ImportError as exc:
        raise RuntimeError(
            "langkit not installed -- pip install langkit[all]"
        ) from exc

    def _langkit(input_text, response, context):
        t0 = time.time()
        if not input_text:
            return JudgeResult("langkit_whylabs", "UNCLEAR", None,
                               None, int((time.time() - t0) * 1000))
        try:
            metrics = extract({"prompt": input_text})
            inj_score = metrics.get("prompt.injection", 0.0)
            # LangKit injection score: higher = more injection-like
            verdict = "BREACH" if inj_score > 0.5 else "OK"
            return JudgeResult(
                "langkit_whylabs", verdict,
                raw_score=inj_score, threshold=0.5,
                latency_ms=int((time.time() - t0) * 1000),
                detail={"langkit_metrics":
                        {k: v for k, v in metrics.items()
                         if isinstance(v, (int, float))}},
                dimension="safety")
        except Exception as exc:
            return JudgeResult(
                "langkit_whylabs", "ERROR", None, None,
                int((time.time() - t0) * 1000), error=str(exc))

    register_judge("langkit_whylabs", _langkit)


# Phoenix's hallucination prompt template (public; Apache-2.0 from
# arize-ai/phoenix). Used by our Phoenix-methodology shim below so
# we can run the same eval methodology on platforms where
# arize-phoenix-evals can't install (Windows sqlean.py issue, etc.).
_PHOENIX_HALLUCINATION_PROMPT = """\
In this task, you will be presented with a query, a reference text
and an answer. The answer is generated to the question based on the
reference text. The answer may contain false information. You must
use the reference text to determine if the answer to the question
contains false information, if the answer is consistent with the
reference text. Please read the reference text carefully before
answering.

    [BEGIN DATA]
    ************
    [Query]: {query}
    ************
    [Reference text]: {reference}
    ************
    [Answer]: {response}
    ************
    [END DATA]

Your response must be a single word, either "factual" or
"hallucinated", and should not contain any text or characters aside
from that word. "factual" means the answer is consistent with the
reference text. "hallucinated" means the answer contains
information not supported by the reference text.
"""


def register_phoenix_adapter() -> None:
    """Arize Phoenix evals -- methodology adapter using Phoenix's
    public hallucination prompt template via litellm.

    On Linux you can also `pip install arize-phoenix-evals` for the
    OFFICIAL implementation; on Windows the official package's
    sqlean.py dependency fails to build, so this shim uses the same
    prompt + scoring logic via litellm directly. Same evaluation,
    no broken native deps.

    Pair with Phoenix Docker (`docker compose -f docker-compose.phoenix.yml
    up -d`) when you want the Phoenix UI for trace + eval inspection.
    The orchestrator adapter itself doesn't depend on the server --
    it's just the methodology applied to your data.

    NOT registered by default -- caller invokes after litellm is
    installed AND a provider key is in env (OPENAI_API_KEY etc.).
    """
    try:
        import litellm  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "litellm not installed -- pip install litellm") from exc

    def _phoenix(input_text, response, context):
        t0 = time.time()
        if not response:
            return JudgeResult("arize_phoenix", "UNCLEAR", None, None,
                               int((time.time() - t0) * 1000),
                               detail={"reason": "no response"})
        try:
            from litellm import completion
            prompt = _PHOENIX_HALLUCINATION_PROMPT.format(
                query=(input_text or ""),
                reference=(context or ""),
                response=response)
            model = os.environ.get(
                "KYA_PHOENIX_JUDGE_MODEL", "gpt-4o-mini")
            r = completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=10,
                timeout=10.0)
            verdict_str = (r.choices[0].message.content or
                           "").strip().lower()
            if "halluc" in verdict_str:
                verdict = "BREACH"
            elif "factual" in verdict_str:
                verdict = "OK"
            else:
                verdict = "UNCLEAR"
            return JudgeResult(
                "arize_phoenix", verdict, None, None,
                int((time.time() - t0) * 1000),
                detail={"phoenix_label": verdict_str,
                        "model": model,
                        "methodology": "phoenix hallucination "
                                       "prompt template"},
                dimension="faithfulness")
        except Exception as exc:
            return JudgeResult(
                "arize_phoenix", "ERROR", None, None,
                int((time.time() - t0) * 1000), error=str(exc))

    register_judge("arize_phoenix", _phoenix)


# ── Opt-in adapter: multi-LLM judge ensemble ───────────────────────
#
# Why a separate ensemble adapter when openai_judge + arize_phoenix
# already use LLMs:
#   1. **Cross-provider diversity.** GPT-family, Claude-family, and
#      Llama-family give independent verdicts. When they disagree,
#      that's signal — the case is ambiguous and consensus correctly
#      drops to SPLIT/UNCLEAR rather than being railroaded by one
#      provider's training bias.
#   2. **Vendor outage resilience.** If one provider is down or
#      rate-limited, the others still vote. The orchestrator already
#      treats ERROR votes as non-counting, so a single-provider
#      outage doesn't poison the consensus.
#   3. **No bundled OpenRouter dep.** litellm routes to ANY provider
#      via standard model strings; KYA stays framework-agnostic.
#      Customers bring their own provider keys; the adapter picks
#      whichever default models have keys present (or accepts an
#      explicit list).
#
# This is open-source substrate. The `veldt-kya-pro` pack ships a
# CURATED 6-model panel + cost-budget instrumentation + cross-
# provider-disagreement alerting — but the panel mechanics are open
# and customers can register any litellm-compatible model.

# Default conservative panel: 3 widely-available cheap models, one
# per major provider. Filtered at registration time to only the ones
# whose API key is present in env. If the customer wants more, they
# pass an explicit list to `register_multi_llm_judge_adapter`.
DEFAULT_MULTI_LLM_MODELS = (
    ("openai/gpt-4o-mini", "OPENAI_API_KEY"),
    ("anthropic/claude-3-5-haiku-20241022", "ANTHROPIC_API_KEY"),
    ("groq/llama-3.3-70b-versatile", "GROQ_API_KEY"),
)


def _sanitize_judge_suffix(model: str) -> str:
    """Convert a litellm model string into a judge-name suffix that
    survives the orchestrator's dict-key + log-line use. Replace
    every non-alphanumeric character with '_' and collapse runs.
    """
    out = []
    prev_was_underscore = False
    for ch in model:
        if ch.isalnum():
            out.append(ch)
            prev_was_underscore = False
        elif not prev_was_underscore:
            out.append("_")
            prev_was_underscore = True
    return "".join(out).strip("_")


def register_multi_llm_judge_adapter(
    *,
    models: list[str] | None = None,
    dimension: str = "faithfulness",
    timeout_seconds: float = 8.0,
    name_prefix: str = "llm_judge",
) -> list[str]:
    """Register one judge per LLM model. Each calls
    ``llm_judge_refusal_or_hallucination`` (the same prompt used by
    ``openai_judge``) routed via ``litellm`` so any provider works.

    Parameters
    ----------
    models
        Explicit list of litellm-compatible model strings (e.g.
        ``"openai/gpt-4o-mini"``, ``"anthropic/claude-3-5-haiku-20241022"``,
        ``"openrouter/meta-llama/llama-3.3-70b-instruct"``). If
        ``None``, the adapter inspects ``DEFAULT_MULTI_LLM_MODELS``
        and registers a judge for each model whose corresponding
        ``*_API_KEY`` env var is present.
    dimension
        Consensus pool the judges vote in. Default ``"faithfulness"``
        because the underlying prompt asks REFUSAL-vs-HALLUCINATION.
        Override to ``"safety"`` if the customer's prompt has been
        re-templated for jailbreak-success detection.
    timeout_seconds
        Per-model HTTP timeout. The orchestrator's ThreadPoolExecutor
        parallelizes calls so the panel latency is ``max(per-judge)``
        not ``sum(per-judge)``.
    name_prefix
        Prefix for the registered judge name. Final judge name is
        ``"{name_prefix}::{sanitized_model}"`` — keeps the per-judge
        report self-documenting about which model voted what.

    Returns
    -------
    list[str]
        The names of the judges that were actually registered. Empty
        list if no models were supplied AND no default-panel keys
        were present in env.

    Failure semantics
    -----------------
    - If a model's provider key is missing, its judge votes ``ERROR``
      at call time (not at registration). The orchestrator skips
      ERROR votes when computing consensus.
    - If ``litellm`` is not installed, every multi-LLM judge votes
      ``ERROR`` with a clear install hint.
    - One provider outage does NOT block the rest of the panel.

    Examples
    --------
    Default conservative panel (auto-filtered by available keys)::

        from kya.scorer_orchestrator import register_multi_llm_judge_adapter
        register_multi_llm_judge_adapter()

    Premium panel (operator-supplied)::

        register_multi_llm_judge_adapter(models=[
            "openai/gpt-4o",
            "anthropic/claude-3-5-sonnet-20241022",
            "openrouter/meta-llama/llama-3.3-70b-instruct",
            "openrouter/mistralai/mistral-large",
            "openrouter/qwen/qwen-2.5-72b-instruct",
            "openrouter/deepseek/deepseek-chat",
        ])

    Env override (comma-separated list — overrides defaults)::

        KYA_MULTI_LLM_JUDGE_MODELS=openai/gpt-4o,groq/llama-3.3-70b-versatile
    """
    # Env override beats the function default but is overridden by
    # an explicit `models=` kwarg.
    if models is None:
        env_models = os.environ.get(
            "KYA_MULTI_LLM_JUDGE_MODELS", "").strip()
        if env_models:
            models = [m.strip() for m in env_models.split(",")
                      if m.strip()]
    if models is None:
        # Auto-filter: include only defaults whose key is present.
        models = [
            m for m, key_env in DEFAULT_MULTI_LLM_MODELS
            if os.environ.get(key_env)
        ]
        if not models:
            logger.debug(
                "[KYA-SCORER] register_multi_llm_judge_adapter: no "
                "provider keys present for the default panel — no "
                "judges registered. Set OPENAI_API_KEY / "
                "ANTHROPIC_API_KEY / GROQ_API_KEY, OR pass models=[...] "
                "explicitly.")
            return []

    registered: list[str] = []
    for model_str in models:
        judge_name = f"{name_prefix}::{_sanitize_judge_suffix(model_str)}"
        # Capture model_str + name + dimension by default-arg trick so
        # the closure binds them per loop iteration (Python late
        # binding gotcha).
        def _judge_one(
            input_text: str | None,
            response: str | None,
            context: str | None,
            *,
            _model: str = model_str,
            _name: str = judge_name,
            _dim: str = dimension,
            _timeout: float = timeout_seconds,
        ) -> JudgeResult:
            from kya.fiddler_bridge import llm_judge_refusal_or_hallucination
            t0 = time.time()
            if not response:
                return JudgeResult(
                    _name, "UNCLEAR", None, None,
                    int((time.time() - t0) * 1000),
                    detail={"reason": "no response", "model": _model},
                    dimension=_dim)
            verdict_word = llm_judge_refusal_or_hallucination(
                response, context or "",
                model=_model,
                timeout_seconds=_timeout,
            )
            latency = int((time.time() - t0) * 1000)
            if verdict_word is None:
                return JudgeResult(
                    _name, "ERROR", None, None, latency,
                    error=f"llm judge unavailable for model {_model!r} "
                          "(missing key, provider outage, or litellm "
                          "not installed)",
                    detail={"model": _model},
                    dimension=_dim)
            if verdict_word == "HALLUCINATION":
                verdict = "BREACH"
            elif verdict_word == "REFUSAL":
                verdict = "OK"
            else:
                verdict = "UNCLEAR"
            return JudgeResult(
                _name, verdict, raw_score=None, threshold=None,
                latency_ms=latency,
                detail={"llm_verdict": verdict_word, "model": _model},
                dimension=_dim)

        register_judge(judge_name, _judge_one)
        registered.append(judge_name)

    logger.info(
        "[KYA-SCORER] multi-LLM judge ensemble registered: %d judges "
        "across %d models — %s",
        len(registered), len(registered), registered)
    return registered


# ── DX helper: one-line opt-in adapter registration ────────────────


# Maps adapter NAME (the judge it adds) to the registrar function
# and a short description of what it needs.
_AVAILABLE_ADAPTERS = (
    # (judge_name, registrar_callable_path, install_hint, key_hint)
    ("kya_presidio",
     "kya.scorers_presidio:register_presidio_adapter",
     "pip install kya[presidio]",
     None),
    ("arize_phoenix",
     "kya.scorer_orchestrator:register_phoenix_adapter",
     "pip install litellm",
     None),
    ("langkit_whylabs",
     "kya.scorer_orchestrator:register_langkit_adapter",
     "pip install langkit",
     None),
    ("lakera_guard",
     "kya.scorer_orchestrator:register_lakera_adapter",
     None,  # HTTP-only
     "LAKERA_API_KEY"),
    ("nemo_guardrails",
     "kya.scorer_orchestrator:register_nemo_adapter",
     "pip install nemoguardrails",
     None),
    # Multi-LLM judge ensemble: registers ONE judge per model. Listed
    # here under a representative judge_name so the discovery surface
    # shows "this adapter exists" — but the registrar takes optional
    # kwargs (models=[...]), so the actual judge names are
    # `llm_judge::<sanitized-model>` plural.
    ("llm_judge_ensemble",
     "kya.scorer_orchestrator:register_multi_llm_judge_adapter",
     "pip install litellm",
     # Multi-key — needs at least one of OPENAI_API_KEY /
     # ANTHROPIC_API_KEY / GROQ_API_KEY for the auto-filtered default.
     # Or explicit models=[...].
     "OPENAI_API_KEY | ANTHROPIC_API_KEY | GROQ_API_KEY"),
)


def _resolve(dotted: str) -> Callable:
    """Resolve `module:attribute` to the actual callable. Used to
    avoid importing adapter modules at scorer_orchestrator import
    time -- some of them eagerly probe optional deps."""
    mod_name, _, attr = dotted.partition(":")
    import importlib
    return getattr(importlib.import_module(mod_name), attr)


def register_available_adapters(
    *,
    exclude: list[str] | None = None,
    raise_on_error: bool = False,
) -> dict[str, str]:
    """Register every opt-in judge whose dependencies are available.

    Tries each known opt-in adapter in turn. Any adapter whose
    install requirement isn't met, or whose registrar raises, is
    SKIPPED -- the orchestrator never sees it, and the rest of the
    panel continues to work. Returns a status dict
    `{judge_name: status_message}`.

    Why this exists
    ---------------
    A customer running `pip install kya[recommended]` gets:
        - presidio-analyzer        (kya_presidio)
        - litellm                   (arize_phoenix + openai_judge
                                     + fiddler_bridge LLM second-pass;
                                     all provider-agnostic via
                                     KYA_FAITH_JUDGE_MODEL env)
    Then ONE line at startup wires the whole panel:
        from kya.scorer_orchestrator import register_available_adapters
        register_available_adapters()
    Adapters whose extras the customer DIDN'T install are skipped
    gracefully. Adapters whose registrar raises (API change in a
    library, missing env var, etc.) are caught and recorded so the
    customer can see WHY a judge isn't running.

    Customers in regulated industries (legal-discovery, healthcare)
    who must NOT scan for PII can opt out:
        register_available_adapters(exclude=["kya_presidio"])

    Or via env:
        KYA_DISABLE_JUDGES=kya_presidio,arize_phoenix

    Parameters
    ----------
    exclude : optional list of judge names to skip even if their
        deps are installed.
    raise_on_error : if True, re-raise unexpected exceptions from
        registrars (default: log + skip). Useful when bootstrapping
        a new environment and you WANT to fail loudly.

    Returns
    -------
    A dict mapping each adapter name to one of:
        "registered"      -- judge is now in the panel
        "already_registered" -- was registered before this call
        "skipped (excluded)" -- in `exclude` or KYA_DISABLE_JUDGES
        "skipped (no install)" -- ImportError / RuntimeError on import
        "skipped (no api key)" -- registrar said API key missing
        "skipped (error: ...)" -- unexpected registrar exception
    """
    excluded = set(exclude or [])
    env_disable = os.environ.get("KYA_DISABLE_JUDGES", "")
    if env_disable:
        excluded.update(s.strip() for s in env_disable.split(",")
                        if s.strip())

    status: dict[str, str] = {}
    for judge_name, registrar_path, _install_hint, key_hint in _AVAILABLE_ADAPTERS:
        if judge_name in excluded:
            status[judge_name] = "skipped (excluded)"
            continue
        if judge_name in _JUDGES:
            status[judge_name] = "already_registered"
            continue
        # Lakera needs a key BEFORE we attempt registration
        if key_hint and not os.environ.get(key_hint):
            status[judge_name] = f"skipped (no api key: {key_hint})"
            continue
        try:
            registrar = _resolve(registrar_path)
            registrar()
            status[judge_name] = "registered"
        except (ImportError, ModuleNotFoundError) as exc:
            status[judge_name] = "skipped (no install)"
            logger.debug(
                "[KYA-SCORER] %s skipped: not installed (%s)",
                judge_name, exc)
        except RuntimeError as exc:
            # Adapters raise RuntimeError for "library installed but
            # config missing" cases (API key, model file, etc.).
            msg = str(exc)
            if "not installed" in msg.lower():
                status[judge_name] = "skipped (no install)"
            elif "api key" in msg.lower() or "key not set" in msg.lower():
                status[judge_name] = "skipped (no api key)"
            else:
                status[judge_name] = f"skipped (config: {msg[:60]})"
            logger.debug(
                "[KYA-SCORER] %s skipped: %s", judge_name, msg)
        except Exception as exc:
            # Unexpected: log and continue unless caller asked
            # us to fail loudly.
            status[judge_name] = f"skipped (error: {str(exc)[:60]})"
            logger.warning(
                "[KYA-SCORER] %s registrar raised unexpected: %s",
                judge_name, exc)
            if raise_on_error:
                raise

    n_reg = sum(1 for v in status.values() if v == "registered")
    n_skip = len(status) - n_reg
    logger.info(
        "[KYA-SCORER] register_available_adapters: "
        "%d newly registered, %d skipped. Total active judges: %d",
        n_reg, n_skip, len(_JUDGES))
    return status


def report_panel_status() -> dict[str, dict]:
    """Show what's in the active judge panel + what's available to
    register. Useful for `kya doctor`-style diagnostics.

    Returns
    -------
    A dict with two keys:
      "active":    {judge_name: dimension}    -- currently registered
      "available": {judge_name: status_dict}  -- opt-in adapters and
                                                 whether each could
                                                 be registered now.
    """
    # Probe each opt-in without registering. Avoids side effects.
    available: dict[str, dict] = {}
    for judge_name, registrar_path, install_hint, key_hint in _AVAILABLE_ADAPTERS:
        info = {
            "install_hint": install_hint,
            "needs_key": key_hint,
            "key_present": (
                bool(os.environ.get(key_hint))
                if key_hint else None),
        }
        if judge_name in _JUDGES:
            info["status"] = "active"
        elif key_hint and not info["key_present"]:
            info["status"] = "missing_api_key"
        else:
            try:
                # Try resolving the registrar (which imports its
                # deps). If the import succeeds, the adapter is
                # installable.
                _resolve(registrar_path)
                info["status"] = "installable"
            except (ImportError, ModuleNotFoundError):
                info["status"] = "deps_missing"
            except Exception as exc:
                info["status"] = f"error: {str(exc)[:60]}"
        available[judge_name] = info

    # Active judges: name -> dimension. We can't introspect the
    # adapter's dimension without invoking it on a probe input, so
    # the dimension lookup is best-effort.
    active = {name: "active" for name in _JUDGES}

    return {"active": active, "available": available}


# ── Main entry point: parallel multi-judge consensus ───────────────


@dataclass
class DimensionConsensus:
    """Per-dimension breakdown (safety vs faithfulness vs any)."""
    dimension: str
    consensus: str       # "BREACH" | "OK" | "SPLIT" | "UNCLEAR"
    breach_votes: int
    ok_votes: int
    unclear_votes: int
    error_votes: int
    agreement_pct: float
    participating_judges: list[str]


@dataclass
class ConsensusResult:
    """Aggregated verdict across all judges that ran.

    The top-level `consensus` is a HARSH-OR of per-dimension verdicts:
    if ANY dimension fires BREACH, the top-level is BREACH. This
    matches the security-by-default posture: a faithfulness BREACH
    AND a safety OK should still block.
    """
    consensus: str           # "BREACH" | "OK" | "SPLIT" | "UNCLEAR"
    breach_votes: int        # totals across all dimensions
    ok_votes: int
    unclear_votes: int
    error_votes: int
    agreement_pct: float     # max(breach, ok) / decisive
    judges: list[JudgeResult]
    total_latency_ms: int    # max across parallel calls (wall-clock)
    per_dimension: dict[str, DimensionConsensus] = field(
        default_factory=dict)


def check_consensus(
    *,
    input_text: str | None = None,
    response: str | None = None,
    context: str | None = None,
    judges: list[str] | None = None,
    max_workers: int | None = None,
) -> ConsensusResult:
    """Run all (or specified) registered judges IN PARALLEL.
    Aggregate verdicts. Return per-judge + consensus.

    Parameters
    ----------
    input_text, response, context : the data each judge needs.
        Safety judges typically use input_text; faithfulness judges
        typically use response + context.
    judges : optional list of judge names to run. Defaults to ALL
        registered judges.
    max_workers : ThreadPoolExecutor size. Defaults to len(judges).

    Performance: wall-clock latency is max(per-judge latency), not
    sum. Five judges each taking 500ms run in ~500ms total. Fiddler's
    2 req/sec rate-limit STILL applies per-judge per-tenant; if you
    invoke the same judge multiple times in parallel, you'll see
    429s -- but cross-judge parallelism is fine.
    """
    names = judges if judges is not None else list_judges()
    if not names:
        return ConsensusResult(
            "OK", 0, 0, 0, 0, 0.0, [], 0)
    workers = max_workers or len(names)
    t0 = time.time()
    results: list[JudgeResult] = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_name = {
            ex.submit(_JUDGES[name], input_text, response, context): name
            for name in names if name in _JUDGES
        }
        for fut in as_completed(future_to_name):
            try:
                results.append(fut.result())
            except Exception as exc:
                name = future_to_name[fut]
                logger.warning(
                    "[KYA-SCORER] judge %s raised: %s", name, exc)
                results.append(JudgeResult(
                    name, "ERROR", None, None,
                    0, error=str(exc)))

    total_ms = int((time.time() - t0) * 1000)

    # Per-dimension aggregation. Each judge declares which dimension
    # it scores. We compute a separate consensus per dimension because
    # they're orthogonal: a faithfulness BREACH and a safety OK
    # shouldn't average out. "any" judges vote in every dimension's
    # pool -- use sparingly (it conflates orthogonal signals).
    #
    # Dimensions (see JudgeResult.dimension for full semantics):
    #   input_safety   = the USER INPUT (jailbreak / abuse). BREACH
    #                    means agent RECEIVED an attack.
    #   safety         = the AGENT RESPONSE (data leak / unsafe
    #                    content). BREACH means agent COMMITTED a
    #                    violation.
    #   faithfulness   = response grounded + aligned. BREACH means
    #                    hallucination or misalignment.
    DIMENSIONS = ("input_safety", "safety", "faithfulness")
    per_dim: dict[str, DimensionConsensus] = {}
    for dim in DIMENSIONS:
        pool = [r for r in results
                if r.dimension == dim or r.dimension == "any"]
        if not pool:
            continue
        d_breach = sum(1 for r in pool if r.verdict == "BREACH")
        d_ok = sum(1 for r in pool if r.verdict == "OK")
        d_unclear = sum(1 for r in pool if r.verdict == "UNCLEAR")
        d_err = sum(1 for r in pool if r.verdict == "ERROR")
        d_decisive = d_breach + d_ok
        d_agreement = (max(d_breach, d_ok) / d_decisive
                       if d_decisive else 0.0)
        if d_decisive == 0:
            d_cons = "UNCLEAR"
        elif d_breach > d_ok:
            d_cons = "BREACH"
        elif d_ok > d_breach:
            d_cons = "OK"
        else:
            d_cons = "SPLIT"
        per_dim[dim] = DimensionConsensus(
            dimension=dim, consensus=d_cons,
            breach_votes=d_breach, ok_votes=d_ok,
            unclear_votes=d_unclear, error_votes=d_err,
            agreement_pct=d_agreement,
            participating_judges=sorted(r.judge_name for r in pool))

    # Top-level: harsh-OR over dimensions. If ANY dimension BREACHED,
    # top-level is BREACH (security-by-default posture). Otherwise:
    # OK if at least one dimension is OK with majority; SPLIT if any
    # dimension is SPLIT; UNCLEAR if all dimensions are UNCLEAR.
    dim_verdicts = {d.consensus for d in per_dim.values()}
    if "BREACH" in dim_verdicts:
        consensus = "BREACH"
    elif "SPLIT" in dim_verdicts:
        consensus = "SPLIT"
    elif "OK" in dim_verdicts:
        consensus = "OK"
    else:
        consensus = "UNCLEAR"

    # Top-level totals (sum across dimensions for visibility).
    breach = sum(1 for r in results if r.verdict == "BREACH")
    ok = sum(1 for r in results if r.verdict == "OK")
    unclear = sum(1 for r in results if r.verdict == "UNCLEAR")
    errored = sum(1 for r in results if r.verdict == "ERROR")
    decisive = breach + ok
    agreement = (max(breach, ok) / decisive) if decisive else 0.0

    return ConsensusResult(
        consensus=consensus,
        breach_votes=breach, ok_votes=ok,
        unclear_votes=unclear, error_votes=errored,
        agreement_pct=agreement,
        judges=sorted(results, key=lambda r: r.judge_name),
        total_latency_ms=total_ms,
        per_dimension=per_dim)


# ── Signal routing -- consensus dimensions -> KYA signal kinds ─────


# Map per-dimension BREACH verdicts to the KYA signal kind that
# should fire. Lives next to the orchestrator because the dimension
# names are owned here; the deltas live in kya.users.SIGNAL_DELTAS.
#
# Why the asymmetry between input_safety and safety?
#   - input_safety BREACH means the agent RECEIVED an attack. The
#     agent may have refused correctly. Recording a heavy
#     "policy_violation" against the agent in this case is wrong --
#     it punishes the agent for being attacked. We emit a light
#     `received_attack` signal for analytics + a small decay, so
#     repeated attack exposure still surfaces in trust over time.
#   - safety BREACH means the agent COMMITTED a violation (data
#     leak from PyRIT, harmful content from a response-safety judge,
#     etc.). Heavy `policy_violation` is correct.
_DIMENSION_TO_SIGNAL: dict[str, str] = {
    "input_safety": "received_attack",
    "safety": "policy_violation",
    "faithfulness": "hallucination_detected",
}


def signals_from_consensus(
    result: ConsensusResult,
    *,
    on_split: str = "ignore",
) -> list[tuple[str, str]]:
    """Map a ConsensusResult to (signal_kind, dimension) pairs.

    Callers feed these into `record_principal_signal()` to decay
    trust appropriately. Dimensions are returned alongside the
    signal kind so callers can attach them to evidence.

    Parameters
    ----------
    result : ConsensusResult
        From `check_consensus()`.
    on_split : "ignore" | "treat_as_breach"
        SPLIT verdicts mean judges disagreed. Default is "ignore"
        (no signal -- operator decides). "treat_as_breach" is more
        aggressive and useful for high-stakes routes.

    Returns
    -------
    A list of (signal_kind, dimension) tuples. Empty list means the
    consensus did not warrant any trust decay.
    """
    out: list[tuple[str, str]] = []
    for dim, dc in result.per_dimension.items():
        if dc.consensus == "BREACH" or dc.consensus == "SPLIT" and on_split == "treat_as_breach":
            kind = _DIMENSION_TO_SIGNAL.get(dim)
            if kind:
                out.append((kind, dim))
    return out
