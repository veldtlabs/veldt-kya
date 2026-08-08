"""Tests for kya_otlp_bridge.mapper.SpanMapper.extract_gen_ai_cost.

Task #263 Part B — GenAI cost extraction from OTel spans emitted by
LangChain / CrewAI / AutoGen via OpenInference or OpenLLMetry auto-
instrumentation. Pure extraction (no DB, no network). Writer wiring is
a follow-up task.
"""
from __future__ import annotations

import pytest

# CI runs the wheel in a clean venv without optional deps. mapper.py
# lazy-imports litellm inside extract_gen_ai_cost; these tests exercise
# that path so skip the whole module cleanly when litellm is absent.
# See feedback_test_locally_before_push.md.
pytest.importorskip("litellm")

from kya_otlp_bridge.mapper import SpanMapper


@pytest.fixture
def mapper():
    return SpanMapper()


# ── OTel GenAI semconv (standard) ───────────────────────────────────


def test_otel_gen_ai_semconv_extracts_full_cost(mapper, monkeypatch):
    """Standard OTel gen_ai.* attributes → cost row shape.

    Stubs litellm.cost_per_token so the test is deterministic and
    doesn't depend on the live pricing table for gpt-4o-mini."""
    import litellm

    monkeypatch.setattr(
        litellm, "cost_per_token",
        lambda *, model, prompt_tokens, completion_tokens: (0.001, 0.002),
    )

    span = {
        "startTimeUnixNano": 1_000_000_000,
        "endTimeUnixNano":   1_500_000_000,  # 500ms later (500M ns)
        "attributes": {
            "gen_ai.system": "openai",
            "gen_ai.request.model": "gpt-4o-mini",
            "gen_ai.usage.input_tokens": 200,
            "gen_ai.usage.output_tokens": 50,
        },
    }
    r = mapper.extract_gen_ai_cost(span)
    assert r is not None
    assert r["provider"] == "openai"
    assert r["model_used"] == "gpt-4o-mini"
    assert r["input_tokens"] == 200
    assert r["output_tokens"] == 50
    assert abs(r["usd_amount"] - 0.003) < 1e-9  # 0.001 + 0.002
    assert r["latency_ms"] == 500  # 500ms


def test_otel_gen_ai_semconv_prefers_provider_cost_over_computed(mapper, monkeypatch):
    """When the provider ships gen_ai.usage.cost, that authoritative
    value wins over litellm's computed estimate."""
    import litellm

    # If this stub fires, the test caught a regression — cost hierarchy
    # should skip litellm entirely when provider gave us the number.
    def _explode(*a, **kw):
        raise AssertionError("cost_per_token should NOT be called when provider sends usage.cost")

    monkeypatch.setattr(litellm, "cost_per_token", _explode)

    span = {
        "attributes": {
            "gen_ai.system": "openrouter",
            "gen_ai.request.model": "openai/gpt-4o-mini",
            "gen_ai.usage.input_tokens": 200,
            "gen_ai.usage.output_tokens": 50,
            "gen_ai.usage.cost": 0.0042,  # provider-authoritative
        },
    }
    r = mapper.extract_gen_ai_cost(span)
    assert r["usd_amount"] == 0.0042
    assert r["provider"] == "openrouter"


# ── OpenLLMetry / Traceloop convention ──────────────────────────────


def test_openllmetry_llm_dot_attrs(mapper, monkeypatch):
    """OpenLLMetry (llm.request.model, llm.usage.prompt_tokens, …) is
    a common alternative attribute family used by LangChain autoinstr."""
    import litellm

    monkeypatch.setattr(
        litellm, "cost_per_token",
        lambda *, model, prompt_tokens, completion_tokens: (0.005, 0.010),
    )

    span = {
        "attributes": {
            "llm.vendor": "anthropic",
            "llm.request.model": "claude-3-5-sonnet-20241022",
            "llm.usage.prompt_tokens": 500,
            "llm.usage.completion_tokens": 100,
        },
    }
    r = mapper.extract_gen_ai_cost(span)
    assert r["provider"] == "anthropic"
    assert r["model_used"] == "claude-3-5-sonnet-20241022"
    assert r["input_tokens"] == 500
    assert r["output_tokens"] == 100
    assert abs(r["usd_amount"] - 0.015) < 1e-9


# ── OpenInference convention ────────────────────────────────────────


def test_openinference_llm_token_count(mapper, monkeypatch):
    """OpenInference uses llm.token_count.prompt / .completion and
    llm.model_name. Different again — must be handled."""
    import litellm

    monkeypatch.setattr(
        litellm, "cost_per_token",
        lambda *, model, prompt_tokens, completion_tokens: (0.0001, 0.0002),
    )

    span = {
        "attributes": {
            "llm.model_name": "gpt-3.5-turbo",
            "llm.token_count.prompt": 80,
            "llm.token_count.completion": 20,
        },
    }
    r = mapper.extract_gen_ai_cost(span)
    assert r["model_used"] == "gpt-3.5-turbo"
    assert r["input_tokens"] == 80
    assert r["output_tokens"] == 20
    assert abs(r["usd_amount"] - 0.0003) < 1e-9


# ── Non-LLM spans + edge cases ──────────────────────────────────────


def test_non_llm_span_returns_none(mapper):
    """Bridge maps every span through this method. Spans that carry
    no usage/model attributes (HTTP client spans, DB spans, tool_call
    spans) must return None so the caller skips cost extraction."""
    span = {
        "attributes": {
            "http.method": "GET",
            "http.url": "https://api.example.com/",
            "http.status_code": 200,
        },
    }
    assert mapper.extract_gen_ai_cost(span) is None


def test_no_attributes_returns_none(mapper):
    assert mapper.extract_gen_ai_cost({}) is None
    assert mapper.extract_gen_ai_cost({"attributes": None}) is None


def test_unknown_model_falls_back_to_zero(mapper, monkeypatch):
    """If litellm can't price the model (not in its table), we return
    usd=0.0. record_cost_event drops the row — better than guessing.

    Still returns the shape so the caller sees the tokens/model even
    though cost is 0."""
    import litellm

    def _boom(*a, **kw):
        raise Exception("This model isn't mapped yet.")
    monkeypatch.setattr(litellm, "cost_per_token", _boom)

    span = {
        "attributes": {
            "gen_ai.system": "unknown_provider",
            "gen_ai.request.model": "some-obscure-model-x",
            "gen_ai.usage.input_tokens": 100,
            "gen_ai.usage.output_tokens": 50,
        },
    }
    r = mapper.extract_gen_ai_cost(span)
    assert r is not None
    assert r["usd_amount"] == 0.0
    assert r["model_used"] == "some-obscure-model-x"
    # tokens still surface so analytics can show "known usage, unknown cost"
    assert r["input_tokens"] == 100


def test_no_latency_when_span_times_missing(mapper, monkeypatch):
    import litellm
    monkeypatch.setattr(litellm, "cost_per_token",
                        lambda **kw: (0.001, 0.001))
    span = {
        "attributes": {
            "gen_ai.request.model": "gpt-4o-mini",
            "gen_ai.usage.input_tokens": 10,
            "gen_ai.usage.output_tokens": 5,
        },
    }
    r = mapper.extract_gen_ai_cost(span)
    assert r["latency_ms"] is None
    # cost still computed
    assert r["usd_amount"] > 0


def test_llamaindex_total_tokens_only_fallback(mapper, monkeypatch):
    """LlamaIndex + some AutoGen versions emit only total_tokens (no
    prompt/completion split). Review fix MAJOR-2: we surface that as
    input_tokens so the tile has SOMETHING to show instead of None."""
    import litellm
    # Force cost=0 since we can't compute a split from total-only
    monkeypatch.setattr(litellm, "cost_per_token",
                        lambda **kw: (0.0, 0.0))
    span = {
        "attributes": {
            "gen_ai.request.model": "gpt-4o-mini",
            "gen_ai.usage.total_tokens": 250,
            # deliberately: no prompt_tokens, no completion_tokens
        },
    }
    r = mapper.extract_gen_ai_cost(span)
    assert r is not None
    assert r["model_used"] == "gpt-4o-mini"
    assert r["input_tokens"] == 250  # total surfaced here per docstring
    assert r["output_tokens"] is None


def test_microsecond_latency_detected_and_converted(mapper, monkeypatch):
    """Review fix MAJOR-3: pathological pipelines (Jaeger-derived,
    jsontrace exporter) emit MICROSECONDS but populate the same
    startTimeUnixNano field. Detect + convert so we don't report
    latency 1000x too small."""
    import litellm
    monkeypatch.setattr(litellm, "cost_per_token",
                        lambda **kw: (0.001, 0.001))
    # 500_000 apparent "ns" = 0.5ms would be impossibly fast for an
    # LLM call. The heuristic reinterprets it as 500ms (µs source).
    span = {
        "startTimeUnixNano": 1_000_000_000,
        "endTimeUnixNano":   1_000_500_000,   # +500_000 delta
        "attributes": {
            "gen_ai.request.model": "gpt-4o-mini",
            "gen_ai.usage.input_tokens": 10,
            "gen_ai.usage.output_tokens": 5,
        },
    }
    r = mapper.extract_gen_ai_cost(span)
    assert r["latency_ms"] == 500  # reinterpreted from µs source


def test_bad_token_type_survives(mapper, monkeypatch):
    """A malformed span attribute (string where int expected) must not
    crash — extraction is best-effort by contract."""
    import litellm
    monkeypatch.setattr(litellm, "cost_per_token",
                        lambda **kw: (0.0, 0.0))
    span = {
        "attributes": {
            "gen_ai.request.model": "gpt-4o-mini",
            "gen_ai.usage.input_tokens": "not-a-number",
            "gen_ai.usage.output_tokens": None,
        },
    }
    # Model present but usage unparseable → tokens None, but model is
    # still detected so this counts as an LLM span. usd=0.0 since
    # litellm gets 0 tokens.
    r = mapper.extract_gen_ai_cost(span)
    assert r is not None
    assert r["model_used"] == "gpt-4o-mini"
    assert r["input_tokens"] is None
    assert r["output_tokens"] is None
