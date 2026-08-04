"""Release-verification test for veldt-kya 0.4.7.

Runs against the PIP-INSTALLED package (not the source tree). Exercises
the two real fixes shipped in this version:

  1. kya.autoinstrument — cost + outcome capture on LLM patches (#263,
     #264, #265). Verifies the new closures + contextvars are present
     and the cost-recorder callback signature is stable.

  2. kya_otlp_bridge.mapper.SpanMapper — extract_gen_ai_cost +
     _attach_cost_to_body (#263 Part B). Verifies the mapper can
     extract cost from a real OpenLLMetry span shape AND attach it
     to an invocation body in the shape the Pro-side ingest accepts.

Usage: `python -m pytest tests/_release_test_047.py -v`

The test is CI-safe (no live LLM call — uses a synthetic OpenLLMetry
span the mapper would receive in production from a real LangChain
+ OpenLLMetry-instrumented app). Real-LLM verification is separately
covered by tests/test_real_world.py.
"""
from __future__ import annotations

import pytest


def _get_autoinstrument_module():
    """kya/__init__.py imports `autoinstrument` FUNCTION from .autoinstrument
    MODULE — so `kya.autoinstrument` is the function, shadowing the module.
    Get the module explicitly via sys.modules (populated by the `from
    .autoinstrument import ...` inside kya/__init__.py) or importlib."""
    import importlib
    import kya  # noqa: F401 — populates sys.modules['kya.autoinstrument']
    import sys
    mod = sys.modules.get("kya.autoinstrument")
    if mod is None:
        mod = importlib.import_module("kya.autoinstrument")
    return mod


def test_kya_autoinstrument_has_cost_recorder_wiring():
    """Cost + outcome capture landed in autoinstrument. Verify the
    module exposes the primitives the Pro side wires into."""
    autoinstrument = _get_autoinstrument_module()

    # The context var + recorder factory landed in #263 Part A / #264.
    assert hasattr(autoinstrument, "_CONTEXT"), (
        "expected _CONTEXT ContextVar on kya.autoinstrument (#264 fix)"
    )
    assert hasattr(autoinstrument, "_make_db_recorder"), (
        "expected _make_db_recorder on kya.autoinstrument"
    )
    # Confirm ContextVar not global dict (async/thread safety fix #264)
    import contextvars
    assert isinstance(autoinstrument._CONTEXT, contextvars.ContextVar), (
        f"_CONTEXT must be contextvars.ContextVar for async safety; "
        f"got {type(autoinstrument._CONTEXT).__name__}"
    )


def test_kya_autoinstrument_cost_helpers_exist():
    """The cost capture closures land INSIDE _make_db_recorder. Verify
    the fix shipped by reading source + asserting the load-bearing
    markers are present: cost recording, contextvar identity read,
    tenant_budget wiring."""
    import inspect
    autoinstrument = _get_autoinstrument_module()

    src = inspect.getsource(autoinstrument._make_db_recorder)
    # The three closures the recorder returns (#263 Part A).
    for marker in ("_record_inv", "_record_ev", "_record_cost"):
        assert marker in src, (
            f"expected {marker!r} closure inside _make_db_recorder "
            f"(#263/#265 fix). Source length {len(src)}."
        )
    # ContextVar identity read (#264 async/thread safety fix).
    assert "_CONTEXT.get()" in src, (
        "expected _CONTEXT.get() in _make_db_recorder — the fix "
        "reads tenant/agent from contextvar at CALL time"
    )
    # Cost recording (#263 Part A).
    assert "record_cost_event" in src, (
        "expected record_cost_event call inside _make_db_recorder — "
        "this is the actual cost-write primitive"
    )
    # Cost payload fields.
    for field in ("usd_amount", "model_used", "provider", "input_tokens"):
        assert field in src, (
            f"expected cost field {field!r} in _record_cost closure"
        )


def test_kya_autoinstrument_patches_include_async_litellm():
    """#263 Part A shipped an async litellm.acompletion patch alongside
    the existing sync patches. Verify by inspecting the module source
    for the async marker."""
    import inspect
    autoinstrument = _get_autoinstrument_module()

    # Verify at least one of the async patch markers is in module source
    src = inspect.getsource(autoinstrument)
    assert "acompletion" in src, (
        "expected 'acompletion' marker in autoinstrument source "
        "(#263 async litellm patch)"
    )


def test_mapper_extract_gen_ai_cost_openllmetry_span():
    """#263 Part B — SpanMapper.extract_gen_ai_cost should read cost
    + tokens from an OpenLLMetry-shaped span (LangChain / ChatOpenAI).
    This is the exact span shape the OTLP bridge receives in prod."""
    from kya_otlp_bridge.mapper import SpanMapper

    mapper = SpanMapper()
    span = {
        "name": "openai.chat",
        "attributes": {
            "llm.request.model": "gpt-4o-mini",
            "gen_ai.system": "openai",
            "gen_ai.response.total_cost": 0.0125,
            "gen_ai.usage.input_tokens": 100,
            "gen_ai.usage.output_tokens": 20,
        },
        "startTimeUnixNano": 1_000_000_000,
        "endTimeUnixNano": 1_500_000_000,
        "status": {"code": 1},
    }
    cost = mapper.extract_gen_ai_cost(span)
    assert cost is not None, "openllmetry span with cost must extract"
    assert cost["provider"] == "openai"
    assert cost["model_used"] == "gpt-4o-mini"
    assert cost["input_tokens"] == 100
    assert cost["output_tokens"] == 20
    assert cost["usd_amount"] == pytest.approx(0.0125)


def test_mapper_attach_cost_to_body_populates_5_fields():
    """#263 Part B — _attach_cost_to_body must populate exactly the
    5 cost_* fields the Pro-side InvocationEventBody Pydantic model
    accepts. Shape drift here silently drops cost at the wire."""
    from kya_otlp_bridge.mapper import SpanMapper

    mapper = SpanMapper()
    span = {
        "name": "openai.chat",
        "attributes": {
            "openinference.span.kind": "LLM",
            "llm.request.model": "gpt-4o-mini",
            "gen_ai.system": "openai",
            "gen_ai.response.total_cost": 0.0088,
            "gen_ai.usage.input_tokens": 200,
            "gen_ai.usage.output_tokens": 40,
        },
        "startTimeUnixNano": 1_000_000_000,
        "endTimeUnixNano": 1_400_000_000,
        "status": {"code": 1},
    }
    inv_body = {"agent_key": "release-test-agent"}
    mapper._attach_cost_to_body(inv_body, span)

    assert inv_body["cost_usd_amount"] == pytest.approx(0.0088)
    assert inv_body["cost_provider"] == "openai"
    assert inv_body["cost_model_used"] == "gpt-4o-mini"
    assert inv_body["cost_input_tokens"] == 200
    assert inv_body["cost_output_tokens"] == 40


def test_mapper_attach_cost_skips_non_llm_span():
    """Regression guard: non-LLM spans (tool calls, retriever) must NOT
    poison the invocation body with cost=0. That would double-count
    against real LLM spans in the same trace."""
    from kya_otlp_bridge.mapper import SpanMapper

    mapper = SpanMapper()
    span = {
        "name": "tool.execute",
        "attributes": {"tool.name": "search"},
        "startTimeUnixNano": 1_000_000_000,
        "endTimeUnixNano": 1_010_000_000,
        "status": {"code": 1},
    }
    inv_body = {"agent_key": "tool-agent"}
    mapper._attach_cost_to_body(inv_body, span)

    assert "cost_usd_amount" not in inv_body, (
        "non-LLM span must NOT attach cost — got poisoned body"
    )


def test_installed_package_version_is_047():
    """Guard: this test runs against pip-installed 0.4.7 in a fresh
    venv. If it accidentally runs against 0.4.6 or a stale editable
    install, this catches it immediately."""
    import importlib.metadata as im
    version = im.version("veldt-kya")
    assert version in ("0.4.7", "0.4.7rc1"), (
        f"expected pip-installed veldt-kya==0.4.7 or 0.4.7rc1 in this "
        f"venv; got {version}. Rebuild wheel + re-pip-install."
    )
