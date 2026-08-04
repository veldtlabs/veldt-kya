"""
SpanMapper — translates OTel spans into KYA events.

Modular: customers register rules for their own framework's span shape.
Generic enough to work with any OTel-compliant source (OpenCLAW,
OpenLLMetry, Langfuse, traceloop, etc.).

Default ruleset covers common patterns:
  - span name contains "tool" + attributes.tool.name set -> oos check
  - attributes "kya.rogue" = true                         -> direct rogue event
  - attributes "veldt.rogue" = true                       -> Veldt's own emit
  - status code != OK + agent attribute set               -> invocation w/ outcome=error
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Standard data-class hints — used to auto-detect content sensitivity from
# span attributes so KYA's retention policy fires on capture without the
# emitter having to set retention_days explicitly.
_PII_HINT_KEYS = ("data.class", "data.sensitivity", "kya.data_class")
_PII_HINT_VALUES = {"pii", "phi", "pci", "regulated", "secret", "confidential"}


@dataclass
class MapResult:
    """One translated event ready to POST to KYA.

    `event_type`:
      - "rogue":      -> POST /events/rogue
      - "invocation": -> POST /events/invocation
                       AND post each `evidence_payloads` entry to
                       /events/evidence with the resulting invocation_id.
      - "skip":       -> drop, don't POST

    `evidence_payloads` is non-empty when the source span carries content
    we want to persist (prompt text, tool args, tool result, LLM output).
    The bridge chains them: post invocation, capture id, post each
    evidence with `invocation_id` set to that id.
    """

    event_type: str  # "rogue" | "invocation" | "skip"
    body: dict[str, Any]  # ready to send (sans tenant — added by client)
    evidence_payloads: list[dict[str, Any]] = field(default_factory=list)


# Type alias for a custom matcher: takes a parsed span dict, returns 0+ MapResults.
SpanMatcher = Callable[[dict], list[MapResult]]


class SpanMapper:
    """Stack of matchers. First matcher to return non-empty wins.

    Built-in matchers cover the most common shapes; customers add their
    own via `register()` for framework-specific span names.
    """

    def __init__(self, agent_key_attr: str = "agent.key", default_agent_key: str = "otel_agent"):
        self.agent_key_attr = agent_key_attr
        self.default_agent_key = default_agent_key
        self._matchers: list[SpanMatcher] = []
        # Order matters — register specific matchers BEFORE generic ones.
        # Explicit KYA-tagged spans always win; framework-shape matchers
        # come next; generic / status-based fallbacks last.
        self.register(self._explicit_rogue_attr)
        self.register(self._veldt_rogue_attr)
        self.register(self._openclaw_tool_execution)
        self.register(self._openinference_span)
        self.register(self._openllmetry_genai_span)
        self.register(self._tool_oos_check)
        self.register(self._error_status_invocation)

    def register(self, matcher: SpanMatcher) -> None:
        """Add a custom matcher. Runs after the built-ins."""
        self._matchers.append(matcher)

    # ── public entrypoint ─────────────────────────────────────────────

    def map_span(self, span: dict) -> list[MapResult]:
        """Convert one OTel span dict to 0+ KYA events.

        `span` is the parsed JSON shape — typically:
          {"name": "...", "attributes": {...}, "status": {...}, "events": [...]}
        """
        if not isinstance(span, dict):
            return []
        for matcher in self._matchers:
            try:
                results = matcher(span)
            except Exception as exc:
                logger.warning("[OTLP-BRIDGE] matcher raised: %s", exc)
                continue
            if results:
                return results
        return []

    # ── helpers exposed for custom matchers ──────────────────────────

    @staticmethod
    def normalize_agent_key(raw: str) -> str:
        """Normalize a raw agent identifier to KYA's registry shape.

        KYA's CustomAgentCreate validator requires `^[a-z0-9_]+$` — but
        common OTel conventions emit hyphenated, dotted, or mixed-case
        names (e.g., `openclaw-gateway-real`, `MyAgent.Worker`).
        Without normalization, the same conceptual agent ends up with
        TWO principals: one from the customer-registered definition
        (underscored) and one from the OTel-emitted runtime signal
        (hyphenated). Static risk lives on the first; rogue signals
        on the second; the dashboard can't unify them.

        Normalization:
          - lowercase
          - replace runs of [^a-z0-9_] (hyphen, dot, space, slash, ...) with `_`
          - strip leading/trailing underscores
          - truncate to 50 chars (registry max)
        """
        import re as _re

        if not raw:
            return raw or ""
        s = _re.sub(r"[^a-z0-9_]+", "_", str(raw).lower()).strip("_")
        return s[:50] if len(s) > 50 else s

    def get_agent_key(self, span: dict) -> str:
        attrs = span.get("attributes") or {}
        raw = (
            attrs.get(self.agent_key_attr)
            or attrs.get("agent_key")
            or attrs.get("agent.name")
            or attrs.get("service.name")
            or self.default_agent_key
        )
        return self.normalize_agent_key(raw)

    @staticmethod
    def get_duration_ms(span: dict) -> int | None:
        """Return span duration in ms.

        Prefer an explicit `duration_ms` attribute if the emitter set one,
        otherwise compute from `endTimeUnixNano - startTimeUnixNano` (which
        is the OTLP/JSON-spec native form — strings on the wire). Returns
        None if neither path yields a usable number.
        """
        attrs = span.get("attributes") or {}
        raw = attrs.get("duration_ms")
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
        try:
            start = int(span.get("startTimeUnixNano") or 0)
            end = int(span.get("endTimeUnixNano") or 0)
            if end > start > 0:
                return (end - start) // 1_000_000
        except (TypeError, ValueError):
            pass
        return None

    # ── evidence extraction helpers ───────────────────────────────────

    @staticmethod
    def _detect_data_classes(attrs: dict) -> list[str] | None:
        """Heuristically extract data classes from span attributes.
        Returns None when nothing sensitive is hinted (avoids over-triggering
        retention windows on every span)."""
        out: set[str] = set()
        for k in _PII_HINT_KEYS:
            v = attrs.get(k)
            if not v:
                continue
            for token in str(v).lower().replace(",", " ").split():
                if token in _PII_HINT_VALUES:
                    out.add(token)
        return sorted(out) if out else None

    @staticmethod
    def _safe_json_load(raw: Any) -> Any:
        """Some OpenInference attributes ship as JSON strings (e.g.
        llm.input_messages on the OTLP/HTTP JSON encoding). Parse opportunistically;
        return the raw value when not a JSON-shaped string."""
        if isinstance(raw, (dict, list)):
            return raw
        if isinstance(raw, str):
            s = raw.strip()
            if s and s[0] in "[{":
                try:
                    return json.loads(s)
                except Exception:
                    return raw
        return raw

    def _extract_openinference_evidence(self, span: dict) -> list[dict[str, Any]]:
        """Build evidence payload dicts from OpenInference span attributes.
        Covers LangChain, LlamaIndex, CrewAI, DSPy, AutoGen, OpenAI Agents
        SDK, Anthropic SDK, Bedrock, Vertex, MistralAI, Groq — every
        framework instrumented via OpenInference exposes these attrs in
        the same shape.

        Returns a list of evidence dicts ready for /events/evidence (sans
        `invocation_id` which the bridge fills in post-invocation-create).
        """
        attrs = span.get("attributes") or {}
        kind = (attrs.get("openinference.span.kind") or "").upper()
        evidence: list[dict[str, Any]] = []
        data_classes = self._detect_data_classes(attrs)
        common = {
            "source": "openinference",
            "span_id": span.get("spanId") or span.get("span_id"),
            "data_classes": data_classes,
        }

        # LLM span — input_messages + output_messages
        if kind == "LLM":
            inputs = self._safe_json_load(attrs.get("llm.input_messages"))
            if inputs:
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "prompt",
                        "role": "user",
                        "payload": {"messages": inputs},
                    }
                )
            outputs = self._safe_json_load(attrs.get("llm.output_messages"))
            if outputs:
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "response",
                        "role": "assistant",
                        "payload": {"messages": outputs},
                    }
                )
            # Some emitters use generic input.value / output.value
            if not inputs and attrs.get("input.value"):
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "prompt",
                        "role": "user",
                        "payload": {"content": str(attrs["input.value"])},
                    }
                )
            if not outputs and attrs.get("output.value"):
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "response",
                        "role": "assistant",
                        "payload": {"content": str(attrs["output.value"])},
                    }
                )

        # TOOL span — args + result
        elif kind == "TOOL":
            tool_name = attrs.get("tool.name") or attrs.get("gen_ai.tool.name") or "unknown"
            args_raw = self._safe_json_load(attrs.get("tool.parameters")) or self._safe_json_load(
                attrs.get("input.value")
            )
            if args_raw is not None:
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "tool_call",
                        "role": "assistant",
                        "payload": {"tool_name": tool_name, "args": args_raw},
                    }
                )
            result_raw = self._safe_json_load(attrs.get("output.value"))
            if result_raw is not None:
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "tool_result",
                        "role": "tool",
                        "payload": {"tool_name": tool_name, "output": result_raw},
                    }
                )

        # AGENT span — final output (intermediate steps come from child LLM/TOOL spans)
        elif kind == "AGENT":
            if attrs.get("output.value"):
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "response",
                        "role": "assistant",
                        "payload": {"content": str(attrs["output.value"])},
                    }
                )
            if attrs.get("input.value"):
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "prompt",
                        "role": "user",
                        "payload": {"content": str(attrs["input.value"])},
                    }
                )

        # RETRIEVER span — RAG retrieval. The query is "what the agent
        # asked for"; the documents are "what the agent saw" — both belong
        # in evidence because hallucinated answers usually trace back to a
        # retriever that pulled bad context.
        elif kind == "RETRIEVER":
            query = self._safe_json_load(attrs.get("input.value"))
            if query is not None:
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "tool_call",  # treat as a "retrieval" tool call
                        "role": "assistant",
                        "payload": {"tool_name": "retriever", "args": {"query": query}},
                    }
                )
            docs = self._safe_json_load(attrs.get("retrieval.documents"))
            if docs is None:
                docs = self._safe_json_load(attrs.get("output.value"))
            if docs is not None:
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "tool_result",
                        "role": "tool",
                        "payload": {"tool_name": "retriever", "documents": docs},
                    }
                )

        # GUARDRAIL span — safety / policy check. Compliance gold: proves
        # the gate actually fired, not just that the policy existed.
        elif kind == "GUARDRAIL":
            decision = attrs.get("guardrail.decision") or attrs.get("output.value", "unknown")
            reason = attrs.get("guardrail.reason") or attrs.get("guardrail.rationale", "")
            policy = attrs.get("guardrail.policy") or attrs.get("policy.name", "")
            evidence.append(
                {
                    **common,
                    "evidence_kind": "system_message",
                    "role": "system",
                    "payload": {
                        "guardrail_decision": str(decision),
                        "guardrail_reason": str(reason),
                        "guardrail_policy": str(policy),
                        "input": self._safe_json_load(attrs.get("input.value")),
                    },
                }
            )

        # EVALUATOR span — LLM-judge or rule-based evaluation step. Verdicts
        # are evidence for "did this output meet the bar?".
        elif kind == "EVALUATOR":
            verdict = self._safe_json_load(
                attrs.get("evaluator.verdict") or attrs.get("output.value")
            )
            if verdict is not None:
                evidence.append(
                    {
                        **common,
                        "evidence_kind": "system_message",
                        "role": "system",
                        "payload": {
                            "evaluator_verdict": verdict,
                            "evaluator_name": attrs.get("evaluator.name", "unknown"),
                            "input": self._safe_json_load(attrs.get("input.value")),
                        },
                    }
                )

        return evidence

    def _extract_openllmetry_evidence(self, span: dict) -> list[dict[str, Any]]:
        """Build evidence from OpenLLMetry / OTel GenAI semconv attributes.

        Different attribute family from OpenInference:
            gen_ai.prompt.{n}.role + gen_ai.prompt.{n}.content
            gen_ai.completion.{n}.role + gen_ai.completion.{n}.content
            gen_ai.tool.call.0.arguments
            traceloop.entity.input / traceloop.entity.output (Traceloop)
        """
        attrs = span.get("attributes") or {}
        evidence: list[dict[str, Any]] = []
        data_classes = self._detect_data_classes(attrs)
        common = {
            "source": "openllmetry",
            "span_id": span.get("spanId") or span.get("span_id"),
            "data_classes": data_classes,
        }

        # Collect indexed prompt + completion entries
        prompts: list[dict[str, str]] = []
        completions: list[dict[str, str]] = []
        for k, v in attrs.items():
            if not isinstance(k, str):
                continue
            if k.startswith("gen_ai.prompt.") and k.endswith(".content"):
                idx = k.split(".")[2]
                role = attrs.get(f"gen_ai.prompt.{idx}.role", "user")
                prompts.append({"role": str(role), "content": str(v)})
            elif k.startswith("gen_ai.completion.") and k.endswith(".content"):
                idx = k.split(".")[2]
                role = attrs.get(f"gen_ai.completion.{idx}.role", "assistant")
                completions.append({"role": str(role), "content": str(v)})

        if prompts:
            evidence.append(
                {
                    **common,
                    "evidence_kind": "prompt",
                    "role": "user",
                    "payload": {"messages": prompts},
                }
            )
        if completions:
            evidence.append(
                {
                    **common,
                    "evidence_kind": "response",
                    "role": "assistant",
                    "payload": {"messages": completions},
                }
            )

        # Tool call args + result
        tool_name = attrs.get("gen_ai.tool.name") or attrs.get("tool.name")
        tool_args = (
            self._safe_json_load(attrs.get("gen_ai.tool.call.arguments"))
            or self._safe_json_load(attrs.get("gen_ai.tool.call.0.arguments"))
            or self._safe_json_load(attrs.get("tool.parameters"))
        )
        if tool_name and tool_args is not None:
            evidence.append(
                {
                    **common,
                    "evidence_kind": "tool_call",
                    "role": "assistant",
                    "payload": {"tool_name": tool_name, "args": tool_args},
                }
            )

        # Traceloop entity input/output (fallback shape some frameworks use)
        if not prompts and attrs.get("traceloop.entity.input"):
            evidence.append(
                {
                    **common,
                    "evidence_kind": "prompt",
                    "role": "user",
                    "payload": {"content": str(attrs["traceloop.entity.input"])},
                }
            )
        if not completions and attrs.get("traceloop.entity.output"):
            evidence.append(
                {
                    **common,
                    "evidence_kind": "response",
                    "role": "assistant",
                    "payload": {"content": str(attrs["traceloop.entity.output"])},
                }
            )

        return evidence

    # ── GenAI cost extraction (task #263 Part B) ─────────────────────
    #
    # LangChain / CrewAI / AutoGen customers use OTel spans emitted by
    # OpenInference or OpenLLMetry auto-instrumentation. Those spans
    # carry usage attributes (input_tokens, output_tokens, model) but
    # KYA's OTLP bridge previously extracted only prompt/completion/
    # tool_call evidence — never cost. That left every OTel-instrumented
    # customer with an empty "$ spend" tile even though LangChain has
    # all the data needed.
    #
    # This method reads the standardized attribute names and returns a
    # dict compatible with kya.tenant_budget.record_cost_event(). The
    # writer layer (bridge or Pro-side ingest) is responsible for
    # persistence — this method is pure extraction.

    def extract_gen_ai_cost(self, span: dict) -> dict | None:
        """Extract cost + usage from a GenAI span.

        Returns None when the span has no usage/model attributes (i.e.
        this is not an LLM span). Returns a dict shaped for
        record_cost_event(...) otherwise:

            {
              "provider": "openai" | "anthropic" | ...,
              "model_used": "gpt-4o-mini",
              "input_tokens": int | None,
              "output_tokens": int | None,
              "usd_amount": float,      # 0.0 when unresolvable
              "latency_ms": int | None,
            }

        Recognized attribute families:
          * OTel GenAI semconv (spec): gen_ai.request.model,
            gen_ai.usage.input_tokens, gen_ai.usage.output_tokens,
            gen_ai.system, gen_ai.usage.cost (some emitters)
          * OpenLLMetry / Traceloop: llm.request.model,
            llm.usage.prompt_tokens, llm.usage.completion_tokens,
            gen_ai.response.total_cost
          * OpenInference: llm.token_count.prompt,
            llm.token_count.completion, llm.model_name

        Cost source hierarchy (authoritative first):
          1) gen_ai.usage.cost   — provider-returned billed cost
          2) gen_ai.response.total_cost / llm.usage.total_cost
          3) litellm.cost_per_token() on (model, tokens)  — fallback
          4) 0.0 — signals "we don't know", record_cost_event drops it
        """
        attrs = span.get("attributes") or {}
        if not isinstance(attrs, dict):
            return None

        # Model — try every convention. Prefer request.model over
        # response.model since request is what the customer paid for.
        model_used = (
            attrs.get("gen_ai.request.model")
            or attrs.get("gen_ai.response.model")
            or attrs.get("llm.request.model")
            or attrs.get("llm.model_name")
        )

        # Provider — OTel GenAI semconv puts this in gen_ai.system.
        # OpenLLMetry sometimes uses llm.vendor.
        provider = (
            attrs.get("gen_ai.system")
            or attrs.get("llm.vendor")
            or attrs.get("llm.provider")
        )

        # Usage tokens — three overlapping conventions
        def _int(*keys):
            for k in keys:
                v = attrs.get(k)
                if v is not None:
                    try:
                        return int(v)
                    except (TypeError, ValueError):
                        continue
            return None

        input_tokens = _int(
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.prompt_tokens",
            "llm.usage.prompt_tokens",
            "llm.token_count.prompt",
        )
        output_tokens = _int(
            "gen_ai.usage.output_tokens",
            "gen_ai.usage.completion_tokens",
            "llm.usage.completion_tokens",
            "llm.token_count.completion",
        )

        # LlamaIndex + some AutoGen emit only total_tokens (no prompt/
        # completion split). Surface it as a fallback so the display
        # tile has SOMETHING to show — cost will still be zero without
        # the split, but at least "known usage, unknown cost breakdown"
        # is honest.
        total_tokens = _int(
            "gen_ai.usage.total_tokens",
            "llm.usage.total_tokens",
            "llm.token_count.total",
        )
        if total_tokens is not None and input_tokens is None and output_tokens is None:
            # Store the total in input_tokens with output=0 so downstream
            # analytics see the correct total. Not a lie: prompt+completion
            # ~= total for chat completions.
            input_tokens = total_tokens

        # If nothing usage-related was present, this is not an LLM span.
        # Return None so the caller can skip it entirely.
        if not (model_used or input_tokens or output_tokens):
            return None

        # Cost — prefer provider-returned then LiteLLM's pricing table
        usd = 0.0
        for k in (
            "gen_ai.usage.cost",
            "gen_ai.response.total_cost",
            "llm.usage.total_cost",
        ):
            v = attrs.get(k)
            if v is not None:
                try:
                    usd = float(v)
                    break
                except (TypeError, ValueError):
                    continue
        if not usd and model_used and (input_tokens or output_tokens):
            try:
                import litellm
                # cost_per_token returns (prompt_cost_usd, completion_cost_usd)
                pc, cc = litellm.cost_per_token(
                    model=str(model_used),
                    prompt_tokens=input_tokens or 0,
                    completion_tokens=output_tokens or 0,
                )
                usd = float((pc or 0.0) + (cc or 0.0))
            except Exception as _cost_exc:
                # DEBUG log so SREs can distinguish two failure modes:
                #   1) model not in LiteLLM's pricing map (silent-drift
                #      when LiteLLM releases upstream but our pin is
                #      stale — expected, not an error)
                #   2) LiteLLM API surface changed (cost_per_token
                #      signature drift) — that IS a bug we need to
                #      catch fast. The exception message tells them
                #      apart.
                _log = logging.getLogger(__name__)
                _log.debug(
                    "[KYA-OTLP-BRIDGE] litellm.cost_per_token failed for model=%s: %s",
                    model_used, _cost_exc,
                )
                usd = 0.0

        # Latency — span end - start. OTLP-native spans emit nanoseconds
        # (the spec), but some collector pipelines (Jaeger-derived,
        # jsontrace exporter) emit microseconds as ints. Detect the
        # anomaly: if the raw delta is small enough that ns interpretation
        # yields sub-millisecond latency for a REAL LLM call (which is
        # never <10ms in practice), treat the delta as microseconds.
        latency_ms = None
        start_ts = span.get("startTimeUnixNano") or span.get("start_time_unix_nano")
        end_ts = span.get("endTimeUnixNano") or span.get("end_time_unix_nano")
        try:
            if start_ts is not None and end_ts is not None:
                delta = int(end_ts) - int(start_ts)
                if delta <= 0:
                    latency_ms = 0
                else:
                    # ns interpretation
                    lat_ms_ns = delta // 1_000_000
                    # µs interpretation
                    lat_ms_us = delta // 1_000
                    # If ns interpretation yields <1ms but µs yields a
                    # sensible LLM latency (10ms..10min), the source is
                    # microseconds. LLM calls under 1ms are impossible
                    # in the real world; this heuristic only kicks in
                    # for pathological pipelines.
                    if lat_ms_ns < 1 and 10 <= lat_ms_us <= 600_000:
                        latency_ms = lat_ms_us
                    else:
                        latency_ms = max(0, lat_ms_ns)
        except (TypeError, ValueError):
            latency_ms = None

        return {
            "provider": str(provider) if provider else None,
            "model_used": str(model_used) if model_used else None,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "usd_amount": usd,
            "latency_ms": latency_ms,
        }

    def _attach_cost_to_body(self, inv_body: dict, span: dict) -> None:
        """Merge extracted GenAI cost into an invocation POST body.

        Called at every invocation-body construction site. Guards against
        non-LLM spans (returns None from extract) and zero-cost extractions
        (no usable data — avoid emitting cost=0.0 which would double as
        signal on the dashboard).

        Only populates the 5 fields the Pro-side InvocationEventBody
        Pydantic model accepts (task #263 Part B-2).
        """
        try:
            cost = self.extract_gen_ai_cost(span)
        except Exception:
            return
        if not cost:
            return
        usd = cost.get("usd_amount") or 0.0
        if usd <= 0:
            return
        inv_body["cost_usd_amount"] = float(usd)
        if cost.get("provider"):
            inv_body["cost_provider"] = str(cost["provider"])[:64]
        if cost.get("model_used"):
            inv_body["cost_model_used"] = str(cost["model_used"])[:256]
        if cost.get("input_tokens") is not None:
            inv_body["cost_input_tokens"] = int(cost["input_tokens"])
        if cost.get("output_tokens") is not None:
            inv_body["cost_output_tokens"] = int(cost["output_tokens"])

    # ── built-in matchers ─────────────────────────────────────────────

    def _explicit_rogue_attr(self, span: dict) -> list[MapResult]:
        """Highest-priority shortcut: emitter has marked the span as rogue."""
        attrs = span.get("attributes") or {}
        kind = attrs.get("kya.rogue.event_type")
        if not kind or kind not in {"oos_tool", "data_leak", "cross_tenant"}:
            return []
        body = {
            "event_type": kind,
            "agent_key": self.get_agent_key(span),
            "actor_agent_key": attrs.get("kya.rogue.actor_agent_key") or self.get_agent_key(span),
        }
        if kind == "oos_tool":
            body["tool"] = attrs.get("kya.rogue.tool") or attrs.get("tool.name")
        elif kind == "data_leak":
            body["data_class"] = attrs.get("kya.rogue.data_class", "internal")
            if attrs.get("kya.rogue.evidence"):
                body["evidence"] = attrs["kya.rogue.evidence"]
        elif kind == "cross_tenant":
            body["actual_tid"] = attrs.get("kya.rogue.actual_tid")
        if attrs.get("kya.user_id"):
            body["user_id"] = attrs["kya.user_id"]
        return [MapResult(event_type="rogue", body=body)]

    def _veldt_rogue_attr(self, span: dict) -> list[MapResult]:
        """Veldt's own rogue.py emits spans with `veldt.rogue=true`."""
        attrs = span.get("attributes") or {}
        if attrs.get("veldt.rogue") is not True:
            return []
        agent_key = self.get_agent_key(span)
        kind = (span.get("name") or "").split(".")[-1]  # "veldt.rogue.oos_tool" -> "oos_tool"
        if kind not in {"oos_tool", "data_leak", "cross_tenant"}:
            return []
        body: dict[str, Any] = {
            "event_type": kind,
            "agent_key": agent_key,
            "actor_agent_key": agent_key,
        }
        if kind == "oos_tool":
            body["tool"] = attrs.get("tool.name", "unknown")
        elif kind == "data_leak":
            body["data_class"] = attrs.get("data.class", "internal")
        elif kind == "cross_tenant":
            body["actual_tid"] = attrs.get("tenant.actual")
        return [MapResult(event_type="rogue", body=body)]

    def _openclaw_tool_execution(self, span: dict) -> list[MapResult]:
        """Translate OpenCLAW gateway's `openclaw.tool.execution` span.

        Real-world OpenCLAW deployments emit these via the
        `@openclaw/diagnostics-otel` plugin. They don't carry kya.rogue.*
        tags out of the box — the customer's runtime has no Veldt-specific
        instrumentation. This matcher bridges the gap with no changes
        required on the OpenCLAW side.

        Always emits an `invocation` event (neutral activity tracking).

        If `KYA_OPENCLAW_TOOL_ALLOWLIST` is set (JSON array of canonical
        OpenCLAW tool names), tools NOT in the list also emit an
        `oos_tool` rogue event. Without the env var set, no oos_tool is
        emitted — KYA still records the invocation but doesn't flag it.
        """
        if (span.get("name") or "") != "openclaw.tool.execution":
            return []
        attrs = span.get("attributes") or {}
        tool_name = attrs.get("openclaw.toolName") or attrs.get("gen_ai.tool.name")
        if not tool_name:
            return []

        # Agent-key resolution: real-binary openclaw.tool.execution spans
        # don't carry openclaw.agent (per the diagnostics-otel docs). The
        # tool name itself is namespaced (`<plugin>.<tool>`), so we derive
        # the plugin from the prefix as the most natural per-plugin agent
        # identifier. Falls back to service.name then the catch-all.
        tn = str(tool_name)
        plugin_from_tool = tn.split(".", 1)[0] if "." in tn else None
        raw_agent_key = (
            attrs.get("openclaw.agent")
            or attrs.get("openclaw.harness.plugin")
            or plugin_from_tool
            or attrs.get("service.name")
            or "openclaw_agent"
        )
        # Normalize to KYA registry shape (hyphens -> underscores etc.)
        # so static-risk definition + runtime signals land on the SAME
        # principal id in the dashboard card.
        agent_key = self.normalize_agent_key(raw_agent_key)
        err_cat = attrs.get("openclaw.errorCategory")
        outcome = "success" if err_cat in (None, "", "none") else "error"

        results: list[MapResult] = []
        inv_body: dict[str, Any] = {
            "agent_key": agent_key,
            "mode": "observed",
            "outcome": outcome,
        }
        dur = self.get_duration_ms(span)
        if dur is not None:
            inv_body["duration_ms"] = dur
        self._attach_cost_to_body(inv_body, span)
        results.append(MapResult(event_type="invocation", body=inv_body))

        allowlist_raw = os.environ.get("KYA_OPENCLAW_TOOL_ALLOWLIST", "").strip()
        if allowlist_raw:
            try:
                allow = set(json.loads(allowlist_raw))
            except Exception as exc:
                logger.warning("[OTLP-BRIDGE] failed to parse KYA_OPENCLAW_TOOL_ALLOWLIST: %s", exc)
                allow = set()
            if allow and tool_name not in allow:
                results.append(
                    MapResult(
                        event_type="rogue",
                        body={
                            "event_type": "oos_tool",
                            "agent_key": agent_key,
                            "actor_agent_key": agent_key,
                            "tool": tool_name,
                        },
                    )
                )
        return results

    def _openinference_span(self, span: dict) -> list[MapResult]:
        """Translate OpenInference-instrumented spans.

        OpenInference (Arize) is the OTel instrumentation library that
        covers LangChain, LlamaIndex, DSPy, CrewAI, AutoGen, OpenAI Agents
        SDK, Anthropic SDK, Bedrock, MistralAI, Vertex, Groq — all with
        ONE standardized span shape. So a single matcher here gets KYA
        coverage of ~12 frameworks with no per-framework code.

        Key attributes:
          - `openinference.span.kind`  AGENT | TOOL | CHAIN | LLM | RETRIEVER
          - `tool.name`                 for TOOL spans
          - `llm.model_name`            model identifier
          - `agent.name`                explicit agent name when emitter sets it
          - `session.id`, `user.id`     correlation IDs

        Emission strategy:
          - TOOL spans      -> invocation event (success/error). If a tool
                               allowlist is configured AND tool isn't in it,
                               also emit an oos_tool rogue event.
          - AGENT spans     -> invocation event (activity rate signal).
          - Other kinds     -> skip. CHAIN/LLM/EMBEDDING are too noisy at
                               agent granularity; their failures roll up
                               via the parent AGENT span's status.

        Tool allowlist: env `KYA_OPENINFERENCE_TOOL_ALLOWLIST` as a JSON
        array. Same shape as the OpenCLAW allowlist.
        """
        attrs = span.get("attributes") or {}
        kind = (attrs.get("openinference.span.kind") or "").upper()
        # In-scope OpenInference kinds:
        #   AGENT      — agent execution boundary (invocation row + evidence)
        #   TOOL       — tool call + result (invocation + evidence)
        #   LLM        — model call (evidence-only, parent AGENT owns invocation)
        #   RETRIEVER  — RAG fetch — what chunks the agent saw IS evidence
        #   GUARDRAIL  — safety/policy gate — when it blocks IS audit gold
        #   EVALUATOR  — LLM-judge step — verdicts go in evidence
        # Skip: CHAIN (AGENT covers it), EMBEDDING/RERANKER (noise),
        # UNKNOWN (by definition).
        if kind not in {"AGENT", "TOOL", "LLM", "RETRIEVER", "GUARDRAIL", "EVALUATOR"}:
            return []

        # LLM-only spans → evidence-only (no invocation row). The matcher
        # returns a single MapResult with event_type="skip" but with
        # evidence_payloads populated; the bridge handles the special case
        # of attaching to the parent span's invocation if available.
        # For v1 simplicity we emit a self-contained MapResult that the
        # bridge will route — LLM spans without a parent AGENT span in the
        # same batch are dropped at this layer (it's noise without context).
        if kind == "LLM":
            payloads = self._extract_openinference_evidence(span)
            if not payloads:
                return []
            # Tag with the resolved agent_key so the bridge can defer the
            # post if needed. Today: we emit a system-message-only invocation
            # so the LLM call has a parent and evidence is queryable.
            raw_agent_key = (
                attrs.get("agent.name") or attrs.get("service.name") or self.default_agent_key
            )
            agent_key = self.normalize_agent_key(raw_agent_key)
            inv_body: dict[str, Any] = {
                "agent_key": agent_key,
                "mode": "observed",
                "outcome": "success",
            }
            dur = self.get_duration_ms(span)
            if dur is not None:
                inv_body["duration_ms"] = dur
            if attrs.get("session.id"):
                inv_body["correlation_id"] = attrs["session.id"]
            self._attach_cost_to_body(inv_body, span)
            return [
                MapResult(
                    event_type="invocation",
                    body=inv_body,
                    evidence_payloads=payloads,
                )
            ]

        # Status -> outcome. OTLP json: "STATUS_CODE_ERROR"; protobuf: int 2.
        status = span.get("status") or {}
        raw_code = status.get("code", "")
        is_error = (
            raw_code == 2
            if isinstance(raw_code, int)
            else str(raw_code).upper() in {"ERROR", "STATUS_CODE_ERROR"}
        )
        outcome = "error" if is_error else "success"

        # Agent-key resolution.
        # For AGENT spans: prefer agent.name, then span name itself
        #   (frameworks like CrewAI emit `<AgentName>.run` as the span name).
        # For TOOL spans:  prefer agent.name, then service.name — falling
        #   back to the catch-all rather than misattributing to the tool.
        if kind == "AGENT":
            raw_agent_key = (
                attrs.get("agent.name")
                or attrs.get("crewai.agent.role")  # CrewAI-specific
                or attrs.get("autogen.agent.name")  # AutoGen-specific
                or (span.get("name") or "").split(".")[0]
                or attrs.get("service.name")
                or self.default_agent_key
            )
        else:
            # TOOL / RETRIEVER / GUARDRAIL / EVALUATOR all attribute to the
            # parent agent — they're sub-steps of one agent's execution.
            raw_agent_key = (
                attrs.get("agent.name")
                or attrs.get("crewai.agent.role")
                or attrs.get("autogen.agent.name")
                or attrs.get("service.name")
                or self.default_agent_key
            )
        agent_key = self.normalize_agent_key(raw_agent_key)

        results: list[MapResult] = []
        inv_body: dict[str, Any] = {
            "agent_key": agent_key,
            "mode": "observed",
            "outcome": outcome,
        }
        dur = self.get_duration_ms(span)
        if dur is not None:
            inv_body["duration_ms"] = dur
        if attrs.get("session.id"):
            inv_body["correlation_id"] = attrs["session.id"]
        self._attach_cost_to_body(inv_body, span)

        # Extract content evidence so the bridge can chain it to this
        # invocation post (the bridge fills invocation_id once the
        # invocation row is created).
        evidence_payloads = self._extract_openinference_evidence(span)

        results.append(
            MapResult(
                event_type="invocation",
                body=inv_body,
                evidence_payloads=evidence_payloads,
            )
        )

        # OOS-tool detection — only for TOOL spans, only when allowlist set.
        if kind == "TOOL":
            tool_name = attrs.get("tool.name") or attrs.get("gen_ai.tool.name")
            if tool_name:
                allowlist_raw = os.environ.get("KYA_OPENINFERENCE_TOOL_ALLOWLIST", "").strip()
                if allowlist_raw:
                    try:
                        allow = set(json.loads(allowlist_raw))
                    except Exception as exc:
                        logger.warning(
                            "[OTLP-BRIDGE] failed to parse KYA_OPENINFERENCE_TOOL_ALLOWLIST: %s",
                            exc,
                        )
                        allow = set()
                    if allow and tool_name not in allow:
                        results.append(
                            MapResult(
                                event_type="rogue",
                                body={
                                    "event_type": "oos_tool",
                                    "agent_key": agent_key,
                                    "actor_agent_key": agent_key,
                                    "tool": tool_name,
                                },
                            )
                        )
        return results

    def _openllmetry_genai_span(self, span: dict) -> list[MapResult]:
        """Translate OpenLLMetry / OTel GenAI semantic-convention spans.

        OpenLLMetry (Traceloop) and the emerging OTel GenAI semconv don't
        carry `openinference.span.kind` — they key off the `gen_ai.*`
        attribute family and `traceloop.span.kind`. Covers LangChain,
        LlamaIndex, CrewAI, Haystack, etc. via OpenLLMetry; also catches
        Agno's native OTel emission and any framework that's adopted the
        OTel GenAI semconv directly.

        Strategy mirrors the OpenInference matcher but the discriminators
        are different.
        """
        attrs = span.get("attributes") or {}
        traceloop_kind = (attrs.get("traceloop.span.kind") or "").lower()
        gen_ai_op = (attrs.get("gen_ai.operation.name") or "").lower()
        has_tool = bool(attrs.get("gen_ai.tool.name") or attrs.get("tool.name"))
        has_agent = bool(attrs.get("gen_ai.agent.name") or attrs.get("traceloop.workflow.name"))

        is_tool_span = (
            traceloop_kind == "tool"
            or gen_ai_op in {"execute_tool", "tool.execute"}
            or (has_tool and "tool" in (span.get("name") or "").lower())
        )
        is_agent_span = (
            traceloop_kind in {"agent", "workflow"}
            or gen_ai_op in {"invoke_agent", "agent.run"}
            or has_agent
        )
        if not (is_tool_span or is_agent_span):
            return []

        status = span.get("status") or {}
        raw_code = status.get("code", "")
        is_error = (
            raw_code == 2
            if isinstance(raw_code, int)
            else str(raw_code).upper() in {"ERROR", "STATUS_CODE_ERROR"}
        )
        outcome = "error" if is_error else "success"

        raw_agent_key = (
            attrs.get("gen_ai.agent.name")
            or attrs.get("traceloop.workflow.name")
            or attrs.get("traceloop.entity.name")
            or attrs.get("agent.name")
            or attrs.get("service.name")
            or self.default_agent_key
        )
        agent_key = self.normalize_agent_key(raw_agent_key)

        results: list[MapResult] = []
        inv_body: dict[str, Any] = {
            "agent_key": agent_key,
            "mode": "observed",
            "outcome": outcome,
        }
        dur = self.get_duration_ms(span)
        if dur is not None:
            inv_body["duration_ms"] = dur
        if attrs.get("gen_ai.conversation.id") or attrs.get("session.id"):
            inv_body["correlation_id"] = attrs.get("gen_ai.conversation.id") or attrs["session.id"]
        self._attach_cost_to_body(inv_body, span)

        # Same evidence chain pattern as the OpenInference matcher — extract
        # prompts/responses/tool args from gen_ai.* semconv attributes.
        evidence_payloads = self._extract_openllmetry_evidence(span)

        results.append(
            MapResult(
                event_type="invocation",
                body=inv_body,
                evidence_payloads=evidence_payloads,
            )
        )

        # OOS detection — shared allowlist with OpenInference path so
        # operators don't have to configure two env vars for the same
        # logical tool catalog.
        if is_tool_span:
            tool_name = attrs.get("gen_ai.tool.name") or attrs.get("tool.name")
            if tool_name:
                allowlist_raw = os.environ.get("KYA_OPENINFERENCE_TOOL_ALLOWLIST", "").strip()
                if allowlist_raw:
                    try:
                        allow = set(json.loads(allowlist_raw))
                    except Exception:
                        allow = set()
                    if allow and tool_name not in allow:
                        results.append(
                            MapResult(
                                event_type="rogue",
                                body={
                                    "event_type": "oos_tool",
                                    "agent_key": agent_key,
                                    "actor_agent_key": agent_key,
                                    "tool": tool_name,
                                },
                            )
                        )
        return results

    def _tool_oos_check(self, span: dict) -> list[MapResult]:
        """Spans named like 'tool.execute' with an out-of-scope attribute."""
        attrs = span.get("attributes") or {}
        name = (span.get("name") or "").lower()
        if "tool" not in name:
            return []
        tool_name = attrs.get("tool.name") or attrs.get("function.name")
        # Only emit when the producer explicitly flagged it OOS
        if not (attrs.get("tool.allowed") is False or attrs.get("tool.oos") is True):
            return []
        if not tool_name:
            return []
        body = {
            "event_type": "oos_tool",
            "agent_key": self.get_agent_key(span),
            "actor_agent_key": self.get_agent_key(span),
            "tool": tool_name,
        }
        return [MapResult(event_type="rogue", body=body)]

    def _error_status_invocation(self, span: dict) -> list[MapResult]:
        """Span with ERROR status from an agent -> invocation outcome=error.

        OTLP status code can be a string ("ERROR" / "STATUS_CODE_ERROR")
        in JSON form OR an int (2 = ERROR) in protobuf form. Handle both.
        """
        status = span.get("status") or {}
        raw_code = status.get("code", "")
        if isinstance(raw_code, int):
            # OTLP integer codes: 0=UNSET, 1=OK, 2=ERROR
            is_error = raw_code == 2
        else:
            is_error = str(raw_code).upper() in {"ERROR", "STATUS_CODE_ERROR"}
        if not is_error:
            return []
        attrs = span.get("attributes") or {}
        if not (attrs.get("agent.name") or attrs.get(self.agent_key_attr)):
            return []
        body = {
            "agent_key": self.get_agent_key(span),
            "mode": attrs.get("agent.mode", "observed"),
            "outcome": "error",
        }
        dur = self.get_duration_ms(span)
        if dur is not None:
            body["duration_ms"] = dur
        if attrs.get("correlation_id"):
            body["correlation_id"] = attrs["correlation_id"]
        # Failed LLM calls still cost money (rate-limit 429, timeout after
        # provider consumed input tokens, etc.) — attach cost so error-heavy
        # tenants get accurate spend attribution.
        self._attach_cost_to_body(body, span)
        return [MapResult(event_type="invocation", body=body)]
