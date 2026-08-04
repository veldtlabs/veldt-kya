"""
kya.autoinstrument — zero-config capture for custom agents + direct LLM SDK calls.

Problem
-------
Frameworks like LangChain, CrewAI, AutoGen emit OpenInference / OpenLLMetry
spans that KYA's OTLP bridge ingests automatically. But two real-world
paths bypass that:

1. **Custom / hand-rolled agents** — a Python loop that calls OpenAI/
   Anthropic/etc. directly without any framework, with no instrumentation
   library installed.

2. **Direct LLM SDK calls bypassing the agent framework** — e.g., a helper
   function that calls `openai.chat.completions.create()` outside the
   agent's main loop.

Both result in zero evidence rows because nothing is hooked.

What this module does
---------------------
`autoinstrument()` monkey-patches the SDK clients the agent uses (OpenAI,
Anthropic, LiteLLM) so every chat-completion call captures:
  - the input messages (prompt evidence row)
  - the response output (response evidence row)
  - tool calls if present (tool_call evidence row per call)

It uses `kya.record_evidence` directly (no HTTP roundtrip) or a supplied
client. One call covers both gaps for the lifetime of the process.

Usage
-----
    from kya import autoinstrument, record_evidence, record_invocation

    autoinstrument(
        db=session,                  # SQLAlchemy session OR
        # client=kya_http_client,    # KyaClient instance
        tenant_id="...",
        agent_key="my_custom_agent",
        data_classes=["pii"],        # optional — auto-applies retention
    )
    # From here, ALL openai.chat.completions.create() calls auto-capture.

What it does NOT cover (honest scope)
-------------------------------------
- Out-of-band side effects: `os.system("curl ...")`, raw file writes,
  shell-outs to other binaries. These are by definition outside the
  Python interpreter's observability. **Mitigation:** sandbox the agent
  process — network egress firewall, syscall allowlist, filesystem
  sandbox (Docker seccomp, Kata Containers, gVisor).
- Async streaming responses partially captured — we record the full
  message on completion, not token-by-token.
- HTTP clients other than the supported SDK wrappers (raw `requests.post`
  to OpenAI's endpoint) — patch only fires when the SDK's class method
  is called.
"""

from __future__ import annotations

import contextvars
import logging
import os
import threading
import time
import uuid
from typing import Any

logger = logging.getLogger(__name__)


# Patch state — global because monkey-patches are process-wide and
# duplicate patches would double-capture.
_PATCHED_LOCK = threading.Lock()
_PATCHED: dict[str, Any] = {}  # client_class -> original_method


class _InstrumentationContext:
    """Captures the per-invocation state injected into each patched call.

    Stored in a ``contextvars.ContextVar`` so concurrent agents in the
    same Python process (asyncio tasks, thread pools, forked workers
    with proper propagation) each see their own context — no cross-
    agent leaks of ``invocation_id`` or ``correlation_id``.
    """

    def __init__(self, *, recorder, agent_key, tenant_id, correlation_id, data_classes):
        self.recorder = recorder  # function(invocation_id, kind, payload, role) -> None
        self.agent_key = agent_key
        self.tenant_id = tenant_id
        self.correlation_id = correlation_id
        self.data_classes = data_classes
        self.invocation_id: int | None = None
        self.started_at = time.time()


# ContextVar isolates the current agent's context across asyncio tasks
# and thread-local scope. ``.get(None)`` yields None when no
# autoinstrument() has been called on this task/thread yet.
_CONTEXT: contextvars.ContextVar[_InstrumentationContext | None] = contextvars.ContextVar(
    "kya_autoinstrument_context", default=None
)


def _make_db_recorder(db_factory, data_classes):
    """Build a recorder fn that writes through the SDK functions (no HTTP).

    NOTE: tenant_id and agent_key are NOT captured in the closure here —
    they are read from ``_CONTEXT.get()`` at CALL time. This is essential
    for concurrent-agent isolation: monkey-patches are process-wide, so
    every wrapped LLM call shares one recorder function. Reading identity
    from the per-task ContextVar means task A's calls attribute to
    tenant A even when task B was the most recent autoinstrument()."""
    from .evidence import record_evidence
    from .invocations import record_invocation
    from .tenant_budget import record_cost_event

    def _record_inv() -> int | None:
        ctx = _CONTEXT.get()
        if ctx is None:
            return None
        try:
            with db_factory() as db:
                return record_invocation(
                    db,
                    tenant_id=ctx.tenant_id,
                    agent_key=ctx.agent_key,
                    mode="autonomous",
                    outcome="success",
                    correlation_id=ctx.correlation_id,
                )
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] record_invocation failed: %s", exc)
            return None

    def _record_ev(invocation_id: int, kind: str, payload: dict, role: str | None):
        if not invocation_id:
            return
        ctx = _CONTEXT.get()
        if ctx is None:
            return
        try:
            with db_factory() as db:
                record_evidence(
                    db,
                    tenant_id=ctx.tenant_id,
                    invocation_id=invocation_id,
                    evidence_kind=kind,
                    payload=payload,
                    role=role,
                    source="autoinstrument",
                    correlation_id=ctx.correlation_id,
                    data_classes=ctx.data_classes,
                )
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] record_evidence(%s) failed: %s", kind, exc)

    # Cache KYA_ENV once at recorder-build time — cheap but avoids the
    # per-call os.environ lookup on the hot path.
    env_label = (os.environ.get("KYA_ENV") or "").strip() or None

    def _record_cost(
        invocation_id: int | None,
        *,
        model_used: str | None,
        provider: str | None,
        usd_amount: float,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        latency_ms: int | None = None,
        outcome: str = "success",
    ) -> None:
        # record_cost_event() itself skips when usd_amount <= 0, but we
        # gate here too so we don't open a session for a no-op.
        if usd_amount is None or usd_amount <= 0:
            return
        ctx = _CONTEXT.get()
        if ctx is None:
            return
        try:
            with db_factory() as db:
                record_cost_event(
                    db,
                    tenant_id=ctx.tenant_id,
                    agent_key=ctx.agent_key,
                    usd_amount=float(usd_amount),
                    model_used=model_used,
                    provider=provider,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    latency_ms=latency_ms,
                    outcome=outcome,
                    invocation_id=invocation_id,
                    environment=env_label,
                )
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] record_cost_event failed: %s", exc)

    return _record_inv, _record_ev, _record_cost


def _make_http_recorder(client, data_classes):
    """Build a recorder fn that posts through KyaClient (HTTP).

    Same isolation pattern as _make_db_recorder — reads agent_key from
    the per-task ContextVar rather than closing over it at patch time.
    Ensures concurrent tasks each attribute their calls correctly."""

    def _record_inv() -> int | None:
        ctx = _CONTEXT.get()
        if ctx is None:
            return None
        try:
            result = client.record_invocation(
                agent_key=ctx.agent_key,
                mode="autonomous",
                outcome="success",
                correlation_id=ctx.correlation_id,
            )
            return int(result.get("invocation_id", 0)) or None
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] http record_invocation failed: %s", exc)
            return None

    def _record_ev(invocation_id: int, kind: str, payload: dict, role: str | None):
        if not invocation_id:
            return
        ctx = _CONTEXT.get()
        if ctx is None:
            return
        try:
            client.record_evidence(
                invocation_id=invocation_id,
                evidence_kind=kind,
                payload=payload,
                role=role,
                source="autoinstrument",
                correlation_id=ctx.correlation_id,
                data_classes=ctx.data_classes,
            )
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] http record_evidence(%s) failed: %s", kind, exc)

    def _record_cost(invocation_id, **kw):
        # KyaClient has no record_cost_event endpoint yet — cost tracking
        # is db_factory-mode only. Silently skip in HTTP mode so the LLM
        # call itself always returns cleanly. Once the HTTP endpoint
        # ships (companion task on veldt-kya-pro dashboard_api), this
        # stub becomes a real POST.
        return

    return _record_inv, _record_ev, _record_cost


def _capture_call(
    record_inv, record_ev, messages: list, response_content: str, tool_calls: list | None
):
    """Common capture for one LLM call: ensure invocation_id, emit prompt
    + response + each tool_call evidence row."""
    ctx = _CONTEXT.get()
    if ctx is None:
        return
    if ctx.invocation_id is None:
        ctx.invocation_id = record_inv()
    inv = ctx.invocation_id
    if not inv:
        return
    if messages:
        record_ev(inv, "prompt", {"messages": messages}, "user")
    if response_content:
        record_ev(inv, "response", {"content": response_content}, "assistant")
    for tc in tool_calls or []:
        record_ev(inv, "tool_call", tc, "assistant")


def _usage_field(usage, keys: tuple[str, ...]) -> int | None:
    """Extract a numeric usage field regardless of whether ``usage`` is a
    dict, a Pydantic model, or a SimpleNamespace. Returns None on miss."""
    if usage is None:
        return None
    for k in keys:
        val = usage.get(k) if isinstance(usage, dict) else getattr(usage, k, None)
        if val is not None:
            try:
                return int(val)
            except (TypeError, ValueError):
                continue
    return None


def _capture_error(
    record_inv,
    record_ev,
    messages: list,
    exc: BaseException,
    *,
    model_hint: str | None,
) -> None:
    """Record an error evidence row when the LLM call raises.

    Best-effort — every failure path silently no-ops so the customer's
    original exception propagates unchanged. We do NOT re-raise here;
    that's the caller's job (bare `raise` in the wrapper).

    Note: we deliberately DO NOT record a cost row on error. Most SDK
    exceptions (RateLimitError, APIConnectionError, AuthenticationError)
    carry no billable usage; the few that do (Anthropic 529 after
    partial-billing) can't be reliably extracted without SDK-specific
    parsing. Cost accuracy > cost completeness — a $0 error is honest,
    an inflated fake is not.
    """
    try:
        ctx = _CONTEXT.get()
        if ctx is None:
            return
        if ctx.invocation_id is None:
            ctx.invocation_id = record_inv()
        inv = ctx.invocation_id
        if not inv:
            return
        if messages:
            record_ev(inv, "prompt", {"messages": _msgs_to_dicts(messages)}, "user")
        # Use "system_message" (whitelisted in kya.evidence.VALID_EVIDENCE_KINDS)
        # with a distinct kind marker inside the payload so consumers can
        # filter for LLM errors via payload['kind'] == 'llm_error'.
        record_ev(
            inv,
            "system_message",
            {
                "kind": "llm_error",
                "error_type": type(exc).__name__,
                "message": str(exc)[:2000],  # cap payload
                "model": model_hint,
            },
            "system",
        )
    except Exception as inner:
        logger.debug("[KYA-AUTOINST] _capture_error itself failed: %s", inner)


def _capture_cost(
    record_cost,
    response: Any,
    *,
    provider_hint: str | None,
    start_ns: int,
    end_ns: int | None = None,
    model_hint: str | None = None,
) -> None:
    """Extract cost + usage from an LLM response and hand off to record_cost.

    Best-effort semantics: every failure path silently returns so the
    LLM call itself is never impacted.

    Requires ``litellm`` to be importable (it holds the maintained
    pricing table for 100+ providers). Without it, we skip cost writes
    rather than guess prices — an honest empty $ tile beats a wrong one.
    """
    if response is None:
        return
    try:
        import litellm  # noqa: F401 — imported for cost calculator + provider hints
    except ImportError:
        return  # no pricing table available — cost silently disabled

    try:
        # Prefer LiteLLM's own provider detection when the response
        # carries it (LiteLLM sets _hidden_params on every completion).
        provider = provider_hint
        hidden = getattr(response, "_hidden_params", None) or {}
        if not isinstance(hidden, dict):
            hidden = {}
        if hidden.get("custom_llm_provider"):
            provider = str(hidden["custom_llm_provider"])

        model_used = getattr(response, "model", None) or model_hint

        # If the model string carries a provider prefix (`azure/gpt-4`,
        # `openrouter/openai/gpt-4o-mini`, `bedrock/anthropic.claude-...`),
        # prefer that over provider_hint. This catches AzureOpenAI +
        # OpenRouter routed through the OpenAI SDK (same Completions
        # class, no _hidden_params, so provider_hint="openai" would
        # otherwise misattribute).
        if (
            provider in (None, "openai", "anthropic")
            and model_used
            and "/" in model_used
        ):
            prefix = model_used.split("/", 1)[0].lower()
            if prefix in ("azure", "openrouter", "bedrock", "vertex_ai", "cohere", "groq"):
                provider = prefix

        usage = getattr(response, "usage", None)
        input_tokens = _usage_field(usage, ("prompt_tokens", "input_tokens"))
        output_tokens = _usage_field(usage, ("completion_tokens", "output_tokens"))

        # Cost-source hierarchy (authoritative first):
        #  1) LiteLLM's own response_cost (set on every completion; already
        #     reconciled against the provider's usage.cost if present).
        #  2) usage.cost as returned by the provider (OpenRouter etc).
        #  3) Recompute via litellm.completion_cost() using the local
        #     pricing table.
        #  4) None found → usd=0.0, record_cost_event drops the row.
        usd = 0.0
        raw = hidden.get("response_cost")
        if raw is None and usage is not None:
            raw = (
                usage.get("cost")
                if isinstance(usage, dict)
                else getattr(usage, "cost", None)
            )
        if raw is not None:
            try:
                usd = float(raw)
            except (TypeError, ValueError):
                raw = None
        if not raw:
            try:
                usd = float(litellm.completion_cost(completion_response=response) or 0.0)
            except Exception as exc:
                # Common cause: OpenRouter/local-proxy routes LiteLLM's
                # pricing table doesn't map. Not fatal — we just record
                # 0 cost, and record_cost_event() will drop it (honest
                # skip since we truly don't know the cost).
                logger.debug("[KYA-AUTOINST] litellm.completion_cost failed: %s", exc)
                usd = 0.0

        # Prefer the caller-supplied end_ns (measured immediately after
        # orig_*() returns) so latency reflects the LLM call alone —
        # not the capture overhead that runs between orig_*() and now.
        _stop_ns = end_ns if end_ns is not None else time.perf_counter_ns()
        latency_ms = max(0, int((_stop_ns - start_ns) / 1_000_000))
        ctx = _CONTEXT.get()
        inv = ctx.invocation_id if ctx else None
        record_cost(
            inv,
            model_used=model_used,
            provider=provider,
            usd_amount=usd,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
        )
    except Exception as exc:
        logger.debug("[KYA-AUTOINST] _capture_cost failed: %s", exc)


# ── OpenAI patch ────────────────────────────────────────────────────


def _patch_openai(record_inv, record_ev, record_cost) -> bool:
    """Wrap openai.OpenAI().chat.completions.create. Returns True if
    successfully patched, False if the openai client isn't importable."""
    try:
        from openai.resources.chat.completions import Completions
    except ImportError:
        return False

    if "openai.Completions.create" in _PATCHED:
        return True  # already patched

    orig_create = Completions.create

    def wrapped(self, *args, **kw):
        messages = kw.get("messages") or []
        _t0 = time.perf_counter_ns()
        try:
            result = orig_create(self, *args, **kw)
        except Exception as exc:
            # Record error evidence for the failed call, then re-raise
            # preserving type + traceback (bare `raise`, not `raise exc`).
            _capture_error(record_inv, record_ev, messages, exc, model_hint=kw.get("model"))
            raise
        _t1 = time.perf_counter_ns()  # LLM-only elapsed; excludes capture overhead
        try:
            # Result is a ChatCompletion with .choices[0].message
            choice = result.choices[0] if getattr(result, "choices", None) else None
            content = getattr(getattr(choice, "message", None), "content", "") if choice else ""
            tool_calls_raw = (
                getattr(getattr(choice, "message", None), "tool_calls", None) if choice else None
            )
            tcs = []
            for tc in tool_calls_raw or []:
                try:
                    tcs.append(
                        {
                            "tool_name": tc.function.name,
                            "args": tc.function.arguments,
                        }
                    )
                except Exception:
                    continue
            _capture_call(record_inv, record_ev, _msgs_to_dicts(messages), content, tcs)
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] openai capture failed: %s", exc)
        _capture_cost(
            record_cost,
            result,
            provider_hint="openai",
            start_ns=_t0,
            end_ns=_t1,
            model_hint=kw.get("model"),
        )
        return result

    Completions.create = wrapped
    _PATCHED["openai.Completions.create"] = orig_create
    logger.info("[KYA-AUTOINST] patched openai.Completions.create")
    return True


# ── Anthropic patch ─────────────────────────────────────────────────


def _patch_anthropic(record_inv, record_ev, record_cost) -> bool:
    try:
        from anthropic.resources.messages.messages import Messages
    except ImportError:
        return False

    if "anthropic.Messages.create" in _PATCHED:
        return True

    orig_create = Messages.create

    def wrapped(self, *args, **kw):
        messages = kw.get("messages") or []
        _t0 = time.perf_counter_ns()
        try:
            result = orig_create(self, *args, **kw)
        except Exception as exc:
            _capture_error(record_inv, record_ev, messages, exc, model_hint=kw.get("model"))
            raise
        _t1 = time.perf_counter_ns()  # LLM-only elapsed; excludes capture overhead
        try:
            # Result is a Message with .content (list of TextBlock / ToolUseBlock)
            content_blocks = getattr(result, "content", []) or []
            text_parts = []
            tcs = []
            for block in content_blocks:
                btype = getattr(block, "type", None)
                if btype == "text":
                    text_parts.append(getattr(block, "text", ""))
                elif btype == "tool_use":
                    tcs.append(
                        {
                            "tool_name": getattr(block, "name", "unknown"),
                            "args": getattr(block, "input", {}),
                        }
                    )
            _capture_call(
                record_inv, record_ev, _msgs_to_dicts(messages), "\n".join(text_parts), tcs
            )
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] anthropic capture failed: %s", exc)
        _capture_cost(
            record_cost,
            result,
            provider_hint="anthropic",
            start_ns=_t0,
            end_ns=_t1,
            model_hint=kw.get("model"),
        )
        return result

    Messages.create = wrapped
    _PATCHED["anthropic.Messages.create"] = orig_create
    logger.info("[KYA-AUTOINST] patched anthropic.Messages.create")
    return True


# ── LiteLLM patch (covers any LiteLLM-routed model) ─────────────────


def _patch_litellm(record_inv, record_ev, record_cost) -> bool:
    try:
        import litellm
    except ImportError:
        return False

    if "litellm.completion" in _PATCHED:
        return True

    orig_completion = litellm.completion

    def wrapped(*args, **kw):
        messages = kw.get("messages") or (args[1] if len(args) > 1 else [])
        _t0 = time.perf_counter_ns()
        try:
            result = orig_completion(*args, **kw)
        except Exception as exc:
            _capture_error(record_inv, record_ev, messages, exc, model_hint=kw.get("model"))
            raise
        _t1 = time.perf_counter_ns()  # LLM-only elapsed; excludes capture overhead
        try:
            # LiteLLM normalizes responses to OpenAI's ChatCompletion shape
            choice = result.choices[0] if getattr(result, "choices", None) else None
            content = ""
            tcs = []
            if choice:
                msg = getattr(choice, "message", None) or {}
                content = (
                    msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
                )
                raw_tcs = (
                    msg.get("tool_calls")
                    if isinstance(msg, dict)
                    else getattr(msg, "tool_calls", None)
                )
                for tc in raw_tcs or []:
                    fn = (
                        tc.get("function")
                        if isinstance(tc, dict)
                        else getattr(tc, "function", None)
                    )
                    if fn:
                        tcs.append(
                            {
                                "tool_name": fn.get("name")
                                if isinstance(fn, dict)
                                else getattr(fn, "name", ""),
                                "args": fn.get("arguments")
                                if isinstance(fn, dict)
                                else getattr(fn, "arguments", ""),
                            }
                        )
            _capture_call(record_inv, record_ev, _msgs_to_dicts(messages), content, tcs)
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] litellm capture failed: %s", exc)
        # For LiteLLM the response carries _hidden_params.custom_llm_provider,
        # so _capture_cost's own provider detection wins over this hint.
        _capture_cost(
            record_cost, result, provider_hint=None, start_ns=_t0, model_hint=kw.get("model")
        )
        return result

    litellm.completion = wrapped
    _PATCHED["litellm.completion"] = orig_completion
    logger.info("[KYA-AUTOINST] patched litellm.completion")

    # Also patch the async entry point. LiteLLM's `acompletion` is a
    # separate coroutine — the sync `completion` wrapper we installed
    # above does NOT intercept `await acompletion(...)`. Production
    # async servers (FastAPI, Starlette) route through acompletion,
    # so without this every async call bypasses cost/evidence capture.
    #
    # ContextVar propagation across `await` is native to Python — the
    # ctx set by autoinstrument() flows through the coroutine.
    orig_acompletion = getattr(litellm, "acompletion", None)
    if orig_acompletion is not None and "litellm.acompletion" not in _PATCHED:

        async def wrapped_a(*args, **kw):
            messages = kw.get("messages") or (args[1] if len(args) > 1 else [])
            _t0 = time.perf_counter_ns()
            try:
                result = await orig_acompletion(*args, **kw)
            except Exception as exc:
                _capture_error(record_inv, record_ev, messages, exc, model_hint=kw.get("model"))
                raise
            _t1 = time.perf_counter_ns()
            try:
                choice = result.choices[0] if getattr(result, "choices", None) else None
                content = ""
                tcs = []
                if choice:
                    msg = getattr(choice, "message", None) or {}
                    content = (
                        msg.get("content", "")
                        if isinstance(msg, dict)
                        else getattr(msg, "content", "")
                    )
                _capture_call(record_inv, record_ev, _msgs_to_dicts(messages), content, tcs)
            except Exception as exc:
                logger.debug("[KYA-AUTOINST] litellm acapture failed: %s", exc)
            _capture_cost(
                record_cost, result, provider_hint=None, start_ns=_t0, end_ns=_t1,
                model_hint=kw.get("model"),
            )
            return result

        litellm.acompletion = wrapped_a
        _PATCHED["litellm.acompletion"] = orig_acompletion
        logger.info("[KYA-AUTOINST] patched litellm.acompletion")

    return True


def _msgs_to_dicts(messages: list) -> list[dict]:
    """Normalize message list to [{role, content}, ...] regardless of source.
    OpenAI accepts dicts; LangChain wraps in BaseMessage; Anthropic uses dicts.
    """
    out = []
    for m in messages or []:
        if isinstance(m, dict):
            out.append({"role": m.get("role", "unknown"), "content": str(m.get("content", ""))})
        else:
            out.append(
                {
                    "role": getattr(m, "role", None) or getattr(m, "type", "unknown"),
                    "content": getattr(m, "content", str(m)),
                }
            )
    return out


# ── Public API ──────────────────────────────────────────────────────


def autoinstrument(
    *,
    db_factory: Any = None,
    client: Any = None,
    tenant_id: str,
    agent_key: str,
    correlation_id: str | None = None,
    data_classes: list[str] | None = None,
    sdks: list[str] | None = None,
) -> dict[str, bool]:
    """Monkey-patch LLM SDKs so every call captures prompt/response/tool
    evidence automatically. Returns a dict of {sdk_name: patched_bool}.

    Required: exactly one of `db_factory` (callable returning a SQLAlchemy
    session) OR `client` (KyaClient instance). The recorder writes through
    that channel.

    Args:
        db_factory: Callable that returns a session context manager —
            e.g., `lambda: Session()`. Used when KYA's storage is local
            to the process (SDK direct-write path).
        client: KyaClient instance — used when KYA is over HTTP.
        tenant_id: Tenant scope for every captured row.
        agent_key: Agent identity for the captured invocation row.
        correlation_id: UUID for the request tree (auto-generated when None).
        data_classes: e.g. ["pii", "phi"] — auto-applied to every evidence
            row so retention policies fire.
        sdks: Subset of SDKs to patch. Default ["openai", "anthropic",
            "litellm"]. Pass an explicit list to skip / scope.

    Returns:
        {"openai": True/False, "anthropic": True/False, "litellm": True/False}
        — True means successfully patched (SDK was importable), False means
        the SDK isn't installed in this env (silently skipped).
    """
    if (db_factory is None) == (client is None):
        raise ValueError("autoinstrument requires exactly one of db_factory= or client=")
    if not tenant_id or not agent_key:
        raise ValueError("tenant_id and agent_key are required")

    # Recorders no longer close over tenant_id/agent_key — they read
    # from _CONTEXT.get() at call time. This is what makes concurrent
    # agents actually isolated: monkey-patches are process-wide, so
    # the shared wrapped function must resolve identity per call.
    if db_factory is not None:
        record_inv, record_ev, record_cost = _make_db_recorder(db_factory, data_classes)
    else:
        record_inv, record_ev, record_cost = _make_http_recorder(client, data_classes)

    # Install the context — patched methods read from ContextVar.get().
    # NOTE: ContextVar.set() writes into the CURRENT task/thread's copy
    # of the var, so this call binds the context to whichever task
    # invoked autoinstrument(). Child tasks that inherit context (i.e.
    # spawned before this set) will see the new context automatically;
    # sibling tasks spawned in a different context branch will not —
    # which is exactly the isolation we want.
    _CONTEXT.set(
        _InstrumentationContext(
            recorder=(record_inv, record_ev, record_cost),
            agent_key=agent_key,
            tenant_id=tenant_id,
            correlation_id=correlation_id or str(uuid.uuid4()),
            data_classes=data_classes,
        )
    )

    targets = set(sdks or ["openai", "anthropic", "litellm"])
    result = {}
    with _PATCHED_LOCK:
        if "openai" in targets:
            result["openai"] = _patch_openai(record_inv, record_ev, record_cost)
        if "anthropic" in targets:
            result["anthropic"] = _patch_anthropic(record_inv, record_ev, record_cost)
        if "litellm" in targets:
            result["litellm"] = _patch_litellm(record_inv, record_ev, record_cost)
    return result


def deinstrument() -> None:
    """Restore all monkey-patched SDK methods to their originals.

    Use in tests or when shutting down a process — the global patch is
    process-wide and persists for the lifetime of the import otherwise.
    """
    with _PATCHED_LOCK:
        for key, orig in list(_PATCHED.items()):
            try:
                if key == "openai.Completions.create":
                    from openai.resources.chat.completions import Completions

                    Completions.create = orig
                elif key == "anthropic.Messages.create":
                    from anthropic.resources.messages.messages import Messages

                    Messages.create = orig
                elif key == "litellm.completion":
                    import litellm

                    litellm.completion = orig
                elif key == "litellm.acompletion":
                    import litellm

                    litellm.acompletion = orig
            except Exception as exc:
                logger.debug("[KYA-AUTOINST] deinstrument(%s) failed: %s", key, exc)
        _PATCHED.clear()
    _CONTEXT.set(None)
    logger.info("[KYA-AUTOINST] deinstrumented all patched SDKs")


def patched_sdks() -> list[str]:
    """Return the list of SDK method keys currently patched. For
    introspection/tests."""
    return list(_PATCHED.keys())
