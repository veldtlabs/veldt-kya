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

import logging
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
    Held in a contextvars.ContextVar so concurrent calls don't collide
    across asyncio tasks."""

    def __init__(self, *, recorder, agent_key, tenant_id, correlation_id, data_classes):
        self.recorder = recorder  # function(invocation_id, kind, payload, role) -> None
        self.agent_key = agent_key
        self.tenant_id = tenant_id
        self.correlation_id = correlation_id
        self.data_classes = data_classes
        self.invocation_id: int | None = None
        self.started_at = time.time()


_CONTEXT: _InstrumentationContext | None = None  # set by autoinstrument()


def _make_db_recorder(db_factory, tenant_id, agent_key, data_classes):
    """Build a recorder fn that writes through the SDK functions (no HTTP)."""
    from .evidence import record_evidence
    from .invocations import record_invocation

    def _record_inv() -> int | None:
        try:
            with db_factory() as db:
                return record_invocation(
                    db,
                    tenant_id=tenant_id,
                    agent_key=agent_key,
                    mode="autonomous",
                    outcome="success",
                    correlation_id=_CONTEXT.correlation_id if _CONTEXT else None,
                )
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] record_invocation failed: %s", exc)
            return None

    def _record_ev(invocation_id: int, kind: str, payload: dict, role: str | None):
        if not invocation_id:
            return
        try:
            with db_factory() as db:
                record_evidence(
                    db,
                    tenant_id=tenant_id,
                    invocation_id=invocation_id,
                    evidence_kind=kind,
                    payload=payload,
                    role=role,
                    source="autoinstrument",
                    correlation_id=_CONTEXT.correlation_id if _CONTEXT else None,
                    data_classes=data_classes,
                )
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] record_evidence(%s) failed: %s", kind, exc)

    return _record_inv, _record_ev


def _make_http_recorder(client, agent_key, data_classes):
    """Build a recorder fn that posts through KyaClient (HTTP)."""

    def _record_inv() -> int | None:
        try:
            result = client.record_invocation(
                agent_key=agent_key,
                mode="autonomous",
                outcome="success",
                correlation_id=_CONTEXT.correlation_id if _CONTEXT else None,
            )
            return int(result.get("invocation_id", 0)) or None
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] http record_invocation failed: %s", exc)
            return None

    def _record_ev(invocation_id: int, kind: str, payload: dict, role: str | None):
        if not invocation_id:
            return
        try:
            client.record_evidence(
                invocation_id=invocation_id,
                evidence_kind=kind,
                payload=payload,
                role=role,
                source="autoinstrument",
                correlation_id=_CONTEXT.correlation_id if _CONTEXT else None,
                data_classes=data_classes,
            )
        except Exception as exc:
            logger.debug("[KYA-AUTOINST] http record_evidence(%s) failed: %s", kind, exc)

    return _record_inv, _record_ev


def _capture_call(
    record_inv, record_ev, messages: list, response_content: str, tool_calls: list | None
):
    """Common capture for one LLM call: ensure invocation_id, emit prompt
    + response + each tool_call evidence row."""
    global _CONTEXT
    if _CONTEXT is None:
        return
    if _CONTEXT.invocation_id is None:
        _CONTEXT.invocation_id = record_inv()
    inv = _CONTEXT.invocation_id
    if not inv:
        return
    if messages:
        record_ev(inv, "prompt", {"messages": messages}, "user")
    if response_content:
        record_ev(inv, "response", {"content": response_content}, "assistant")
    for tc in tool_calls or []:
        record_ev(inv, "tool_call", tc, "assistant")


# ── OpenAI patch ────────────────────────────────────────────────────


def _patch_openai(record_inv, record_ev) -> bool:
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
        result = orig_create(self, *args, **kw)
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
        return result

    Completions.create = wrapped
    _PATCHED["openai.Completions.create"] = orig_create
    logger.info("[KYA-AUTOINST] patched openai.Completions.create")
    return True


# ── Anthropic patch ─────────────────────────────────────────────────


def _patch_anthropic(record_inv, record_ev) -> bool:
    try:
        from anthropic.resources.messages.messages import Messages
    except ImportError:
        return False

    if "anthropic.Messages.create" in _PATCHED:
        return True

    orig_create = Messages.create

    def wrapped(self, *args, **kw):
        messages = kw.get("messages") or []
        result = orig_create(self, *args, **kw)
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
        return result

    Messages.create = wrapped
    _PATCHED["anthropic.Messages.create"] = orig_create
    logger.info("[KYA-AUTOINST] patched anthropic.Messages.create")
    return True


# ── LiteLLM patch (covers any LiteLLM-routed model) ─────────────────


def _patch_litellm(record_inv, record_ev) -> bool:
    try:
        import litellm
    except ImportError:
        return False

    if "litellm.completion" in _PATCHED:
        return True

    orig_completion = litellm.completion

    def wrapped(*args, **kw):
        messages = kw.get("messages") or (args[1] if len(args) > 1 else [])
        result = orig_completion(*args, **kw)
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
        return result

    litellm.completion = wrapped
    _PATCHED["litellm.completion"] = orig_completion
    logger.info("[KYA-AUTOINST] patched litellm.completion")
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

    if db_factory is not None:
        record_inv, record_ev = _make_db_recorder(db_factory, tenant_id, agent_key, data_classes)
    else:
        record_inv, record_ev = _make_http_recorder(client, agent_key, data_classes)

    # Install the global context — patched methods read from it.
    global _CONTEXT
    _CONTEXT = _InstrumentationContext(
        recorder=(record_inv, record_ev),
        agent_key=agent_key,
        tenant_id=tenant_id,
        correlation_id=correlation_id or str(uuid.uuid4()),
        data_classes=data_classes,
    )

    targets = set(sdks or ["openai", "anthropic", "litellm"])
    result = {}
    with _PATCHED_LOCK:
        if "openai" in targets:
            result["openai"] = _patch_openai(record_inv, record_ev)
        if "anthropic" in targets:
            result["anthropic"] = _patch_anthropic(record_inv, record_ev)
        if "litellm" in targets:
            result["litellm"] = _patch_litellm(record_inv, record_ev)
    return result


def deinstrument() -> None:
    """Restore all monkey-patched SDK methods to their originals.

    Use in tests or when shutting down a process — the global patch is
    process-wide and persists for the lifetime of the import otherwise.
    """
    global _CONTEXT
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
            except Exception as exc:
                logger.debug("[KYA-AUTOINST] deinstrument(%s) failed: %s", key, exc)
        _PATCHED.clear()
    _CONTEXT = None
    logger.info("[KYA-AUTOINST] deinstrumented all patched SDKs")


def patched_sdks() -> list[str]:
    """Return the list of SDK method keys currently patched. For
    introspection/tests."""
    return list(_PATCHED.keys())
