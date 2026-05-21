"""LangChain auto-wire — captures every step of an agent's execution.

Drop a `KyaLangchainHandler` into any LangChain agent / chain / LLM call and
KYA records the full event sequence: prompt → tool_call → tool_result →
intermediate model responses → final response. No manual `record_evidence`
calls needed.

What gets captured
------------------
Per LangChain callback (subset — we hook every event LangChain emits):
    on_chat_model_start / on_llm_start  → prompt (system + user messages)
    on_chat_model_end   / on_llm_end    → response (each model output)
    on_tool_start                       → tool_call (name + args)
    on_tool_end                         → tool_result (output text)
    on_agent_action                     → tool_call (agent's planning decision)
    on_agent_finish                     → response (final agent output)
    on_chain_start                      → invocation_id assigned (if absent)
    on_chain_end                        → invocation outcome=success
    on_chain_error / on_llm_error /     → invocation outcome=error + evidence
        on_tool_error                       row capturing the exception

Multi-step agents (ReAct, Tools agent, OpenAI Functions) produce a full
chain of evidence rows — first call to last — automatically.

Multi-agent
-----------
A delegation pattern (parent agent → child agent) carries `correlation_id`
across handlers via constructor parameter so the full request tree is
reconstructible via `list_invocations(correlation_id=...)`.

Usage
-----
    from kya_hooks import KyaClient
    from kya_hooks.langchain import KyaLangchainHandler

    client = KyaClient(base_url="http://kya:17000", token="...")
    handler = KyaLangchainHandler(
        client,
        agent_key="ops_agent",
        mode="hybrid",            # configured human_loop mode
        data_classes=["pii"],     # PII content → auto-applies GDPR retention
    )

    # Pass into ANY LangChain call:
    agent_executor.invoke({"input": user_msg}, config={"callbacks": [handler]})

    # Or set globally:
    from langchain_core.callbacks import set_handler
    set_handler(handler)

Exception-safe by design — a handler exception MUST NOT break the agent's
request path. All KYA calls are wrapped in try/except with structured logs.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

logger = logging.getLogger(__name__)

try:
    from langchain_core.callbacks import BaseCallbackHandler

    _HAS_LANGCHAIN = True
except ImportError:  # pragma: no cover
    _HAS_LANGCHAIN = False

    class BaseCallbackHandler:  # minimal stub so the file imports without LangChain
        pass


class KyaLangchainHandler(BaseCallbackHandler):
    """LangChain callback that auto-records the full event sequence into
    KYA's invocation + evidence tables.

    Args:
        client: A KyaClient instance (or anything with the same record_*
            method shape — duck-typed for testability).
        agent_key: The KYA agent_key this handler is bound to. Required.
        mode: Configured human_loop mode for this agent. Defaults
            "observed". Mapped to KYA's VALID_MODES.
        principal_kind / principal_id: Optional attribution for who
            triggered this invocation (user/agent/service_account).
        correlation_id: Optional UUID linking multiple agents' invocations
            into one request tree. Auto-generated if absent.
        parent_invocation_id: Set when this handler runs inside a
            delegated agent — links back to the parent agent's invocation
            row so the call tree reconstructs correctly.
        data_classes: e.g. ["pii", "phi"] — auto-applied to every
            evidence row this handler emits so the strictest regulator
            retention window kicks in without per-call config.
        capture_intermediate_responses: when True (default), every
            on_*_model_end fires a `response` row. When False, only
            on_agent_finish records. Default is permissive — turn off if
            you have very chatty multi-turn agents and storage cost is
            an issue.
        capture_errors: when True (default), tool/chain/llm errors are
            captured as evidence rows with kind=system_message.
    """

    def __init__(
        self,
        client: Any,
        *,
        agent_key: str,
        mode: str = "observed",
        principal_kind: str | None = None,
        principal_id: str | None = None,
        correlation_id: str | None = None,
        parent_invocation_id: int | None = None,
        data_classes: list[str] | None = None,
        capture_intermediate_responses: bool = True,
        capture_errors: bool = True,
    ):
        if not agent_key:
            raise ValueError("KyaLangchainHandler requires a non-empty agent_key")
        if not _HAS_LANGCHAIN:
            logger.warning(
                "[KYA-LC] langchain_core not installed — handler will be inert. "
                "pip install langchain-core to activate."
            )
        self.client = client
        self.agent_key = agent_key
        self.mode = mode
        self.principal_kind = principal_kind
        self.principal_id = principal_id
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.parent_invocation_id = parent_invocation_id
        self.data_classes = list(data_classes) if data_classes else None
        self.capture_intermediate_responses = capture_intermediate_responses
        self.capture_errors = capture_errors

        # Per-handler state — set lazily on first event
        self._invocation_id: int | None = None
        self._started_at: float | None = None

    # ── invocation lifecycle ───────────────────────────────────────

    def _ensure_invocation(self) -> int | None:
        """Lazy-create the invocation row on first event. Returns the
        invocation_id or None on failure (handler degrades gracefully)."""
        if self._invocation_id is not None:
            return self._invocation_id
        try:
            result = self.client.record_invocation(
                agent_key=self.agent_key,
                mode=self.mode,
                outcome="in_progress",
                principal_kind=self.principal_kind,
                principal_id=self.principal_id,
                parent_invocation_id=self.parent_invocation_id,
                correlation_id=self.correlation_id,
            )
            self._invocation_id = int(result.get("invocation_id", 0)) or None
            self._started_at = time.time()
        except Exception as exc:
            logger.warning("[KYA-LC] record_invocation failed: %s", exc)
            self._invocation_id = None
        return self._invocation_id

    def _emit(self, evidence_kind: str, payload: dict, role: str | None = None) -> None:
        """Safely fire one evidence row. Exception-swallowed by design
        so a logging issue never breaks the agent."""
        inv = self._ensure_invocation()
        if inv is None:
            return
        try:
            self.client.record_evidence(
                invocation_id=inv,
                evidence_kind=evidence_kind,
                payload=payload,
                role=role,
                source="langchain",
                correlation_id=self.correlation_id,
                data_classes=self.data_classes,
            )
        except Exception as exc:
            logger.debug("[KYA-LC] record_evidence(%s) failed: %s", evidence_kind, exc)

    def _close(self, outcome: str) -> None:
        """Mark the invocation finished. LangChain triggers this on
        on_chain_end / on_agent_finish / on_chain_error."""
        if self._invocation_id is None:
            return
        try:
            duration_ms = int((time.time() - self._started_at) * 1000) if self._started_at else None
            self.client.record_invocation(
                agent_key=self.agent_key,
                mode=self.mode,
                outcome=outcome,
                duration_ms=duration_ms,
                principal_kind=self.principal_kind,
                principal_id=self.principal_id,
                parent_invocation_id=self.parent_invocation_id,
                correlation_id=self.correlation_id,
            )
        except Exception as exc:
            logger.debug("[KYA-LC] invocation close failed: %s", exc)

    # ── LangChain callback overrides ───────────────────────────────
    # NB: arg shapes match langchain_core.callbacks.BaseCallbackHandler
    # signatures. We accept **kwargs liberally because LC's signatures
    # shift between minor versions.

    def on_chat_model_start(
        self, serialized, messages, *, run_id=None, parent_run_id=None, **kw
    ) -> None:
        # `messages` is list[list[BaseMessage]] (one inner list per chat).
        # Flatten to a simple [{role, content}, ...] for portable payload.
        try:
            flat: list[dict] = []
            for batch in messages or []:
                for m in batch or []:
                    flat.append(
                        {
                            "role": getattr(m, "type", "unknown"),
                            "content": getattr(m, "content", str(m)),
                        }
                    )
            self._emit("prompt", {"messages": flat}, role="user")
        except Exception as exc:
            logger.debug("[KYA-LC] on_chat_model_start failed: %s", exc)

    def on_llm_start(self, serialized, prompts, *, run_id=None, parent_run_id=None, **kw) -> None:
        # Plain LLM (non-chat) call — `prompts` is list[str].
        try:
            self._emit("prompt", {"prompts": list(prompts or [])}, role="user")
        except Exception as exc:
            logger.debug("[KYA-LC] on_llm_start failed: %s", exc)

    def on_chat_model_end(self, response, *, run_id=None, parent_run_id=None, **kw) -> None:
        if not self.capture_intermediate_responses:
            return
        try:
            # LLMResult.generations is list[list[Generation]]
            outputs: list[str] = []
            for batch in getattr(response, "generations", []) or []:
                for gen in batch or []:
                    msg = getattr(gen, "message", None)
                    if msg is not None:
                        outputs.append(getattr(msg, "content", str(msg)))
                    else:
                        outputs.append(getattr(gen, "text", str(gen)))
            self._emit("response", {"outputs": outputs}, role="assistant")
        except Exception as exc:
            logger.debug("[KYA-LC] on_chat_model_end failed: %s", exc)

    # LangChain emits on_llm_end for plain LLM calls; reuse the same logic
    on_llm_end = on_chat_model_end

    def on_tool_start(
        self, serialized, input_str, *, run_id=None, parent_run_id=None, **kw
    ) -> None:
        try:
            tool_name = (serialized or {}).get("name", "unknown_tool")
            # input_str may be a JSON string or freeform — store as-is
            self._emit(
                "tool_call",
                {"tool_name": tool_name, "args": input_str},
                role="assistant",
            )
        except Exception as exc:
            logger.debug("[KYA-LC] on_tool_start failed: %s", exc)

    def on_tool_end(self, output, *, run_id=None, parent_run_id=None, **kw) -> None:
        try:
            # output is typically a string; could be ToolMessage in newer LC
            result_text = getattr(output, "content", None) or str(output)
            self._emit("tool_result", {"output": result_text}, role="tool")
        except Exception as exc:
            logger.debug("[KYA-LC] on_tool_end failed: %s", exc)

    def on_agent_action(self, action, *, run_id=None, parent_run_id=None, **kw) -> None:
        try:
            self._emit(
                "tool_call",
                {
                    "tool_name": getattr(action, "tool", "unknown"),
                    "args": getattr(action, "tool_input", {}),
                    "agent_reasoning": getattr(action, "log", ""),
                },
                role="assistant",
            )
        except Exception as exc:
            logger.debug("[KYA-LC] on_agent_action failed: %s", exc)

    def on_agent_finish(self, finish, *, run_id=None, parent_run_id=None, **kw) -> None:
        try:
            return_values = getattr(finish, "return_values", {}) or {}
            self._emit(
                "response",
                {
                    "output": return_values.get("output", ""),
                    "log": getattr(finish, "log", ""),
                },
                role="assistant",
            )
            self._close("success")
        except Exception as exc:
            logger.debug("[KYA-LC] on_agent_finish failed: %s", exc)

    def on_chain_start(self, serialized, inputs, *, run_id=None, parent_run_id=None, **kw) -> None:
        # First chain start lazy-creates the invocation. Subsequent
        # nested chain starts are noops (invocation already exists).
        self._ensure_invocation()

    def on_chain_end(self, outputs, *, run_id=None, parent_run_id=None, **kw) -> None:
        # Only close once — the outermost chain end matches our invocation.
        # Tag with the final output as a system_message for audit.
        try:
            self._emit("system_message", {"chain_outputs": dict(outputs or {})})
        except Exception:
            pass
        self._close("success")

    def on_chain_error(self, error, *, run_id=None, parent_run_id=None, **kw) -> None:
        if self.capture_errors:
            try:
                self._emit(
                    "system_message",
                    {"error": str(error), "error_type": type(error).__name__},
                )
            except Exception:
                pass
        self._close("error")

    def on_llm_error(self, error, *, run_id=None, parent_run_id=None, **kw) -> None:
        if self.capture_errors:
            try:
                self._emit(
                    "system_message",
                    {"error": str(error), "error_type": type(error).__name__, "stage": "llm"},
                )
            except Exception:
                pass

    def on_tool_error(self, error, *, run_id=None, parent_run_id=None, **kw) -> None:
        if self.capture_errors:
            try:
                self._emit(
                    "tool_result",
                    {"error": str(error), "error_type": type(error).__name__},
                    role="tool",
                )
            except Exception:
                pass

    # ── inspection helpers (tests + dashboard) ─────────────────────

    @property
    def invocation_id(self) -> int | None:
        return self._invocation_id

    @property
    def correlation(self) -> str:
        return self.correlation_id
