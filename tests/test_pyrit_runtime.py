"""Regression tests for kya_redteam.pyrit_runtime — PyRIT 0.13 adapter.

What this validates
-------------------
- **Counter instrumentation** (Fix #1): KyaWrappedChatTarget tracks
  ``http_sends_total`` + ``http_send_failures`` per instance; all four
  paths (success / exception / error / empty) increment correctly.
- **Return-shape contract** (Fix #2): ``run_via_pyrit``'s return dict
  surfaces ``total_http_sends`` and ``http_send_failures`` so the
  orchestrator can debit budget at HTTP-call granularity.
- **Concurrency lock** (Fix #5): ``_pyrit_central_memory_lock`` is RLock;
  same-thread reentry is safe; lock guards the WHOLE attack lifecycle.
- **multi_turn integration** (Fix #3 + #4): ``_conversation_from_pyrit``
  populates ``result.target_calls`` from ``total_http_sends``; the
  dispatch loop back-debits budget atomically by ``n=total_http_sends``.

Tests requiring the optional ``pyrit`` package skip via importorskip.
"""
from __future__ import annotations

import asyncio
import threading

import pytest


# ── No-pyrit-required tests ─────────────────────────────────────────


class TestModuleLevel:
    """Lock + import wiring — runnable without pyrit installed."""

    def test_pyrit_central_memory_lock_is_rlock(self):
        from kya_redteam.pyrit_runtime import _pyrit_central_memory_lock
        type_name = type(_pyrit_central_memory_lock).__name__
        assert "RLock" in type_name, (
            f"expected RLock for defensive reentrancy parity with "
            f"_garak_io_lock; got {type_name}"
        )

    def test_lock_allows_same_thread_reentry(self):
        """RLock allows same-thread re-acquisition — non-reentrant Lock
        would deadlock here."""
        from kya_redteam.pyrit_runtime import _pyrit_central_memory_lock

        result = {"ok": False}

        def nested():
            with _pyrit_central_memory_lock:
                with _pyrit_central_memory_lock:
                    result["ok"] = True

        t = threading.Thread(target=nested)
        t.start()
        t.join(timeout=5.0)
        assert result["ok"], (
            "RLock failed to allow same-thread reentry — would deadlock "
            "if a future target wraps a recursive caller"
        )


# ── PyRIT-required tests ────────────────────────────────────────────


pyrit = pytest.importorskip("pyrit")


@pytest.fixture(scope="module", autouse=True)
def _pyrit_memory_initialized():
    """PyRIT's PromptChatTarget.__init__ calls CentralMemory.get_memory_instance()
    which raises if memory hasn't been set. In production this happens inside
    run_via_pyrit; in tests we set it once per module."""
    from pyrit.memory import CentralMemory, SQLiteMemory  # type: ignore
    CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:"))
    yield


@pytest.fixture
def _wrapped_class():
    """Build KyaWrappedChatTarget class lazily via _build_chat_target_classes()."""
    from kya_redteam.pyrit_runtime import _build_chat_target_classes
    wrapped_cls, _adv_cls = _build_chat_target_classes()
    return wrapped_cls


class _FakeHttpResponse:
    def __init__(self, output="", error=None, status_code=200):
        self.output = output
        self.error = error
        self.status_code = status_code


class _CountingHttpTarget:
    """Mock HTTP target — records every send call."""

    def __init__(self, mode="success"):
        self.mode = mode
        self.calls = 0

    def send(self, prompt):
        self.calls += 1
        if self.mode == "raise":
            raise RuntimeError("simulated target outage")
        if self.mode == "error":
            return _FakeHttpResponse(output="", error="upstream 502")
        if self.mode == "empty":
            return _FakeHttpResponse(output="")
        return _FakeHttpResponse(
            output=f"reply to {prompt[:20]!r}", status_code=200,
        )


class _FakeMessage:
    def __init__(self, value):
        self._value = value

    def get_value(self):
        return self._value


class TestKyaWrappedChatTargetCounters:
    """Fix #1 — http_sends_total + http_send_failures on each path."""

    def test_success_path_increments_sends_only(self, _wrapped_class):
        target = _CountingHttpTarget(mode="success")
        wrapped = _wrapped_class(target)
        msg = _FakeMessage("hello")
        out = asyncio.run(wrapped.send_prompt_async(message=msg))
        assert wrapped.http_sends_total == 1
        assert wrapped.http_send_failures == 0
        assert len(out) == 1

    def test_exception_path_increments_failure(self, _wrapped_class):
        target = _CountingHttpTarget(mode="raise")
        wrapped = _wrapped_class(target)
        msg = _FakeMessage("hello")
        out = asyncio.run(wrapped.send_prompt_async(message=msg))
        assert wrapped.http_sends_total == 1
        assert wrapped.http_send_failures == 1
        # Must still return a list[Message] so PyRIT's harness doesn't crash
        assert len(out) == 1

    def test_error_response_increments_failure(self, _wrapped_class):
        target = _CountingHttpTarget(mode="error")
        wrapped = _wrapped_class(target)
        msg = _FakeMessage("hello")
        out = asyncio.run(wrapped.send_prompt_async(message=msg))
        assert wrapped.http_sends_total == 1
        assert wrapped.http_send_failures == 1
        assert len(out) == 1

    def test_empty_response_increments_failure(self, _wrapped_class):
        target = _CountingHttpTarget(mode="empty")
        wrapped = _wrapped_class(target)
        msg = _FakeMessage("hello")
        out = asyncio.run(wrapped.send_prompt_async(message=msg))
        assert wrapped.http_sends_total == 1
        assert wrapped.http_send_failures == 1
        assert len(out) == 1

    def test_counters_are_instance_scoped_not_class(self, _wrapped_class):
        """Two wrapped targets must have independent counters."""
        t1 = _CountingHttpTarget(mode="success")
        t2 = _CountingHttpTarget(mode="success")
        w1 = _wrapped_class(t1)
        w2 = _wrapped_class(t2)
        msg = _FakeMessage("hello")
        asyncio.run(w1.send_prompt_async(message=msg))
        asyncio.run(w1.send_prompt_async(message=msg))
        asyncio.run(w2.send_prompt_async(message=msg))
        assert w1.http_sends_total == 2
        assert w2.http_sends_total == 1


class TestMultiTurnIntegrationGuards:
    """Source-level regression guards on the multi_turn dispatch path.

    These don't run PyRIT; they assert the orchestrator file references the
    new counter fields so a future refactor can't silently drop them.
    """

    def _multi_turn_src(self):
        from pathlib import Path
        return (
            Path(__file__).resolve().parents[1]
            / "kya_redteam" / "multi_turn.py"
        ).read_text(encoding="utf-8")

    def test_conversation_from_pyrit_reads_total_http_sends(self):
        src = self._multi_turn_src()
        # Fix #3: result.target_calls must come from total_http_sends
        assert 'pyrit_out.get("total_http_sends"' in src, (
            "regression: _conversation_from_pyrit no longer reads "
            "total_http_sends — back to under-counting via turns_completed"
        )
        assert 'pyrit_out.get("http_send_failures"' in src, (
            "regression: target_errors no longer populated from "
            "http_send_failures — silent target outages back to invisible"
        )

    def test_pyrit_path_does_budget_back_debit(self):
        src = self._multi_turn_src()
        # Fix #4: post-PyRIT atomic back-debit must reference n=total_http_sends
        # via consume_budget. Match either the inline name or the variable.
        assert "n=total_http_sends" in src, (
            "regression: PyRIT path no longer back-debits monthly budget "
            "by total_http_sends — costs back to unbounded vs cap"
        )

    def test_pyrit_path_uses_atomic_consume_budget(self):
        src = self._multi_turn_src()
        # Must be a single atomic call (n=...), NOT a Python-side loop
        assert "consume_budget(" in src
        # Heuristic: the PyRIT section is inside a `pyrit_routed` block
        assert "pyrit_routed" in src


class TestRunViaPyritReturnShape:
    """Fix #2 — return dict surfaces counters."""

    def test_return_dict_documents_required_keys(self):
        """Source-level guard: the run_via_pyrit return statement must
        include both counter keys. Catches a future refactor that drops
        them."""
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[1]
            / "kya_redteam" / "pyrit_runtime.py"
        ).read_text(encoding="utf-8")
        assert '"total_http_sends"' in src, (
            "regression: run_via_pyrit no longer returns total_http_sends"
        )
        assert '"http_send_failures"' in src, (
            "regression: run_via_pyrit no longer returns http_send_failures"
        )
        # Sourced from the wrapped target instance, not invented
        assert "wrapped_target.http_sends_total" in src
        assert "wrapped_target.http_send_failures" in src


class TestStructuralRefactor:
    """Fix #5 — _run_via_pyrit_locked exists and is called under lock."""

    def test_run_via_pyrit_delegates_under_lock(self):
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[1]
            / "kya_redteam" / "pyrit_runtime.py"
        ).read_text(encoding="utf-8")
        # The structural refactor moved the body into a helper under the lock
        assert "_run_via_pyrit_locked" in src, (
            "regression: refactor undone — CentralMemory race re-introduced"
        )
        assert "_pyrit_central_memory_lock" in src
        # The lock wraps the call (not a partial section)
        assert "with _pyrit_central_memory_lock:" in src

    def test_threading_imported_at_top(self):
        from pathlib import Path
        src = (
            Path(__file__).resolve().parents[1]
            / "kya_redteam" / "pyrit_runtime.py"
        ).read_text(encoding="utf-8")
        assert "import threading" in src, (
            "regression: threading import dropped — _pyrit_central_memory_lock "
            "declaration would fail at import time"
        )


# ── Smoke test (no Garak required) — confirms pytest collection works ──


def test_pyrit_available_when_installed():
    """If pyrit imported via importorskip, pyrit_available() must return True."""
    from kya_redteam.pyrit_runtime import pyrit_available
    assert pyrit_available() is True
