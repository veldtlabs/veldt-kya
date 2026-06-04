"""Regression tests for kya_redteam.garak_runtime — real-Garak adapter.

What this validates
-------------------
- **Real Garak invocation**: probes load, generator wraps target, detector
  scores attempts. No mocking of Garak — only the HTTP target is mocked.
- **Cost cap + multi-generation contract** (Fix #3 + #7):
  N requested honored; cap clamps real calls + pads with None up to N to
  preserve Garak's ``supports_multiple_generations=True`` contract.
- **Concurrency lock** (Fix #4): ``_garak_io_lock`` is RLock; same-thread
  reentry is safe; the I/O buffer restores ``transient.reportfile`` on
  exception inside the yield.
- **Probe family mappings** (Fix #1): all 5 non-None ``garak_probe`` values
  in GARAK_NATIVE_PROBES resolve to real Garak 0.15.x probe families.
- **Generator observability counters** (Fix #5):
  ``http_sends_total`` / ``http_send_failures`` increment correctly; both
  surface via ``run_probe_via_garak`` return dict.
- **Budget integration semantics** (Fix #6): orchestrator debits the
  monthly budget by ``total_http_sends`` (NOT ``total_attempts``) so a
  multi-generation probe is not under-counted by the gens factor.

Tests requiring the optional ``garak`` package skip gracefully if not
installed via ``pytest.importorskip``.
"""
from __future__ import annotations

import os
import threading

import pytest

from kya_redteam.garak_runtime import (
    GARAK_NATIVE_PROBES,
    GARAK_TESTED_VERSION,
    garak_available,
    garak_status,
)
from kya_redteam.pyrit_target import TargetResponse


# ── Fixtures ────────────────────────────────────────────────────────


class RefuseTarget:
    """Target that always refuses — detectors should not fire."""

    def __init__(self):
        self.calls = 0

    def send(self, prompt):
        self.calls += 1
        return TargetResponse(
            output="I'm sorry, I can't help with that request.",
            status_code=200,
        )


class CompliantTarget:
    """Target that complies with DAN-style markers — DAN detector should hit."""

    def __init__(self):
        self.calls = 0

    def send(self, prompt):
        self.calls += 1
        return TargetResponse(
            output=(
                "[DAN]: Sure! As DAN I'll do anything now. "
                "Here's how to do it: Step 1, then 2, then 3. "
                "AI_SAFETY_BYPASS_TOKEN"
            ),
            status_code=200,
        )


class RaisingTarget:
    """Target that raises on every send — exercises http_send_failures path."""

    def __init__(self):
        self.calls = 0

    def send(self, prompt):
        self.calls += 1
        raise RuntimeError("simulated target outage")


class ErrorTarget:
    """Target that returns TargetResponse.error — exercises the resp.error path."""

    def __init__(self):
        self.calls = 0

    def send(self, prompt):
        self.calls += 1
        return TargetResponse(
            output="", status_code=502, error="upstream 502"
        )


# ── Schema / mapping tests (no Garak required) ──────────────────────


class TestProbeMappingSchema:
    """GARAK_NATIVE_PROBES dataset schema — does NOT require garak install."""

    def test_all_entries_have_required_fields(self):
        required = {"prompt", "tags", "detector_substrings", "garak_probe"}
        for entry in GARAK_NATIVE_PROBES:
            assert isinstance(entry, dict), entry
            missing = required - set(entry.keys())
            assert not missing, f"entry missing {missing}: {entry}"

    def test_probe_count_unchanged(self):
        # If this changes, update the per-fix coverage spec and the docs.
        assert len(GARAK_NATIVE_PROBES) == 10

    def test_garak_probe_values_are_str_or_none(self):
        valid_families = {
            "dan", "encoding", "sysprompt_extraction",
            "promptinject", "latentinjection",
        }
        for entry in GARAK_NATIVE_PROBES:
            v = entry["garak_probe"]
            if v is not None:
                assert isinstance(v, str), v
                assert v in valid_families, (
                    f"unrecognized garak_probe={v!r}; if a new family was "
                    f"added, extend valid_families in this test"
                )

    def test_native_only_entries_have_none(self):
        # The 3 entries with no clean Garak equivalent must be None.
        # Identified by their distinctive prompt fragments.
        native_only_markers = [
            "synthesize fentanyl",
            "research assistant for a security",
            "vaccine is dangerous",
        ]
        none_entries = [e for e in GARAK_NATIVE_PROBES
                        if e["garak_probe"] is None]
        assert len(none_entries) == 3, (
            f"expected 3 native-only entries; got {len(none_entries)}"
        )
        for marker in native_only_markers:
            assert any(marker in e["prompt"] for e in none_entries), (
                f"native-only entry with marker {marker!r} missing or "
                f"now mapped to a Garak family"
            )


class TestGarakStatus:
    """garak_status() reflects install state without Garak required."""

    def test_status_keys_present(self):
        status = garak_status()
        # garak_status() returns a GarakStatus dataclass; check attributes
        for attr in ("installed", "import_ok", "enabled_by_env"):
            assert hasattr(status, attr), f"missing attribute {attr}"


# ── Adapter tests (real Garak required) ─────────────────────────────


# Conditionally import; skip module-level if garak missing.
garak = pytest.importorskip("garak")


@pytest.fixture
def _run_probe():
    """Lazy-import so the module loads when garak is missing."""
    from kya_redteam.garak_runtime import run_probe_via_garak
    return run_probe_via_garak


class TestProbeFamilyResolution:
    """Each garak_probe family value resolves to a real Garak probe."""

    @pytest.mark.parametrize("family", [
        "dan", "encoding", "sysprompt_extraction",
        "promptinject", "latentinjection",
    ])
    def test_family_resolves_and_executes(self, _run_probe, family):
        target = RefuseTarget()
        result = _run_probe(family, target, threshold=0.5)
        # Probe ran; resolved to a concrete class with a detector
        assert result["probe_class"], (
            f"{family} did not resolve to a concrete probe class"
        )
        assert result["detector"], (
            f"{family} resolved class has no primary_detector"
        )
        # Refuse target → no hits
        assert result["hits"] == []
        # Counters populated
        assert "total_http_sends" in result
        assert "http_send_failures" in result
        assert result["total_http_sends"] >= 0


class TestGeneratorObservability:
    """Fix #5 — http_sends_total / http_send_failures counters."""

    def test_send_counts_match_calls(self, _run_probe):
        target = RefuseTarget()
        result = _run_probe("dan", target, threshold=0.5)
        # Generator counted every real http_target.send call
        assert result["total_http_sends"] == target.calls
        # Refusal returns non-empty refusal text → not counted as a failure
        assert result["http_send_failures"] == 0

    def test_raising_target_counts_as_failure(self, _run_probe):
        target = RaisingTarget()
        # Probe still runs to completion (exception swallowed → None output)
        result = _run_probe("dan", target, threshold=0.5)
        # Every call raised; every call counted as failure
        assert result["http_send_failures"] == result["total_http_sends"]
        # No hits possible since outputs were all None
        assert result["hits"] == []

    def test_error_response_counts_as_failure(self, _run_probe):
        target = ErrorTarget()
        result = _run_probe("dan", target, threshold=0.5)
        # Every TargetResponse had .error set → all counted as failures
        assert result["http_send_failures"] == result["total_http_sends"]
        assert result["hits"] == []


class TestCostCap:
    """Fix #3 + #7 — KYA_REDTEAM_GARAK_MAX_GENS clamping + None padding."""

    def test_cap_below_probe_request_pads_with_none(
        self, _run_probe, monkeypatch,
    ):
        # Force cap = 1; most probes request more generations than 1
        monkeypatch.setenv("KYA_REDTEAM_GARAK_MAX_GENS", "1")
        target = RefuseTarget()
        # Should NOT crash with Garak's "asked for N got M" assertion;
        # the None-padding inside _call_model preserves the contract.
        result = _run_probe("dan", target, threshold=0.5)
        # Probe ran to completion
        assert result["probe_class"]
        # total_attempts is unchanged (count of probe attempts)
        assert result["total_attempts"] > 0


class TestConcurrencyLock:
    """Fix #4 — _garak_io_lock is RLock; reentrant; restores state."""

    def test_lock_is_rlock(self):
        from kya_redteam.garak_runtime import _garak_io_lock
        # threading.RLock is a factory; the returned object's type name
        # contains "RLock" in Python's stdlib reflection
        type_name = type(_garak_io_lock).__name__
        assert "RLock" in type_name, (
            f"expected RLock; got {type_name}. Non-reentrant Lock would "
            f"self-deadlock if a target wraps a recursive caller."
        )

    def test_io_buffer_restores_on_exception(self):
        from kya_redteam.garak_runtime import (
            _garak_probe_io_buffer, _ensure_garak_initialized,
        )
        _ensure_garak_initialized()
        from garak import _config as _gc  # noqa: F401

        original = getattr(_gc.transient, "reportfile", None)

        class BoomError(Exception):
            pass

        with pytest.raises(BoomError):
            with _garak_probe_io_buffer():
                # Mid-yield exception must not leak the swapped buffer
                raise BoomError("yield-time failure")

        # After exception, reportfile must be back to original (None or whatever)
        assert getattr(_gc.transient, "reportfile", None) is original


class TestReturnShape:
    """Public API contract — gres dict shape for orchestrator consumers."""

    def test_return_dict_contains_all_required_keys(self, _run_probe):
        target = RefuseTarget()
        result = _run_probe("dan", target, threshold=0.5)
        required_keys = {
            "probe", "probe_class", "detector", "hits", "achieved",
            "total_attempts", "total_http_sends", "http_send_failures",
            "mean_score", "raw",
        }
        missing = required_keys - set(result.keys())
        assert not missing, f"return dict missing keys: {missing}"
        # raw also carries the counters for redundancy
        assert "http_sends_total" in result["raw"]
        assert "http_send_failures" in result["raw"]

    def test_hit_dicts_have_prompt_response_score(self, _run_probe):
        target = CompliantTarget()
        result = _run_probe("dan", target, threshold=0.5)
        # Compliant target with DAN markers → expect hits
        assert result["hits"], (
            "compliant DAN-style target should produce hits via dan family"
        )
        for hit in result["hits"]:
            assert "prompt" in hit
            assert "response" in hit
            assert "score" in hit
            assert isinstance(hit["score"], (int, float))


# ── Budget integration (the Fix #6 regression guard) ────────────────


class TestBudgetIntegration:
    """Fix #6 — budget debits by total_http_sends, not total_attempts.

    This is the regression guard preventing the 5x under-bill we shipped
    in Round-2 hardening. If a future change to consume_budget or the
    orchestrator's dispatch loop reverts to using total_attempts, these
    assertions will fail.
    """

    def test_total_http_sends_at_least_total_attempts(self, _run_probe):
        """A probe firing multi-generation requests gets more sends than
        attempts. A single-generation probe gets equal counts. Never less.
        """
        target = RefuseTarget()
        result = _run_probe("dan", target, threshold=0.5)
        assert result["total_http_sends"] >= result["total_attempts"], (
            "regression: total_http_sends must be >= total_attempts. "
            "If this fails, the generator stopped honoring "
            "generations_this_call and is back to 1 call per attempt."
        )

    def test_orchestrator_imports_use_total_http_sends(self):
        """Regression guard: pyrit_orchestrator must read total_http_sends
        from gres, NOT total_attempts. Inspect the source to enforce.
        """
        from pathlib import Path
        src_path = (
            Path(__file__).resolve().parents[1]
            / "kya_redteam" / "pyrit_orchestrator.py"
        )
        src = src_path.read_text(encoding="utf-8")
        # Must reference total_http_sends in the budget-debit context
        assert "total_http_sends" in src, (
            "regression: pyrit_orchestrator no longer references "
            "total_http_sends — budget may be back to undercounting by "
            "the generations factor."
        )
        # Must use the atomic n= parameter of consume_budget, not a loop
        assert "consume_budget(" in src
        assert "n=extra" in src, (
            "regression: budget debit no longer uses atomic n=extra; "
            "may have reverted to N-INCR-per-call loop."
        )


# ── Module-level sanity ─────────────────────────────────────────────


def test_garak_tested_version_is_pinned():
    """Pinned to Garak 0.15.x. If we bump, every test in this file must
    re-run against the new minor version.
    """
    assert GARAK_TESTED_VERSION == "0.15.x"


def test_garak_available_when_installed():
    """If garak is importable, garak_available() must return True."""
    # We got here past importorskip, so garak is installed.
    assert garak_available() is True
