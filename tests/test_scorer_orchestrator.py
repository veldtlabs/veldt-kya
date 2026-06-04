"""Tests for the multi-judge scorer orchestrator -- dimension routing,
consensus aggregation, and signal mapping.

These tests are LIVE-API-FREE. We swap stub adapters into the judge
registry so the consensus + signal-routing logic can be verified
without OpenAI / Fiddler / Phoenix calls.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from kya.scorer_orchestrator import (
    _DIMENSION_TO_SIGNAL,
    _JUDGES,
    JudgeResult,
    check_consensus,
    list_judges,
    register_judge,
    signals_from_consensus,
)

# ── Test infrastructure ───────────────────────────────────────────


def _stub(name: str, verdict: str, dimension: str,
          score: float | None = None) -> Callable:
    """Build a stub judge that returns a fixed verdict + dimension."""
    def _adapter(input_text, response, context):
        return JudgeResult(
            judge_name=name, verdict=verdict, raw_score=score,
            threshold=None, latency_ms=1, dimension=dimension)
    return _adapter


@pytest.fixture(autouse=True)
def isolate_registry():
    """Each test starts with an empty registry. Restore the prior
    state on exit so test ordering doesn't matter and we don't
    leak stubs into other tests."""
    saved = dict(_JUDGES)
    _JUDGES.clear()
    yield
    _JUDGES.clear()
    _JUDGES.update(saved)


# ── Dimension routing ─────────────────────────────────────────────


def test_input_safety_and_safety_are_separate_pools():
    """An input_safety BREACH from one judge and a safety OK from
    another should NOT cross-pool. The input_safety dimension fires
    BREACH; the safety dimension stays OK."""
    register_judge("input_only_breach",
                   _stub("input_only_breach", "BREACH",
                         "input_safety", 0.9))
    register_judge("output_only_ok",
                   _stub("output_only_ok", "OK", "safety", 0.0))

    r = check_consensus(input_text="x", response="y", context=None)

    assert "input_safety" in r.per_dimension
    assert "safety" in r.per_dimension
    assert r.per_dimension["input_safety"].consensus == "BREACH"
    assert r.per_dimension["safety"].consensus == "OK"


def test_faithfulness_judges_do_not_outvote_input_safety():
    """The bug we shipped a fix for: a real input-safety BREACH
    must NOT be outvoted by faithfulness judges that scored the
    agent's clean refusal as OK."""
    register_judge("fiddler_input",
                   _stub("fiddler_input", "BREACH",
                         "input_safety", 0.91))
    register_judge("faith_judge_1",
                   _stub("faith_judge_1", "OK", "faithfulness"))
    register_judge("faith_judge_2",
                   _stub("faith_judge_2", "OK", "faithfulness"))
    register_judge("faith_judge_3",
                   _stub("faith_judge_3", "OK", "faithfulness"))

    r = check_consensus(input_text="x", response="y", context=None)

    assert r.per_dimension["input_safety"].consensus == "BREACH"
    assert r.per_dimension["faithfulness"].consensus == "OK"
    # Top-level is harsh-OR: any dimension BREACH => top BREACH.
    assert r.consensus == "BREACH"


def test_any_dimension_judge_votes_in_every_pool():
    """An 'any'-dimension judge still participates in every pool --
    intended for cross-cutting heuristics. Used sparingly because
    it conflates dimensions."""
    register_judge("input_breach",
                   _stub("input_breach", "BREACH",
                         "input_safety", 0.91))
    register_judge("any_ok",
                   _stub("any_ok", "OK", "any"))

    r = check_consensus(input_text="x", response="y", context=None)

    # input_safety: BREACH(1) vs OK(1) from "any_ok" -> SPLIT
    assert r.per_dimension["input_safety"].consensus == "SPLIT"
    # safety: just "any_ok" -> OK
    assert r.per_dimension["safety"].consensus == "OK"
    # faithfulness: just "any_ok" -> OK
    assert r.per_dimension["faithfulness"].consensus == "OK"


# ── Signal routing ────────────────────────────────────────────────


def test_signals_input_safety_breach_emits_received_attack():
    register_judge("fiddler_input",
                   _stub("fiddler_input", "BREACH",
                         "input_safety", 0.91))

    r = check_consensus(input_text="x", response="y", context=None)
    sigs = signals_from_consensus(r)

    assert ("received_attack", "input_safety") in sigs
    # Should NOT emit policy_violation (which would punish the
    # agent for being attacked).
    assert not any(k == "policy_violation" for k, _ in sigs)


def test_signals_safety_breach_emits_policy_violation():
    register_judge("output_safety",
                   _stub("output_safety", "BREACH", "safety", 0.95))

    r = check_consensus(input_text="x", response="y", context=None)
    sigs = signals_from_consensus(r)

    assert ("policy_violation", "safety") in sigs


def test_signals_faithfulness_breach_emits_hallucination():
    register_judge("faith",
                   _stub("faith", "BREACH", "faithfulness", 0.2))

    r = check_consensus(input_text="x", response="y", context=None)
    sigs = signals_from_consensus(r)

    assert ("hallucination_detected", "faithfulness") in sigs


def test_signals_split_ignored_by_default():
    """SPLIT consensus means judges disagreed. Default policy is
    'ignore' -- operator decides. Don't auto-decay trust on SPLIT."""
    register_judge("a",
                   _stub("a", "BREACH", "input_safety", 0.91))
    register_judge("b",
                   _stub("b", "OK", "input_safety", 0.1))

    r = check_consensus(input_text="x", response="y", context=None)
    sigs = signals_from_consensus(r)

    assert r.per_dimension["input_safety"].consensus == "SPLIT"
    assert sigs == []


def test_signals_split_treated_as_breach_when_requested():
    """High-stakes routes can opt into treating SPLIT as BREACH."""
    register_judge("a",
                   _stub("a", "BREACH", "input_safety", 0.91))
    register_judge("b",
                   _stub("b", "OK", "input_safety", 0.1))

    r = check_consensus(input_text="x", response="y", context=None)
    sigs = signals_from_consensus(r, on_split="treat_as_breach")

    assert ("received_attack", "input_safety") in sigs


# ── Mapping table integrity ───────────────────────────────────────


def test_dimension_signal_map_covers_all_routable_dimensions():
    """Every non-'any' dimension should have a signal mapping.
    Catches drift if someone adds a new dimension without wiring
    its signal kind."""
    expected = {"input_safety", "safety", "faithfulness"}
    assert set(_DIMENSION_TO_SIGNAL.keys()) == expected


def test_signal_kinds_are_known_to_users_signal_deltas():
    """The signal kinds the orchestrator emits must be present in
    SIGNAL_DELTAS so trust deltas are intentional (not the -2
    fallback)."""
    from kya.users import SIGNAL_DELTAS
    for kind in _DIMENSION_TO_SIGNAL.values():
        assert kind in SIGNAL_DELTAS, (
            f"signal kind {kind!r} from _DIMENSION_TO_SIGNAL is "
            f"missing from SIGNAL_DELTAS -- would silently fall "
            f"through to the -2 default")


# ── Parallelism + result shape ────────────────────────────────────


def test_check_consensus_runs_all_registered_when_no_filter():
    """No `judges=` filter -> all registered judges run."""
    register_judge("j1", _stub("j1", "OK", "input_safety"))
    register_judge("j2", _stub("j2", "OK", "safety"))
    register_judge("j3", _stub("j3", "OK", "faithfulness"))

    r = check_consensus(input_text="x", response="y", context=None)
    names = {j.judge_name for j in r.judges}

    assert names == {"j1", "j2", "j3"}
    assert sorted(list_judges()) == ["j1", "j2", "j3"]


def test_check_consensus_filter_runs_only_named():
    register_judge("j1", _stub("j1", "OK", "input_safety"))
    register_judge("j2", _stub("j2", "BREACH", "safety"))
    register_judge("j3", _stub("j3", "BREACH", "faithfulness"))

    r = check_consensus(input_text="x", response="y",
                        context=None, judges=["j1"])

    assert {j.judge_name for j in r.judges} == {"j1"}
    assert r.consensus == "OK"  # only j1 ran


def test_top_level_consensus_harsh_or_across_dimensions():
    """Top-level should be BREACH if ANY dimension breaches, even if
    other dimensions are OK. Security-by-default posture."""
    register_judge("input_ok",
                   _stub("input_ok", "OK", "input_safety"))
    register_judge("safety_ok",
                   _stub("safety_ok", "OK", "safety"))
    register_judge("faith_breach",
                   _stub("faith_breach", "BREACH", "faithfulness"))

    r = check_consensus(input_text="x", response="y", context=None)
    assert r.consensus == "BREACH"


# ── register_available_adapters() DX helper ───────────────────────


def test_register_available_adapters_returns_status_dict():
    """The function returns a dict mapping each opt-in adapter to a
    status string. Empty registry to start; each adapter either
    registers, gets excluded, or is skipped with a documented reason."""
    from kya.scorer_orchestrator import register_available_adapters
    status = register_available_adapters()
    assert isinstance(status, dict)
    # Each known opt-in adapter appears in the result
    for expected_judge in (
            "kya_presidio", "arize_phoenix", "langkit_whylabs",
            "lakera_guard", "nemo_guardrails"):
        assert expected_judge in status
        v = status[expected_judge]
        # status is one of the documented values
        assert any(v.startswith(p) for p in (
            "registered", "already_registered",
            "skipped"))


def test_register_available_adapters_skips_lakera_without_key(monkeypatch):
    """No LAKERA_API_KEY env -> lakera_guard is skipped, others
    still try."""
    from kya.scorer_orchestrator import register_available_adapters
    monkeypatch.delenv("LAKERA_API_KEY", raising=False)
    status = register_available_adapters()
    assert "no api key" in status["lakera_guard"]


def test_register_available_adapters_respects_exclude_kwarg():
    """`exclude` opt-out: customer in regulated industry doesn't
    want PII scanning."""
    from kya.scorer_orchestrator import register_available_adapters
    status = register_available_adapters(exclude=["kya_presidio"])
    assert status["kya_presidio"] == "skipped (excluded)"
    assert "kya_presidio" not in _JUDGES


def test_register_available_adapters_respects_env_var(monkeypatch):
    """KYA_DISABLE_JUDGES env var: ops-friendly opt-out for
    customers who can't change code."""
    from kya.scorer_orchestrator import register_available_adapters
    monkeypatch.setenv("KYA_DISABLE_JUDGES",
                       "kya_presidio,arize_phoenix")
    status = register_available_adapters()
    assert status["kya_presidio"] == "skipped (excluded)"
    assert status["arize_phoenix"] == "skipped (excluded)"


def test_register_available_adapters_idempotent():
    """Calling twice doesn't double-register; second call returns
    'already_registered' for whatever the first call registered."""
    from kya.scorer_orchestrator import register_available_adapters
    first = register_available_adapters()
    second = register_available_adapters()
    # Anything that registered in `first` should be
    # already_registered in `second`.
    for name, status in first.items():
        if status == "registered":
            assert second[name] == "already_registered"


def test_register_available_adapters_swallows_unexpected_errors(monkeypatch):
    """If a registrar raises something unexpected, the dx helper
    should NOT take down the rest of the panel. raise_on_error=False
    is the default."""
    # Patch one registrar to blow up
    import kya.scorer_orchestrator as orch
    from kya.scorer_orchestrator import register_available_adapters

    def boom():
        raise ValueError("simulated upstream API drift")

    # Swap registrar resolver to inject our broken adapter for
    # one judge.
    orig_resolve = orch._resolve

    def fake_resolve(path):
        if "presidio" in path:
            return boom
        return orig_resolve(path)

    monkeypatch.setattr(orch, "_resolve", fake_resolve)
    status = register_available_adapters()
    # Presidio skipped because its registrar raised
    assert status["kya_presidio"].startswith("skipped (error")
    # Other adapters still got their attempt -- proves the rest
    # of the panel doesn't die when one registrar misbehaves.
    assert "arize_phoenix" in status
    assert "langkit_whylabs" in status


def test_register_available_adapters_raise_on_error_when_requested(
        monkeypatch):
    """raise_on_error=True surfaces unexpected exceptions to the
    caller so bootstrapping issues fail loudly. The 'expected'
    skips (ImportError, missing key) are still swallowed."""
    import pytest as _pytest

    import kya.scorer_orchestrator as orch
    from kya.scorer_orchestrator import register_available_adapters

    def boom():
        raise ValueError("simulated upstream API drift")

    orig_resolve = orch._resolve

    def fake_resolve(path):
        if "presidio" in path:
            return boom
        return orig_resolve(path)

    monkeypatch.setattr(orch, "_resolve", fake_resolve)
    with _pytest.raises(ValueError):
        register_available_adapters(raise_on_error=True)


def test_report_panel_status_returns_active_and_available():
    """report_panel_status() shows what's in the panel and what
    could be registered. No side effects -- does NOT register
    anything."""
    from kya.scorer_orchestrator import report_panel_status
    before = set(_JUDGES.keys())
    report = report_panel_status()
    after = set(_JUDGES.keys())
    # Probe shouldn't register anything new
    assert before == after
    assert "active" in report
    assert "available" in report
    # Every opt-in adapter has a status in the available section
    for expected in ("kya_presidio", "arize_phoenix",
                     "lakera_guard", "nemo_guardrails"):
        assert expected in report["available"]
        info = report["available"][expected]
        assert "status" in info
        assert "install_hint" in info
        assert "needs_key" in info


# ── Step A regression: keyword judges off by default ─────────────────
# Empirical 2026-06-04 sweep showed kya_attack_patterns has 2/3 FP rate
# on benign refusals and refusal_heuristic abstains on 5/5 modern
# refusal phrasings. Both are removed from the default panel and only
# come back via explicit opt-in registrars.

def test_kya_attack_patterns_not_in_default_panel(tmp_path):
    """Subprocess-isolated check that the import-time default panel
    contains neither kya_attack_patterns nor refusal_heuristic.

    Using a subprocess (rather than importlib.reload) sidesteps the
    autouse-fixture's dict-reference swap and matches how a fresh
    `import kya` would behave for a real customer.
    """
    import json
    import subprocess
    import sys
    from pathlib import Path

    # Hermetic path resolution — works regardless of pytest's cwd
    # (rootdir, tests/, or repo root) because we anchor to this file.
    repo_root = str(Path(__file__).resolve().parent.parent)
    script = (
        "import sys, json;"
        f"sys.path.insert(0, {repo_root!r});"
        "from kya.scorer_orchestrator import list_judges;"
        "print(json.dumps(list_judges()))"
    )
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, (
        f"subprocess failed:\nstdout={out.stdout}\nstderr={out.stderr}"
    )
    defaults = json.loads(out.stdout.strip().splitlines()[-1])
    assert "kya_attack_patterns" not in defaults, (
        f"Step A regression: kya_attack_patterns auto-registered. "
        f"Defaults: {defaults}"
    )
    assert "refusal_heuristic" not in defaults, (
        f"Step A regression: refusal_heuristic auto-registered. "
        f"Defaults: {defaults}"
    )

    # Both opt-in registrars must still exist and reference the
    # original judge functions.
    from kya.scorer_orchestrator import (  # noqa: F401
        _judge_kya_attack_patterns,
        _judge_refusal_heuristic,
        register_kya_attack_patterns_adapter,
        register_refusal_heuristic_adapter,
    )


def test_register_kya_attack_patterns_adapter_opt_in_works():
    """Operators who want the old judge back can opt in via the
    registrar. The opt-in path must register the same callable that
    was previously auto-registered."""
    from kya.scorer_orchestrator import (
        _judge_kya_attack_patterns,
        register_kya_attack_patterns_adapter,
    )
    assert "kya_attack_patterns" not in _JUDGES
    register_kya_attack_patterns_adapter()
    assert "kya_attack_patterns" in _JUDGES
    assert _JUDGES["kya_attack_patterns"] is _judge_kya_attack_patterns


def test_register_refusal_heuristic_adapter_opt_in_works():
    """Same for refusal_heuristic — opt-in returns the original judge."""
    from kya.scorer_orchestrator import (
        _judge_refusal_heuristic,
        register_refusal_heuristic_adapter,
    )
    assert "refusal_heuristic" not in _JUDGES
    register_refusal_heuristic_adapter()
    assert "refusal_heuristic" in _JUDGES
    assert _JUDGES["refusal_heuristic"] is _judge_refusal_heuristic
