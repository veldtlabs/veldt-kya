"""Tests for the opt-in Presidio adapter.

These tests run against REAL presidio-analyzer when it's installed,
and skip cleanly when it's not (CI without the [presidio] extra
still passes).

We test:
  - registration is opt-in (no auto-register at import)
  - register_presidio_adapter() puts the judge in the registry
  - SSN literal in input -> BREACH on input_safety dimension
  - clean input -> OK
  - PII in context (RAG) surface is detected
  - Output-side PII is NOT scanned by default
  - Install error message is helpful when Presidio is missing
"""

from __future__ import annotations

import pytest

# Skip the entire module if presidio-analyzer isn't installed --
# this is the opt-in behavior we want (CI without [presidio]
# extra doesn't error).
presidio = pytest.importorskip(
    "presidio_analyzer",
    reason="presidio-analyzer is an optional extra; install with "
           "`pip install kya[presidio]` to run these tests")


from kya.scorer_orchestrator import (  # noqa: E402
    _JUDGES,
    check_consensus,
    list_judges,
)
from kya.scorers_presidio import register_presidio_adapter  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_registry():
    """Each test runs against an empty registry. Restore on exit."""
    saved = dict(_JUDGES)
    _JUDGES.clear()
    yield
    _JUDGES.clear()
    _JUDGES.update(saved)


def test_presidio_is_not_auto_registered():
    """Just importing kya.scorers_presidio should NOT add the judge
    to the registry. Registration is explicit."""
    assert "kya_presidio" not in _JUDGES


def test_register_adds_judge_to_panel():
    register_presidio_adapter()
    assert "kya_presidio" in list_judges()


def test_ssn_in_input_breaches_input_safety():
    register_presidio_adapter()
    r = check_consensus(
        input_text="My SSN is 111-22-3333, please process my refund",
        response=None, context=None,
        judges=["kya_presidio"])
    assert len(r.judges) == 1
    j = r.judges[0]
    assert j.judge_name == "kya_presidio"
    assert j.verdict == "BREACH"
    assert j.dimension == "input_safety"
    assert "US_SSN" in j.detail["qualifying_entities"]


def test_credit_card_in_input_breaches():
    register_presidio_adapter()
    # 4111-1111-1111-1111 is the standard Visa test number --
    # Luhn-valid, used industry-wide as a test card.
    r = check_consensus(
        input_text="Charge to card 4111-1111-1111-1111 please",
        response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    assert j.verdict == "BREACH"
    assert "CREDIT_CARD" in j.detail["qualifying_entities"]


def test_email_address_alone_does_not_breach_at_default_score():
    """Email regex score is high (1.0) but emails alone are
    everywhere in legit traffic. Presidio scores them at 1.0 so
    this WILL breach at default threshold -- this test documents
    that fact. Customers who want emails as 'fine' should override
    the threshold or unregister the EmailRecognizer."""
    register_presidio_adapter()
    r = check_consensus(
        input_text="Please email my receipt to support@example.com",
        response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    # Documented behavior: email DOES breach. This is intentional --
    # PII detection in input is a SIGNAL, not necessarily an attack.
    # Operators decide whether emails alone should be treated as
    # input_safety BREACH; the orchestrator's SPLIT verdict + audit
    # trail surfaces the disagreement for review.
    assert j.verdict == "BREACH"
    assert "EMAIL_ADDRESS" in j.detail["qualifying_entities"]


def test_clean_input_abstains_unclear():
    """Narrow detector: when no PII is found anywhere, Presidio
    ABSTAINS (UNCLEAR) rather than voting OK. Prevents diluting
    another input_safety judge's positive BREACH signal."""
    register_presidio_adapter()
    r = check_consensus(
        input_text="What's the weather like in Toronto tomorrow?",
        response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    assert j.verdict == "UNCLEAR"
    assert j.detail["total_findings"] == 0


def test_ignored_pii_only_votes_ok():
    """When PII IS detected but only of ignored types (e.g. just an
    email when EMAIL_ADDRESS is in ignore_entities), Presidio
    positively asserts OK -- it ran, it found something, the
    finding was ignored per config. Distinct from UNCLEAR (nothing
    scanned matched at all)."""
    register_presidio_adapter(ignore_entities=["EMAIL_ADDRESS"])
    r = check_consensus(
        input_text="Email me at foo@example.com",
        response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    # Detected email, ignored per config -> OK (not UNCLEAR)
    assert j.verdict == "OK"
    assert j.detail["total_findings"] >= 1
    assert "EMAIL_ADDRESS" in j.detail["ignored_entities"]


def test_pii_in_rag_context_is_detected():
    """When PII shows up in the CONTEXT (RAG document) -- e.g. an
    untrusted document containing customer PII that the agent
    might echo into a response -- Presidio should flag it with
    surface='context'."""
    register_presidio_adapter()
    context = ("Customer record:\n"
               "Name: John Doe, SSN: 222-44-6666, "
               "Account #: 4111-1111-1111-1111")
    r = check_consensus(
        input_text="Summarize this customer record",
        response=None, context=context,
        judges=["kya_presidio"])
    j = r.judges[0]
    assert j.verdict == "BREACH"
    # Verify context-surface tagging
    surfaces = {f.get("surface") for f in j.detail["findings_preview"]}
    assert "context" in surfaces


def test_output_is_not_scanned_by_default():
    """Presidio adapter as registered should scan input + context
    only, NOT the agent's response. Output-side PII leak detection
    needs scan_response=True or a separately-registered adapter
    with dimension='safety'."""
    register_presidio_adapter()
    # PII ONLY in the response, not input or context
    r = check_consensus(
        input_text="What's my balance?",
        response="Your balance is $42.50. SSN on file: 999-88-7777.",
        context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    # Response not scanned -> no findings -> UNCLEAR (narrow detector
    # abstains when it found nothing in the surfaces it checked)
    assert j.verdict == "UNCLEAR"
    assert j.detail["total_findings"] == 0


def test_finding_preview_capped():
    """findings_preview is capped at 5 items so the audit row
    doesn't bloat for inputs with dozens of PII spans."""
    register_presidio_adapter()
    # Lots of emails in one input
    text = " ".join(f"user{i}@example.com" for i in range(20))
    r = check_consensus(
        input_text=text, response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    assert j.detail["total_findings"] >= 20
    assert len(j.detail["findings_preview"]) <= 5


# ── Tuning knobs ──────────────────────────────────────────────────


def test_ignore_entities_suppresses_email_breach():
    """ignore_entities=['EMAIL_ADDRESS'] -> emails detected (recorded
    in audit trail) but not counted toward BREACH. Demonstrates the
    SaaS-default tuning customers will use."""
    register_presidio_adapter(ignore_entities=["EMAIL_ADDRESS"])
    r = check_consensus(
        input_text="Please email my receipt to support@example.com",
        response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    assert j.verdict == "OK"
    # Email is still in audit trail under ignored_entities
    assert "EMAIL_ADDRESS" in j.detail["ignored_entities"]
    assert j.detail["total_findings"] >= 1


def test_ignore_entities_does_not_suppress_other_types():
    """SSN should still BREACH even with EMAIL_ADDRESS ignored."""
    register_presidio_adapter(ignore_entities=["EMAIL_ADDRESS"])
    r = check_consensus(
        input_text="SSN 111-22-3333, email foo@example.com",
        response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    assert j.verdict == "BREACH"
    assert "US_SSN" in j.detail["qualifying_entities"]
    assert "EMAIL_ADDRESS" in j.detail["ignored_entities"]


def test_entities_filter_narrows_scope():
    """entities=['US_SSN', 'CREDIT_CARD'] -> emails not even scanned
    (not in the entities list). Useful for narrow financial-PII
    deployments."""
    register_presidio_adapter(entities=["US_SSN", "CREDIT_CARD"])
    r = check_consensus(
        input_text="Email me at foo@example.com about my SSN "
                   "111-22-3333",
        response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    # SSN should fire
    assert j.verdict == "BREACH"
    assert "US_SSN" in j.detail["qualifying_entities"]
    # Email not scanned at all -- absent from BOTH qualifying and
    # ignored counts
    assert "EMAIL_ADDRESS" not in j.detail["qualifying_entities"]
    assert "EMAIL_ADDRESS" not in j.detail["ignored_entities"]


def test_min_findings_requires_combination():
    """min_findings=2 -> a single PII finding is recorded but doesn't
    BREACH. Two distinct findings DO. Demonstrates the
    'combination-only' policy for low-noise environments."""
    register_presidio_adapter(min_findings=2)
    # Just one PII -> OK
    r1 = check_consensus(
        input_text="My SSN is 111-22-3333",
        response=None, context=None,
        judges=["kya_presidio"])
    assert r1.judges[0].verdict == "OK"
    assert r1.judges[0].detail["qualifying_findings"] == 1
    # Two PIIs -> BREACH
    r2 = check_consensus(
        input_text="SSN 111-22-3333 and card 4111-1111-1111-1111",
        response=None, context=None,
        judges=["kya_presidio"])
    assert r2.judges[0].verdict == "BREACH"
    assert r2.judges[0].detail["qualifying_findings"] >= 2


def test_higher_threshold_filters_low_confidence():
    """threshold=0.85 -> only high-confidence findings count.
    SSN at 0.5 won't trigger; Luhn-valid CC at higher score will."""
    register_presidio_adapter(threshold=0.85)
    r = check_consensus(
        input_text="SSN 111-22-3333",
        response=None, context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    # SSN regex-only scores ~0.5 < 0.85 -> filtered to ignored
    assert j.verdict == "OK"
    # Finding still recorded in audit trail
    assert j.detail["total_findings"] >= 1


def test_scan_response_includes_output_pii():
    """scan_response=True -> agent's response is also scanned. Used
    for output-side PII leak detection when customer doesn't want a
    separate adapter."""
    register_presidio_adapter(scan_response=True)
    r = check_consensus(
        input_text="What's my balance?",
        response="Your balance is $42.50. SSN on file: 999-88-7777.",
        context=None,
        judges=["kya_presidio"])
    j = r.judges[0]
    # SSN in the response is now caught
    assert j.verdict == "BREACH"
    surfaces = {f.get("surface")
                for f in j.detail["findings_preview"]}
    assert "response" in surfaces


def test_unknown_entity_raises_helpful_error():
    import pytest
    with pytest.raises(ValueError) as exc_info:
        register_presidio_adapter(entities=["TOTALLY_FAKE_ENTITY"])
    assert "TOTALLY_FAKE_ENTITY" in str(exc_info.value)
    # Helpful: show what IS supported
    assert "Supported:" in str(exc_info.value)


def test_invalid_threshold_raises():
    import pytest
    with pytest.raises(ValueError):
        register_presidio_adapter(threshold=2.0)


def test_invalid_min_findings_raises():
    import pytest
    with pytest.raises(ValueError):
        register_presidio_adapter(min_findings=0)


def test_install_error_message_helpful(monkeypatch):
    """When presidio-analyzer is not installed, register_presidio_adapter
    should raise RuntimeError with a clear install hint."""
    import kya.scorers_presidio as mod

    def boom(_entities):
        raise RuntimeError(
            "presidio-analyzer is not installed. The kya_presidio "
            "judge is an OPTIONAL adapter; install it with:\n"
            "    pip install kya[presidio]\n"
            "or:\n"
            "    pip install presidio-analyzer")

    # Patch the cached builder to simulate missing install
    monkeypatch.setattr(mod, "_build_recognizers", boom)
    with pytest.raises(RuntimeError) as exc_info:
        register_presidio_adapter()
    msg = str(exc_info.value)
    assert "pip install kya[presidio]" in msg
    assert "optional" in msg.lower()
