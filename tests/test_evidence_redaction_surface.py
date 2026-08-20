"""Redaction-surface allowlist regression tests for record_evidence.

Covers the widened payload-key allowlist added in the 2026-08-20 R2
minor fix: prompt/response/http_body/input/output plus nested
tool_call.input / tool_call.output paths now receive redaction, and
non-string/dict leaf types pass through unchanged per the design
guardrail.
"""
from __future__ import annotations

import os
from typing import Any

import pytest

from kya import _redaction_hooks as rh
from kya.evidence import (
    _REDACTION_TARGET_KEYS,
    _REDACTION_TARGET_NESTED_PATHS,
    _resolve_redaction_target_keys,
    init_evidence_table,
    record_evidence,
)


class _RecordingHook:
    """Hook that redacts every string value + records what it saw."""

    def __init__(self) -> None:
        self.seen: list[dict[str, Any]] = []

    def redact_attrs(self, attrs: dict[str, Any]) -> dict[str, Any]:
        self.seen.append(dict(attrs))
        return {
            k: ("<REDACTED>" if isinstance(v, str) else v)
            for k, v in attrs.items()
        }


def _session():
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from sqlalchemy.orm import sessionmaker

    engine = sqlalchemy.create_engine("sqlite:///:memory:")
    return sqlalchemy, sessionmaker(bind=engine)()


def _read_payload(sqlalchemy, session, evidence_id: int) -> dict:
    import json as _json

    raw = session.execute(
        sqlalchemy.text("SELECT payload FROM kya_evidence WHERE id = :i"),
        {"i": evidence_id},
    ).scalar()
    if isinstance(raw, str):
        return _json.loads(raw)
    return raw


@pytest.fixture(autouse=True)
def _reset_hook():
    rh.set_redaction_hook(None)
    yield
    rh.set_redaction_hook(None)


def test_prompt_key_redacted():
    """Widened surface — string-valued `prompt` gets redacted."""
    assert "prompt" in _REDACTION_TARGET_KEYS
    rh.set_redaction_hook(_RecordingHook())
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        rid = record_evidence(
            session, tenant_id="t", invocation_id=1,
            evidence_kind="prompt",
            payload={"prompt": "my api key is sk-XYZ"},
            source="test",
        )
        row = _read_payload(sqlalchemy, session, rid)
        assert row["prompt"] == "<REDACTED>"
    finally:
        session.close()


def test_response_and_http_body_keys_redacted():
    """Widened surface — response + http_body strings redacted."""
    rh.set_redaction_hook(_RecordingHook())
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        rid = record_evidence(
            session, tenant_id="t", invocation_id=2,
            evidence_kind="response",
            payload={
                "response": "here is your card 4111 1111 1111 1111",
                "http_body": "authorization: Bearer secret-token",
            },
            source="test",
        )
        row = _read_payload(sqlalchemy, session, rid)
        assert row["response"] == "<REDACTED>"
        assert row["http_body"] == "<REDACTED>"
    finally:
        session.close()


def test_nested_tool_call_input_redacted():
    """Widened surface — `tool_call.input` dict path redacted."""
    assert "tool_call.input" in _REDACTION_TARGET_NESTED_PATHS
    rh.set_redaction_hook(_RecordingHook())
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        rid = record_evidence(
            session, tenant_id="t", invocation_id=3,
            evidence_kind="tool_call",
            payload={
                "tool_call": {
                    "name": "shell",
                    "input": {"command": "curl -H 'Authorization: Bearer XYZ'"},
                }
            },
            source="test",
        )
        row = _read_payload(sqlalchemy, session, rid)
        # nested dict → redacted per leaf value
        assert row["tool_call"]["input"]["command"] == "<REDACTED>"
        # sibling untouched
        assert row["tool_call"]["name"] == "shell"
    finally:
        session.close()


def test_numeric_value_passes_through_unchanged():
    """Design guardrail — non-string / non-dict leaves are not redacted."""
    rh.set_redaction_hook(_RecordingHook())
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        rid = record_evidence(
            session, tenant_id="t", invocation_id=4,
            evidence_kind="system_message",
            # `input` is a target key, but the value is an int → skip.
            payload={"input": 42, "output": [1, 2, 3], "response": True},
            source="test",
        )
        row = _read_payload(sqlalchemy, session, rid)
        assert row["input"] == 42
        assert row["output"] == [1, 2, 3]
        assert row["response"] is True
    finally:
        session.close()


def test_env_override_widens_allowlist(monkeypatch):
    """KYA_EVIDENCE_REDACTION_KEYS CSV widens without a code change."""
    monkeypatch.setenv("KYA_EVIDENCE_REDACTION_KEYS", "custom_secret, another")
    keys = _resolve_redaction_target_keys()
    assert "custom_secret" in keys
    assert "another" in keys
    # base keys still present
    for base in _REDACTION_TARGET_KEYS:
        assert base in keys

    rh.set_redaction_hook(_RecordingHook())
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        rid = record_evidence(
            session, tenant_id="t", invocation_id=5,
            evidence_kind="system_message",
            payload={"custom_secret": "sk-live-XYZ"},
            source="test",
        )
        row = _read_payload(sqlalchemy, session, rid)
        assert row["custom_secret"] == "<REDACTED>"
    finally:
        session.close()


def test_no_target_keys_skips_redaction_fast_path():
    """Payloads with no in-scope keys skip the redaction block entirely.

    Sanity check that the pre-check gate short-circuits — the hook must
    never be called when there's nothing to redact. Guards latency.
    """
    hook = _RecordingHook()
    rh.set_redaction_hook(hook)
    sqlalchemy, session = _session()
    try:
        init_evidence_table(session)
        record_evidence(
            session, tenant_id="t", invocation_id=6,
            evidence_kind="system_message",
            payload={"unrelated": {"x": "y"}, "count": 1},
            source="test",
        )
        assert hook.seen == []  # never invoked
    finally:
        session.close()
