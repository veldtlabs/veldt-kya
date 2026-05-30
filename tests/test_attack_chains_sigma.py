"""Tests for the Sigma -> KYA AttackChainRule translator.

Coverage strategy
-----------------
Three layers, each strictly tighter than the last:

1. **Unit tests** — per-mapping behavior. Sigma id slugified into KYA
   id; severity mapping; tag splitting into MITRE technique/tactic;
   logsource -> evidence_kind; each field modifier; AND-chain
   merging; loader rejecting OR/NOT/quantifier/parens conditions
   and conflict-merges.

2. **Real Sigma rules, end-to-end through the engine.** Rules used
   here are taken verbatim from the SigmaHQ format (process_creation,
   network_connection). For each: translate -> load into engine ->
   feed a synthetic event that matches the Sigma `detection` ->
   verify the rule fires and emits the configured signal. These are
   the live tests that prove the translator is a real adapter, not
   a stub.

3. **Bulk dir load** — drop a folder of Sigma YAMLs (mix of
   translatable + intentionally-unsupported) and verify the
   ``(rules, skipped)`` partition is correct.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from kya.attack_chains import (
    AttackChainEngine,
    InMemoryStateStore,
    SigmaTranslateError,
    load_sigma_rule,
    load_sigma_rules_from_dir,
    translate_sigma_to_kya_dict,
)

# ── Helpers ───────────────────────────────────────────────────────


def _engine(rule):
    fired: list[tuple[str, str]] = []

    def emitter(_db, _t, _p, signal_kind, _eid, r):
        fired.append((r.id, signal_kind))

    eng = AttackChainEngine(
        rules=[rule],
        state_store=InMemoryStateStore(),
        signal_emitter=emitter,
    )
    return eng, fired


# ══════════════════════════════════════════════════════════════════
# Layer 1: per-mapping unit tests
# ══════════════════════════════════════════════════════════════════


def test_id_derives_from_sigma_uuid_when_present():
    out = translate_sigma_to_kya_dict({
        "title": "Whatever",
        "id": "abcd-1234",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": "foo.exe"},
            "condition": "selection",
        },
    })
    assert out["id"] == "sigma_abcd_1234"


def test_id_falls_back_to_slugged_title():
    out = translate_sigma_to_kya_dict({
        "title": "Suspicious PowerShell!?",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": "ps.exe"},
            "condition": "selection",
        },
    })
    assert out["id"] == "sigma_suspicious_powershell"


def test_severity_mapping_known_levels():
    for level, expected in [
        ("low", "low"),
        ("medium", "medium"),
        ("high", "high"),
        ("critical", "critical"),
        ("informational", "informational"),
        ("info", "informational"),
        ("xyz", "low"),
    ]:
        out = translate_sigma_to_kya_dict({
            "title": f"x {level}",
            "level": level,
            "logsource": {"category": "log"},
            "detection": {
                "selection": {"a": "b"}, "condition": "selection",
            },
        })
        assert out["severity"] == expected, level


def test_mitre_tags_split_into_attack_and_tactic():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "tags": [
            "attack.execution",
            "attack.t1059.001",
            "attack.t1003",
            "not-a-mitre-tag",
        ],
        "logsource": {"category": "log"},
        "detection": {
            "selection": {"a": "b"}, "condition": "selection",
        },
    })
    md = out["metadata"]
    assert md["mitre_attack"] == ["T1059.001", "T1003"]
    assert md["mitre_tactic"] == ["execution"]


def test_evidence_kind_pulls_from_logsource_category_first():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "logsource": {
            "category": "process_creation",
            "service": "sysmon",
            "product": "windows",
        },
        "detection": {
            "selection": {"a": "b"}, "condition": "selection",
        },
    })
    assert out["steps"][0]["evidence_kind"] == "process_creation"


def test_field_modifier_literal_no_modifier():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "logsource": {"category": "log"},
        "detection": {
            "selection": {"Image": "C:\\Windows\\System32\\foo.exe"},
            "condition": "selection",
        },
    })
    assert out["steps"][0]["match"] == {
        "payload.Image": "C:\\Windows\\System32\\foo.exe"
    }


def test_field_modifier_contains_becomes_glob_star_x_star():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "logsource": {"category": "log"},
        "detection": {
            "selection": {"CommandLine|contains": "-EncodedCommand"},
            "condition": "selection",
        },
    })
    assert out["steps"][0]["match"] == {
        "payload.CommandLine": "glob:*-EncodedCommand*"
    }


def test_field_modifier_startswith_and_endswith():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "logsource": {"category": "log"},
        "detection": {
            "selection": {
                "Path|startswith": "/etc/",
                "Image|endswith": "\\powershell.exe",
            },
            "condition": "selection",
        },
    })
    m = out["steps"][0]["match"]
    assert m["payload.Path"] == "glob:/etc/*"
    assert m["payload.Image"] == "glob:*\\powershell.exe"


def test_field_modifier_regex():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "logsource": {"category": "log"},
        "detection": {
            "selection": {"User|re": "^svc-.*"},
            "condition": "selection",
        },
    })
    assert out["steps"][0]["match"] == {"payload.User": "regex:^svc-.*"}


def test_list_value_becomes_in_spec():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "logsource": {"category": "log"},
        "detection": {
            "selection": {
                "Image": [
                    "powershell.exe",
                    "pwsh.exe",
                ],
            },
            "condition": "selection",
        },
    })
    assert out["steps"][0]["match"] == {
        "payload.Image": "in:[powershell.exe,pwsh.exe]"
    }


def test_and_chain_merges_multiple_selections():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "logsource": {"category": "log"},
        "detection": {
            "selection_a": {"Image|endswith": "\\powershell.exe"},
            "selection_b": {"CommandLine|contains": "-Encoded"},
            "condition": "selection_a and selection_b",
        },
    })
    m = out["steps"][0]["match"]
    assert m["payload.Image"] == "glob:*\\powershell.exe"
    assert m["payload.CommandLine"] == "glob:*-Encoded*"


def test_or_condition_raises_with_clear_reason():
    with pytest.raises(SigmaTranslateError, match="or"):
        translate_sigma_to_kya_dict({
            "title": "x",
            "logsource": {"category": "log"},
            "detection": {
                "selection_a": {"a": "1"},
                "selection_b": {"b": "2"},
                "condition": "selection_a or selection_b",
            },
        })


def test_not_condition_raises_with_clear_reason():
    with pytest.raises(SigmaTranslateError, match="not"):
        translate_sigma_to_kya_dict({
            "title": "x",
            "logsource": {"category": "log"},
            "detection": {
                "selection": {"a": "1"},
                "exclude":   {"b": "2"},
                "condition": "selection and not exclude",
            },
        })


def test_quantifier_condition_raises():
    for cond in (
        "1 of selection_*", "all of selection_*", "any of selection_*",
    ):
        with pytest.raises(SigmaTranslateError):
            translate_sigma_to_kya_dict({
                "title": "x",
                "logsource": {"category": "log"},
                "detection": {
                    "selection_a": {"a": "1"},
                    "condition": cond,
                },
            })


def test_parenthesized_condition_raises():
    with pytest.raises(SigmaTranslateError, match="parenthesized"):
        translate_sigma_to_kya_dict({
            "title": "x",
            "logsource": {"category": "log"},
            "detection": {
                "selection_a": {"a": "1"},
                "selection_b": {"b": "2"},
                "condition": "(selection_a and selection_b)",
            },
        })


def test_keyword_only_selection_raises():
    """Sigma rules that match on raw keywords (a YAML list, not a
    mapping) cannot be translated without a free-text search
    capability, which KYA does not have."""
    with pytest.raises(SigmaTranslateError, match="keyword-only|not a mapping"):
        translate_sigma_to_kya_dict({
            "title": "x",
            "logsource": {"category": "log"},
            "detection": {
                "selection": ["foo", "bar"],
                "condition": "selection",
            },
        })


def test_conflicting_field_merge_raises():
    with pytest.raises(SigmaTranslateError, match="disagree"):
        translate_sigma_to_kya_dict({
            "title": "x",
            "logsource": {"category": "log"},
            "detection": {
                "selection_a": {"Image": "a.exe"},
                "selection_b": {"Image": "b.exe"},
                "condition": "selection_a and selection_b",
            },
        })


def test_empty_match_raises():
    with pytest.raises(SigmaTranslateError, match="empty match"):
        translate_sigma_to_kya_dict({
            "title": "x",
            "logsource": {"category": "log"},
            "detection": {
                "selection": {},
                "condition": "selection",
            },
        })


def test_glob_escape_keeps_literal_asterisk():
    out = translate_sigma_to_kya_dict({
        "title": "x",
        "logsource": {"category": "log"},
        "detection": {
            "selection": {"q|contains": "a*b"},
            "condition": "selection",
        },
    })
    assert out["steps"][0]["match"] == {"payload.q": "glob:*a[*]b*"}


# ══════════════════════════════════════════════════════════════════
# Layer 2: REAL Sigma rules, end-to-end through the engine
# ══════════════════════════════════════════════════════════════════


# Real-format Sigma rule -- SigmaHQ shape for process_creation.
# Detects PowerShell with `-EncodedCommand`.
REAL_SIGMA_POWERSHELL_ENCODED = {
    "title": "PowerShell EncodedCommand",
    "id": "00000000-0000-0000-0000-000000000001",
    "status": "experimental",
    "description": (
        "Detects PowerShell launched with -EncodedCommand, "
        "commonly used to bypass logging."),
    "references": [
        "https://attack.mitre.org/techniques/T1059/001/",
    ],
    "tags": [
        "attack.execution",
        "attack.defense_evasion",
        "attack.t1059.001",
    ],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection_img": {
            "Image|endswith": "\\powershell.exe",
        },
        "selection_cmd": {
            "CommandLine|contains": "-EncodedCommand",
        },
        "condition": "selection_img and selection_cmd",
    },
    "level": "high",
}


def test_live_sigma_powershell_encoded_fires_against_synthetic_event():
    rule = load_sigma_rule(REAL_SIGMA_POWERSHELL_ENCODED)
    # The translated rule lands as a one-step KYA rule with a merged
    # match spec.
    assert rule.severity == "high"
    assert rule.steps[0].evidence_kind == "process_creation"
    assert rule.metadata["mitre_attack"] == ["T1059.001"]
    assert "execution" in rule.metadata["mitre_tactic"]
    assert "defense_evasion" in rule.metadata["mitre_tactic"]

    engine, fired = _engine(rule)
    matched = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_under_test",
        evidence_kind="process_creation",
        payload={
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand SQBuAA==",
        },
        occurred_at_ts=100.0,
    )
    assert matched == [rule.id]
    assert fired == [
        (rule.id, f"rogue_sigma_{rule.id}"),
    ]


def test_live_sigma_powershell_encoded_does_not_fire_on_clean_event():
    rule = load_sigma_rule(REAL_SIGMA_POWERSHELL_ENCODED)
    engine, fired = _engine(rule)
    matched = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_under_test",
        evidence_kind="process_creation",
        payload={
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe foo.txt",
        },
        occurred_at_ts=100.0,
    )
    assert matched == []
    assert fired == []


# Second real rule: outbound curl-shaped exfiltration. List-value +
# contains modifier together exercise a different code path.
REAL_SIGMA_CURL_EXFIL = {
    "title": "Suspicious curl Exfiltration",
    "id": "00000000-0000-0000-0000-000000000002",
    "status": "stable",
    "description": "Detects curl uploading to a non-corporate domain.",
    "tags": [
        "attack.exfiltration",
        "attack.t1041",
    ],
    "logsource": {"category": "process_creation"},
    "detection": {
        "selection": {
            "Image|endswith": [
                "\\curl.exe",
                "/curl",
            ],
            "CommandLine|contains": "--data",
        },
        "condition": "selection",
    },
    "level": "critical",
}


def test_live_sigma_curl_exfil_with_list_value_raises_clear_error():
    """A Sigma selection that combines ``|endswith`` with a LIST
    value is ambiguous in v1: we don't compose modifiers across list
    entries. The translator raises with a clear reason so the
    operator knows to split into two rules (one per Image)."""
    with pytest.raises(SigmaTranslateError, match="list"):
        load_sigma_rule(REAL_SIGMA_CURL_EXFIL)


# A simpler list-value rule (no modifier) DOES translate -- the
# ``in:`` spec captures the alternatives cleanly.
REAL_SIGMA_TOOL_ALLOWLIST_VIOLATION = {
    "title": "Risky LOLBin Invocation",
    "id": "00000000-0000-0000-0000-000000000003",
    "logsource": {"category": "process_creation"},
    "detection": {
        "selection": {
            "Image": [
                "C:\\Windows\\System32\\certutil.exe",
                "C:\\Windows\\System32\\bitsadmin.exe",
                "C:\\Windows\\System32\\regsvr32.exe",
            ],
        },
        "condition": "selection",
    },
    "level": "medium",
}


def test_live_sigma_lolbin_in_spec_fires_for_any_listed_value():
    rule = load_sigma_rule(REAL_SIGMA_TOOL_ALLOWLIST_VIOLATION)
    engine, fired = _engine(rule)
    matched = engine.process_evidence(
        None,
        tenant_id="t1", principal_id="agent_x",
        evidence_kind="process_creation",
        payload={"Image": "C:\\Windows\\System32\\bitsadmin.exe"},
        occurred_at_ts=100.0,
    )
    assert matched == [rule.id]
    assert fired == [(rule.id, f"rogue_sigma_{rule.id}")]


# A real Sigma rule that uses an unsupported construct (OR over
# selections) -- we expect a clean translate error, not a half-built
# rule.
REAL_SIGMA_OR_RULE = {
    "title": "Two-Variant Anomaly",
    "id": "00000000-0000-0000-0000-000000000004",
    "logsource": {"category": "process_creation"},
    "detection": {
        "selection_a": {"Image|endswith": "\\malware_a.exe"},
        "selection_b": {"Image|endswith": "\\malware_b.exe"},
        "condition": "selection_a or selection_b",
    },
    "level": "high",
}


def test_live_sigma_or_rule_rejects_cleanly():
    with pytest.raises(SigmaTranslateError, match="or"):
        load_sigma_rule(REAL_SIGMA_OR_RULE)


# ══════════════════════════════════════════════════════════════════
# Layer 3: bulk-load a directory (translatable + skipped, partitioned)
# ══════════════════════════════════════════════════════════════════


def test_load_sigma_rules_from_dir_partitions_translatable_and_skipped(
    tmp_path: Path,
):
    """Drop a mix of v1-translatable and unsupported Sigma rules in
    a directory; the bulk loader must return the translatable rules
    AND a list of skipped paths with reasons -- never a partial
    rule, never a crash."""
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML not installed")

    (tmp_path / "ok_powershell.yml").write_text(
        yaml.safe_dump(REAL_SIGMA_POWERSHELL_ENCODED), encoding="utf-8")
    (tmp_path / "ok_lolbin.yml").write_text(
        yaml.safe_dump(REAL_SIGMA_TOOL_ALLOWLIST_VIOLATION),
        encoding="utf-8")
    (tmp_path / "skip_or.yml").write_text(
        yaml.safe_dump(REAL_SIGMA_OR_RULE), encoding="utf-8")
    (tmp_path / "skip_list_with_modifier.yml").write_text(
        yaml.safe_dump(REAL_SIGMA_CURL_EXFIL), encoding="utf-8")

    rules, skipped = load_sigma_rules_from_dir(tmp_path)

    assert len(rules) == 2
    # Sigma id is preferred for KYA rule id (a slugged UUID), so the
    # title isn't in the id -- check titles via metadata instead.
    titles = {r.metadata.get("sigma_title", "") for r in rules}
    assert any("PowerShell" in t for t in titles)
    assert any("LOLBin" in t or "Risky" in t for t in titles)

    skipped_files = [Path(p).name for p, _ in skipped]
    assert "skip_or.yml" in skipped_files
    assert "skip_list_with_modifier.yml" in skipped_files
    for _, reason in skipped:
        # Every skipped entry carries a non-empty explanation -- the
        # operator can act on it.
        assert reason


def test_load_sigma_rules_from_missing_dir_returns_empty_and_one_skip():
    rules, skipped = load_sigma_rules_from_dir("/path/that/does/not/exist")
    assert rules == []
    assert len(skipped) == 1
    assert "directory not found" in skipped[0][1]
