"""Public-API contract — assert kya's exported surface doesn't drift.

The list below is the contract. Any change is a semver event:
  • added name → minor bump
  • removed/renamed → major bump

Run from sdk/ in a venv with `pip install -e .` (or against an
installed wheel). Used by .github/workflows/sdk-build.yml.
"""

import kya

EXPECTED_API = {
    # Risk scoring
    "AgentRiskScore",
    "RiskFactor",
    "bucket_for",
    "score_agent",
    "is_write_tool",
    "is_admin_tool",
    "set_tool_catalog",
    # Data classes
    "DATA_CLASSES",
    "CLASS_WEIGHTS",
    "DEFAULT_TOOL_CLASSIFICATIONS",
    "classify_tool",
    "infer_data_classes",
    "sensitivity_weight",
    "set_class_weights",
    "set_tool_classifications",
    # Security caps
    "SECURITY_CAPS",
    "CAPABILITY_WEIGHTS",
    "DEFAULT_TOOL_CAPABILITIES",
    "classify_tool_capabilities",
    "infer_capabilities",
    "capability_weight",
    "set_capability_weights",
    "set_tool_capabilities",
    # Multi-framework normalization
    "normalize_agent_def",
    "SupportedFramework",
    # Versioning + rollback
    "snapshot_agent",
    "list_versions",
    "get_version",
    "rollback_to",
    # Unified storage setup
    "init_storage",
    # Forensic evidence capture (HMAC-chained)
    "VALID_EVIDENCE_KINDS",
    "init_evidence_table",
    "record_evidence",
    "list_evidence",
    "get_evidence",
    "verify_chain",
    "prune_expired_evidence",
    # Zero-config capture for custom agents + direct LLM SDK calls
    "autoinstrument",
    "deinstrument",
    "patched_sdks",
    # Rogue signal recording
    "record_oos_tool_attempt",
    "record_cross_tenant_attempt",
    "get_rogue_signals",
    "rogue_score",
    "get_governance_summary",
    "get_anomalies",
    # Compliance
    "REGIMES",
    "REGIME_RETENTION_DAYS",
    "REGIME_BREACH_NOTIFY",
    "eu_ai_act_tier",
    "required_controls",
    "elevated_severity",
    "max_retention_days",
    "compliance_summary",
    # Integrity + lineage
    "canonical_hash",
    "detect_drift",
    "lineage_chain",
    "lineage_risk_inheritance",
    "verify_signature",
    # Principal trust + delegation
    "PRINCIPAL_KINDS",
    "PrincipalTrust",
    "record_principal_signal",
    "record_principal_clean",
    "get_principal_trust",
    "list_principals",
    "delegation_trust_weight",
    # Invocation tracking
    "VALID_MODES",
    "VALID_OUTCOMES",
    "record_invocation",
    "list_invocations",
    "mode_distribution",
    "active_parallel_invocations",
    "ingest_lag_stats",
    "new_correlation_id",
    # Request-level rollups
    "RequestSummary",
    "summarize_request",
    "list_recent_requests",
    "request_score",
    # Fault attribution + LLM judge
    "DivergenceReport",
    "agent_divergence_score",
    "JudgeResult",
    "judge_alignment",
    "judged_divergence",
    # Phoenix poll
    "PollResult",
    "poll_phoenix_evals",
    "start_phoenix_poll_thread",
    "stop_phoenix_poll_thread",
}


def test_expected_names_are_exported():
    """Every name in the contract above MUST be importable from kya."""
    missing = sorted(n for n in EXPECTED_API if not hasattr(kya, n))
    assert not missing, (
        f"Public-API regression: {len(missing)} names removed from kya:\n  " + "\n  ".join(missing)
    )


def test_no_private_leakage():
    """Anything in __all__ MUST also exist on the module."""
    declared = set(getattr(kya, "__all__", []))
    missing = sorted(n for n in declared if not hasattr(kya, n))
    assert not missing, f"__all__ declares names that don't exist on kya: {missing}"


def test_no_veldt_runtime_leak():
    """Importing kya MUST NOT pull in Veldt-runtime modules.

    Runs `import kya` in a subprocess so other tests' sys.modules
    pollution can't contaminate the check. Only a fresh interpreter
    shows whether `import kya` ALONE pulls in forbidden modules.
    """
    import json
    import subprocess
    import sys as _sys

    code = (
        "import sys, json\n"
        "import kya\n"
        "forbidden = ('fastapi','uvicorn','starlette','decisions','services','routes','agents.api','agents.registry')\n"
        "leaked = sorted(m for m in sys.modules if any(m == k or m.startswith(k + '.') for k in forbidden))\n"
        "print(json.dumps(leaked))\n"
    )
    result = subprocess.run(
        [_sys.executable, "-c", code], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    leaked = json.loads(result.stdout.strip())
    assert not leaked, f"runtime leak after `import kya`: {leaked}"
