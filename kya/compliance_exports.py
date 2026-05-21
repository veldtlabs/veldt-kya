"""Phase 6 — regulator-grade export formatters.

Thin format adapters over the existing `_build_regulator_pack`
(routes/admin_agents.py) — they reshape the same KYA data into the
field layouts a model-risk officer (SR 11-7) or an AIMS auditor
(ISO 42001) expects in their evidence file.

Two exports:
    sr_11_7_model_card(pack)        — Fed SR 11-7 §V model documentation
    iso_42001_aims_export(packs)    — ISO/IEC 42001 management-system bundle

Both are pure transformations: they accept a regulator pack (or list
of packs) as input and return a regulator-shaped dict ready to serve
as JSON or render as PDF in a downstream tool. KYA itself does not
produce PDFs — the JSON is the canonical artifact; PDF rendering is
left to the operator's evidence workflow (the existing
`decisions/reports` pipeline already has the fpdf2 dep).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from .compliance import REGIME_RETENTION_DAYS, compliance_summary


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────
# SR 11-7  Model Card
# ─────────────────────────────────────────────────────────────────────


def sr_11_7_model_card(pack: dict, *, agent_def: dict) -> dict:
    """Format a single agent's regulator-pack as an SR 11-7 model card.

    Section structure follows SR 11-7 §V (Model Development & Validation):
        - Identity            — model_id, owner, version
        - Purpose & Use       — description, intended scope
        - Methodology         — model type, providers, capabilities
        - Inputs / Outputs    — data classes consumed/emitted, tool surface
        - Assumptions         — declared trust signals (model_trust, env)
        - Limitations         — denied tools, human-loop posture
        - Implementation      — controls, RBAC roles, governance mode
        - Monitoring          — anomalies + effective risk + judge history
        - Governance          — version history + approvals + attestation chain
        - Incidents           — open + resolved
    """
    monitoring = pack.get("monitoring") or {}
    response = pack.get("response") or {}
    controls = pack.get("controls") or {}
    classification = pack.get("classification") or {}
    meta = pack.get("meta") or {}

    return {
        "document_type": "SR 11-7 Model Card",
        "generated_at": _utc_now(),
        "agent_key": pack.get("agent_key"),
        "identity": {
            "model_id": pack.get("agent_key"),
            "model_name": meta.get("name"),
            "owner_team": agent_def.get("owner_team"),
            "on_call": agent_def.get("on_call"),
            "version_count": meta.get("version_count"),
            "first_registered_at": meta.get("created_at"),
        },
        "purpose_and_use": {
            "description": agent_def.get("description"),
            "intended_scope": agent_def.get("intended_scope"),
            "deployment_environment": agent_def.get("environment"),
        },
        "methodology": {
            "model_type": "llm_agent",
            "underlying_model": agent_def.get("model"),
            "framework": agent_def.get("framework") or "veldt",
            "tool_surface": controls.get("tools") or [],
            "denied_tools": controls.get("denied_tools") or [],
            "delegation_allowed": bool(agent_def.get("delegation_allowed", False)),
        },
        "inputs_outputs": {
            "data_classes_handled": agent_def.get("data_classes") or [],
            "input_sources": agent_def.get("input_sources") or [],
            "writes_to": ("yes" if classification.get("write_tool_count", 0) > 0 else "no"),
            "admin_capable": ("yes" if classification.get("admin_tool_count", 0) > 0 else "no"),
        },
        "assumptions": {
            "model_trust": agent_def.get("model_trust"),
            "review_status": agent_def.get("review_status"),
            "supply_chain": agent_def.get("dependencies") or [],
            "cites_sources": bool(agent_def.get("cites_sources", False)),
        },
        "limitations": {
            "human_loop": controls.get("human_loop"),
            "can_override": controls.get("can_override"),
            "can_revert": controls.get("can_revert"),
            "denied_tools": controls.get("denied_tools") or [],
            "access_level": controls.get("access_level"),
        },
        "implementation_controls": {
            "required_roles": controls.get("required_roles") or [],
            "governance_summary": pack.get("governance"),
            "compliance": compliance_summary(
                agent_def,
                classification.get("score", 0),
            ),
        },
        "monitoring": {
            "effective_risk": monitoring.get("effective_risk"),
            "rogue_signals": monitoring.get("rogue"),
            "anomalies": monitoring.get("anomalies") or [],
            "realtime_windows": monitoring.get("realtime_windows"),
            "judge_count": response.get("judge_count", 0),
            "judge_history_sample": (response.get("judge_history") or [])[:10],
        },
        "governance_evidence": {
            "version_count": meta.get("version_count"),
            "incidents_total": response.get("incidents_count", 0),
            "audit_log_total": response.get("audit_count", 0),
            "attestation_chain_count": ((pack.get("attestation") or {}).get("count", 0)),
            "attestation_chain_valid": ((pack.get("attestation") or {}).get("chain_valid")),
        },
        "open_incidents": [
            r for r in (response.get("incidents") or []) if r.get("resolution_status") == "open"
        ],
        "sr_11_7_section_map": {
            "V.A_model_dev": "methodology + inputs_outputs",
            "V.B_model_val": "monitoring + governance_evidence",
            "VI_governance": "implementation_controls + governance_evidence",
            "VII_oversight": "open_incidents + monitoring.anomalies",
        },
    }


# ─────────────────────────────────────────────────────────────────────
# ISO/IEC 42001  AIMS Documentation Bundle
# ─────────────────────────────────────────────────────────────────────


def iso_42001_aims_export(
    packs: Iterable[dict],
    *,
    agent_defs: dict[str, dict],
    tenant_id: str,
) -> dict:
    """Format an entire tenant inventory as an ISO 42001 AIMS document set.

    Maps each agent into ISO 42001's required documented information:
        Clause 4   — Context (the agent inventory itself)
        Clause 5   — Leadership (owner_team, on_call)
        Clause 6   — Planning (risk register: bucket + factors)
        Clause 7.5 — Documented information (version history + attestation)
        Clause 8.2 — Operations (AI system impact assessment via data classes)
        Clause 9   — Performance (monitoring + nonconformities = incidents)
    """
    inventory = []
    risk_register = []
    nonconformities = []
    impact_assessments = []
    documented_info = []

    for pack in packs:
        ak = pack.get("agent_key")
        if not ak:
            continue
        agent_def = agent_defs.get(ak, {})
        meta = pack.get("meta") or {}
        classification = pack.get("classification") or {}
        response = pack.get("response") or {}
        monitoring = pack.get("monitoring") or {}

        # Inventory row
        inventory.append(
            {
                "model_id": ak,
                "name": meta.get("name") or ak,
                "owner_team": agent_def.get("owner_team"),
                "environment": agent_def.get("environment"),
                "compliance_scope": agent_def.get("compliance_scope") or [],
            }
        )

        # Risk register row (Clause 6.1)
        risk_register.append(
            {
                "model_id": ak,
                "risk_score": classification.get("score"),
                "risk_bucket": classification.get("bucket"),
                "effective_risk": monitoring.get("effective_risk"),
                "top_factors": (classification.get("factors") or [])[:5],
            }
        )

        # Impact assessment (Clause 8.2)
        impact_assessments.append(
            {
                "model_id": ak,
                "data_classes": agent_def.get("data_classes") or [],
                "blast_radius": agent_def.get("blast_radius"),
                "delegation_allowed": bool(agent_def.get("delegation_allowed", False)),
                "access_level": (pack.get("controls") or {}).get("access_level"),
            }
        )

        # Documented info (Clause 7.5)
        documented_info.append(
            {
                "model_id": ak,
                "version_count": meta.get("version_count"),
                "attestation_count": (pack.get("attestation") or {}).get("count", 0),
                "attestation_chain_valid": (pack.get("attestation") or {}).get("chain_valid"),
                "audit_log_count": response.get("audit_count", 0),
            }
        )

        # Nonconformities (Clause 9 / 10) = open incidents
        for inc in response.get("incidents") or []:
            if inc.get("resolution_status") != "resolved":
                nonconformities.append(
                    {
                        "model_id": ak,
                        "incident_id": inc.get("id"),
                        "severity": inc.get("severity"),
                        "action_taken": inc.get("action_taken"),
                        "resolution_status": inc.get("resolution_status"),
                    }
                )

    return {
        "document_type": "ISO/IEC 42001 — AIMS Documented Information",
        "generated_at": _utc_now(),
        "tenant_id": tenant_id,
        "scope_statement": (
            "AI Management System covering all registered AI agents under "
            "the tenant's KYA platform. Statement of Applicability driven "
            "by agent compliance_scope tags."
        ),
        "clause_4_context": {
            "agent_inventory_count": len(inventory),
            "agent_inventory": inventory,
        },
        "clause_6_planning_risk_register": risk_register,
        "clause_7_5_documented_information": documented_info,
        "clause_8_2_impact_assessments": impact_assessments,
        "clause_9_performance": {
            "monitoring_program": "Effective-risk score + rogue signals + "
            "burst-anomaly detection per agent.",
            "retention_days_max": max(
                (
                    REGIME_RETENTION_DAYS.get(s, 0)
                    for ad in agent_defs.values()
                    for s in (ad.get("compliance_scope") or [])
                ),
                default=0,
            ),
            "nonconformities_open": len(nonconformities),
            "nonconformities": nonconformities,
        },
    }


# ─────────────────────────────────────────────────────────────────────
# Regime → agent rollup (drives the dashboard "Agents under Regime X" tab)
# ─────────────────────────────────────────────────────────────────────


def agents_grouped_by_regime(agent_defs: dict[str, dict]) -> dict[str, list[str]]:
    """For each compliance regime that ANY agent declares, return the
    list of agent_keys in that regime's scope. Empty regimes are
    omitted so the UI doesn't show empty buckets."""
    by_regime: dict[str, list[str]] = {}
    for ak, ad in agent_defs.items():
        for regime in ad.get("compliance_scope") or []:
            by_regime.setdefault(str(regime).lower(), []).append(ak)
    for k in list(by_regime.keys()):
        by_regime[k] = sorted(by_regime[k])
    return by_regime
