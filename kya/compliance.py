"""
Compliance scope — regulatory regimes the agent operates under.

Different from data sensitivity: HIPAA is an *obligation* (audit log
retention, breach reporting), PHI is *content* (personal health data).
An agent can be in HIPAA scope without touching PHI today (because it
might tomorrow) and conversely.

Compliance tags DON'T directly add risk points — they're obligations,
not threats. They DO:
  - Drive audit-log retention rules (HIPAA = 6 years, SOX = 7 years)
  - Elevate ANY rogue signal to CRITICAL severity (a small leak on a
    GDPR-scoped agent = breach notification under Article 33)
  - Map EU AI Act risk tiers to required controls (Art. 14 oversight,
    Art. 13 transparency, Art. 12 record-keeping)
  - Surface to the operator which regimes apply, so the operator knows
    what's at stake

Supported regimes
-----------------
    gdpr        — EU General Data Protection Regulation
    eu_ai_act   — EU AI Act (Regulation 2024/1689)
    hipaa       — US Health Insurance Portability Act (PHI)
    sox         — US Sarbanes-Oxley (financial reporting integrity)
    pci         — PCI-DSS (cardholder data)
    ccpa        — California Consumer Privacy Act
    glba        — Gramm-Leach-Bliley (financial)
    ferpa       — Family Educational Rights and Privacy Act
    iso_27001   — ISO/IEC 27001 information security
    soc2        — SOC 2 Type II

EU AI Act risk tiers (Article 6)
--------------------------------
    unacceptable — banned outright (social scoring, etc.)
    high         — strict requirements (Art. 9-15: risk mgmt, transparency,
                   human oversight, accuracy, robustness)
    limited      — transparency obligations only (Art. 50)
    minimal      — voluntary code of conduct

KYA's static risk_score → EU AI Act tier mapping is heuristic. Score >=
85 (critical) or `can_override=True` + sensitive data classes → "high".
Score 60-84 → "limited". Below 60 → "minimal".

Public API
----------
    REGIMES                                              — known names
    REGIME_RETENTION_DAYS                                — required log retention
    eu_ai_act_tier(risk_score, can_override, data_classes) -> str
    required_controls(scope: list[str], tier: str) -> list[dict]
    elevated_severity(base_severity, scope) -> str        — bump on regulated agent
"""

from collections.abc import Iterable

REGIMES = {
    # Civilian / commercial
    "gdpr",
    "eu_ai_act",
    "hipaa",
    "sox",
    "pci",
    "ccpa",
    "glba",
    "ferpa",
    "iso_27001",
    "soc2",
    # Defense / aerospace / federal
    "itar",  # International Traffic in Arms Regulations
    "ear",  # Export Administration Regulations
    "cmmc",  # Cybersecurity Maturity Model Certification (DoD)
    "fedramp",  # Federal Risk and Authorization Management Program
    "dfars_252_204_7012",  # DoD covered defense info safeguarding
    "nist_800_171",  # CUI protection in non-federal systems
    "nist_800_53",  # Security & privacy controls for federal info systems
    "fips_140_2",  # Cryptographic module validation
    "fips_140_3",  # Successor to FIPS 140-2
    # International equivalents
    "irap",  # Australian Information Security Registered Assessors
    "cccs",  # Canadian Centre for Cyber Security
    "c5",  # German BSI Cloud Computing Compliance Catalogue
    "esquema_nacional",  # Spanish national security framework
    "il5",
    "il6",  # DoD Impact Levels (IL5 = NSS, IL6 = SECRET)
    # AI / model risk + financial-sector regimes (Phase 6 compliance pack)
    "nydfs_500",  # NYDFS 23 NYCRR Part 500 — cyber + 72-hr notify
    "dora",  # EU Digital Operational Resilience Act (2022/2554)
    "sr_11_7",  # Fed SR 11-7 — Model Risk Management
    "iso_42001",  # ISO/IEC 42001 — AI Management System
    "eo_14110",  # US EO 14110 / NIST AI 600-1 evidence
    "ai_bor",  # OSTP AI Bill of Rights (algorithmic discrimination)
}

# Minimum days the governance audit log must be retained for each regime.
# Statutory minimums where cited; common industry defaults otherwise.
REGIME_RETENTION_DAYS = {
    # Civilian
    "gdpr": 365 * 6,  # GDPR Art. 30 + DPA guidance — 6 yrs typical
    "eu_ai_act": 365 * 10,  # AI Act Art. 12 + 19 — 10 yrs for high-risk
    "hipaa": 365 * 6,  # 45 CFR §164.530(j)(2)
    "sox": 365 * 7,  # SEC Rule 17a-4
    "pci": 365 * 1,  # PCI-DSS 10.7 — minimum 1 yr (3 mo online)
    "ccpa": 365 * 2,  # CCPA recordkeeping — 24 months
    "glba": 365 * 5,  # 16 CFR Part 314 — Safeguards Rule
    "ferpa": 365 * 5,  # 34 CFR §99.32 — 5 yrs after disclosure record
    "iso_27001": 365 * 3,  # ISO/IEC 27001 control A.5.34 (record retention)
    "soc2": 365 * 3,  # AICPA TSP common control retention
    # Defense / federal
    "itar": 365 * 5,  # 22 CFR §122.5 — ITAR record retention
    "ear": 365 * 5,  # 15 CFR §762.6 — EAR records 5 yrs
    "cmmc": 365 * 6,  # CMMC L2 audit retention align with 800-171
    "fedramp": 365 * 3,  # FedRAMP AU-11 baseline
    "dfars_252_204_7012": 365 * 6,  # DFARS — incident response records
    "nist_800_171": 365 * 6,  # 3.3.1 audit log retention
    "nist_800_53": 365 * 6,  # AU-11 — federal baseline
    "fips_140_2": 365 * 3,  # validation record retention
    "fips_140_3": 365 * 3,  # successor to 140-2
    "irap": 365 * 7,  # ASD ISM logging guideline
    "cccs": 365 * 7,  # CCCS ITSG-33 audit retention
    "c5": 365 * 6,  # BSI C5 logging requirement
    "esquema_nacional": 365 * 6,  # ENS audit log retention
    "il5": 365 * 6,  # DoD CC SRG Impact Level 5
    "il6": 365 * 25,  # IL6 = SECRET — long-term retention
    # Phase 6 compliance pack
    "nydfs_500": 365 * 5,  # 23 NYCRR §500.06 — 5 yrs audit retention
    "dora": 365 * 5,  # DORA Art. 16 — ICT records 5 yrs
    "sr_11_7": 365 * 7,  # SR 11-7 model documentation lifecycle
    "iso_42001": 365 * 3,  # ISO 42001 Clause 7.5 — documented info
    "eo_14110": 365 * 7,  # NIST AI 600-1 evidence retention
    "ai_bor": 365 * 5,  # OSTP — algorithmic accountability records
}

# Regimes that require time-bounded incident notification to an external
# regulator/authority. Used by the notify shim to know which incidents must
# be emitted before the SLA expires (and which destination format to use).
# breach_window_hours = SLA the regulator imposes on detection-to-notify.
REGIME_BREACH_NOTIFY = {
    "gdpr": {
        "window_hours": 72,
        "format": "edpb_breach",
        "authority": "Lead Supervisory Authority (Art. 33 GDPR)",
    },
    "nydfs_500": {
        "window_hours": 72,
        "format": "nydfs_breach",
        "authority": "NYDFS Superintendent (23 NYCRR §500.17)",
    },
    "dora": {
        "window_hours": 24,
        "format": "esma_dora",
        "authority": "Competent national authority (DORA Art. 19)",
    },
    "hipaa": {
        "window_hours": 24 * 60,
        "format": "hhs_breach",
        "authority": "HHS OCR (45 CFR §164.408)",
    },
}


def eu_ai_act_tier(risk_score: int, can_override: bool, data_classes: list[str]) -> str:
    """Heuristic mapping to EU AI Act Article 6 risk tier.

    Real classification requires a legal review against Annex III. This
    is a screening signal — when KYA flags "high", that should trigger
    the compliance team's deeper assessment.
    """
    sensitive = {"phi", "financial", "secret", "pii"} & set(data_classes or [])
    if risk_score >= 85:
        return "high"
    if can_override and sensitive:
        return "high"
    if risk_score >= 60:
        return "limited"
    return "minimal"


def required_controls(scope: Iterable[str], eu_tier: str = "minimal") -> list[dict]:
    """Return the list of controls the agent must satisfy.

    Each control: {control_id, source, description, status_field}.
    The `status_field` names a key the operator/UI should populate to
    record evidence (e.g., "human_oversight_documented_at").
    """
    controls: list[dict] = []
    scope_set = {s.lower() for s in (scope or [])}

    # EU AI Act high-risk obligations
    if "eu_ai_act" in scope_set and eu_tier == "high":
        controls.extend(
            [
                {
                    "id": "eu_ai_act_art_9",
                    "source": "EU AI Act Art. 9",
                    "description": "Risk management system established and documented.",
                    "status_field": "risk_mgmt_documented_at",
                },
                {
                    "id": "eu_ai_act_art_10",
                    "source": "EU AI Act Art. 10",
                    "description": "Training data governance and quality criteria.",
                    "status_field": "data_governance_documented_at",
                },
                {
                    "id": "eu_ai_act_art_12",
                    "source": "EU AI Act Art. 12",
                    "description": "Automatic logging of operations (audit trail).",
                    "status_field": "logging_enabled",
                },
                {
                    "id": "eu_ai_act_art_13",
                    "source": "EU AI Act Art. 13",
                    "description": "Transparency: users informed they interact with an AI.",
                    "status_field": "transparency_disclosed",
                },
                {
                    "id": "eu_ai_act_art_14",
                    "source": "EU AI Act Art. 14",
                    "description": "Effective human oversight — in_the_loop or hybrid mode required.",
                    "status_field": "human_oversight_mode",
                },
                {
                    "id": "eu_ai_act_art_15",
                    "source": "EU AI Act Art. 15",
                    "description": "Accuracy, robustness and cybersecurity met.",
                    "status_field": "robustness_tested_at",
                },
            ]
        )

    # GDPR
    if "gdpr" in scope_set:
        controls.extend(
            [
                {
                    "id": "gdpr_art_30",
                    "source": "GDPR Art. 30",
                    "description": "Records of processing activities maintained.",
                    "status_field": "ropa_id",
                },
                {
                    "id": "gdpr_art_32",
                    "source": "GDPR Art. 32",
                    "description": "Appropriate technical and organizational measures.",
                    "status_field": "tom_documented",
                },
                {
                    "id": "gdpr_art_33",
                    "source": "GDPR Art. 33",
                    "description": "Breach notification within 72h (data_leak event triggers this clock).",
                    "status_field": "breach_notification_sla",
                },
            ]
        )

    # HIPAA
    if "hipaa" in scope_set:
        controls.extend(
            [
                {
                    "id": "hipaa_164_312",
                    "source": "45 CFR §164.312",
                    "description": "Technical safeguards: access controls + audit.",
                    "status_field": "hipaa_audit_enabled",
                },
                {
                    "id": "hipaa_164_530",
                    "source": "45 CFR §164.530",
                    "description": "6-year retention of audit log + sanction policy.",
                    "status_field": "hipaa_retention_days",
                },
            ]
        )

    # SOX
    if "sox" in scope_set:
        controls.append(
            {
                "id": "sox_404",
                "source": "SOX §404",
                "description": "Internal control over financial reporting (ICFR).",
                "status_field": "icfr_tested_at",
            }
        )

    # NYDFS 23 NYCRR Part 500
    if "nydfs_500" in scope_set:
        controls.extend(
            [
                {
                    "id": "nydfs_500_02",
                    "source": "23 NYCRR §500.02",
                    "description": "Cybersecurity program documented and risk-assessed.",
                    "status_field": "cyber_program_documented_at",
                },
                {
                    "id": "nydfs_500_06",
                    "source": "23 NYCRR §500.06",
                    "description": "Audit trail design + 5-year retention.",
                    "status_field": "audit_trail_designed",
                },
                {
                    "id": "nydfs_500_17",
                    "source": "23 NYCRR §500.17",
                    "description": "Notify Superintendent within 72h of cybersecurity event.",
                    "status_field": "breach_notification_sla_72h",
                },
            ]
        )

    # DORA (EU Digital Operational Resilience Act)
    if "dora" in scope_set:
        controls.extend(
            [
                {
                    "id": "dora_art_5",
                    "source": "DORA Art. 5",
                    "description": "ICT risk management framework approved by mgmt body.",
                    "status_field": "ict_risk_framework_approved_at",
                },
                {
                    "id": "dora_art_17",
                    "source": "DORA Art. 17",
                    "description": "ICT-related incident management process.",
                    "status_field": "incident_mgmt_process",
                },
                {
                    "id": "dora_art_19",
                    "source": "DORA Art. 19",
                    "description": "Major ICT incidents reported to competent authority "
                    "within initial notification window (≤24h).",
                    "status_field": "breach_notification_sla_24h",
                },
                {
                    "id": "dora_art_24",
                    "source": "DORA Art. 24",
                    "description": "Threat-led penetration testing (TLPT) for "
                    "critical operators every 3 years.",
                    "status_field": "tlpt_last_run_at",
                },
            ]
        )

    # SR 11-7 (Federal Reserve Model Risk Management)
    if "sr_11_7" in scope_set:
        controls.extend(
            [
                {
                    "id": "sr_11_7_dev",
                    "source": "SR 11-7 §V Model Development",
                    "description": "Documented model development including data, "
                    "methodology, assumptions, limitations.",
                    "status_field": "model_card_exported_at",
                },
                {
                    "id": "sr_11_7_val",
                    "source": "SR 11-7 §V Model Validation",
                    "description": "Independent validation: conceptual soundness, "
                    "ongoing monitoring, outcomes analysis.",
                    "status_field": "model_validation_completed_at",
                },
                {
                    "id": "sr_11_7_gov",
                    "source": "SR 11-7 §VI Governance",
                    "description": "Model inventory + risk rating maintained.",
                    "status_field": "model_inventory_id",
                },
            ]
        )

    # ISO/IEC 42001 (AI Management System)
    if "iso_42001" in scope_set:
        controls.extend(
            [
                {
                    "id": "iso_42001_6_1",
                    "source": "ISO 42001 §6.1",
                    "description": "AI risks + opportunities identified and addressed.",
                    "status_field": "ai_risk_register_id",
                },
                {
                    "id": "iso_42001_7_5",
                    "source": "ISO 42001 §7.5",
                    "description": "Documented information for the AIMS maintained.",
                    "status_field": "aims_export_id",
                },
                {
                    "id": "iso_42001_8_2",
                    "source": "ISO 42001 §8.2",
                    "description": "AI system impact assessment performed.",
                    "status_field": "ai_impact_assessment_id",
                },
                {
                    "id": "iso_42001_9_1",
                    "source": "ISO 42001 §9.1",
                    "description": "Monitoring, measurement, analysis, evaluation.",
                    "status_field": "monitoring_program_id",
                },
            ]
        )

    # EO 14110 / NIST AI 600-1
    if "eo_14110" in scope_set:
        controls.append(
            {
                "id": "nist_ai_600_1_gv",
                "source": "NIST AI 600-1 §GV",
                "description": "Documented safety + security testing evidence.",
                "status_field": "attestation_chain_verified_at",
            }
        )

    # OSTP AI Bill of Rights
    if "ai_bor" in scope_set:
        controls.append(
            {
                "id": "ai_bor_safe",
                "source": "OSTP AI BoR §1 Safe and Effective",
                "description": "Algorithmic discrimination tracked via incidents.",
                "status_field": "discrimination_incidents_reviewed_at",
            }
        )

    return controls


def elevated_severity(base_severity: str, scope: Iterable[str]) -> str:
    """A regulated agent should escalate ANY rogue signal one tier.

    A PII leak on a non-regulated agent is "critical". The same leak on a
    GDPR-scoped agent triggers a 72-hour breach-notification clock — same
    severity in KYA terms but with much heavier downstream consequences.
    Escalation rules:
        info     → warning   (regulated agents shouldn't have informational rogue events)
        warning  → critical  (regulated context turns warnings into incidents)
        critical → critical  (already at the top)
    """
    if not scope:
        return base_severity
    return {"info": "warning", "warning": "critical"}.get(base_severity, base_severity)


def max_retention_days(scope: Iterable[str]) -> int:
    """The longest retention window required across all applicable regimes."""
    if not scope:
        return 0
    return max((REGIME_RETENTION_DAYS.get(s.lower(), 0) for s in scope), default=0)


def compliance_summary(agent_def: dict, risk_score: int) -> dict:
    """Compact compliance block for the KYA card."""
    scope = list(agent_def.get("compliance_scope") or [])
    data_classes = list(agent_def.get("data_classes") or [])
    can_override = bool(agent_def.get("can_override", False))
    eu_tier = eu_ai_act_tier(risk_score, can_override, data_classes)
    controls = required_controls(scope, eu_tier)
    return {
        "scope": scope,
        "eu_ai_act_tier": eu_tier,
        "required_controls": controls,
        "retention_days": max_retention_days(scope),
    }
