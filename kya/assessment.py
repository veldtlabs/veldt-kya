"""Autonomous Systems Trust Assessment orchestrator.

The 30-day Trust Assessment we offer (free or paid) is a deliverable:
the customer points us at their tenant + the agents they care about,
we run this orchestrator, and they receive a structured Findings
document covering the five pillars of an assessment:

  1. Trust scoring         -- score_agent + principal trust + EU AI tier
  2. Authority mapping     -- RBAC grants per agent; admin-grant flags
  3. Delegation analysis   -- delegation_readiness_report + divergence
  4. Provenance assessment -- versioning + drift via canonical_hash
  5. Evidence chain review -- HMAC chain verification + optional
                              Ed25519-signed offline export

Design properties
-----------------
* **Composition over reinvention.** Every pillar calls existing public
  primitives (``score_agent``, ``get_principal_trust``, ``list_grants``,
  ``delegation_readiness_report``, ``agent_divergence_score``,
  ``list_versions``, ``canonical_hash``, ``verify_chain``,
  ``signed_export``). The orchestrator adds no detection logic of its
  own; it lifts what's already in KYA into a single Findings shape.
* **Fail-soft per pillar.** A failure in one pillar surfaces as a
  finding and the rest of the assessment still runs. The whole report
  never crashes the caller.
* **Per-pillar reusability.** Each pillar function is exported, so
  callers can run a single section (e.g. only evidence-chain review)
  without the full assessment.
* **Backend-agnostic.** Works on any SQLAlchemy session the underlying
  primitives support (PG / MySQL / SQLite / DuckDB).

Public API
----------
    Finding              -- one structured finding
    AssessmentReport     -- full report (5 pillars + rollup + optional
                            signed evidence artifact)
    run_assessment(...)  -- one call: all five pillars, rolled up
    pillar_trust_scoring(...)
    pillar_authority_mapping(...)
    pillar_delegation_analysis(...)
    pillar_provenance_assessment(...)
    pillar_evidence_chain_review(...)

Severity scale: informational < low < medium < high < critical.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Pillar names (canonical strings used in Finding.pillar)
PILLAR_TRUST = "trust_scoring"
PILLAR_AUTHORITY = "authority_mapping"
PILLAR_DELEGATION = "delegation_analysis"
PILLAR_PROVENANCE = "provenance_assessment"
PILLAR_EVIDENCE = "evidence_chain_review"

_PILLARS_IN_ORDER = (
    PILLAR_TRUST, PILLAR_AUTHORITY, PILLAR_DELEGATION,
    PILLAR_PROVENANCE, PILLAR_EVIDENCE,
)

_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Principal-trust threshold below which trust_scoring emits a finding.
_TRUST_FLOOR = 40


# ── Data shapes ────────────────────────────────────────────────────


@dataclass
class Finding:
    """One structured assessment finding.

    A finding is the unit of communication between the orchestrator
    and the human reading the report. Every finding belongs to exactly
    one pillar, carries a single severity, and (when actionable) a
    concrete recommendation.
    """

    pillar: str
    severity: str  # one of _SEVERITY_RANK keys
    title: str
    detail: str
    recommendation: str | None = None
    references: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pillar": self.pillar,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "references": [dict(r) for r in self.references],
        }


@dataclass
class AssessmentReport:
    """The full 5-pillar report produced by ``run_assessment``."""

    tenant_id: str
    scope_agents: list[str]
    window_days: int
    generated_at: str  # ISO 8601, wall-clock UTC

    trust_scoring: list[Finding] = field(default_factory=list)
    authority_mapping: list[Finding] = field(default_factory=list)
    delegation_analysis: list[Finding] = field(default_factory=list)
    provenance_assessment: list[Finding] = field(default_factory=list)
    evidence_chain_review: list[Finding] = field(default_factory=list)

    headline_severity: str = "informational"
    summary: str = ""
    signed_export_ref: dict | None = None

    # ── Accessors ──

    @property
    def findings(self) -> list[Finding]:
        return list(
            self.trust_scoring
            + self.authority_mapping
            + self.delegation_analysis
            + self.provenance_assessment
            + self.evidence_chain_review
        )

    @property
    def per_pillar(self) -> dict[str, list[Finding]]:
        return {
            PILLAR_TRUST: self.trust_scoring,
            PILLAR_AUTHORITY: self.authority_mapping,
            PILLAR_DELEGATION: self.delegation_analysis,
            PILLAR_PROVENANCE: self.provenance_assessment,
            PILLAR_EVIDENCE: self.evidence_chain_review,
        }

    # ── Serialization ──

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "scope_agents": list(self.scope_agents),
            "window_days": self.window_days,
            "generated_at": self.generated_at,
            "headline_severity": self.headline_severity,
            "summary": self.summary,
            "signed_export_ref": (
                dict(self.signed_export_ref)
                if self.signed_export_ref else None
            ),
            "trust_scoring": [f.to_dict() for f in self.trust_scoring],
            "authority_mapping": [
                f.to_dict() for f in self.authority_mapping],
            "delegation_analysis": [
                f.to_dict() for f in self.delegation_analysis],
            "provenance_assessment": [
                f.to_dict() for f in self.provenance_assessment],
            "evidence_chain_review": [
                f.to_dict() for f in self.evidence_chain_review],
        }

    def to_markdown(self) -> str:
        """Human-readable Markdown report. Suitable for posting to a
        ticket, attaching to an email, or rendering in a dashboard."""
        lines: list[str] = [
            "# Autonomous Systems Trust Assessment",
            "",
            f"- **Tenant**: `{self.tenant_id}`",
            f"- **Scope**: {len(self.scope_agents)} agent(s) "
            f"{', '.join(f'`{a}`' for a in self.scope_agents) or '_none_'}",
            f"- **Window**: {self.window_days} days",
            f"- **Generated**: {self.generated_at}",
            f"- **Headline severity**: **{self.headline_severity.upper()}**",
            "",
            "## Summary",
            "",
            self.summary or "_no summary_",
            "",
        ]
        sections = (
            ("Trust Scoring", self.trust_scoring),
            ("Authority Mapping", self.authority_mapping),
            ("Delegation Analysis", self.delegation_analysis),
            ("Provenance Assessment", self.provenance_assessment),
            ("Evidence Chain Review", self.evidence_chain_review),
        )
        for name, findings in sections:
            lines.append(f"## {name}")
            lines.append("")
            if not findings:
                lines.append("_No findings._")
                lines.append("")
                continue
            for fnd in findings:
                lines.append(f"### [{fnd.severity.upper()}] {fnd.title}")
                lines.append("")
                lines.append(fnd.detail)
                if fnd.recommendation:
                    lines.append("")
                    lines.append(f"**Recommendation:** {fnd.recommendation}")
                lines.append("")
        if self.signed_export_ref:
            lines.append("## Cryptographic Artifact")
            lines.append("")
            lines.append(
                "Ed25519-signed evidence export attached "
                "(verifiable offline with the public key).")
            lines.append("")
        return "\n".join(lines)


# ── Internal helpers ───────────────────────────────────────────────


def _max_severity(findings: list[Finding]) -> str:
    if not findings:
        return "informational"
    return max(
        findings,
        key=lambda f: _SEVERITY_RANK.get(f.severity, 0),
    ).severity


def _safe_call(
    pillar: str,
    fn: Callable[..., list[Finding]],
    /, **kwargs: Any,
) -> list[Finding]:
    """Run a pillar function; convert any exception into a single
    informational finding so the assessment never crashes whole."""
    try:
        return fn(**kwargs)
    except Exception as exc:
        logger.warning(
            "[ASSESSMENT] %s pillar raised: %s", pillar, exc)
        return [Finding(
            pillar=pillar, severity="informational",
            title=f"{pillar} pillar failed during run",
            detail=f"Exception: {exc!r}. Other pillars were still executed.",
        )]


def _maybe_get(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``obj[key]`` whether obj is a dict or an attribute object."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ══════════════════════════════════════════════════════════════════
# Pillar 1 -- Trust scoring
# ══════════════════════════════════════════════════════════════════


def pillar_trust_scoring(
    db, *, tenant_id: str, agent_keys: list[str], window_days: int,
) -> list[Finding]:
    """Pillar 1: latest static score, current principal trust, and
    EU AI Act tier per scoped agent."""
    from .compliance import compliance_summary
    from .principals import get_principal_trust
    from .risk import score_agent
    from .versioning import get_version, list_versions

    out: list[Finding] = []
    for agent_key in agent_keys:
        # ── static risk score (from latest version) ──
        agent_def = None
        vno = None
        try:
            # list_versions returns NEWEST FIRST (.desc()), so the
            # latest snapshot is at index 0. Field name is
            # ``version_no``, not ``version``.
            versions = list_versions(db, tenant_id, agent_key) or []
            if not versions:
                out.append(Finding(
                    pillar=PILLAR_TRUST, severity="medium",
                    title=f"Agent '{agent_key}' has no version snapshot",
                    detail=(
                        "No declared definition is on record for this "
                        "agent. Static risk cannot be computed without a "
                        "snapshot."),
                    recommendation=(
                        "Call snapshot_agent() at agent-registration time "
                        "so the declared definition is auditable."),
                    references=[{"agent_key": agent_key}],
                ))
            else:
                latest_meta = versions[0]
                vno = _maybe_get(latest_meta, "version_no")
                ver = (
                    get_version(db, tenant_id, agent_key, vno)
                    if vno is not None else None
                )
                agent_def = _maybe_get(ver, "definition")
        except Exception as exc:
            logger.debug(
                "[ASSESSMENT] version lookup failed for %s: %s",
                agent_key, exc)

        if agent_def:
            try:
                score = score_agent(agent_def)
                sev_map = {
                    "critical": "critical", "high": "high",
                    "medium": "medium", "low": "low",
                }
                sev = sev_map.get(score.bucket, "informational")
                top_factors = sorted(
                    score.factors, key=lambda f: f.delta, reverse=True,
                )[:3]
                top_str = ", ".join(
                    f"{f.name}(+{f.delta})" for f in top_factors
                ) or "no notable factors"
                out.append(Finding(
                    pillar=PILLAR_TRUST, severity=sev,
                    title=(
                        f"Agent '{agent_key}' static risk: "
                        f"{score.score}/100 ({score.bucket})"),
                    detail=f"Top contributing factors: {top_str}.",
                    recommendation=(
                        "Review access_level / tools / deployment "
                        "for the top contributors."
                        if sev in ("high", "critical") else None),
                    references=[{
                        "agent_key": agent_key, "version": vno,
                        "score": score.score, "bucket": score.bucket,
                    }],
                ))
                # EU AI Act / compliance context.
                try:
                    cs = compliance_summary(agent_def, score.score)
                    tier = cs.get("eu_ai_act_tier")
                    if tier in ("unacceptable", "high"):
                        out.append(Finding(
                            pillar=PILLAR_TRUST,
                            severity=("critical" if tier == "unacceptable"
                                      else "high"),
                            title=(
                                f"Agent '{agent_key}' falls in EU AI "
                                f"Act tier: {tier}"),
                            detail=(
                                "EU AI Act enforcement is binding from "
                                "Aug 2 2026. This agent requires the "
                                "controls listed."),
                            recommendation=(
                                "Verify required controls: "
                                + ", ".join(cs.get("required_controls", []))),
                            references=[{
                                "agent_key": agent_key,
                                "eu_ai_act_tier": tier,
                                "retention_days": cs.get("retention_days"),
                            }],
                        ))
                except Exception as exc:
                    logger.debug(
                        "[ASSESSMENT] compliance_summary for %s: %s",
                        agent_key, exc)
            except Exception as exc:
                logger.debug(
                    "[ASSESSMENT] score_agent for %s: %s",
                    agent_key, exc)

        # ── principal trust (runtime, signal-driven) ──
        try:
            trust = get_principal_trust(
                db, tenant_id, "agent", agent_key)
            ts = _maybe_get(trust, "trust_score")
            if ts is not None and ts < _TRUST_FLOOR:
                out.append(Finding(
                    pillar=PILLAR_TRUST, severity="high",
                    title=(
                        f"Agent '{agent_key}' principal trust low: "
                        f"{ts}/100"),
                    detail=(
                        f"Principal trust is below the {_TRUST_FLOOR} "
                        f"floor, reflecting accumulated rogue/policy "
                        f"signals. Behavior at runtime has decayed trust."),
                    recommendation=(
                        "Investigate the most recent rogue signals; "
                        "consider tightening RBAC or pausing the agent."),
                    references=[{
                        "agent_key": agent_key, "trust_score": ts,
                    }],
                ))
        except Exception as exc:
            logger.debug(
                "[ASSESSMENT] principal trust read for %s: %s",
                agent_key, exc)

    return out


# ══════════════════════════════════════════════════════════════════
# Pillar 2 -- Authority mapping
# ══════════════════════════════════════════════════════════════════


def pillar_authority_mapping(
    db, *, tenant_id: str, agent_keys: list[str], window_days: int,
) -> list[Finding]:
    """Pillar 2: KYA-action RBAC grants per agent; flag admin grants."""
    from .rbac import list_grants

    out: list[Finding] = []
    for agent_key in agent_keys:
        try:
            grants = list_grants(
                db, tenant_id=tenant_id,
                principal_kind="agent", principal_id=agent_key,
            ) or []
            actions = [
                _maybe_get(g, "action") or g for g in grants
            ]
            # "Admin-level" = wildcards (kya.* / *.* etc.), explicit
            # admin actions, override actions, and rollback (mutates
            # historical state).
            def _is_admin(a: str) -> bool:
                s = str(a).lower()
                return (
                    "admin" in s
                    or "override" in s
                    or "rollback" in s
                    or s == "kya.*"
                    or s.endswith(".*")
                )
            admin_actions = [
                str(a) for a in actions if _is_admin(a)
            ]
            if not grants:
                out.append(Finding(
                    pillar=PILLAR_AUTHORITY, severity="medium",
                    title=f"Agent '{agent_key}' has no RBAC grants",
                    detail=(
                        "No KYA-action grants recorded. Under RBAC block "
                        "mode this agent cannot perform any KYA-protected "
                        "actions."),
                    recommendation=(
                        "Explicitly grant the minimum action set the "
                        "agent needs via grant_action()."),
                    references=[{"agent_key": agent_key}],
                ))
            elif admin_actions:
                out.append(Finding(
                    pillar=PILLAR_AUTHORITY, severity="high",
                    title=(
                        f"Agent '{agent_key}' holds admin-level grants"),
                    detail=(
                        f"Admin / override grants: "
                        f"{', '.join(admin_actions)}. Admin authority "
                        "should be explicit and minimum-necessary."),
                    recommendation=(
                        "Review each admin grant; revoke any that are "
                        "no longer required."),
                    references=[{
                        "agent_key": agent_key,
                        "admin_actions": admin_actions,
                    }],
                ))
            else:
                preview = ", ".join(str(a) for a in actions[:6])
                more = "" if len(actions) <= 6 else (
                    f" (+{len(actions) - 6} more)")
                out.append(Finding(
                    pillar=PILLAR_AUTHORITY, severity="informational",
                    title=(
                        f"Agent '{agent_key}' has {len(grants)} "
                        f"non-admin grant(s)"),
                    detail=f"Granted actions: {preview}{more}.",
                    references=[{
                        "agent_key": agent_key,
                        "grant_count": len(grants),
                    }],
                ))
        except Exception as exc:
            logger.debug(
                "[ASSESSMENT] list_grants for %s: %s", agent_key, exc)
    return out


# ══════════════════════════════════════════════════════════════════
# Pillar 3 -- Delegation analysis
# ══════════════════════════════════════════════════════════════════


def pillar_delegation_analysis(
    db, *, tenant_id: str, agent_keys: list[str], window_days: int,
) -> list[Finding]:
    """Pillar 3: tenant-wide delegation readiness + per-agent
    fault-attribution divergence."""
    from .delegation_analytics import delegation_readiness_report
    from .fault_attribution import agent_divergence_score

    out: list[Finding] = []

    # ── tenant-wide delegation triage ──
    try:
        report = delegation_readiness_report(
            db, tenant_id=tenant_id, window_days=window_days,
        ) or {}
        for entry in (report.get("attention") or []):
            rec = _maybe_get(entry, "recommendation") or ""
            rec_lc = str(rec).lower()
            if "block" in rec_lc:
                sev = "high"
            elif "investigate" in rec_lc or "spike" in rec_lc:
                sev = "medium"
            else:
                sev = "low"
            title = (
                _maybe_get(entry, "title")
                or f"Delegation recommendation: {rec or 'review'}"
            )
            out.append(Finding(
                pillar=PILLAR_DELEGATION, severity=sev,
                title=str(title)[:200],
                detail=str(entry)[:600],
                recommendation=str(rec) if rec else None,
                references=[{"delegation_entry": entry}],
            ))
    except Exception as exc:
        logger.debug(
            "[ASSESSMENT] delegation_readiness_report: %s", exc)

    # ── per-agent divergence ──
    for agent_key in agent_keys:
        try:
            d = agent_divergence_score(
                db, tenant_id=tenant_id, agent_key=agent_key,
                window_days=window_days,
            )
            if d is None or d.classification in (
                    "insufficient_data", "intentional"):
                continue
            sev_map = {"agent_misbehavior": "high", "mixed": "medium"}
            sev = sev_map.get(d.classification, "low")
            out.append(Finding(
                pillar=PILLAR_DELEGATION, severity=sev,
                title=(
                    f"Agent '{agent_key}' divergence: "
                    f"{d.classification} "
                    f"({d.divergence_score:.2f})"),
                detail=d.interpretation or "",
                recommendation=(
                    "Investigate recent refused/blocked invocations "
                    "and consider tightening delegation policy."),
                references=[{
                    "agent_key": agent_key,
                    "total_invocations": d.total_invocations,
                    "refused": d.refused_count,
                    "blocked": d.blocked_count,
                    "error": d.error_count,
                }],
            ))
        except Exception as exc:
            logger.debug(
                "[ASSESSMENT] divergence for %s: %s", agent_key, exc)

    return out


# ══════════════════════════════════════════════════════════════════
# Pillar 4 -- Provenance assessment
# ══════════════════════════════════════════════════════════════════


def pillar_provenance_assessment(
    db, *, tenant_id: str, agent_keys: list[str], window_days: int,
) -> list[Finding]:
    """Pillar 4: versioning history + drift detection between the
    two most recent snapshots."""
    from .integrity import canonical_hash
    from .versioning import get_version, list_versions

    out: list[Finding] = []
    for agent_key in agent_keys:
        try:
            # list_versions returns NEWEST FIRST and ONLY metadata;
            # the full ``definition`` blob lives in get_version's
            # response. So we always have to walk version_no -> def.
            versions = list_versions(db, tenant_id, agent_key) or []
            n = len(versions) if isinstance(versions, list) else 0
            if n == 0:
                continue  # already surfaced by trust_scoring
            if n == 1:
                out.append(Finding(
                    pillar=PILLAR_PROVENANCE, severity="informational",
                    title=(
                        f"Agent '{agent_key}': baseline version on record"),
                    detail=(
                        "One version snapshot exists. No history yet to "
                        "compare for drift."),
                    references=[{"agent_key": agent_key, "version_count": n}],
                ))
                continue
            latest_vno = _maybe_get(versions[0], "version_no")
            prev_vno = _maybe_get(versions[1], "version_no")
            latest_full = (
                get_version(db, tenant_id, agent_key, latest_vno)
                if latest_vno is not None else None
            )
            prev_full = (
                get_version(db, tenant_id, agent_key, prev_vno)
                if prev_vno is not None else None
            )
            latest_def = _maybe_get(latest_full, "definition")
            prev_def = _maybe_get(prev_full, "definition")
            drift = bool(
                latest_def and prev_def
                and canonical_hash(latest_def) != canonical_hash(prev_def)
            )
            if drift:
                out.append(Finding(
                    pillar=PILLAR_PROVENANCE, severity="medium",
                    title=(
                        f"Agent '{agent_key}': definition drift detected"),
                    detail=(
                        f"Latest version's canonical hash differs from "
                        f"the prior snapshot. {n} versions on record."),
                    recommendation=(
                        "Review the diff between the two most recent "
                        "versions and confirm the change was authorized."),
                    references=[{
                        "agent_key": agent_key, "version_count": n,
                    }],
                ))
            else:
                out.append(Finding(
                    pillar=PILLAR_PROVENANCE, severity="informational",
                    title=(
                        f"Agent '{agent_key}': {n} versions, no drift "
                        f"between latest two"),
                    detail="Most recent snapshots match by canonical hash.",
                    references=[{
                        "agent_key": agent_key, "version_count": n,
                    }],
                ))
        except Exception as exc:
            logger.debug(
                "[ASSESSMENT] provenance for %s: %s", agent_key, exc)
    return out


# ══════════════════════════════════════════════════════════════════
# Pillar 5 -- Evidence chain review (+ optional signed export)
# ══════════════════════════════════════════════════════════════════


def pillar_evidence_chain_review(
    db,
    *,
    tenant_id: str,
    agent_keys: list[str],
    window_days: int,
    signing_key_pem: str | None = None,
) -> tuple[list[Finding], dict | None]:
    """Pillar 5: verify HMAC evidence chains across the window.

    If ``signing_key_pem`` is provided AND at least one chain was
    successfully verified, also generate an Ed25519-signed offline
    audit export and return its reference dict (caller stores it as
    AssessmentReport.signed_export_ref).
    """
    from .evidence import verify_chain
    from .invocations import list_invocations

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=window_days)
    total_checked = 0
    broken_chains: list[int] = []
    out: list[Finding] = []

    for agent_key in agent_keys:
        invs: list[Any] = []
        try:
            # list_invocations signatures vary across SDK versions; try
            # the windowed form first, fall back to the simple one.
            try:
                invs = list_invocations(
                    db, tenant_id=tenant_id, agent_key=agent_key,
                    since=start, limit=500,
                ) or []
            except TypeError:
                invs = list_invocations(
                    db, tenant_id=tenant_id, agent_key=agent_key,
                    limit=500,
                ) or []
        except Exception as exc:
            logger.debug(
                "[ASSESSMENT] list_invocations for %s: %s",
                agent_key, exc)

        for inv in invs:
            inv_id = _maybe_get(inv, "id")
            if inv_id is None:
                continue
            try:
                r = verify_chain(db, tenant_id, int(inv_id))
                total_checked += 1
                if not _maybe_get(r, "valid", False):
                    broken_chains.append(int(inv_id))
            except Exception as exc:
                logger.debug(
                    "[ASSESSMENT] verify_chain inv=%s: %s",
                    inv_id, exc)

    if total_checked == 0:
        out.append(Finding(
            pillar=PILLAR_EVIDENCE, severity="informational",
            title="No evidence chains in window",
            detail=(
                f"No invocations with verifiable evidence were found "
                f"in the last {window_days} days for the scoped agents."),
        ))
    elif broken_chains:
        out.append(Finding(
            pillar=PILLAR_EVIDENCE, severity="critical",
            title=(
                f"{len(broken_chains)} broken evidence chain(s) detected"),
            detail=(
                f"Verified {total_checked} chains in the {window_days}-day "
                f"window; {len(broken_chains)} failed HMAC re-computation. "
                f"This indicates tampering, key rotation issues, or "
                f"corrupted rows."),
            recommendation=(
                "Inspect the broken invocations urgently. If tampering "
                "is suspected, rotate the evidence signing key and "
                "investigate the principals who wrote those rows."),
            references=[{
                "broken_invocation_ids": broken_chains[:20],
                "chains_checked": total_checked,
            }],
        ))
    else:
        out.append(Finding(
            pillar=PILLAR_EVIDENCE, severity="informational",
            title=f"All {total_checked} evidence chain(s) verified",
            detail=(
                f"Every HMAC chain in the {window_days}-day window "
                f"recomputed successfully -- no tampering detected."),
            references=[{"chains_verified": total_checked}],
        ))

    signed_ref: dict | None = None
    if signing_key_pem and total_checked > 0:
        try:
            from .audit_export import signed_export
            export = signed_export(
                db, tenant_id=tenant_id,
                start=start, end=end,
                signing_key_pem=signing_key_pem,
            )
            signed_ref = {
                "export_id": _maybe_get(export, "export_id"),
                "row_count": _maybe_get(export, "row_count"),
                "schema_version": _maybe_get(export, "schema_version"),
            }
            out.append(Finding(
                pillar=PILLAR_EVIDENCE, severity="informational",
                title="Signed evidence export attached",
                detail=(
                    "Ed25519-signed offline-verifiable audit export "
                    "generated. Auditors can verify with only the "
                    "export + customer public key."),
                references=[signed_ref],
            ))
        except Exception as exc:
            logger.warning(
                "[ASSESSMENT] signed_export failed: %s", exc)
            out.append(Finding(
                pillar=PILLAR_EVIDENCE, severity="low",
                title="Signed evidence export could not be generated",
                detail=f"Reason: {exc!r}.",
            ))
    return out, signed_ref


# ══════════════════════════════════════════════════════════════════
# Orchestrator
# ══════════════════════════════════════════════════════════════════


def run_assessment(
    db,
    *,
    tenant_id: str,
    agent_keys: list[str],
    window_days: int = 30,
    signing_key_pem: str | None = None,
) -> AssessmentReport:
    """Run all five pillars and emit a single ``AssessmentReport``.

    Fail-soft per pillar: a failure in one section becomes a finding
    and the rest of the assessment still runs. Headline severity is
    the max severity across all findings.

    If ``signing_key_pem`` is provided AND the evidence pillar verified
    at least one chain, an Ed25519-signed offline-verifiable export is
    attached.
    """
    generated_at = datetime.now(timezone.utc).isoformat()
    report = AssessmentReport(
        tenant_id=tenant_id,
        scope_agents=list(agent_keys),
        window_days=window_days,
        generated_at=generated_at,
    )

    common = dict(
        db=db, tenant_id=tenant_id, agent_keys=agent_keys,
        window_days=window_days,
    )

    report.trust_scoring = _safe_call(
        PILLAR_TRUST, pillar_trust_scoring, **common)
    report.authority_mapping = _safe_call(
        PILLAR_AUTHORITY, pillar_authority_mapping, **common)
    report.delegation_analysis = _safe_call(
        PILLAR_DELEGATION, pillar_delegation_analysis, **common)
    report.provenance_assessment = _safe_call(
        PILLAR_PROVENANCE, pillar_provenance_assessment, **common)

    # Evidence pillar is special-cased because it also returns a
    # signed-export reference, not just findings.
    try:
        evidence_findings, signed_ref = pillar_evidence_chain_review(
            **common, signing_key_pem=signing_key_pem,
        )
        report.evidence_chain_review = evidence_findings
        report.signed_export_ref = signed_ref
    except Exception as exc:
        logger.warning(
            "[ASSESSMENT] evidence pillar raised: %s", exc)
        report.evidence_chain_review = [Finding(
            pillar=PILLAR_EVIDENCE, severity="informational",
            title="Evidence pillar failed during run",
            detail=f"Exception: {exc!r}.",
        )]

    # Rollup
    report.headline_severity = _max_severity(report.findings)
    counts = {p: len(report.per_pillar[p]) for p in _PILLARS_IN_ORDER}
    report.summary = (
        f"Trust Assessment over {window_days} days for "
        f"{len(agent_keys)} agent(s). Findings: "
        f"{counts[PILLAR_TRUST]} trust, "
        f"{counts[PILLAR_AUTHORITY]} authority, "
        f"{counts[PILLAR_DELEGATION]} delegation, "
        f"{counts[PILLAR_PROVENANCE]} provenance, "
        f"{counts[PILLAR_EVIDENCE]} evidence. Headline: "
        f"{report.headline_severity.upper()}."
    )
    return report
