"""Sigma -> KYA AttackChainRule translator.

Sigma is the de-facto OSS rule format for security detection
(https://github.com/SigmaHQ/sigma). It's used by Elastic, Splunk,
Wazuh, Chronicle, and most SIEMs. Customers arriving at KYA almost
always already have a Sigma rule library; this adapter lets them
keep using it.

Scope of v1 -- what translates
==============================
* Single-selection rules (``condition: selection`` or
  ``condition: <name>``) -- the bulk of public Sigma rules.
* AND-chain selections (``condition: a and b`` -> merged match
  spec). Order in an AND chain has no semantic meaning so we treat
  the result as a single-step KYA rule.

Scope of v1 -- what does NOT translate (raises SigmaTranslateError)
==================================================================
* OR conditions -- split into two KYA rules.
* NOT (selection-level), ``1 of``/``all of``/``any of``, ``count()``.
* Parenthesized conditions.
* Keyword-only rules (free-text search without field anchors).

These are intentional limits: each unsupported construct yields a
clear error, NOT a silent partial translation that could miss
detections.

Field modifier mapping
======================
Sigma modifier     -> KYA match spec
-----------------     -------------------------
(no modifier)         literal equality
``|contains``         ``glob:*<v>*``
``|startswith``       ``glob:<v>*``
``|endswith``         ``glob:*<v>``
``|re`` / ``|regex``  ``regex:<v>``
list of values        ``in:[v1, v2, ...]``

Metadata preserved
==================
* ``id`` -> ``metadata.sigma_id`` (also used to derive the KYA rule id)
* ``title`` -> ``metadata.sigma_title``
* ``status`` -> ``metadata.sigma_status``
* ``references`` -> ``metadata.references``
* ``tags`` -> split into ``metadata.mitre_attack`` (technique IDs)
  and ``metadata.mitre_tactic`` (tactic names)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ._loader import (
    AttackChainRule,
    RuleLoadError,
    load_rule,
)

logger = logging.getLogger(__name__)


class SigmaTranslateError(ValueError):
    """The Sigma rule can't be translated to a KYA AttackChainRule.

    Always names the offending feature so operators can either split
    the rule (for ``or``) or wait for the feature to land.
    """


_SIGMA_LEVEL_TO_KYA_SEVERITY = {
    "informational": "informational",
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Sigma tag forms we map onto KYA metadata:
#   ``attack.t<N>`` / ``attack.t<N>.<sub>``  -> MITRE technique id
#   ``attack.<tactic>``                      -> MITRE tactic name
_MITRE_TECHNIQUE_RE = re.compile(
    r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)
_MITRE_TACTIC_PREFIX = "attack."

_SUPPORTED_MODIFIERS = frozenset({
    "", "contains", "startswith", "endswith", "re", "regex",
})


# ── ID + severity + tags ──────────────────────────────────────────


def _normalize_id(sigma_id: str | None, title: str | None) -> str:
    """Pick a stable KYA rule id. Sigma id (UUID) is preferred;
    otherwise a slug of the title; otherwise raise."""
    candidate: str | None = None
    if sigma_id and isinstance(sigma_id, str) and sigma_id.strip():
        candidate = sigma_id.strip().lower()
    elif title and isinstance(title, str) and title.strip():
        candidate = title.strip().lower()
    if not candidate:
        raise SigmaTranslateError(
            "Sigma rule has neither `id` nor `title` -- cannot "
            "derive a KYA rule id")
    s = re.sub(r"[^a-z0-9_]+", "_", candidate).strip("_")[:80]
    return f"sigma_{s}" if s else "sigma_unnamed"


def _map_severity(sigma_level: Any) -> str:
    if not isinstance(sigma_level, str):
        return "low"
    return _SIGMA_LEVEL_TO_KYA_SEVERITY.get(
        sigma_level.strip().lower(), "low")


def _extract_mitre(tags: Any) -> tuple[list[str], list[str]]:
    """Return (technique_ids, tactic_names) from Sigma ``tags``."""
    if not isinstance(tags, list):
        return [], []
    techniques: list[str] = []
    tactics: list[str] = []
    seen_tech: set[str] = set()
    seen_tactic: set[str] = set()
    for t in tags:
        if not isinstance(t, str):
            continue
        ts = t.strip().lower()
        m = _MITRE_TECHNIQUE_RE.match(ts)
        if m:
            base, sub = m.group(1), m.group(2)
            tid = f"T{base}" + (f".{sub}" if sub else "")
            if tid not in seen_tech:
                techniques.append(tid)
                seen_tech.add(tid)
            continue
        if ts.startswith(_MITRE_TACTIC_PREFIX):
            tactic = ts[len(_MITRE_TACTIC_PREFIX):]
            if tactic and tactic not in seen_tactic:
                tactics.append(tactic)
                seen_tactic.add(tactic)
    return techniques, tactics


def _evidence_kind_from_logsource(logsource: Any) -> str:
    """Pick the canonical evidence_kind for a Sigma logsource. We
    prefer ``category`` (e.g. ``process_creation``) and fall back to
    ``service``, then ``product``."""
    if not isinstance(logsource, dict):
        return "log_event"
    for key in ("category", "service", "product"):
        v = logsource.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "log_event"


# ── Selection translation ─────────────────────────────────────────


def _split_field(key: str) -> tuple[str, str]:
    """Split ``field|modifier`` -> ``(field, modifier)``."""
    if "|" not in key:
        return key.strip(), ""
    head, *rest = key.split("|")
    # v1 doesn't compose multiple modifiers -- the first wins, the
    # rest must be empty or the spec is rejected.
    primary = rest[0].strip().lower() if rest else ""
    extras = [r.strip().lower() for r in rest[1:]]
    if any(extras):
        raise SigmaTranslateError(
            f"composed modifiers on field {key!r} are not supported "
            f"in v1 (got |{'|'.join([primary] + extras)})")
    return head.strip(), primary


def _escape_glob(s: str) -> str:
    """Make a substring safe to embed in a glob-pattern surround --
    fnmatch interprets ``*``, ``?``, ``[``. Use the fnmatch-supported
    character-class escape ``[*]`` / ``[?]`` so a Sigma literal that
    happens to contain these chars matches literally."""
    return s.replace("[", "[[]").replace("*", "[*]").replace("?", "[?]")


def _escape_in_value(v: Any) -> str:
    """Escape a value for inclusion inside ``in:[...]``. KYA's
    ``_parse_in_spec`` handles paired quoting; if a value contains
    a comma, whitespace, or a quote character we wrap it so it
    survives the split."""
    s = str(v)
    needs_quote = ("," in s) or any(c.isspace() for c in s)
    if not needs_quote:
        return s
    if '"' not in s:
        return f'"{s}"'
    return f"'{s}'"


def _translate_one(
    field: str, modifier: str, value: Any,
) -> tuple[str, str]:
    """Convert a Sigma ``field<|mod>: value`` pair into a KYA
    ``(field_path, match_spec)`` pair."""
    if modifier not in _SUPPORTED_MODIFIERS:
        raise SigmaTranslateError(
            f"unsupported field modifier ``|{modifier}`` on "
            f"``{field}`` -- v1 supports: contains, startswith, "
            f"endswith, re, regex (or no modifier)")
    if isinstance(value, list):
        if modifier:
            raise SigmaTranslateError(
                f"``{field}|{modifier}`` cannot be applied to a list "
                f"value in v1 (split into multiple rules)")
        parts = ",".join(_escape_in_value(v) for v in value)
        return field, f"in:[{parts}]"
    if isinstance(value, bool):
        # Sigma occasionally uses booleans for boolean fields; the
        # canonical KYA literal forms are the lowercased strings.
        return field, "true" if value else "false"
    sval = str(value)
    if modifier == "contains":
        return field, f"glob:*{_escape_glob(sval)}*"
    if modifier == "startswith":
        return field, f"glob:{_escape_glob(sval)}*"
    if modifier == "endswith":
        return field, f"glob:*{_escape_glob(sval)}"
    if modifier in ("re", "regex"):
        return field, f"regex:{sval}"
    return field, sval


# ── Condition parsing ────────────────────────────────────────────


def _flatten_condition(condition: str) -> list[str]:
    """Return the list of selection names in an AND-chain condition.

    ``selection`` -> ``["selection"]``
    ``a and b``    -> ``["a", "b"]``

    Anything that includes ``or``, ``not``, quantifiers, or
    parentheses raises :class:`SigmaTranslateError`.
    """
    s = (condition or "").strip().lower()
    if not s:
        raise SigmaTranslateError("condition is empty")
    if re.fullmatch(r"[a-z0-9_]+", s):
        return [s]
    padded = f" {s} "
    for forbidden in (" or ", " not ", " 1 of ", " all of ", " any of "):
        if forbidden in padded:
            raise SigmaTranslateError(
                f"v1 cannot translate condition {condition!r}: "
                f"contains {forbidden.strip()!r}; split into "
                f"multiple rules or wait for the feature to land")
    if "(" in s or ")" in s:
        raise SigmaTranslateError(
            f"v1 cannot translate parenthesized condition "
            f"{condition!r}")
    parts = [p.strip() for p in re.split(r"\band\b", s) if p.strip()]
    if not parts or not all(
            re.fullmatch(r"[a-z0-9_]+", p) for p in parts):
        raise SigmaTranslateError(
            f"v1 cannot parse condition {condition!r}")
    return parts


# ── Top-level translation ─────────────────────────────────────────


def translate_sigma_to_kya_dict(
    sigma: dict,
    *,
    correlate_by: tuple[str, ...] = ("tenant_id", "principal_id"),
    emits_signal_prefix: str = "rogue_sigma",
    field_prefix: str = "payload.",
) -> dict:
    """Translate a parsed Sigma rule into a KYA v1 rule dict that
    :func:`kya.attack_chains.load_rule` will accept.

    Args:
        sigma: parsed Sigma rule.
        correlate_by: KYA correlate_by tuple to inject; Sigma has no
            equivalent so the operator chooses the scope.
        emits_signal_prefix: KYA signals follow the ``rogue_*``
            convention; the translated rule's ``emits_signal`` is
            ``{prefix}_{rule_id}``.
        field_prefix: dotted-path prefix prepended to every Sigma
            field name when emitting the KYA ``match`` spec. Defaults
            to ``"payload."`` because KYA's evidence convention puts
            SIEM-style fields under the event payload (the engine
            looks them up via :func:`kya.attack_chains.field_value`).
            Bridges that land fields at the top level of the event
            context can pass ``field_prefix=""``.

    Raises:
        SigmaTranslateError: rule uses a construct outside v1 scope.
    """
    if not isinstance(sigma, dict):
        raise SigmaTranslateError(
            "Sigma rule must be a mapping at top level")

    sigma_id = sigma.get("id")
    title = sigma.get("title")
    description = sigma.get("description") or ""

    rule_id = _normalize_id(
        str(sigma_id) if sigma_id else None,
        str(title) if title else None)

    severity = _map_severity(sigma.get("level"))
    evidence_kind = _evidence_kind_from_logsource(sigma.get("logsource"))

    detection = sigma.get("detection")
    if not isinstance(detection, dict):
        raise SigmaTranslateError(
            f"[{rule_id}] `detection` is required and must be a mapping")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaTranslateError(
            f"[{rule_id}] `detection.condition` is required and "
            f"must be a string")

    selection_names = _flatten_condition(condition)
    selections_lc: dict[str, Any] = {
        k.lower(): v for k, v in detection.items() if k != "condition"
    }
    merged_match: dict[str, str] = {}
    for name in selection_names:
        sel = selections_lc.get(name)
        if sel is None:
            raise SigmaTranslateError(
                f"[{rule_id}] condition references unknown selection "
                f"{name!r}")
        if not isinstance(sel, dict):
            raise SigmaTranslateError(
                f"[{rule_id}] selection {name!r} is not a mapping -- "
                f"v1 only supports field-based selections "
                f"(no keyword-only rules)")
        for key, value in sel.items():
            field, modifier = _split_field(str(key))
            if not field:
                raise SigmaTranslateError(
                    f"[{rule_id}] empty field name in selection "
                    f"{name!r}")
            kya_field, kya_spec = _translate_one(field, modifier, value)
            # Prepend the engine's field-lookup namespace. SIEM fields
            # land under ``payload.*`` by KYA convention so the engine
            # can pull them out of the event context the same way the
            # shipped rules do.
            prefixed_field = f"{field_prefix}{kya_field}" if field_prefix else kya_field
            if (prefixed_field in merged_match
                    and merged_match[prefixed_field] != kya_spec):
                raise SigmaTranslateError(
                    f"[{rule_id}] selections {selection_names!r} "
                    f"disagree on field {prefixed_field!r} "
                    f"({merged_match[prefixed_field]!r} vs {kya_spec!r}) "
                    f"-- v1 cannot merge conflicting matches")
            merged_match[prefixed_field] = kya_spec

    if not merged_match:
        raise SigmaTranslateError(
            f"[{rule_id}] translated to an empty match spec -- "
            f"refusing to ship a rule that matches everything")

    techniques, tactics = _extract_mitre(sigma.get("tags"))

    refs_raw = sigma.get("references") or []
    references = [r for r in refs_raw if isinstance(r, str)]

    metadata: dict[str, Any] = {
        "source": "sigma",
    }
    if sigma_id:
        metadata["sigma_id"] = str(sigma_id)
    if title:
        metadata["sigma_title"] = str(title)
    status = sigma.get("status")
    if isinstance(status, str) and status.strip():
        metadata["sigma_status"] = status.strip().lower()
    if techniques:
        metadata["mitre_attack"] = techniques
    if tactics:
        metadata["mitre_tactic"] = tactics
    if references:
        metadata["references"] = references

    return {
        "version": 1,
        "id": rule_id,
        "description": (
            description if isinstance(description, str) else ""),
        "severity": severity,
        "emits_signal": f"{emits_signal_prefix}_{rule_id}",
        "correlate_by": list(correlate_by),
        "steps": [
            {
                "id": "detection",
                "evidence_kind": evidence_kind,
                "match": merged_match,
            }
        ],
        "metadata": metadata,
    }


def load_sigma_rule(
    raw: dict | str | Path,
    *,
    correlate_by: tuple[str, ...] = ("tenant_id", "principal_id"),
    emits_signal_prefix: str = "rogue_sigma",
    field_prefix: str = "payload.",
) -> AttackChainRule:
    """Translate Sigma -> KYA dict -> AttackChainRule in one call.

    Accepts the same surface as :func:`load_rule_from_yaml`: a parsed
    dict, a YAML string, or a path (str / :class:`pathlib.Path`).
    """
    sigma_dict: dict
    source_label: str
    if isinstance(raw, dict):
        sigma_dict = raw
        source_label = (
            f"<sigma:{raw.get('id') or raw.get('title') or 'inline'}>"
        )
    else:
        try:
            import yaml
        except ImportError as exc:
            raise SigmaTranslateError(
                "PyYAML required for load_sigma_rule when raw is "
                "string/path; install with "
                "`pip install veldt-kya[attack_chains]` "
                "or `pip install pyyaml`."
            ) from exc

        if isinstance(raw, Path):
            source_label = str(raw)
            text = raw.read_text(encoding="utf-8")
        elif isinstance(raw, str) and Path(raw).is_file():
            source_label = raw
            text = Path(raw).read_text(encoding="utf-8")
        else:
            source_label = "<inline sigma yaml>"
            text = str(raw)

        sigma_dict = yaml.safe_load(text)
        if not isinstance(sigma_dict, dict):
            raise SigmaTranslateError(
                f"[{source_label}] Sigma YAML must parse to a mapping")

    kya_dict = translate_sigma_to_kya_dict(
        sigma_dict,
        correlate_by=correlate_by,
        emits_signal_prefix=emits_signal_prefix,
        field_prefix=field_prefix,
    )
    # Pass through KYA's own v1 validator. Any RuleLoadError here is
    # a translator bug -- the message is preserved for diagnosis.
    return load_rule(kya_dict, source_label=source_label)


def load_sigma_rules_from_dir(
    directory: str | Path,
    *,
    pattern: str = "*.yml",
    correlate_by: tuple[str, ...] = ("tenant_id", "principal_id"),
    emits_signal_prefix: str = "rogue_sigma",
    field_prefix: str = "payload.",
) -> tuple[list[AttackChainRule], list[tuple[str, str]]]:
    """Bulk-load every Sigma rule in ``directory``.

    Returns ``(rules, skipped)`` where ``skipped`` is a list of
    ``(path, reason)`` pairs for rules that could not be translated
    (or-of-selections, complex conditions, keyword-only, ...). Skipped
    rules are NOT fatal -- real Sigma libraries always have a long
    tail of v1-unsupported constructs; the caller ships what loaded
    and addresses the rest later.
    """
    d = Path(directory)
    if not d.is_dir():
        return [], [(str(d), "directory not found")]
    rules: list[AttackChainRule] = []
    skipped: list[tuple[str, str]] = []
    for path in sorted(d.glob(pattern)):
        try:
            rule = load_sigma_rule(
                path,
                correlate_by=correlate_by,
                emits_signal_prefix=emits_signal_prefix,
                field_prefix=field_prefix,
            )
            rules.append(rule)
        except (SigmaTranslateError, RuleLoadError) as exc:
            skipped.append((str(path), str(exc)))
            logger.info(
                "[KYA-SIGMA] skipped %s: %s", path, exc)
    # Stable order across reloads.
    rules.sort(key=lambda r: r.id)
    return rules, skipped
