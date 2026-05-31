"""
Rule loader for attack-chain DSL.

Three loading surfaces, ONE in-memory representation:

  1. load_rule(dict)        -- caller-supplied dict (tests, programmatic)
  2. load_rule_from_yaml()  -- YAML file or string
  3. load_rule_from_class() -- Python class (decorator API; see below)

All three produce an `AttackChainRule` dataclass instance. The engine
never sees the source format -- it only sees the dataclass. This is
the firewall that lets us add/replace loaders without touching the
engine OR existing customer rules.

Versioning
----------
Every rule declares `version: <int>`. The loader registry maps
version -> validator/parser function. To add v2, register a new
handler; v1 rules keep loading forever.

Currently shipped versions:
  - 1: YAML-flat schema (see docstring below)

The dataclass shape (post-parse) is INDEPENDENT of the version --
loaders translate from version-specific surface to the canonical
shape, so the engine doesn't branch on version.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._matchers import MatcherError, validate_matcher_spec

logger = logging.getLogger(__name__)


# ── Errors ──────────────────────────────────────────────────────────


class RuleLoadError(ValueError):
    """Malformed rule definition. Includes the rule id (when parseable)
    and the field path that failed, so operators can fix YAML easily."""


# ── In-memory representation (STABLE -- do not change shape) ────────


@dataclass(frozen=True)
class StepSpec:
    """One step in an attack-chain rule. Frozen because we treat
    rule definitions as immutable after load."""
    id: str
    evidence_kind: str
    match: dict[str, Any] = field(default_factory=dict)
    # Prior steps that must complete before this step can match.
    #
    # The canonical in-memory representation is ALWAYS a tuple. The
    # loader accepts two surface forms and normalises:
    #   * ``after: "step1"``               -> ``("step1",)``
    #   * ``after: ["step1", "step2"]``    -> ``("step1", "step2")``
    #   * ``after: null`` / omitted        -> ``()``
    #
    # An empty tuple means "no prerequisites" (the step can fire
    # from the start). A non-empty tuple means **all** listed steps
    # must have completed -- AND-join semantics. OR-of-steps is
    # expressed by writing two rules, not by overloading this field.
    after: tuple[str, ...] = field(default_factory=tuple)
    # Optional: within N seconds of the LATEST `after` predecessor
    # completing (None = no time bound). When there are multiple
    # `after` entries the engine measures from the most recent one.
    within_seconds: int | None = None


# Allowed values for AttackChainRule.mode. "linear" is the historical
# behaviour (steps fire in declared order); "dag" enables AND-joins
# across the step graph so a chain can model branch-and-join attack
# patterns.
RULE_MODES = frozenset({"linear", "dag"})


@dataclass(frozen=True)
class AttackChainRule:
    """The CANONICAL in-memory shape, regardless of source format.

    Engines and state stores work against THIS shape. Loaders are
    responsible for translating from YAML / Python class / dict
    into this dataclass. Customer-visible API surface for programmatic
    rule construction.
    """
    id: str
    version: int
    description: str
    severity: str  # informational | low | medium | high | critical
    emits_signal: str
    correlate_by: tuple[str, ...]
    steps: tuple[StepSpec, ...]
    # Execution model for the step graph.
    #   * ``linear`` (default) -- steps must complete in the order
    #     they were declared; ``after`` is honored as a single
    #     predecessor; a chain advances index by index.
    #   * ``dag``              -- each step is ready when ALL of its
    #     ``after`` entries are in the completed set (AND-join);
    #     steps may complete in any order; the rule fires when the
    #     completed set covers every declared step.
    #
    # Backward-compatible default keeps every existing rule behaving
    # exactly as before. Customers opt into DAG semantics per rule
    # when they need branch-and-join patterns.
    mode: str = "linear"
    # Global window cap (in addition to per-step `within_seconds`).
    # None = no global cap.
    window_seconds: int | None = None
    # Free-form metadata operators can attach (tags, references to
    # mitre ATT&CK technique IDs, etc.). Engine ignores; preserved
    # for downstream tools.
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Loader registry (pluggable per schema version) ──────────────────


_VERSION_LOADERS: dict[int, Callable[[dict, str], AttackChainRule]] = {}


def register_loader(
    version: int,
    fn: Callable[[dict, str], AttackChainRule],
) -> None:
    """Plug in a new schema-version loader.

    Two-arg callable: (raw_dict, source_label) -> AttackChainRule.
    `source_label` is used in error messages (e.g., file path).
    Lets the SDK extend the rule grammar without touching the engine.
    """
    _VERSION_LOADERS[version] = fn


# ── v1 schema loader (the only shipped version today) ────────────


_VALID_SEVERITIES = frozenset({
    "informational", "low", "medium", "high", "critical",
})


def _load_v1(raw: dict, source_label: str) -> AttackChainRule:
    """Parse a v1-shape dict into an AttackChainRule.

    v1 SCHEMA (YAML / dict form):

        version: 1                              # required, int
        id: <rule_id>                           # required, str, unique
        description: <free text>                # optional, default ""
        severity: <one of _VALID_SEVERITIES>    # required
        emits_signal: <signal_kind str>         # required (record_principal_signal kind)
        correlate_by: [tenant_id, principal_id] # required, list of str
        window_seconds: <int>                   # optional global cap
        steps:                                  # required, >=1 step
          - id: <step_id>                       # required, unique within rule
            evidence_kind: <evidence_kind>      # required
            match:                              # optional field->spec map
              payload.tool: file_read
              payload.path: "glob:/etc/*"
            after: <prior step id>              # optional
            within_seconds: 60                  # optional per-step time bound
        metadata:                               # optional dict
          mitre_attack: T1555.001
          tags: [exfiltration, filesystem]
    """
    def _bail(msg: str) -> None:
        rid = raw.get("id", "<unknown>")
        raise RuleLoadError(f"[{source_label}:{rid}] {msg}")

    if not isinstance(raw, dict):
        raise RuleLoadError(f"[{source_label}] rule must be a dict")

    rid = raw.get("id")
    if not (isinstance(rid, str) and rid.strip()):
        raise RuleLoadError(
            f"[{source_label}] rule.id must be a non-empty string")

    description = raw.get("description") or ""
    if not isinstance(description, str):
        _bail("description must be a string if present")

    severity = raw.get("severity")
    if severity not in _VALID_SEVERITIES:
        _bail(f"severity must be one of {sorted(_VALID_SEVERITIES)}, "
              f"got {severity!r}")

    emits = raw.get("emits_signal")
    if not (isinstance(emits, str) and emits.strip()):
        _bail("emits_signal must be a non-empty string")

    corr_raw = raw.get("correlate_by")
    if not isinstance(corr_raw, (list, tuple)) or not corr_raw:
        _bail("correlate_by must be a non-empty list of field names")
    if not all(isinstance(x, str) and x for x in corr_raw):
        _bail("correlate_by entries must be non-empty strings")
    correlate_by = tuple(corr_raw)

    window_seconds = raw.get("window_seconds")
    if window_seconds is not None and not (
            isinstance(window_seconds, int) and window_seconds > 0):
        _bail("window_seconds must be a positive int if present")

    # ``mode`` is optional with a backward-compatible default. Linear
    # rules behave exactly as they did before this field existed. DAG
    # rules let any step fire when all of its ``after`` entries are in
    # the completed set -- enabling branch-and-join attack patterns
    # (e.g. recon + creds-read in parallel, then exfil joins on both).
    mode = raw.get("mode", "linear")
    if mode not in RULE_MODES:
        _bail(
            f"mode must be one of {sorted(RULE_MODES)!r}; got {mode!r}")

    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        _bail("steps must be a non-empty list")

    seen_step_ids: set[str] = set()
    steps: list[StepSpec] = []
    for i, step in enumerate(steps_raw):
        if not isinstance(step, dict):
            _bail(f"steps[{i}] must be a dict")
        sid = step.get("id")
        if not (isinstance(sid, str) and sid.strip()):
            _bail(f"steps[{i}].id must be a non-empty string")
        if sid in seen_step_ids:
            _bail(f"steps[{i}].id={sid!r} duplicates a prior step")
        seen_step_ids.add(sid)

        ekind = step.get("evidence_kind")
        if not (isinstance(ekind, str) and ekind.strip()):
            _bail(f"steps[{sid}].evidence_kind must be a non-empty string")

        match_raw = step.get("match") or {}
        if not isinstance(match_raw, dict):
            _bail(f"steps[{sid}].match must be a dict (field -> spec)")
        for path, spec in match_raw.items():
            if not isinstance(path, str) or not path:
                _bail(f"steps[{sid}].match key must be non-empty str")
            try:
                validate_matcher_spec(spec)
            except MatcherError as exc:
                _bail(f"steps[{sid}].match[{path}]: {exc}")

        # ``after`` accepts three surface forms; we always normalise
        # to a tuple of step ids. An empty tuple means "no
        # prerequisite". DAG rules typically use the list form for
        # AND-joins; linear rules typically use the single-string
        # form. Both are accepted in either mode.
        after_raw = step.get("after")
        if after_raw is None:
            after: tuple[str, ...] = ()
        elif isinstance(after_raw, str):
            after = (after_raw,) if after_raw.strip() else ()
        elif isinstance(after_raw, (list, tuple)):
            if not all(isinstance(x, str) and x.strip() for x in after_raw):
                _bail(
                    f"steps[{sid}].after list entries must be non-empty "
                    f"strings; got {after_raw!r}")
            after = tuple(after_raw)
        else:
            _bail(
                f"steps[{sid}].after must be a string, list of strings, "
                f"or null; got {type(after_raw).__name__}")

        for prior in after:
            if prior == sid:
                _bail(
                    f"steps[{sid}].after references itself -- a step "
                    f"cannot be its own prerequisite")
            if prior not in seen_step_ids:
                # For ``linear`` rules this preserves the historical
                # constraint (must be declared earlier). For ``dag``
                # rules we keep the same constraint -- declaring
                # predecessors first makes cycle detection trivial.
                _bail(
                    f"steps[{sid}].after={prior!r} references unknown "
                    f"prior step (must be declared earlier in `steps`)")

        within = step.get("within_seconds")
        if within is not None and not (
                isinstance(within, int) and within > 0):
            _bail(f"steps[{sid}].within_seconds must be positive int")
        if within is not None and not after:
            _bail(
                f"steps[{sid}].within_seconds requires `after` to "
                f"define which prior step to measure from")

        steps.append(StepSpec(
            id=sid, evidence_kind=ekind, match=dict(match_raw),
            after=after, within_seconds=within,
        ))

    metadata = raw.get("metadata") or {}
    if not isinstance(metadata, dict):
        _bail("metadata must be a dict if present")

    return AttackChainRule(
        id=rid,
        version=1,
        description=description,
        severity=severity,
        emits_signal=emits,
        correlate_by=correlate_by,
        steps=tuple(steps),
        mode=mode,
        window_seconds=window_seconds,
        metadata=dict(metadata),
    )


register_loader(1, _load_v1)


# ── Public API ──────────────────────────────────────────────────────


def load_rule(
    raw: dict,
    source_label: str = "<dict>",
) -> AttackChainRule:
    """Load a single rule from a dict.

    The dict must include a `version` field; the appropriate
    registered loader is dispatched. Unknown versions raise
    RuleLoadError (rather than silently no-oping) so operators see
    the problem immediately.

    Programmatic API surface -- use this in tests and dynamic rule
    construction.
    """
    if not isinstance(raw, dict):
        raise RuleLoadError(
            f"[{source_label}] rule must be a dict, got "
            f"{type(raw).__name__}")
    version = raw.get("version")
    if not isinstance(version, int):
        raise RuleLoadError(
            f"[{source_label}] rule.version is required and must be int")
    loader = _VERSION_LOADERS.get(version)
    if loader is None:
        raise RuleLoadError(
            f"[{source_label}] no loader registered for version "
            f"{version}; available: {sorted(_VERSION_LOADERS)}")
    return loader(raw, source_label)


def load_rule_from_yaml(
    yaml_text_or_path: str | Path,
) -> AttackChainRule:
    """Load one rule from a YAML string or file path.

    Detects path-vs-string heuristically: if the input is a Path
    instance, or a string that exists on disk as a file, read the
    file. Otherwise parse as a literal YAML string.

    Optional dependency: PyYAML. ImportError raised on first call if
    not installed (fail-loud here -- caller asked for YAML).
    """
    try:
        import yaml
    except ImportError as exc:
        raise RuleLoadError(
            "PyYAML required for load_rule_from_yaml; "
            "pip install veldt-kya[attack_chains] or pip install pyyaml"
        ) from exc

    if isinstance(yaml_text_or_path, Path):
        source = str(yaml_text_or_path)
        text = yaml_text_or_path.read_text(encoding="utf-8")
    elif (isinstance(yaml_text_or_path, str)
          and os.path.isfile(yaml_text_or_path)):
        source = yaml_text_or_path
        text = Path(yaml_text_or_path).read_text(encoding="utf-8")
    else:
        source = "<inline yaml>"
        text = yaml_text_or_path

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"[{source}] YAML parse error: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuleLoadError(f"[{source}] YAML must be a mapping at top level")
    return load_rule(raw, source_label=source)


def load_rules_from_dir(
    directory: str | Path,
    *,
    pattern: str = "*.yml",
) -> list[AttackChainRule]:
    """Load every YAML file matching `pattern` from `directory`.

    Errors in one file do NOT prevent loading the rest -- each failure
    is logged with the file path and skipped. Returns the list of
    successfully-loaded rules. Empty list if no files match or all
    fail.

    Caller controls the order in which rules apply (sorted by id at
    return) so behavior is deterministic across loaders.
    """
    directory = Path(directory)
    if not directory.is_dir():
        logger.debug(
            "[KYA-CHAINS] rule dir %s does not exist -- 0 rules loaded",
            directory)
        return []
    out: list[AttackChainRule] = []
    for path in sorted(directory.glob(pattern)):
        try:
            rule = load_rule_from_yaml(path)
        except RuleLoadError as exc:
            logger.warning(
                "[KYA-CHAINS] skipping malformed rule %s: %s",
                path, exc)
            continue
        out.append(rule)
    # Stable order across multiple loaders -- by id.
    out.sort(key=lambda r: r.id)
    return out


# ── Convenience: Python class-based rule authoring ──────────────────
# (For engineers who want rules in code rather than YAML.)


def rule_from_class(cls: type) -> AttackChainRule:
    """Build a rule from a Python class with the same field names
    as the dataclass.

    Example:

        class FilesystemExfiltration:
            version = 1
            id = "filesystem_exfiltration"
            severity = "high"
            emits_signal = "rogue_filesystem_exfiltration"
            correlate_by = ["tenant_id", "principal_id"]
            steps = [
                {"id": "recon", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "file_read",
                           "payload.path": "glob:/etc/*"}},
                {"id": "exfil", "evidence_kind": "tool_call",
                 "match": {"payload.tool": "http",
                           "payload.method": "POST"},
                 "after": "recon", "within_seconds": 60},
            ]

        rule = rule_from_class(FilesystemExfiltration)

    Lets engineers express rules with full Python tooling (autocomplete,
    refactoring, type checking) without authoring YAML. Same canonical
    dataclass output, same engine.
    """
    raw = {k: getattr(cls, k) for k in dir(cls) if not k.startswith("_")}
    return load_rule(raw, source_label=f"<class {cls.__name__}>")
