"""
Match primitives for attack-chain rules.

Pure functions. No DB, no state, no I/O. Two responsibilities:

  1. `field_value(obj, dotted_path)` -- safely read `payload.path.to.x`
     out of nested evidence dicts. Returns None on any missing key
     (never KeyError / AttributeError). Used by the loader for
     validation AND by the engine for matching, so the access
     semantics are defined exactly once.

  2. `match_value(actual, spec)` -- apply a matcher spec to a value.
     Spec syntax (DRY across loader + engine):
       "literal-string"           -> exact equality (default)
       "glob:/etc/*"              -> fnmatch glob
       "regex:^Bearer .+$"        -> re.fullmatch
       "in:[a,b,c]"               -> set membership (also accepts list/tuple)
       "not:<matcher>"            -> negation of inner matcher
       <list of strings>          -> ANY-of (first matching wins)
       <bool/int/float/None>      -> exact equality

Spec error handling: malformed specs raise MatcherError at PARSE
time (during load_rule), never during match. Keep the runtime fast.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Iterable


class MatcherError(ValueError):
    """Raised when a matcher spec is malformed at parse time."""


# ── Field access ────────────────────────────────────────────────────


def field_value(obj: Any, dotted_path: str) -> Any:
    """Read `obj[a][b][c]` from a dotted-path string.

    Returns None on any missing key, missing attribute, list index out
    of range, or non-dict/non-list intermediate. Never raises.

    Supports list indexing via bracket notation:
        field_value({"a": [{"b": 1}, {"b": 2}]}, "a[1].b")  -> 2

    Empty string returns the object itself (useful for "match the
    whole evidence row").
    """
    if dotted_path == "":
        return obj
    cur = obj
    # Split on dots first; then handle [N] within each segment.
    for raw_segment in dotted_path.split("."):
        if cur is None:
            return None
        segment = raw_segment
        # Pull out trailing [N] indexers (one or more).
        idx_list: list[int] = []
        while segment.endswith("]") and "[" in segment:
            lb = segment.rfind("[")
            try:
                idx_list.insert(0, int(segment[lb + 1:-1]))
            except ValueError:
                return None
            segment = segment[:lb]
        # Read the named key/attribute (segment may be "" if path
        # starts with [N]; treat as "use cur directly")
        if segment != "":
            if isinstance(cur, dict):
                cur = cur.get(segment)
            else:
                cur = getattr(cur, segment, None)
        if cur is None:
            return None
        # Apply any indexers
        for idx in idx_list:
            if not isinstance(cur, (list, tuple)):
                return None
            if idx < 0 or idx >= len(cur):
                return None
            cur = cur[idx]
    return cur


# ── Matcher spec parsing + evaluation ───────────────────────────────


_PREFIX_LITERAL = "literal:"
_PREFIX_GLOB = "glob:"
_PREFIX_REGEX = "regex:"
_PREFIX_IN = "in:"
_PREFIX_NOT = "not:"


def _parse_in_spec(spec_body: str) -> tuple[Any, ...]:
    """Parse 'in:[a,b,c]' -> ('a','b','c'). Strips whitespace.
    Supports unquoted bare-word values; numeric values are coerced to
    int/float. For string values with commas, callers should pass a
    list directly (programmatic) rather than the string form."""
    s = spec_body.strip()
    if not (s.startswith("[") and s.endswith("]")):
        raise MatcherError(
            f"'in:' spec must be [a,b,c] form, got {spec_body!r}")
    inner = s[1:-1].strip()
    if not inner:
        return ()
    parts = [p.strip() for p in inner.split(",")]
    out: list[Any] = []
    for p in parts:
        # Strip optional quotes
        if (p.startswith('"') and p.endswith('"')) or \
                (p.startswith("'") and p.endswith("'")):
            out.append(p[1:-1])
        else:
            # Numeric coercion
            try:
                out.append(int(p))
            except ValueError:
                try:
                    out.append(float(p))
                except ValueError:
                    out.append(p)
    return tuple(out)


def match_value(actual: Any, spec: Any) -> bool:
    """Apply a matcher spec to an actual value. Returns bool.

    See module docstring for spec syntax. Spec types other than str /
    list / scalar treat as exact equality (after coercion to str on
    one side).
    """
    # List/tuple spec -> ANY-of, recurse
    if isinstance(spec, (list, tuple)):
        return any(match_value(actual, item) for item in spec)

    # Non-string scalar -> exact equality
    if not isinstance(spec, str):
        return actual == spec

    # String spec with prefix
    if spec.startswith(_PREFIX_NOT):
        return not match_value(actual, spec[len(_PREFIX_NOT):])
    if spec.startswith(_PREFIX_GLOB):
        if not isinstance(actual, str):
            return False
        return fnmatch.fnmatchcase(actual, spec[len(_PREFIX_GLOB):])
    if spec.startswith(_PREFIX_REGEX):
        if not isinstance(actual, str):
            return False
        try:
            return re.fullmatch(spec[len(_PREFIX_REGEX):], actual) is not None
        except re.error:
            return False  # malformed at runtime -> no match
    if spec.startswith(_PREFIX_IN):
        try:
            choices = _parse_in_spec(spec[len(_PREFIX_IN):])
        except MatcherError:
            return False
        return actual in choices
    if spec.startswith(_PREFIX_LITERAL):
        return actual == spec[len(_PREFIX_LITERAL):]

    # Default: bare string -> exact equality (after coercion)
    if isinstance(actual, str):
        return actual == spec
    return str(actual) == spec


# ── Validation helpers (used by loader) ─────────────────────────────


def validate_matcher_spec(spec: Any) -> None:
    """Raise MatcherError if `spec` is malformed.

    Called by the loader so that bad rules are rejected at LOAD time
    rather than failing silently at match time. Recursively validates
    list-of-specs (any-of) and not-of-spec (negation).
    """
    if isinstance(spec, (list, tuple)):
        if not spec:
            raise MatcherError("any-of matcher list cannot be empty")
        for item in spec:
            validate_matcher_spec(item)
        return
    if not isinstance(spec, str):
        return  # scalar equality is always valid
    if spec.startswith(_PREFIX_NOT):
        validate_matcher_spec(spec[len(_PREFIX_NOT):])
        return
    if spec.startswith(_PREFIX_REGEX):
        try:
            re.compile(spec[len(_PREFIX_REGEX):])
        except re.error as exc:
            raise MatcherError(
                f"invalid regex {spec!r}: {exc}") from exc
        return
    if spec.startswith(_PREFIX_IN):
        _parse_in_spec(spec[len(_PREFIX_IN):])  # raises on malformed
        return
    if spec.startswith(_PREFIX_GLOB):
        # fnmatch has no compile-time error; any string is "valid"
        return
    if spec.startswith(_PREFIX_LITERAL):
        return
    # Bare string -> literal equality, always valid
    return


def all_match(actual: dict, spec_map: dict[str, Any]) -> bool:
    """Convenience: every `field -> spec` in spec_map must match.

    Field paths are dotted; spec values are matcher specs. Empty
    spec_map matches anything (used for "any evidence of kind X").
    """
    if not spec_map:
        return True
    for path, spec in spec_map.items():
        if not match_value(field_value(actual, path), spec):
            return False
    return True
