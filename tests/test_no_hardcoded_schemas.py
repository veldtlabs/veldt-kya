"""Guard against regressions where new tables hardcode a schema.

KYA tables must apply their schema through ``dialect_schema_qualifier()``
in ``kya._portable``, NOT by writing the literal string ``"prov_schema"``
(or any other schema name) directly in DDL or raw SQL. This test scans
the open SDK source and fails if it finds an offending hardcoded name.

If you legitimately need to reference the legacy schema name (e.g., in
a documentation docstring), add the file to ``ALLOWED_FILES`` with a
short reason in the docstring of that file.
"""
from __future__ import annotations

import pathlib
import re

# Source roots to scan
_KYA_ROOT = pathlib.Path(__file__).resolve().parent.parent / "kya"

# Files where the literal string is allowed:
#   - _portable.py: defines the legacy default (until v0.1.6 changed
#     it to None); references the name in its own docstring.
#   - storage.py: may mention prov_schema in upgrade-note docstrings.
_ALLOWED_FILES = {
    "_portable.py",
    "storage.py",
}

# Patterns we consider hardcoded use. We match the literal name in
# string-quoted form (single or double quotes) because that's the
# only context where it would actually affect runtime behavior.
_PATTERNS = [
    re.compile(r"""['"]prov_schema['"]"""),
    re.compile(r"""schema\s*=\s*['"]prov_schema['"]"""),
    re.compile(r"""['"]\w+\.prov_schema['"]"""),
]


def test_no_hardcoded_prov_schema_in_kya_source():
    """Scan kya/ for any hardcoded 'prov_schema' string. Any file not
    in _ALLOWED_FILES that contains the literal must be refactored to
    use ``dialect_schema_qualifier()`` or ``schema_args()``."""
    offenders = []
    for path in _KYA_ROOT.rglob("*.py"):
        if path.name in _ALLOWED_FILES:
            continue
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pat in _PATTERNS:
            for m in pat.finditer(text):
                # Skip occurrences inside a comment line
                line_start = text.rfind("\n", 0, m.start()) + 1
                line = text[line_start:m.start()]
                if "#" in line:
                    continue
                # Report the offending line
                line_end = text.find("\n", m.start())
                full_line = text[line_start:line_end].strip()
                line_no = text[:m.start()].count("\n") + 1
                offenders.append(
                    f"{path.relative_to(_KYA_ROOT.parent)}:{line_no}: "
                    f"{full_line[:120]}")
    assert not offenders, (
        "Hardcoded 'prov_schema' string found in source -- use "
        "dialect_schema_qualifier() / schema_args() from kya._portable "
        "so the schema is dialect-aware and env-overridable:\n\n  "
        + "\n  ".join(offenders))


def test_no_hardcoded_schema_in_raw_sql():
    """Catch the pattern ``text('FROM prov_schema.<table>')`` etc.,
    INCLUDING inside triple-quoted ``text(\"\"\"...\"\"\")`` blocks
    that the previous single-line regex missed.

    Strategy:
      1. Strip ``# comment`` lines so the legacy-docstring mentions
         don't false-positive.
      2. Grep the whole-file text for bare ``prov_schema.<word>``
         occurrences -- catches single-quoted, double-quoted, AND
         triple-quoted SQL alike.

    Raw SQL should use ``qual_for_raw_sql(db)`` (for KYA tables) or
    ``qual_for_raw_sql_decisions(db)`` (for veldt-decisions tables).
    """
    bare_pat = re.compile(r"\bprov_schema\.\w+")
    for path in _KYA_ROOT.rglob("*.py"):
        if path.name in _ALLOWED_FILES:
            continue
        if "__pycache__" in path.parts:
            continue
        # Strip full-line comments so docstring mentions of the legacy
        # name in narrative prose don't false-positive. (Inline
        # comments after code are still scanned -- intentional, since
        # they could mask a real refactor miss.)
        lines = path.read_text(
            encoding="utf-8", errors="ignore").splitlines(keepends=True)
        stripped = "".join(
            "" if ln.lstrip().startswith("#") else ln
            for ln in lines)
        for m in bare_pat.finditer(stripped):
            line_no = stripped[:m.start()].count("\n") + 1
            line_start = stripped.rfind("\n", 0, m.start()) + 1
            line_end = stripped.find("\n", m.start())
            full_line = stripped[
                line_start:(line_end if line_end != -1 else len(stripped))
            ].strip()
            raise AssertionError(
                f"Hardcoded 'prov_schema.{m.group()[13:]}' found in raw "
                f"SQL at {path.relative_to(_KYA_ROOT.parent)}:{line_no}\n"
                f"  {full_line[:120]}\n"
                "Use qual_for_raw_sql(db) (KYA tables) or "
                "qual_for_raw_sql_decisions(db) (decisions tables) "
                "from kya._portable.")


def test_default_schema_is_none_in_v0_1_6():
    """The default schema MUST be None as of v0.1.6 (was 'prov_schema'
    in 0.1.5 and earlier). Customers running on the legacy schema
    must set KYA_VERSIONS_SCHEMA=prov_schema explicitly."""
    import os

    from kya._portable import dialect_schema_qualifier
    # Save + clear env var
    saved = os.environ.pop("KYA_VERSIONS_SCHEMA", None)
    try:
        result = dialect_schema_qualifier()
        assert result is None, (
            f"dialect_schema_qualifier() returned {result!r} but v0.1.6 "
            "default MUST be None (= dialect's default schema). "
            "If you reverted this on purpose, update this test too.")
    finally:
        if saved is not None:
            os.environ["KYA_VERSIONS_SCHEMA"] = saved
