"""Phase 3c attack-chain matchers -- pure functional tests.

Tests the match primitives in isolation. No DB, no state, no engine.
If these regress, the whole rule DSL falls over -- so they're tight.
"""

from __future__ import annotations

import pytest

from kya.attack_chains._matchers import (
    MatcherError,
    all_match,
    field_value,
    match_value,
    validate_matcher_spec,
)


# ── field_value ────────────────────────────────────────────────────


def test_field_value_simple_dotted_path():
    obj = {"payload": {"tool": "file_read", "path": "/etc/passwd"}}
    assert field_value(obj, "payload.tool") == "file_read"
    assert field_value(obj, "payload.path") == "/etc/passwd"


def test_field_value_missing_key_returns_none():
    obj = {"payload": {"tool": "file_read"}}
    assert field_value(obj, "payload.path") is None
    assert field_value(obj, "missing.key") is None
    assert field_value(obj, "payload.tool.nested") is None


def test_field_value_empty_path_returns_object():
    obj = {"a": 1}
    assert field_value(obj, "") == obj


def test_field_value_list_indexing():
    obj = {"items": [{"name": "alice"}, {"name": "bob"}]}
    assert field_value(obj, "items[0].name") == "alice"
    assert field_value(obj, "items[1].name") == "bob"


def test_field_value_list_out_of_range_returns_none():
    obj = {"items": [1, 2]}
    assert field_value(obj, "items[5]") is None


def test_field_value_handles_non_dict_intermediate():
    """Trying to access .x on a string/int/None should not raise."""
    assert field_value({"a": "stringval"}, "a.nested") is None
    assert field_value({"a": 42}, "a.nested") is None
    assert field_value({"a": None}, "a.nested") is None


def test_field_value_supports_attribute_access():
    """If the object is a class instance (not a dict), getattr works."""
    class Obj:
        x = 5
    assert field_value({"o": Obj()}, "o.x") == 5


# ── match_value: literal / default ─────────────────────────────────


def test_match_value_literal_equality_default():
    assert match_value("hello", "hello")
    assert not match_value("hello", "world")


def test_match_value_literal_prefix_explicit():
    assert match_value("hello", "literal:hello")
    assert not match_value("hello", "literal:world")


def test_match_value_int_equality():
    assert match_value(42, 42)
    assert not match_value(42, 43)


def test_match_value_bool_equality():
    assert match_value(True, True)
    assert not match_value(True, False)


def test_match_value_str_int_coercion_one_way():
    """Bare str spec compared to int -> coerce int -> str."""
    assert match_value(42, "42")  # int 42 -> "42" == "42"
    assert not match_value(42, "43")


# ── match_value: glob ──────────────────────────────────────────────


def test_match_value_glob_matches():
    assert match_value("/etc/passwd", "glob:/etc/*")
    assert match_value("/etc/shadow", "glob:/etc/*")


def test_match_value_glob_does_not_match():
    assert not match_value("/var/log/syslog", "glob:/etc/*")


def test_match_value_glob_case_sensitive():
    assert not match_value("/ETC/passwd", "glob:/etc/*")


def test_match_value_glob_non_string_actual_returns_false():
    assert not match_value(42, "glob:*")
    assert not match_value(None, "glob:*")


# ── match_value: regex ─────────────────────────────────────────────


def test_match_value_regex_matches():
    assert match_value("Bearer abc123", r"regex:^Bearer .+$")


def test_match_value_regex_fullmatch_semantics():
    """re.fullmatch -- prefix must match the WHOLE string."""
    assert match_value("Bearer abc", r"regex:Bearer .+")
    assert not match_value("Foo Bearer abc", r"regex:Bearer .+")


def test_match_value_regex_malformed_returns_false():
    """At RUNTIME, malformed regex -> False (don't crash matching).
    validate_matcher_spec catches at LOAD time."""
    # Validation rejects this at load time; if it somehow leaked
    # through, runtime returns False.
    assert not match_value("anything", "regex:[unclosed")


# ── match_value: in: (set membership) ──────────────────────────────


def test_match_value_in_string_set():
    assert match_value("a", "in:[a,b,c]")
    assert match_value("b", "in:[a,b,c]")
    assert not match_value("d", "in:[a,b,c]")


def test_match_value_in_numeric_set():
    assert match_value(42, "in:[42,99]")
    assert not match_value(7, "in:[42,99]")


def test_match_value_in_with_quoted_strings():
    """Quoted strings get unquoted at parse time."""
    assert match_value("a", 'in:["a","b"]')
    assert match_value("hello world", 'in:["hello world"]')


def test_match_value_in_does_not_split_commas_inside_quotes():
    """Documented limitation: the 'in:[a,b,c]' string form splits
    on bare commas. To match a value containing a comma, callers
    pass a Python list directly:
        ["a,b", "c"]
    rather than the string-form 'in:["a,b","c"]'."""
    # Programmatic list works:
    assert match_value("a,b", ["a,b", "c"])
    # String-form with comma-in-quoted-value is NOT supported:
    # 'in:["a,b","c"]' would split on the inner comma. Operators
    # needing this should use the list form.


# ── match_value: not: (negation) ───────────────────────────────────


def test_match_value_not_inverts():
    assert match_value("hello", "not:world")
    assert not match_value("hello", "not:hello")


def test_match_value_not_with_glob():
    assert match_value("/var/log/syslog", "not:glob:/etc/*")
    assert not match_value("/etc/passwd", "not:glob:/etc/*")


# ── match_value: list spec (any-of) ────────────────────────────────


def test_match_value_list_any_of():
    spec = ["glob:/etc/*", "glob:*/.ssh/*"]
    assert match_value("/etc/passwd", spec)
    assert match_value("/home/alice/.ssh/id_rsa", spec)
    assert not match_value("/var/log/syslog", spec)


# ── validate_matcher_spec ──────────────────────────────────────────


def test_validate_accepts_well_formed_specs():
    validate_matcher_spec("hello")
    validate_matcher_spec("literal:hello")
    validate_matcher_spec("glob:/etc/*")
    validate_matcher_spec("regex:.+")
    validate_matcher_spec("in:[a,b]")
    validate_matcher_spec("not:hello")
    validate_matcher_spec(["a", "b"])
    validate_matcher_spec(42)
    validate_matcher_spec(True)


def test_validate_rejects_malformed_regex():
    with pytest.raises(MatcherError, match="invalid regex"):
        validate_matcher_spec("regex:[unclosed")


def test_validate_rejects_malformed_in():
    with pytest.raises(MatcherError, match="'in:'"):
        validate_matcher_spec("in:no-brackets")


def test_validate_rejects_empty_any_of_list():
    with pytest.raises(MatcherError, match="empty"):
        validate_matcher_spec([])


def test_validate_recurses_into_not_and_list():
    with pytest.raises(MatcherError, match="invalid regex"):
        validate_matcher_spec("not:regex:[unclosed")
    with pytest.raises(MatcherError, match="invalid regex"):
        validate_matcher_spec(["ok", "regex:[unclosed"])


# ── all_match ──────────────────────────────────────────────────────


def test_all_match_empty_spec_matches_anything():
    assert all_match({}, {})
    assert all_match({"any": "value"}, {})


def test_all_match_all_fields_must_match():
    actual = {"payload": {"tool": "file_read", "path": "/etc/passwd"}}
    spec = {
        "payload.tool": "file_read",
        "payload.path": "glob:/etc/*",
    }
    assert all_match(actual, spec)


def test_all_match_fails_on_any_mismatch():
    actual = {"payload": {"tool": "http", "path": "/etc/passwd"}}
    spec = {
        "payload.tool": "file_read",  # mismatch
        "payload.path": "glob:/etc/*",  # matches
    }
    assert not all_match(actual, spec)


def test_all_match_missing_field_fails():
    actual = {"payload": {"tool": "file_read"}}
    spec = {"payload.path": "/etc/passwd"}  # field doesn't exist
    assert not all_match(actual, spec)
