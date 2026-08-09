"""Tests for kya.optional_hooks."""
from __future__ import annotations

import pytest

from kya.optional_hooks import (
    HOOK_HITL_ENCRYPT,
    HOOK_REVOCATION_CHECKER,
    HOOK_REVOCATION_CHECKER_FACTORY,
    HOOK_REVOCATION_ERROR,
    _clear_hooks_for_tests,
    get_hook,
    list_hooks,
    register_hook,
)


@pytest.fixture(autouse=True)
def _isolated_registry():
    _clear_hooks_for_tests()
    yield
    _clear_hooks_for_tests()


def test_get_hook_returns_none_for_unregistered_name():
    assert get_hook("nothing_here") is None
    assert get_hook(HOOK_REVOCATION_CHECKER) is None
    assert get_hook("") is None


def test_register_get_roundtrip_preserves_object_identity():
    sentinel = object()
    register_hook("test_hook", sentinel)
    assert get_hook("test_hook") is sentinel


def test_register_accepts_callables_classes_and_instances():
    def fn(x): return x + 1
    class SomeClass: pass
    instance = SomeClass()

    register_hook("callable", fn)
    register_hook("class", SomeClass)
    register_hook("instance", instance)

    assert get_hook("callable")(41) == 42
    assert get_hook("class") is SomeClass
    assert get_hook("instance") is instance


def test_reregistration_replaces_prior_entry():
    register_hook("k", "first")
    register_hook("k", "second")
    assert get_hook("k") == "second"


def test_list_hooks_returns_sorted_names():
    register_hook("z_last", 1)
    register_hook("a_first", 1)
    register_hook("m_middle", 1)
    assert list_hooks() == ["a_first", "m_middle", "z_last"]


def test_list_hooks_returns_all_registered_names():
    for name in ["a", "b", "c", "d", "e"]:
        register_hook(name, name)
    assert set(list_hooks()) == {"a", "b", "c", "d", "e"}


def test_clear_hooks_for_tests_wipes_registry():
    register_hook("survives?", 1)
    _clear_hooks_for_tests()
    assert get_hook("survives?") is None
    assert list_hooks() == []


def test_well_known_hook_name_constants_are_stable_strings():
    # Constant values are wire format; freeze here so a rename fails a test.
    assert HOOK_HITL_ENCRYPT == "hitl_encrypt"
    assert HOOK_REVOCATION_CHECKER == "revocation_checker"
    assert HOOK_REVOCATION_CHECKER_FACTORY == "revocation_checker_factory"
    assert HOOK_REVOCATION_ERROR == "revocation_error"


def test_registry_survives_reimport():
    register_hook("persist_check", "value_1")
    import importlib
    import kya.optional_hooks as m
    importlib.reload(m)
    assert m.get_hook("persist_check") == "value_1"
