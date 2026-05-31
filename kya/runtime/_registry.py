"""Parser registry for runtime-security sources.

Each parser registers itself at import time (in
``kya.runtime.parsers.__init__``); the bridge calls
:func:`get_parser` to dispatch. The registry is the only place that
knows which parsers exist, so adding a new tool means one import +
one ``register_parser`` call -- no edits to bridge or canonical types.
"""
from __future__ import annotations

import logging
from typing import Protocol

from ._canonical import RuntimeEvent, SourceTool

logger = logging.getLogger(__name__)


class RuntimeParserError(ValueError):
    """A parser was asked to handle a payload it cannot interpret.

    Raised by individual parsers when the caller forced a specific
    ``source_tool`` but the raw payload is unmistakably the wrong
    shape (so silently returning ``None`` would hide a misconfigured
    pipeline). The bridge logs and drops the event but never re-raises
    into the caller.
    """


class Parser(Protocol):
    """Contract every per-tool parser implements.

    The Protocol form means parsers can be plain modules, classes,
    or callables -- whatever fits the tool. KYA's shipped parsers are
    modules with module-level functions.
    """

    def can_parse(self, raw: dict) -> bool:
        """Cheap shape-check used by autodetect. Must NOT raise on
        any input; return False for anything not obviously yours."""
        ...

    def parse(self, raw: dict) -> RuntimeEvent | None:
        """Translate the raw payload into a canonical event, or
        return ``None`` if this parser cannot meaningfully handle it.
        Should raise :class:`RuntimeParserError` only when the caller
        explicitly forced this parser and the payload is wrong shape.
        """
        ...


_REGISTRY: dict[SourceTool, Parser] = {}


def register_parser(source_tool: SourceTool, parser: Parser) -> None:
    """Register a parser for one source tool.

    Idempotent: re-registering a parser for the same tool replaces the
    previous binding (useful for test isolation and downstream
    overrides). A debug log records the swap.
    """
    if source_tool in _REGISTRY:
        logger.debug(
            "[KYA-RUNTIME] re-registering parser for %s (replacing %r)",
            source_tool, type(_REGISTRY[source_tool]).__name__,
        )
    _REGISTRY[source_tool] = parser


def get_parser(source_tool: SourceTool) -> Parser | None:
    """Return the registered parser for ``source_tool`` or ``None``."""
    return _REGISTRY.get(source_tool)


def list_parsers() -> tuple[SourceTool, ...]:
    """Return the registered source tools in registration order.

    Useful for ``--help`` output and integration tests verifying that
    the bundle of expected parsers is in fact registered.
    """
    return tuple(_REGISTRY.keys())


def autodetect_parser(raw: dict) -> tuple[SourceTool, Parser] | None:
    """Find the first registered parser whose ``can_parse`` returns
    True for ``raw``. Used by :func:`kya.runtime.ingest` when the
    caller doesn't name a source tool. Returns ``None`` if no parser
    claims the payload.
    """
    for tool, parser in _REGISTRY.items():
        try:
            if parser.can_parse(raw):
                return tool, parser
        except Exception:  # noqa: BLE001
            # A buggy parser must NOT block autodetect on other tools.
            logger.exception(
                "[KYA-RUNTIME] parser %s.can_parse raised on autodetect",
                tool,
            )
    return None
