"""Bundled runtime-security parsers.

Importing this package registers every shipped parser with
``kya.runtime._registry``. Adding a new parser is two lines:
import the module, then call ``register_parser`` at the bottom.
"""
from __future__ import annotations

from .._registry import register_parser
from . import falco as _falco_module

register_parser("falco", _falco_module)

__all__: list[str] = []
