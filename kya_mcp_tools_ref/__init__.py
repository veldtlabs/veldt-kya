"""KYA Reference MCP Tools — an executor backend for the KYA MCP gateway.

Purpose
-------
This package is a **reference implementation**, not a product. It exists to
show how any MCP-capable tool can be exposed through the KYA gateway and
inherit the platform's identity, policy, and evidence guarantees with zero
governance code in the tool itself.

Architecture
------------
The gateway is the sole governance authority::

    MCP client (Claude Code, Cursor, ...)
        │
        ▼
    kya-gateway (identity → policy → verdict → evidence)
        │  forwards ONLY on verdict == "allow"
        ▼
    kya_mcp_tools_ref  ← this package (pure executor)

The reference tools never call ``record_invocation``, ``evaluate``, or
``record_evidence``. If the gateway did not forward, the tool never ran.
Denied requests are physically incapable of reaching the executor.

Fork this to expose your own tools
----------------------------------
1. Add a tool function to ``kya_mcp_tools_ref.tools``.
2. Register it in ``kya_mcp_tools_ref.tools.TOOLS``.
3. Point your ``kya-gateway`` backend config at this server.
4. Your existing enterprise ABAC/RBAC/regimes apply automatically.

Install profile
---------------
``pip install veldt-kya`` installs this package for import-only use
(``import kya_mcp_tools_ref`` works and exposes :data:`__version__`).
The runnable server has additional runtime deps (``aiohttp``, ``httpx``)
that live behind the ``mcp-tools-ref`` extra so bare installs stay small
and free of unused transitive dependencies. To run the server::

    pip install "veldt-kya[mcp-tools-ref]"
    python -m kya_mcp_tools_ref --port 18090

To access server / tool internals in code, import from the submodules
explicitly — they are NOT re-exported at package top level, precisely
so that ``import kya_mcp_tools_ref`` never triggers the heavy imports::

    from kya_mcp_tools_ref.server import run
    from kya_mcp_tools_ref.tools import (
        TOOLS, ToolResult, get_invocation_counters, reset_invocation_counters,
    )

Public API (bare install)
-------------------------
* :data:`__version__` — package version string.

Quickstart (with the extra)::

    python -m kya_mcp_tools_ref --port 18090

Or via Docker::

    docker run veldtlabs/mcp-tools-reference:0.1.0

Ships 3 governed tools by default (``governed_file_read``,
``governed_file_write``, ``governed_http_fetch``), plus an optional
``governed_bash`` when ``KYA_MCP_ENABLE_BASH=1`` at boot.

Security posture
----------------
* Binds to the internal container network only; the docker-compose entry
  publishes NO host port. Direct external access is not part of the
  supported deployment.
* ``governed_bash`` is disabled unless ``KYA_MCP_ENABLE_BASH=1`` at boot,
  and only commands in the configured allowlist run.
* Test-only endpoints (``/_test/reset_counters``) return 404 unless
  ``KYA_MCP_TEST_MODE=1``. Production images MUST NOT set this env.
"""
from __future__ import annotations

__version__ = "0.1.0"

__all__ = [
    "__version__",
]
