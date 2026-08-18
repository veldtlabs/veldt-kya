"""CLI entrypoint for the reference MCP tools server.

Usage::

    kya-mcp-tools-ref --host 0.0.0.0 --port 18090

Env vars honored (all optional except where noted):

    KYA_MCP_ENABLE_BASH=1      Register the ``governed_bash`` tool. Refused
                               to register otherwise. No default.
    KYA_MCP_BASH_ALLOWLIST     Comma-separated allowlist of commands
                               permitted by ``governed_bash``. Applies only
                               when the tool is enabled. Default: safe list
                               shipped in ``kya_mcp_tools_ref.config``.
    KYA_MCP_TEST_MODE=1        Expose ``POST /_test/reset_counters``.
                               Production images MUST NOT set this.
"""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint. Returns process exit code."""
    parser = argparse.ArgumentParser(
        prog="kya-mcp-tools-ref",
        description=(
            "Reference MCP tools backend for the KYA gateway. Not a product; "
            "a template for exposing your own governed tools."
        ),
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=18090, help="Bind port (default: 18090)")
    args = parser.parse_args(argv)

    # NB: no gateway health probe on boot — the gateway is protected from
    # accidental direct exposure at the docker-compose network boundary
    # (no `ports:` mapping on this service). See package docstring.
    from kya_mcp_tools_ref.server import run
    run(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
