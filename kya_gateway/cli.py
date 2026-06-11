"""Command-line interface for KYA Gateway.

Entry point installed as ``kya-gateway`` via pyproject.toml:

    [project.scripts]
    kya-gateway = "kya_gateway.cli:main"

Usage::

    kya-gateway --config gateway.yaml --port 8080
    kya-gateway --validate-config gateway.yaml
    kya-gateway --version
"""
from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from kya_gateway import __version__
from kya_gateway.config import GatewayConfig
from kya_gateway.errors import GatewayConfigError
from kya_gateway.server import Gateway

logger = logging.getLogger(__name__)


def _make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kya-gateway",
        description="KYA Gateway — MCP-compatible reverse proxy.",
    )
    p.add_argument("--config", "-c", required=False,
                   help="Path to gateway.yaml")
    p.add_argument("--port", "-p", type=int, default=None,
                   help="Override port from config")
    p.add_argument("--host", "-H", default=None,
                   help="Override bind host from config")
    p.add_argument("--validate-config", metavar="PATH",
                   help="Validate the YAML config and exit (0 if ok, 1 if not).")
    p.add_argument("--version", action="version",
                   version=f"kya-gateway {__version__}")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = _make_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    # ─── --validate-config ────────────────────────────────────────
    if args.validate_config:
        try:
            cfg = GatewayConfig.from_yaml(args.validate_config)
        except GatewayConfigError as exc:
            print(f"INVALID: {exc}", file=sys.stderr)
            return 1
        print(f"OK: parsed {len(cfg.backends)} backend(s), "
              f"identity methods={cfg.identity.methods}")
        return 0

    # ─── run server ────────────────────────────────────────────────
    if not args.config:
        parser.error("--config is required unless --validate-config is given")
    try:
        cfg = GatewayConfig.from_yaml(args.config)
    except GatewayConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1

    gw = Gateway(cfg)
    gw.run(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":   # pragma: no cover
    sys.exit(main())
