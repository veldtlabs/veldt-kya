"""KYA Gateway — MCP-compatible reverse proxy that wraps the KYA policy stack.

Public API:
    Gateway          — instantiate, configure, run.
    GatewayConfig    — typed config loaded from YAML.
    run()            — convenience for "load config + serve".

Quickstart::

    from kya_gateway import Gateway, GatewayConfig

    cfg = GatewayConfig.from_yaml("gateway.yaml")
    gw = Gateway(cfg)
    gw.run(host="0.0.0.0", port=8080)

Or from the CLI::

    kya-gateway --config gateway.yaml --port 8080

See ``docs/requirements/kya_gateway.md`` for the full design.
"""
from __future__ import annotations

__version__ = "0.1.0"

from kya_gateway.config import GatewayConfig
from kya_gateway.errors import (
    BackendUnreachable,
    GatewayConfigError,
    GatewayError,
    IdentityBindingFailed,
    PolicyDenied,
)
from kya_gateway.server import Gateway, build_app

__all__ = [
    "__version__",
    "Gateway",
    "GatewayConfig",
    "build_app",
    "GatewayError",
    "GatewayConfigError",
    "PolicyDenied",
    "BackendUnreachable",
    "IdentityBindingFailed",
    "run",
]


def run(config_path: str, host: str = "0.0.0.0", port: int = 8080) -> None:
    """Convenience entry point: load config from path and serve."""
    cfg = GatewayConfig.from_yaml(config_path)
    Gateway(cfg).run(host=host, port=port)
