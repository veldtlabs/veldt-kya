"""Env-driven config for the reference MCP tools server.

Kept intentionally minimal — this is a reference implementation. Anything
that needs richer config (per-tenant allowlists, dynamic reloads) belongs
in a customer's own fork or in the KYA gateway.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


# Default bash allowlist: introspection-only, no arguments meaningful.
# Deliberately tight: commands whose arg parsing / output could become a
# broader surface (ls, cat, echo) are OUT of the default. Bash execution
# uses argv-only (no shell=True); no pipes, redirects, substitution.
# A customer who needs more adds it via KYA_MCP_BASH_ALLOWLIST.
_DEFAULT_BASH_ALLOWLIST = ("whoami", "pwd", "hostname", "date")


# Default HTTP fetch allowlist: EMPTY. Reference is opt-in per host.
# Without configuration, governed_http_fetch returns a "no allowed hosts"
# error rather than becoming an SSRF primitive out-of-the-box. Customers
# add trusted hosts via KYA_MCP_HTTP_ALLOWLIST (comma-separated FQDNs).
# In addition to allowlist checks, the tool rejects (regardless of
# allowlist) loopback, link-local (169.254.0.0/16), RFC1918 private
# ranges, and cloud metadata endpoints (169.254.169.254).
_DEFAULT_HTTP_ALLOWLIST: tuple[str, ...] = ()


# Default scratch root for file_read / file_write. Overridable via
# KYA_MCP_SCRATCH_ROOT env for test isolation. The Dockerfile mounts
# a volume at this path so container restarts do not wipe state.
_DEFAULT_SCRATCH_ROOT = "/var/lib/kya-mcp-tools-ref/scratch"


@dataclass(frozen=True)
class RefConfig:
    """Runtime config resolved from environment variables at startup."""

    enable_bash: bool
    bash_allowlist: tuple[str, ...]
    http_allowlist: tuple[str, ...]
    scratch_root: str
    test_mode: bool

    @classmethod
    def from_env(cls) -> "RefConfig":
        """Read env vars once at boot. Never re-read at request time."""
        enable_bash = os.environ.get("KYA_MCP_ENABLE_BASH") == "1"
        raw_bash_allow = os.environ.get("KYA_MCP_BASH_ALLOWLIST", "")
        bash_allowlist = (
            tuple(cmd.strip() for cmd in raw_bash_allow.split(",") if cmd.strip())
            if raw_bash_allow
            else _DEFAULT_BASH_ALLOWLIST
        )
        raw_http_allow = os.environ.get("KYA_MCP_HTTP_ALLOWLIST", "")
        http_allowlist = (
            tuple(host.strip().lower() for host in raw_http_allow.split(",") if host.strip())
            if raw_http_allow
            else _DEFAULT_HTTP_ALLOWLIST
        )
        scratch_root = os.path.realpath(
            os.environ.get("KYA_MCP_SCRATCH_ROOT", _DEFAULT_SCRATCH_ROOT)
        )
        test_mode = os.environ.get("KYA_MCP_TEST_MODE") == "1"
        return cls(
            enable_bash=enable_bash,
            bash_allowlist=bash_allowlist,
            http_allowlist=http_allowlist,
            scratch_root=scratch_root,
            test_mode=test_mode,
        )
