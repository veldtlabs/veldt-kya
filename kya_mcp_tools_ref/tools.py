"""Reference tool implementations.

Safety invariant
----------------
The reference backend is intentionally **dumb with respect to governance**,
but **not unsafe with respect to execution**. The gateway decides whether
an action may occur; the backend still prevents obvious executor-level
escapes:

* filesystem traversal (path containment, symlink escape, encoded traversal)
* shell injection (argv-only exec, never ``shell=True``)
* SSRF (hostname allowlist + block loopback / link-local / RFC1918 /
  cloud-metadata endpoints)

That is executor hardening, not a new KYA governance primitive.

Contract every tool honors
--------------------------
1. Signature: ``def <tool>(arguments: dict[str, Any]) -> ToolResult``.
2. Increments its module-level ``_invocation_counter`` on every call
   (BEFORE any early return). The counter measures **backend calls**,
   not executions — a call that hits the tool body but exits early on
   bad input still counts as an invocation, because the request DID
   reach the backend. That is exactly the invariant the gateway
   enforcement sabotage test relies on::

       DENY / FLAG_FOR_REVIEW at gateway → invocation counter = 0
       ALLOW                              → invocation counter = 1

   If a test needs to prove a real side effect occurred, assert on a
   separate result signal (file exists, subprocess exit code, HTTP body).
3. Returns a :class:`ToolResult` with ``content`` (list of MCP content
   parts) and ``is_error`` (bool). Never raises for expected failure
   paths (bad args, exec failure); raises only for programming bugs.
4. Emits NO evidence, calls NO ``kya.record_*`` primitives. The gateway
   is the sole evidence authority.

Tool registry
-------------
:data:`TOOLS` is a mapping ``name -> ToolSpec``. Each spec advertises a
``regimes`` field naming which compliance regimes the tool is relevant to.
Regimes are advertised in ``tools/list`` metadata only — evidence storage
does not currently persist them, so compliance-by-regime queries must
join on ``tool_name`` at query time. See package docstring.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from kya_mcp_tools_ref.config import RefConfig


# ─── Data types ─────────────────────────────────────────────────────


@dataclass
class ToolResult:
    """The shape a tool returns. Mirrors MCP tools/call result semantics."""

    content: list[dict[str, Any]]
    is_error: bool = False


def _text(msg: str) -> list[dict[str, Any]]:
    """Wrap a string as a single MCP text-content part."""
    return [{"type": "text", "text": msg}]


def _err(msg: str) -> ToolResult:
    """Uniform error-result shape."""
    return ToolResult(content=_text(msg), is_error=True)


# ─── Execution limits (constants — not env-configurable) ────────────
#
# Kept tight for reference-safety. Customer forks can raise these but
# should honor the gateway's HITL body cap (1MB) to avoid the silent-
# 428-no-pending-id degradation.

_MAX_FILE_READ_BYTES = 1_000_000        # 1MB — mirrors gateway HITL cap
_MAX_FILE_WRITE_BYTES = 1_000_000       # 1MB
_MAX_HTTP_RESPONSE_BYTES = 1_000_000    # 1MB
_MAX_BASH_OUTPUT_BYTES = 65_536         # 64KB
_BASH_TIMEOUT_SECONDS = 5.0
_HTTP_TIMEOUT_SECONDS = 10.0

# Chars that would give the shell semantic meaning if it ever saw the
# input. governed_bash uses shell=False (argv-only), but rejecting these
# in args is defence-in-depth against a future maintainer flipping the
# switch. Also rejected in the command name itself.
_SHELL_METACHARS = frozenset(";&|`$()<>\n\r\t\"'\\ ")

# Cloud metadata endpoints. is_link_local already covers these, but
# named explicitly to make the intent obvious in reviews and to catch
# future non-169.254 metadata endpoints (e.g., GCP fd00:ec2::254 IPv6).
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})


# ─── Per-tool invocation counters ───────────────────────────────────
#
# These are module-level ints. The server pins single-worker
# (aiohttp default) so counters are process-global and stable
# for observability and integration testing.
#
# CRITICAL: increment MUST be the first line of every tool body.
# The counter measures BACKEND CALLS, not executions. If a request
# reached the backend at all — even for a bad-arg early return — it
# counts. That's what the enforcement sabotage-verify asserts on:
#
#   DENY / FLAG_FOR_REVIEW at gateway → counter must stay 0
#   ALLOW                              → counter increments to 1

_invocation_counter_bash: int = 0
_invocation_counter_file_read: int = 0
_invocation_counter_file_write: int = 0
_invocation_counter_http_fetch: int = 0


def get_invocation_counters() -> dict[str, int]:
    """Snapshot all invocation counters. Used by the test-only reset endpoint."""
    return {
        "governed_bash": _invocation_counter_bash,
        "governed_file_read": _invocation_counter_file_read,
        "governed_file_write": _invocation_counter_file_write,
        "governed_http_fetch": _invocation_counter_http_fetch,
    }


def reset_invocation_counters() -> None:
    """Test-only. Called by ``POST /_test/reset_counters`` (env-guarded)."""
    global _invocation_counter_bash
    global _invocation_counter_file_read
    global _invocation_counter_file_write
    global _invocation_counter_http_fetch
    _invocation_counter_bash = 0
    _invocation_counter_file_read = 0
    _invocation_counter_file_write = 0
    _invocation_counter_http_fetch = 0


# ─── Config-holder module global (populated by server.run) ──────────
#
# Tools read from this rather than accepting config as a parameter so
# the MCP dispatcher can call handlers uniformly. Set once at boot.

_CFG: RefConfig | None = None


def bind_config(cfg: RefConfig) -> None:
    """Called once at server startup. Must precede first tool invocation."""
    global _CFG
    _CFG = cfg


def _get_cfg() -> RefConfig:
    if _CFG is None:
        raise RuntimeError("kya_mcp_tools_ref.tools.bind_config() must be called before invoking tools")
    return _CFG


# ─── Path containment helper ────────────────────────────────────────


def _contain_path(user_path: str, scratch_root: str) -> str:
    """Resolve ``user_path`` and verify it stays under ``scratch_root``.

    Returns the canonical absolute path. Raises ValueError on any escape
    attempt. Rejects:

    * Empty / non-string input.
    * Any ``..`` segment (even after normalization — defence in depth).
    * Absolute paths that do not resolve under scratch_root.
    * Relative paths whose realpath escapes scratch_root (symlink escape).

    Note on realpath: this reads the filesystem to resolve symlinks, so
    an attacker who plants a symlink pointing outside scratch AFTER this
    call still cannot escape — we open by the realpath returned here,
    not by the original user_path.
    """
    if not isinstance(user_path, str) or not user_path:
        raise ValueError("path must be a non-empty string")

    # Reject explicit .. segments before any resolution. realpath would
    # normalize them, but that means "foo/../bar" resolves to "bar" —
    # which could accidentally succeed if bar exists. Explicit rejection
    # keeps the intent visible.
    parts = user_path.replace("\\", "/").split("/")
    if ".." in parts:
        raise ValueError("path must not contain '..' segments")

    # Join under scratch_root (join is a no-op if user_path is absolute
    # AND that abs path is under scratch_root — we still verify below).
    if os.path.isabs(user_path):
        candidate = user_path
    else:
        candidate = os.path.join(scratch_root, user_path)

    canonical = os.path.realpath(candidate)
    # Trailing sep on scratch_root so /scratch does not accept /scratchpad.
    root_with_sep = scratch_root.rstrip(os.sep) + os.sep
    if not (canonical == scratch_root.rstrip(os.sep) or canonical.startswith(root_with_sep)):
        raise ValueError("path escapes scratch root")

    return canonical


# ─── Tool implementations ───────────────────────────────────────────


def governed_bash(arguments: dict[str, Any]) -> ToolResult:
    """Execute an allowlisted shell command via argv (never ``shell=True``).

    Only registered when ``KYA_MCP_ENABLE_BASH=1``. Only commands in the
    configured allowlist run. No pipes, no redirects, no command
    substitution, no shell metachars in command or args.
    """
    global _invocation_counter_bash
    _invocation_counter_bash += 1

    cfg = _get_cfg()

    command = arguments.get("command")
    args = arguments.get("args", [])
    if not isinstance(command, str) or not command:
        return _err("command must be a non-empty string")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return _err("args must be a list of strings")

    # Metachar check on command name and every arg. Defence-in-depth
    # against shell=True regressions AND against tricks like passing
    # `;evil` as an argument that some future customer's tool body
    # might concatenate into a shell string.
    if any(ch in _SHELL_METACHARS for ch in command):
        return _err("command name contains disallowed characters")
    for arg in args:
        if any(ch in _SHELL_METACHARS for ch in arg):
            return _err("arg contains disallowed characters")

    if command not in cfg.bash_allowlist:
        return _err(f"command '{command}' not in allowlist")

    try:
        # shell=False is the whole point; argv exec, no shell interpretation.
        # env={} strips inherited env to prevent LD_PRELOAD / PATH tricks.
        completed = subprocess.run(  # noqa: S603 (allowlist enforced above)
            [command, *args],
            capture_output=True,
            timeout=_BASH_TIMEOUT_SECONDS,
            shell=False,
            env={"PATH": "/usr/bin:/bin"},
        )
    except subprocess.TimeoutExpired:
        return _err(f"command timed out after {_BASH_TIMEOUT_SECONDS}s")
    except FileNotFoundError:
        return _err(f"command '{command}' not found on PATH")

    stdout = completed.stdout[:_MAX_BASH_OUTPUT_BYTES].decode("utf-8", errors="replace")
    stderr = completed.stderr[:_MAX_BASH_OUTPUT_BYTES].decode("utf-8", errors="replace")
    body = f"exit={completed.returncode}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    return ToolResult(content=_text(body), is_error=completed.returncode != 0)


def governed_file_read(arguments: dict[str, Any]) -> ToolResult:
    """Read a file from the container's scratch filesystem.

    Enforces path containment + size cap. Rejects symlinks/traversal.
    """
    global _invocation_counter_file_read
    _invocation_counter_file_read += 1

    cfg = _get_cfg()
    try:
        canonical = _contain_path(arguments.get("path", ""), cfg.scratch_root)
    except ValueError as exc:
        return _err(str(exc))

    if not os.path.exists(canonical):
        return _err("file not found under scratch root")
    if not os.path.isfile(canonical):
        return _err("not a regular file")

    size = os.path.getsize(canonical)
    if size > _MAX_FILE_READ_BYTES:
        return _err(f"file too large ({size} > {_MAX_FILE_READ_BYTES} bytes)")

    with open(canonical, "rb") as fh:
        data = fh.read(_MAX_FILE_READ_BYTES + 1)
    if len(data) > _MAX_FILE_READ_BYTES:
        return _err("file exceeded size cap during read (raced with grow?)")

    return ToolResult(content=_text(data.decode("utf-8", errors="replace")))


def governed_file_write(arguments: dict[str, Any]) -> ToolResult:
    """Write a file to the container's scratch filesystem.

    Enforces path containment + size cap. Rejects overwriting a symlink
    that resolves outside the scratch root.
    """
    global _invocation_counter_file_write
    _invocation_counter_file_write += 1

    cfg = _get_cfg()
    content = arguments.get("content")
    if not isinstance(content, str):
        return _err("content must be a string")

    # Fast fail on oversize BEFORE touching the filesystem.
    content_bytes = content.encode("utf-8")
    if len(content_bytes) > _MAX_FILE_WRITE_BYTES:
        return _err(
            f"content too large ({len(content_bytes)} > {_MAX_FILE_WRITE_BYTES} bytes); "
            f"also above gateway HITL cap — see README"
        )

    try:
        canonical = _contain_path(arguments.get("path", ""), cfg.scratch_root)
    except ValueError as exc:
        return _err(str(exc))

    # If target already exists AS a symlink, opening it for write would
    # follow the link and modify the target. Reject that outright.
    if os.path.islink(canonical):
        return _err("refusing to write through existing symlink")

    parent = os.path.dirname(canonical)
    if not os.path.isdir(parent):
        # Create intermediate dirs under scratch root. _contain_path
        # already verified the parent is under scratch, so os.makedirs
        # cannot escape.
        os.makedirs(parent, exist_ok=True)

    with open(canonical, "wb") as fh:
        fh.write(content_bytes)

    return ToolResult(content=_text(f"wrote {len(content_bytes)} bytes"))


def _resolve_and_verify_host(hostname: str) -> None:
    """Resolve ``hostname`` to IPs and verify none are loopback / link-local /
    RFC1918 / cloud-metadata. Raises ValueError on any policy violation.

    Called AFTER hostname allowlist check. TOCTOU note: DNS could change
    between this check and the actual HTTP request. For a reference
    implementation, resolving once is acceptable — a determined attacker
    with control of DNS is a broader problem than SSRF hardening solves.
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"hostname resolution failed: {exc}") from exc

    for family, _type, _proto, _canon, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        if ip_str in _METADATA_IPS:
            raise ValueError(f"hostname resolves to cloud metadata endpoint: {ip_str}")
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"unparseable resolved address: {ip_str}") from None
        if ip.is_loopback:
            raise ValueError(f"hostname resolves to loopback: {ip_str}")
        if ip.is_link_local:
            raise ValueError(f"hostname resolves to link-local: {ip_str}")
        if ip.is_private:
            raise ValueError(f"hostname resolves to RFC1918 private: {ip_str}")
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ValueError(f"hostname resolves to disallowed range: {ip_str}")


def governed_http_fetch(arguments: dict[str, Any]) -> ToolResult:
    """Fetch an HTTP(S) URL. GET only. SSRF-hardened."""
    global _invocation_counter_http_fetch
    _invocation_counter_http_fetch += 1

    cfg = _get_cfg()
    url = arguments.get("url")
    method = arguments.get("method", "GET")
    if not isinstance(url, str) or not url:
        return _err("url must be a non-empty string")
    if method != "GET":
        return _err("only GET is supported in this reference")

    try:
        parsed = urlparse(url)
    except ValueError:
        return _err("malformed URL")
    if parsed.scheme not in ("http", "https"):
        return _err(f"scheme '{parsed.scheme}' not allowed (only http/https)")
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return _err("URL is missing hostname")

    if not cfg.http_allowlist:
        return _err(
            "no HTTP hosts allowed — set KYA_MCP_HTTP_ALLOWLIST to enable governed_http_fetch"
        )
    if hostname not in cfg.http_allowlist:
        return _err(f"hostname '{hostname}' not in KYA_MCP_HTTP_ALLOWLIST")

    try:
        _resolve_and_verify_host(hostname)
    except ValueError as exc:
        return _err(str(exc))

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            resp = client.get(url)
    except httpx.HTTPError as exc:
        return _err(f"HTTP error: {exc}")

    body = resp.content[:_MAX_HTTP_RESPONSE_BYTES].decode("utf-8", errors="replace")
    header_summary = f"HTTP/{resp.http_version} {resp.status_code}\n"
    return ToolResult(
        content=_text(header_summary + body),
        is_error=resp.status_code >= 400,
    )


# ─── Registry (built at import time; respects RefConfig.enable_bash) ─


@dataclass(frozen=True)
class ToolSpec:
    """MCP tools/list metadata + the callable that implements it."""

    name: str
    description: str
    input_schema: dict[str, Any]
    regimes: tuple[str, ...]  # advertised only; not persisted (see docstring)
    handler: Callable[[dict[str, Any]], ToolResult] = field(hash=False)


def build_registry(cfg: RefConfig) -> dict[str, ToolSpec]:
    """Build the tool registry, honoring cfg.enable_bash.

    ``governed_bash`` is registered ONLY when ``cfg.enable_bash`` is True.
    Absence from the registry means it also disappears from ``tools/list``
    — clients cannot discover it, and the gateway cannot forward calls
    the backend won't recognize.
    """
    registry: dict[str, ToolSpec] = {}

    registry["governed_file_read"] = ToolSpec(
        name="governed_file_read",
        description="Read a file from the reference server's scratch filesystem.",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        regimes=("hipaa", "sox", "gdpr", "iso_27001", "soc2"),
        handler=governed_file_read,
    )
    registry["governed_file_write"] = ToolSpec(
        name="governed_file_write",
        description="Write a file to the reference server's scratch filesystem.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
        regimes=("hipaa", "sox", "gdpr", "iso_27001", "soc2"),
        handler=governed_file_write,
    )
    registry["governed_http_fetch"] = ToolSpec(
        name="governed_http_fetch",
        description=(
            "Fetch an HTTP(S) URL. GET only. Hostname must be in "
            "KYA_MCP_HTTP_ALLOWLIST; loopback / link-local / RFC1918 / "
            "cloud-metadata rejected regardless of allowlist."
        ),
        input_schema={
            "type": "object",
            "properties": {"url": {"type": "string"}, "method": {"type": "string", "enum": ["GET"]}},
            "required": ["url"],
        },
        regimes=("gdpr", "iso_27001", "soc2"),
        handler=governed_http_fetch,
    )

    if cfg.enable_bash:
        registry["governed_bash"] = ToolSpec(
            name="governed_bash",
            description=(
                f"Execute an allowlisted shell command via argv (no shell). "
                f"Allowlist: {', '.join(cfg.bash_allowlist)}."
            ),
            input_schema={
                "type": "object",
                "properties": {"command": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}}},
                "required": ["command"],
            },
            regimes=("iso_27001", "cmmc"),
            handler=governed_bash,
        )

    return registry


# Populated lazily by server.run() so `RefConfig.from_env()` runs once
# at boot, not at import time (avoids test-suite pollution).
TOOLS: dict[str, ToolSpec] = {}
