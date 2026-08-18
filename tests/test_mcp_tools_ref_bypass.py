"""End-to-end regression coverage for the reference MCP tools backend.

Requires a live docker stack:

    * ``kya-gateway`` reachable on ``localhost:18080``
    * ``kya-mcp-tools-ref`` reachable only inside the docker network,
      accessed via ``docker exec kya-mcp-tools-ref curl ...`` for
      test-only counter reads.

Both containers are stood up via the top-level docker-compose file. If
either is not healthy the whole module is skipped so unit-only runs do
not fail on unrelated infrastructure.

Covers:

    1. Prefix-repeat bypass ``reference.reference.governed_bash`` is
       rejected — this used to slip past the RBAC deny rule for
       ``mcp.reference.governed_bash`` because the backend stripped only
       the trailing dot segment while the gateway used first-dot
       semantics, producing a mismatched action string.
    2. Non-string ``params.name`` no longer crashes the gateway with a
       500 + leaked traceback.
    3. Legitimate bare tool names still reach the backend.
    4. Legitimate single-prefix tool names still reach the backend.
    5. The 403 deny response carries an ``X-KYA-Verdict`` header.
"""
from __future__ import annotations

import json
import subprocess

import pytest

pytest.importorskip("httpx")
import httpx  # noqa: E402

pytestmark = pytest.mark.integration


_GATEWAY_URL = "http://localhost:18080/mcp"
_REF_CONTAINER = "kya-mcp-tools-ref"
# Stable did:key used across the wave tests. Public key, not a secret.
_TEST_DID = "did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8"


def _docker_curl(path: str, *, method: str = "GET") -> dict:
    """Shell into the reference container and hit its test-only API.

    The container has no host-side port mapping (defence-in-depth so no
    external caller can ever reach the ungoverned backend); ``docker
    exec`` is the only route in from a host-side pytest run.
    """
    args = ["docker", "exec", _REF_CONTAINER, "curl", "-sS"]
    if method != "GET":
        args += ["-X", method]
    args += [f"http://localhost:18090{path}"]
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker exec curl {path} failed: rc={result.returncode} "
            f"stderr={result.stderr!r} stdout={result.stdout!r}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"non-JSON response from {path}: {result.stdout!r}"
        ) from exc


def _get_counters() -> dict[str, int]:
    payload = _docker_curl("/_test/counters", method="GET")
    return dict(payload.get("counters", {}))


def _reset_counters() -> dict[str, int]:
    """Zero the counters. Returns the pre-reset snapshot for observation."""
    payload = _docker_curl("/_test/reset_counters", method="POST")
    return dict(payload.get("pre_reset_counters", {}))


@pytest.fixture(scope="module")
def gateway_url() -> str:
    return _GATEWAY_URL


@pytest.fixture(scope="module")
def did_header() -> dict[str, str]:
    return {
        "content-type": "application/json",
        "X-KYA-DID": _TEST_DID,
    }


@pytest.fixture(scope="module", autouse=True)
def _require_live_stack() -> None:
    """Skip the whole module if the gateway or reference backend isn't up."""
    # Gateway health probe.
    try:
        resp = httpx.get("http://localhost:18080/healthz", timeout=2.0)
    except httpx.HTTPError as exc:
        pytest.skip(f"kya-gateway unreachable on localhost:18080: {exc}")
    if resp.status_code != 200:
        pytest.skip(f"kya-gateway healthz returned {resp.status_code}")
    # Reference backend probe via docker exec (no host port).
    try:
        _docker_curl("/healthz", method="GET")
    except RuntimeError as exc:
        pytest.skip(f"{_REF_CONTAINER} not reachable via docker exec: {exc}")
    # Ensure test-mode endpoints are actually mounted.
    try:
        _get_counters()
    except RuntimeError as exc:
        pytest.skip(
            f"{_REF_CONTAINER} /_test/counters unavailable "
            f"(KYA_MCP_TEST_MODE=1 not set?): {exc}"
        )


@pytest.fixture(autouse=True)
def _reset_between_tests() -> None:
    """Every test starts with counters at zero."""
    _reset_counters()
    yield


def _tools_call(name, arguments: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


# ─── 1. Prefix-repeat bypass ──────────────────────────────────────


def test_prefix_repeat_bypass_rejected(gateway_url, did_header):
    """``reference.reference.governed_bash`` MUST NOT execute.

    Before the fix this returned HTTP 200 with ``stdout=root`` because
    the gateway used first-dot semantics for the RBAC action string
    (``mcp.reference.reference.governed_bash`` — no matching deny rule)
    while the backend used last-dot semantics for tool lookup
    (resolving to bare ``governed_bash``). Now both layers reject the
    malformed name.
    """
    resp = httpx.post(
        gateway_url,
        headers=did_header,
        json=_tools_call(
            "reference.reference.governed_bash",
            {"command": "whoami"},
        ),
        timeout=5.0,
    )
    # Either 400 (gateway-side reject) or 404 (backend-side reject if a
    # future refactor moves the check). Both are fail-closed.
    assert resp.status_code in (400, 404), (
        f"unexpected status {resp.status_code}: {resp.text}"
    )
    # Body must NOT contain a successful tool result — no shell output.
    assert "root" not in resp.text, (
        "bypass appears to have executed the shell command"
    )
    # Belt + suspenders: the backend counter for governed_bash must
    # stay at zero. If it incremented, the request reached the backend
    # AND the backend executed the tool — either would be a bypass.
    counters = _get_counters()
    assert counters.get("governed_bash", 0) == 0, (
        f"governed_bash counter incremented to {counters.get('governed_bash')}"
    )


# ─── 2. Non-string params.name ────────────────────────────────────


def test_non_string_tool_name_rejected(gateway_url, did_header):
    """Integer ``params.name`` used to raise TypeError → 500 with a
    traceback in the gateway logs. Must now return a clean 400."""
    resp = httpx.post(
        gateway_url,
        headers=did_header,
        json=_tools_call(42, {}),  # type: ignore[arg-type]
        timeout=5.0,
    )
    assert resp.status_code == 400, (
        f"expected 400, got {resp.status_code}: {resp.text}"
    )
    body = resp.json()
    assert "error" in body, body
    # -32602 is the JSON-RPC "Invalid params" code.
    assert body["error"]["code"] == -32602, body


# ─── 3. Bare tool name (no backend prefix) ────────────────────────


def test_legitimate_bare_tool_name_still_works(gateway_url, did_header, tmp_path):
    """A bare tool name (no ``<backend>.`` prefix) must still route to
    the ``default`` backend if configured. In the demo stack ``default``
    points at the sample-agents container which does NOT run
    ``governed_file_read`` — so we assert the request is dispatched at
    the gateway (not rejected as malformed) without asserting a 200.

    The reference backend counter must NOT increment: bare names route
    to the ``default`` backend, not to ``reference``.
    """
    resp = httpx.post(
        gateway_url,
        headers=did_header,
        json=_tools_call("governed_file_read", {"path": "does-not-exist"}),
        timeout=5.0,
    )
    # Gateway accepted the shape (not 400 malformed). It may bubble a
    # 502 from the default backend or a JSON-RPC error — anything
    # except a 400-malformed proves the parser did not reject.
    assert resp.status_code != 400 or "MALFORMED_TOOL_NAME" not in resp.text, (
        f"gateway wrongly rejected bare tool name: {resp.text}"
    )
    counters = _get_counters()
    assert counters.get("governed_file_read", 0) == 0, (
        "bare name should route to 'default' backend, not 'reference'"
    )


# ─── 4. Single-prefix tool name ───────────────────────────────────


def test_legitimate_single_prefix_still_works(gateway_url, did_header):
    """``reference.governed_file_read`` MUST still route + execute."""
    resp = httpx.post(
        gateway_url,
        headers=did_header,
        json=_tools_call(
            "reference.governed_file_read",
            {"path": "sanity-check.txt"},
        ),
        timeout=10.0,
    )
    assert resp.status_code == 200, (
        f"expected 200 on legitimate call, got {resp.status_code}: {resp.text}"
    )
    counters = _get_counters()
    assert counters.get("governed_file_read", 0) == 1, (
        f"expected backend counter=1, got {counters}"
    )


# ─── 5. Deny 403 carries X-KYA-Verdict header ─────────────────────


def test_x_kya_verdict_header_present_on_deny(gateway_url, did_header):
    """The legit deny target ``reference.governed_bash`` returns 403.

    The 403 body already carries ``data.verdict=deny``; this test locks
    in the header parity so a consumer can branch on the header alone.
    """
    resp = httpx.post(
        gateway_url,
        headers=did_header,
        json=_tools_call(
            "reference.governed_bash",
            {"command": "whoami"},
        ),
        timeout=5.0,
    )
    assert resp.status_code == 403, (
        f"expected 403, got {resp.status_code}: {resp.text}"
    )
    assert resp.headers.get("X-KYA-Verdict") == "deny", (
        f"missing/unexpected X-KYA-Verdict header: {dict(resp.headers)}"
    )
    counters = _get_counters()
    assert counters.get("governed_bash", 0) == 0, (
        "deny should stop the request before it reaches the backend"
    )
