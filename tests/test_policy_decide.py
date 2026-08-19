"""Integration tests for ``POST /v1/policy/decide``.

The decide endpoint runs the SAME policy pipeline as ``POST /mcp`` but
returns the verdict WITHOUT forwarding to a backend. Its purpose is to
let hook-based clients (e.g., PreToolUse hooks) obtain a policy decision
before invoking a tool.

Contract (see gateway server for canonical shape):

    {
      "verdict": "allow" | "deny" | "flag_for_review",
      "reason_codes": [...],
      "signal_kind": "<canonical KYA signal>",
      "pending_id": "<uuid>" | null,
      "evidence_id": "<uuid>" | null,
      "evaluator_name": "<name>" | null,
      "policy_hash": "<hex>" | null
    }

Invariants under test:
    * NO backend forward. Backend counters MUST stay at 0 for every
      decide call regardless of verdict.
    * Evidence row IS still written with ``kind=gateway_verdict``.
    * flag_for_review still creates a ``kya_pending_invocations`` row.
    * Malformed / non-string / nested-dot ``tool_name`` -> HTTP 400.
    * Missing DID -> HTTP 401.
    * Pipeline crash -> HTTP 500 with a fail-closed deny body.

Requires the same live docker stack as ``test_mcp_tools_ref_wave_e2e.py``.
"""
from __future__ import annotations

import json
import subprocess
import time
import uuid

import pytest

pytest.importorskip("httpx")
import httpx  # noqa: E402

pytestmark = pytest.mark.integration


# --- Constants ----------------------------------------------------------

_DECIDE_URL = "http://localhost:18080/v1/policy/decide"
_GATEWAY_HEALTHZ = "http://localhost:18080/healthz"
_REF_CONTAINER = "kya-mcp-tools-ref"
_TEST_DID = "did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8"
_PG_DSN = (
    "host=localhost port=18432 dbname=veldt_kya "
    "user=veldt password=veldt_kya_2026"
)
_REQUIRED_KEYS = frozenset({
    "verdict", "reason_codes", "signal_kind",
    "pending_id", "evidence_id", "evaluator_name", "policy_hash",
})


# --- docker/curl helpers (mirror gateway-integration conventions) ------


def _docker_curl(path: str, *, method: str = "GET") -> dict:
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
    payload = _docker_curl("/_test/reset_counters", method="POST")
    return dict(payload.get("pre_reset_counters", {}))


# --- Fixtures ----------------------------------------------------------


@pytest.fixture(scope="module")
def decide_url() -> str:
    return _DECIDE_URL


@pytest.fixture(scope="module")
def did_header() -> dict[str, str]:
    return {
        "content-type": "application/json",
        "X-KYA-DID": _TEST_DID,
    }


@pytest.fixture(scope="module", autouse=True)
def _require_live_stack() -> None:
    """Skip the whole module if the gateway or reference backend isn't up."""
    try:
        resp = httpx.get(_GATEWAY_HEALTHZ, timeout=2.0)
    except httpx.HTTPError as exc:
        pytest.skip(f"kya-gateway unreachable on localhost:18080: {exc}")
    if resp.status_code != 200:
        pytest.skip(f"kya-gateway healthz returned {resp.status_code}")
    try:
        _docker_curl("/healthz", method="GET")
    except RuntimeError as exc:
        pytest.skip(f"{_REF_CONTAINER} not reachable via docker exec: {exc}")
    try:
        _get_counters()
    except RuntimeError as exc:
        pytest.skip(
            f"{_REF_CONTAINER} /_test/counters unavailable "
            f"(KYA_MCP_TEST_MODE=1 not set?): {exc}"
        )


@pytest.fixture(autouse=True)
def _reset_between_tests() -> None:
    _reset_counters()
    yield


def _connect_pg():
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        return psycopg2.connect(_PG_DSN, connect_timeout=3)
    except psycopg2.OperationalError as exc:  # pragma: no cover
        pytest.skip(f"kya-postgres unreachable on localhost:18432: {exc}")


def _decide(tool_name, tool_input=None, *, headers=None, extra=None):
    """Wire helper — always uses the module DID header unless overridden."""
    hdr = {"content-type": "application/json", "X-KYA-DID": _TEST_DID}
    if headers is not None:
        hdr = headers
    payload = {"tool_name": tool_name}
    if tool_input is not None:
        payload["tool_input"] = tool_input
    if extra is not None:
        payload.update(extra)
    return httpx.post(_DECIDE_URL, headers=hdr, json=payload, timeout=10.0)


def _assert_full_envelope(body: dict) -> None:
    """Every non-error decide response MUST carry all 7 canonical keys."""
    missing = _REQUIRED_KEYS - set(body.keys())
    assert not missing, f"missing required keys: {missing} (body={body})"


# --- Tests --------------------------------------------------------------


def test_decide_allow_returns_full_envelope(decide_url, did_header):
    """governed_file_read -> allow, full envelope, no backend hit."""
    resp = _decide("reference.governed_file_read", {"path": "/etc/passwd"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    _assert_full_envelope(body)
    assert body["verdict"] == "allow", body
    assert body["signal_kind"], f"signal_kind must be populated: {body}"
    assert body["evaluator_name"], (
        f"evaluator_name must be populated (#340 attribution): {body}"
    )
    # evidence_id is a UUID-string OR None (best-effort). When present
    # it MUST parse as a well-formed identifier — for the current
    # integer-id evidence chain we accept a stringified int.
    if body["evidence_id"] is not None:
        assert str(body["evidence_id"]).strip(), body
    counters = _get_counters()
    # No backend was called — every counter MUST stay at 0.
    assert all(v == 0 for v in counters.values()), counters


def test_decide_deny_returns_rbac_signal(decide_url, did_header):
    """governed_bash -> deny, RBAC_DENY reason, rbac_refusal signal."""
    resp = _decide("reference.governed_bash", {"command": "whoami"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    _assert_full_envelope(body)
    assert body["verdict"] == "deny", body
    assert "RBAC_DENY" in body["reason_codes"], body
    assert body["signal_kind"] == "rbac_refusal", body
    counters = _get_counters()
    assert all(v == 0 for v in counters.values()), counters


def test_decide_flag_returns_pending_id(decide_url, did_header):
    """governed_http_fetch -> flag_for_review with pending_id UUID."""
    resp = _decide(
        "reference.governed_http_fetch", {"url": "https://example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    _assert_full_envelope(body)
    assert body["verdict"] == "flag_for_review", body
    assert body["pending_id"], f"pending_id must be populated: {body}"
    # Validate UUID shape.
    uuid.UUID(body["pending_id"])
    assert "REQUIRES_HUMAN" in body["reason_codes"], body
    assert body["signal_kind"], f"signal_kind must be populated: {body}"

    # A pending row MUST exist in Postgres for this pending_id.
    conn = _connect_pg()
    try:
        deadline = time.time() + 5.0
        row = None
        while time.time() < deadline:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, action, principal_id, status "
                    "FROM kya_pending_invocations WHERE id = %s",
                    (body["pending_id"],),
                )
                row = cur.fetchone()
            if row is not None:
                break
            conn.rollback()
            time.sleep(0.1)
        assert row is not None, (
            f"pending row missing for id={body['pending_id']}"
        )
        assert row[1] == "mcp.reference.governed_http_fetch", row
        assert row[2] == _TEST_DID, row
        assert row[3] == "pending", row
    finally:
        conn.close()

    counters = _get_counters()
    assert all(v == 0 for v in counters.values()), counters


def test_decide_writes_evidence_row_matching_evidence_id(
    decide_url, did_header,
):
    """The returned evidence_id MUST correspond to a real
    kya_evidence row with kind=gateway_verdict."""
    resp = _decide("reference.governed_file_read", {"path": "/etc/passwd"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    _assert_full_envelope(body)
    evid = body["evidence_id"]
    if evid is None:
        pytest.skip(
            "evidence_id absent — evidence write is best-effort per /mcp; "
            "cannot verify row when write did not surface an id"
        )
    conn = _connect_pg()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, evidence_kind, payload ->> 'external_subject' "
                "FROM kya_evidence WHERE id = %s",
                (int(evid),),
            )
            row = cur.fetchone()
        assert row is not None, f"no kya_evidence row for id={evid}"
        assert row[1] == "gateway_verdict", row
        assert row[2] == _TEST_DID, row
    finally:
        conn.close()


def test_decide_arbitrary_tool_name_works(decide_url, did_header):
    """Primary hook use case — an unregistered tool name (e.g., 'Bash'
    from a Claude Code hook) MUST return a verdict envelope, and the
    backend counters MUST stay at 0."""
    resp = _decide("Bash", {"command": "npm test"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    _assert_full_envelope(body)
    assert body["verdict"] in {"allow", "deny", "flag_for_review"}, body
    counters = _get_counters()
    assert all(v == 0 for v in counters.values()), counters


def test_decide_nested_tool_name_rejected(decide_url, did_header):
    """Nested-dot tool_name -> HTTP 400 with MALFORMED_TOOL_NAME."""
    resp = _decide("reference.reference.governed_bash", {"command": "ls"})
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert "MALFORMED_TOOL_NAME" in (body.get("reason_codes") or []), body
    counters = _get_counters()
    assert all(v == 0 for v in counters.values()), counters


def test_decide_missing_did_returns_401(decide_url):
    """No X-KYA-DID header -> HTTP 401."""
    resp = httpx.post(
        _DECIDE_URL,
        headers={"content-type": "application/json"},
        json={"tool_name": "reference.governed_file_read"},
        timeout=10.0,
    )
    assert resp.status_code == 401, resp.text
    body = resp.json()
    assert "error" in body, body


def test_decide_non_string_tool_name_rejected(decide_url, did_header):
    """tool_name=42 -> HTTP 400, not 500."""
    resp = httpx.post(
        _DECIDE_URL,
        headers={"content-type": "application/json", "X-KYA-DID": _TEST_DID},
        json={"tool_name": 42},
        timeout=10.0,
    )
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert "MALFORMED_TOOL_NAME" in (body.get("reason_codes") or []), body


def test_decide_response_shape_forward_compat(decide_url, did_header):
    """Response is a FLAT dict, has all 7 required keys, and unknown
    keys are tolerated (forward-compat)."""
    resp = _decide("reference.governed_file_read", {"path": "/etc/passwd"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Flat dict — no metadata nesting.
    assert isinstance(body, dict), body
    for k, v in body.items():
        # Top-level values may be lists (reason_codes) or scalars, but
        # they MUST NOT be nested dicts (contract disallows the
        # "metadata" nesting per KYA convention).
        assert not isinstance(v, dict), (
            f"top-level key {k!r} is a dict — contract requires flat "
            f"shape: {body}"
        )
    # All 7 required keys present.
    for k in _REQUIRED_KEYS:
        assert k in body, f"missing required key {k!r} in {body}"
    # Unknown keys are permitted — we don't assert body.keys() ==
    # _REQUIRED_KEYS. New top-level keys may be added in future
    # versions and clients MUST tolerate them.


@pytest.mark.parametrize("tool_name,expected", [
    # Baseline — canonical form still denies.
    ("reference.governed_bash",        "deny"),
    # Case-flip on tool segment.
    ("reference.Governed_bash",        "deny"),
    # Case-flip on backend segment.
    ("REFERENCE.governed_bash",        "deny"),
    # Mixed case on the tool.
    ("reference.governed_bAsh",        "deny"),
    # Trailing ASCII space — stripped by canonicalizer.
    ("reference.governed_bash ",       "deny"),
    # Leading ASCII space on backend.
    (" reference.governed_bash",       "deny"),
    # Full-width Latin ｂ (U+FF42) folds to b via NFKC.
    ("reference.governed_ｂash",   "deny"),
])
def test_decide_canonicalization_prevents_bypass(
    decide_url, did_header, tool_name, expected,
):
    """Deep-sabotage regression — case flips and NFKC-foldable variants
    of a denied tool name MUST resolve to the canonical action string
    and hit the same deny rule. Previously all of these returned allow."""
    resp = _decide(tool_name, {"command": "whoami"})
    assert resp.status_code == 200, (tool_name, resp.text)
    body = resp.json()
    assert body["verdict"] == expected, (tool_name, body)
    if expected == "deny":
        assert "RBAC_DENY" in body["reason_codes"], (tool_name, body)


@pytest.mark.parametrize("tool_name", [
    # Zero-width space suffix (U+200B) — Cf category, rejected.
    "reference.governed_bash​",
    # Cyrillic о (U+043E) homoglyph for Latin o — NFKC does NOT fold
    # this; fix rejects all non-ASCII in tool identifiers.
    "reference.gоverned_bash",
    # Embedded ASCII whitespace (survives strip) — not a valid
    # tool identifier.
    "reference.governed bash",
])
def test_decide_invisible_smuggle_rejected(decide_url, did_header, tool_name):
    """Invisible-format / homoglyph / embedded-whitespace tool names MUST
    fail-closed as HTTP 400 MALFORMED_TOOL_NAME. A legitimate caller has
    no reason to send a ZWSP, Cyrillic look-alike, or embedded space in
    a tool identifier."""
    resp = _decide(tool_name, {"command": "whoami"})
    assert resp.status_code == 400, (tool_name, resp.text)
    body = resp.json()
    assert "MALFORMED_TOOL_NAME" in (body.get("reason_codes") or []), (
        tool_name, body,
    )



def test_decide_nbsp_suffix_still_denied(decide_url, did_header):
    """NBSP (U+00A0) is a Zs whitespace char — Python's ``str.strip()``
    treats it as whitespace and strips it during canonicalization. The
    resulting canonical form matches the RBAC deny rule → the attack
    is neutralized as a legitimate deny verdict (not an error). Both
    outcomes are safe; this test locks in the observed behavior so a
    future canonicalizer change doesn't accidentally open the bypass."""
    resp = _decide("reference.governed_bash ", {"command": "whoami"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "deny", body
    assert "RBAC_DENY" in body["reason_codes"], body

def test_decide_oversized_body_returns_413(decide_url, did_header):
    """A 10 MB body MUST be rejected at ingress with HTTP 413 and
    PAYLOAD_TOO_LARGE. Prior to this fix, /decide admitted 10 MB
    bodies; the evidence writer's 1 MB cap then silently dropped the
    audit row, leaving callers with allow + evidence_id=null."""
    huge_arg = "x" * (10 * 1024 * 1024)
    resp = httpx.post(
        _DECIDE_URL,
        headers={"content-type": "application/json", "X-KYA-DID": _TEST_DID},
        json={
            "tool_name": "reference.governed_file_read",
            "tool_input": {"path": huge_arg},
        },
        timeout=30.0,
    )
    assert resp.status_code == 413, resp.text
    body = resp.json()
    assert "PAYLOAD_TOO_LARGE" in (body.get("reason_codes") or []), body


def test_decide_oversized_tool_name_returns_400(decide_url, did_header):
    """A 100 kB tool_name MUST be rejected as MALFORMED_TOOL_NAME.
    The canonicalizer's per-segment 256-byte cap fires before the
    RBAC scan can be poisoned by an enormous input."""
    huge_name = "reference." + ("a" * 100_000)
    resp = _decide(huge_name, {"command": "x"})
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert "MALFORMED_TOOL_NAME" in (body.get("reason_codes") or []), body


def test_decide_duplicate_tool_name_key_rejected(decide_url, did_header):
    """Duplicate top-level ``tool_name`` keys MUST be rejected with
    HTTP 400 MALFORMED_BODY. json.loads is last-wins — otherwise an
    attacker could shadow an allowed name with a denied one."""
    raw = (
        b'{"tool_name": "reference.governed_file_read",'
        b' "tool_name": "reference.governed_bash",'
        b' "tool_input": {"command": "whoami"}}'
    )
    resp = httpx.post(
        _DECIDE_URL,
        headers={"content-type": "application/json", "X-KYA-DID": _TEST_DID},
        content=raw,
        timeout=10.0,
    )
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert "MALFORMED_BODY" in (body.get("reason_codes") or []), body


@pytest.mark.parametrize("bad_input", ["string", 42, [1, 2, 3], True, 3.14])
def test_decide_non_dict_tool_input_rejected(decide_url, did_header, bad_input):
    """tool_input MUST be a JSON object (or absent). Any other type
    (string, list, number, bool) silently no-ops arguments-aware policy
    predicates and hides the real payload from the evidence writer, so
    ingress rejects with HTTP 400 + MALFORMED_BODY."""
    resp = httpx.post(
        _DECIDE_URL,
        headers={"content-type": "application/json", "X-KYA-DID": _TEST_DID},
        json={
            "tool_name": "reference.governed_file_read",
            "tool_input": bad_input,
        },
        timeout=10.0,
    )
    assert resp.status_code == 400, (bad_input, resp.text)
    body = resp.json()
    assert "MALFORMED_BODY" in (body.get("reason_codes") or []), (
        bad_input, body,
    )


def test_decide_no_backend_forward_ever(decide_url, did_header):
    """After 10 decide calls of various verdicts, ALL backend
    counters MUST remain at 0. Locks in invariant #1."""
    _reset_counters()
    calls = [
        ("reference.governed_file_read", {"path": "/etc/passwd"}),
        ("reference.governed_bash", {"command": "whoami"}),
        ("reference.governed_http_fetch", {"url": "https://example.com"}),
        ("reference.governed_file_read", {"path": "/tmp/x"}),
        ("reference.governed_bash", {"command": "id"}),
        ("Bash", {"command": "ls"}),
        ("reference.governed_file_read", {"path": "/etc/hostname"}),
        ("reference.governed_http_fetch", {"url": "https://example.org"}),
        ("Read", {"file_path": "/tmp/foo"}),
        ("reference.governed_bash", {"command": "pwd"}),
    ]
    for name, args in calls:
        r = _decide(name, args)
        # Every call MUST return a 200 (verdict lives in body, not HTTP).
        assert r.status_code == 200, (name, r.text)
    counters = _get_counters()
    # NO backend counter may have moved.
    assert all(v == 0 for v in counters.values()), counters
