"""Integration test suite covering the ``flag_for_review`` verdict path
for the reference MCP tools backend + gateway pair.

Complements ``test_mcp_tools_ref_wave_e2e.py`` (which covers ``allow`` +
``deny``). The gateway supports three verdicts; this module proves the
third — human-in-the-loop review — end-to-end through the running stack:

    * HTTP 428 Precondition Required with a valid pending-id header +
      JSON-RPC error body carrying ``verdict=flag_for_review`` and
      ``reason_codes=[REQUIRES_HUMAN]``.
    * A pending-invocations row is written to Postgres with the DID
      preserved in request_headers and the request body captured as
      ciphertext (encrypted at rest).
    * A ``gateway_verdict`` evidence row is written with
      ``verdict=flag_for_review`` and ``evaluator_name`` populated.
    * Two concurrent flagged requests receive distinct pending-ids and
      neither one reaches the backend (counter stays 0).

Requires the same live docker stack as ``test_mcp_tools_ref_wave_e2e.py``.
Also requires the Postgres instance reachable on ``localhost:18432`` for
the pending + evidence row assertions; those specific tests skip if
psycopg2 or the DB is unreachable rather than failing the whole module.

The demo RBAC rule that drives ``flag_for_review`` on
``mcp.reference.governed_http_fetch`` for the agent principal kind is
defined in ``ops/demo/gateway.yaml``; this test file only observes its
externally visible effect.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import time
import uuid

import pytest

pytest.importorskip("httpx")
import httpx  # noqa: E402

pytestmark = pytest.mark.integration


# --- Constants ----------------------------------------------------------

_GATEWAY_URL = "http://localhost:18080/mcp"
_GATEWAY_HEALTHZ = "http://localhost:18080/healthz"
_REF_CONTAINER = "kya-mcp-tools-ref"
_TEST_DID = "did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8"
# Postgres reachable from host (compose maps 18432 -> 5432 on kya-postgres).
_PG_DSN = (
    "host=localhost port=18432 dbname=veldt_kya "
    "user=veldt password=veldt_kya_2026"
)
# The RBAC-flagged action string as recorded in kya_pending_invocations.
_FLAGGED_ACTION = "mcp.reference.governed_http_fetch"
# A hostname on the HTTP allowlist; the flag_for_review verdict fires at
# the gateway before the SSRF post-DNS check, but keeping the URL well-
# formed avoids any ambiguity in a future gateway version.
_FLAGGED_URL = "https://example.com"


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


def _tools_call(name: str, arguments: dict | None = None, *, req_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def _connect_pg():
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        return psycopg2.connect(_PG_DSN, connect_timeout=3)
    except psycopg2.OperationalError as exc:  # pragma: no cover - env-dependent
        pytest.skip(f"kya-postgres unreachable on localhost:18432: {exc}")


def _fetch_pending_row(conn, pending_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, tenant_id, principal_kind, principal_id, action,
                   status, request_headers,
                   octet_length(request_body_ciphertext) AS body_len
              FROM kya_pending_invocations
             WHERE id = %s
            """,
            (pending_id,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    cols = [
        "id", "tenant_id", "principal_kind", "principal_id", "action",
        "status", "request_headers", "body_len",
    ]
    return dict(zip(cols, row))


def _wait_for_pending_row(
    conn, pending_id: str, *, timeout: float = 5.0,
) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = _fetch_pending_row(conn, pending_id)
        if row is not None:
            return row
        conn.rollback()
        time.sleep(0.1)
    return None


def _fetch_max_evidence_id(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(id), 0) FROM kya_evidence")
        return int(cur.fetchone()[0])


def _wait_for_flag_evidence(
    conn, *, since_id: int, timeout: float = 5.0,
) -> dict | None:
    """Poll for the newest gateway_verdict/flag_for_review row for our DID."""
    deadline = time.time() + timeout
    row = None
    while time.time() < deadline:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, invocation_id, evidence_kind, evaluator_name,
                       payload
                  FROM kya_evidence
                 WHERE evidence_kind = 'gateway_verdict'
                   AND id > %s
                   AND payload ->> 'external_subject' = %s
                   AND payload ->> 'verdict' = %s
                   AND payload -> 'tool_call' ->> 'name'
                       LIKE %s
                 ORDER BY id DESC
                 LIMIT 1
                """,
                (
                    since_id, _TEST_DID, "flag_for_review",
                    "%governed_http_fetch%",
                ),
            )
            row = cur.fetchone()
        if row is not None:
            cols = [
                "id", "invocation_id", "evidence_kind", "evaluator_name",
                "payload",
            ]
            return dict(zip(cols, row))
        conn.rollback()
        time.sleep(0.1)
    return None


def _extract_pending_id(resp: httpx.Response) -> str:
    header_val = resp.headers.get("x-kya-pending-id") or resp.headers.get(
        "X-KYA-Pending-Id"
    )
    assert header_val, dict(resp.headers)
    # Validate it's a real UUID (strict format).
    uuid.UUID(header_val)
    return header_val


# --- Category 1 - Externally visible 428 response ----------------------


def test_flag_for_review_returns_428_with_pending_id(gateway_url, did_header):
    """flag_for_review path: HTTP 428, header + body carry pending_id,
    reason_codes=[REQUIRES_HUMAN], backend counter stays 0."""
    resp = httpx.post(
        gateway_url,
        headers=did_header,
        json=_tools_call(
            "reference.governed_http_fetch",
            {"url": _FLAGGED_URL},
        ),
        timeout=10.0,
    )
    assert resp.status_code == 428, (
        f"expected 428 Precondition Required, got {resp.status_code}: "
        f"{resp.text!r}"
    )
    pending_id = _extract_pending_id(resp)

    body = resp.json()
    err = body.get("error") or {}
    assert err.get("code") == -32007, body
    assert "flag_for_review" in (err.get("message") or ""), body

    data = err.get("data") or {}
    assert data.get("verdict") == "flag_for_review", body
    assert data.get("pending_id") == pending_id, (data, pending_id)
    reason_codes = data.get("reason_codes") or []
    assert "REQUIRES_HUMAN" in reason_codes, body

    counters = _get_counters()
    assert counters.get("governed_http_fetch", 0) == 0, counters


# --- Category 2 - Postgres side-effects --------------------------------


def test_flag_for_review_writes_pending_row(gateway_url, did_header):
    """A flag_for_review verdict MUST persist a kya_pending_invocations
    row with the DID + action captured and the request body encrypted
    at rest (ciphertext bytes present)."""
    conn = _connect_pg()
    try:
        resp = httpx.post(
            gateway_url,
            headers=did_header,
            json=_tools_call(
                "reference.governed_http_fetch",
                {"url": _FLAGGED_URL},
            ),
            timeout=10.0,
        )
        assert resp.status_code == 428, resp.text
        pending_id = _extract_pending_id(resp)

        row = _wait_for_pending_row(conn, pending_id, timeout=5.0)
        assert row is not None, (
            f"no kya_pending_invocations row surfaced for id={pending_id} "
            f"within 5s"
        )
        assert row["status"] == "pending", row
        assert row["action"] == _FLAGGED_ACTION, row
        assert row["principal_id"] == _TEST_DID, row
        # Request body is encrypted at rest — we can't assert on the
        # plaintext, only that the ciphertext column is non-empty.
        assert row["body_len"] and row["body_len"] > 0, row
        # request_headers is JSONB (not encrypted) and MUST retain the DID
        # header the caller sent, so an operator reviewing the pending
        # request can attribute it.
        headers_dict = row["request_headers"] or {}
        did_captured = (
            headers_dict.get("x-kya-did")
            or headers_dict.get("X-KYA-DID")
        )
        assert did_captured == _TEST_DID, headers_dict

        # And the backend was never called.
        counters = _get_counters()
        assert counters.get("governed_http_fetch", 0) == 0, counters
    finally:
        conn.close()


def test_flag_for_review_writes_gateway_evidence_row(gateway_url, did_header):
    """A flag_for_review verdict MUST write a kya_evidence row with
    evidence_kind=gateway_verdict, verdict=flag_for_review, and
    evaluator_name populated (attribution invariant)."""
    conn = _connect_pg()
    try:
        baseline_id = _fetch_max_evidence_id(conn)
        resp = httpx.post(
            gateway_url,
            headers=did_header,
            json=_tools_call(
                "reference.governed_http_fetch",
                {"url": _FLAGGED_URL},
            ),
            timeout=10.0,
        )
        assert resp.status_code == 428, resp.text
        pending_id = _extract_pending_id(resp)

        evidence = _wait_for_flag_evidence(
            conn, since_id=baseline_id, timeout=5.0,
        )
        assert evidence is not None, (
            f"no gateway_verdict/flag_for_review evidence surfaced for "
            f"DID {_TEST_DID} after HTTP 428 (baseline id={baseline_id}, "
            f"pending_id={pending_id})"
        )
        payload = evidence["payload"]
        assert payload.get("verdict") == "flag_for_review", payload
        # Evaluator attribution — non-empty string.
        assert evidence["evaluator_name"], (
            f"evaluator_name empty on evidence row id={evidence['id']}"
        )
        # Reason-code attribution is preserved on the evidence row too.
        reason_codes = payload.get("reason_codes") or []
        assert "REQUIRES_HUMAN" in reason_codes, payload
    finally:
        conn.close()


# --- Category 3 - Concurrency ------------------------------------------


@pytest.mark.asyncio
async def test_two_concurrent_flags_get_distinct_pending_ids(
    gateway_url, did_header,
):
    """Two concurrent flagged requests MUST receive distinct pending_ids
    (no id collision under async load) and neither may reach the backend.
    Both rows must land in kya_pending_invocations."""
    conn = _connect_pg()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r1_coro = client.post(
                gateway_url, headers=did_header,
                json=_tools_call(
                    "reference.governed_http_fetch",
                    {"url": _FLAGGED_URL},
                    req_id=1,
                ),
            )
            r2_coro = client.post(
                gateway_url, headers=did_header,
                json=_tools_call(
                    "reference.governed_http_fetch",
                    {"url": _FLAGGED_URL},
                    req_id=2,
                ),
            )
            r1, r2 = await asyncio.gather(r1_coro, r2_coro)

        assert r1.status_code == 428, r1.text
        assert r2.status_code == 428, r2.text
        pid1 = _extract_pending_id(r1)
        pid2 = _extract_pending_id(r2)
        assert pid1 != pid2, (pid1, pid2)

        # Both rows must exist in Postgres.
        row1 = _wait_for_pending_row(conn, pid1, timeout=5.0)
        row2 = _wait_for_pending_row(conn, pid2, timeout=5.0)
        assert row1 is not None, f"pending row missing for {pid1}"
        assert row2 is not None, f"pending row missing for {pid2}"
        assert row1["status"] == "pending", row1
        assert row2["status"] == "pending", row2

        # Backend still zero — no bypass under concurrency.
        counters = _get_counters()
        assert counters.get("governed_http_fetch", 0) == 0, counters
    finally:
        conn.close()


# --- Category 4 - HITL approve/reject resume ---------------------------
#
# HITL decide/resume via an authenticated dashboard-api endpoint is out of
# scope for this integration test. Driving it would require:
#
#   1. A stable authenticated dashboard-api endpoint reachable from the
#      host (a valid ``kya_api_tokens`` bearer token; the demo stack does
#      not expose a stable known token to the host).
#   2. Coordinating the resume-execution path back to the gateway/backend
#      so that an approve actually re-plays the original tool call and
#      increments the counter.
#
# The pending-row + evidence-row invariants above already prove the
# flag_for_review path deposits the state that a HITL approve/reject
# operates on. Resume state-machine testing is out of scope here.


def test_approve_resumes_and_increments_counter():
    """HITL approve → backend counter increments.

    Requires a stable authenticated dashboard-api resume endpoint reachable
    from the host, which the demo stack does not expose. Out of scope for
    this integration test.
    """
    pytest.skip(
        "HITL approve/resume requires a host-reachable, authenticated "
        "dashboard-api endpoint that the demo stack does not expose. "
        "Out of scope for this integration test."
    )


def test_reject_denies_and_counter_stays_zero():
    """HITL reject → backend counter stays 0, pending row → rejected.

    Same dependency as ``test_approve_resumes_and_increments_counter``.
    """
    pytest.skip(
        "HITL reject requires a host-reachable, authenticated "
        "dashboard-api endpoint that the demo stack does not expose. "
        "Out of scope for this integration test."
    )
