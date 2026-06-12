"""Tests for kya.did_methods.web — did:web resolver.

HTTP is mocked via ``responses`` (already in KYA's test deps). No live
network calls in this suite.
"""
from __future__ import annotations

import json
import os

import pytest

os.environ["KYA_DID_RESOLVERS"] = "key,web,jwk"

from kya.did import (
    DIDDocumentTooLarge,
    DIDInvalidIdentifier,
    DIDResolutionFailed,
    resolve_did,
)
from kya.did_methods.web import _suffix_to_url

# ─── URL derivation ──────────────────────────────────────────────────


def test_root_host_well_known_path():
    """did:web:example.com → https://example.com/.well-known/did.json"""
    assert _suffix_to_url("example.com") == "https://example.com/.well-known/did.json"


def test_host_with_path():
    """did:web:example.com:user42 → https://example.com/user42/did.json"""
    assert _suffix_to_url("example.com:user42") == "https://example.com/user42/did.json"


def test_deep_path():
    assert (
        _suffix_to_url("example.com:tenants:acme:agents:planner")
        == "https://example.com/tenants/acme/agents/planner/did.json"
    )


def test_url_encoded_port():
    """did:web:example.com%3A8443 should decode the port."""
    assert (
        _suffix_to_url("example.com%3A8443")
        == "https://example.com:8443/.well-known/did.json"
    )


def test_empty_suffix_raises():
    with pytest.raises(DIDInvalidIdentifier):
        _suffix_to_url("")


# ─── End-to-end resolution (mocked HTTP) ────────────────────────────


@pytest.fixture
def example_doc() -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:example.com",
        "verificationMethod": [
            {
                "id": "did:web:example.com#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:example.com",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
            }
        ],
        "authentication": ["did:web:example.com#key-1"],
        "assertionMethod": ["did:web:example.com#key-1"],
    }


def test_resolve_well_known(monkeypatch, example_doc):
    """did:web:example.com fetches /.well-known/did.json."""
    captured: dict = {}

    class MockResponse:
        status_code = 200

        def iter_content(self, chunk_size=8192, decode_unicode=False):
            yield json.dumps(example_doc).encode("utf-8")

    def fake_get(url, headers=None, timeout=None, allow_redirects=None, stream=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["allow_redirects"] = allow_redirects
        return MockResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)

    doc = resolve_did("did:web:example.com")
    assert captured["url"] == "https://example.com/.well-known/did.json"
    assert captured["allow_redirects"] is False  # SSRF defense
    assert doc.id == "did:web:example.com"
    assert len(doc.verification_methods) == 1
    assert doc.verification_methods[0].public_key_jwk["crv"] == "Ed25519"


def test_resolve_oversized_doc_raises(monkeypatch):
    """A DID document larger than the cap is rejected."""

    class MockResponse:
        status_code = 200

        def iter_content(self, chunk_size=8192, decode_unicode=False):
            # Yield a stream that exceeds the cap when accumulated.
            yield b"x" * 8192
            yield b"x" * 8192
            yield b"x" * 8192  # 24 KB — way under default 256 KB

    def fake_get(url, **kw):
        return MockResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setenv("KYA_DID_WEB_MAX_DOC_BYTES", "1024")  # 1 KB cap

    with pytest.raises(DIDDocumentTooLarge):
        resolve_did("did:web:example.com")


def test_non_200_status_raises(monkeypatch):
    class MockResponse:
        status_code = 404

        def iter_content(self, **kw):
            yield b""

    def fake_get(url, **kw):
        return MockResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    with pytest.raises(DIDResolutionFailed, match="404"):
        resolve_did("did:web:example.com")


def test_invalid_json_raises(monkeypatch):
    class MockResponse:
        status_code = 200

        def iter_content(self, **kw):
            yield b"not json {{{"

    def fake_get(url, **kw):
        return MockResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    with pytest.raises(DIDResolutionFailed, match="JSON"):
        resolve_did("did:web:example.com")


# ─── B1: SSRF defense — block private/loopback/link-local IPs ─────────


def _fail_on_http(monkeypatch):
    """Install a requests.get that fails the test if HTTP is attempted.

    Use this to assert the resolver rejects a DID *before* any network
    call. Anything calling requests.get marks the test as a failure.
    """
    state = {"called": False}

    def fake_get(url, **kw):
        state["called"] = True
        raise AssertionError(
            f"SSRF: resolver attempted HTTP to {url!r} — should have been "
            f"blocked before any network call"
        )

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    return state


def test_ssrf_rejects_aws_metadata_ip(monkeypatch):
    """did:web:169.254.169.254 must NOT issue an HTTP request.

    169.254/16 is link-local; cloud metadata sits at 169.254.169.254 on
    AWS / GCP / Azure. A resolver that fetches it leaks IAM creds, instance
    identity, etc.
    """
    state = _fail_on_http(monkeypatch)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:169.254.169.254")
    assert state["called"] is False


def test_ssrf_rejects_loopback_ipv4(monkeypatch):
    state = _fail_on_http(monkeypatch)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:127.0.0.1")
    assert state["called"] is False


def test_ssrf_rejects_loopback_ipv4_with_port(monkeypatch):
    state = _fail_on_http(monkeypatch)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:127.0.0.1%3A8500")  # consul/vault default
    assert state["called"] is False


def test_ssrf_rejects_private_rfc1918(monkeypatch):
    state = _fail_on_http(monkeypatch)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:10.0.0.1")
    assert state["called"] is False


def test_ssrf_rejects_private_172_range(monkeypatch):
    state = _fail_on_http(monkeypatch)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:172.16.0.1")
    assert state["called"] is False


def test_ssrf_rejects_private_192_range(monkeypatch):
    state = _fail_on_http(monkeypatch)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:192.168.1.1")
    assert state["called"] is False


def test_ssrf_rejects_unspecified_zero(monkeypatch):
    state = _fail_on_http(monkeypatch)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:0.0.0.0")
    assert state["called"] is False


def test_ssrf_rejects_dns_name_resolving_to_private(monkeypatch):
    """If a hostname's DNS lookup yields a private IP, reject.

    Models DNS rebinding: attacker registers evil.example pointing at
    127.0.0.1 (or AWS metadata IP). The resolver must catch this even
    when the DID is presented as a hostname, not an IP literal.
    """
    state = _fail_on_http(monkeypatch)

    import socket
    def fake_getaddrinfo(host, port, *a, **kw):
        # Simulate hostname → loopback
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:evil.example")
    assert state["called"] is False


# ─── B2: Hostname / segment validation — block path traversal ─────────


def test_host_with_slash_after_decode_rejected(monkeypatch):
    """did:web:evil.com%2F..%40victim.com decodes to 'evil.com/..@victim.com'.

    Pct-decoded slashes/@ injected into the host segment turn the host
    into a URL path + userinfo. Must be rejected during URL construction.
    """
    _fail_on_http(monkeypatch)
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did("did:web:evil.example%2F..%40victim.example")


def test_host_with_question_mark_rejected(monkeypatch):
    """did:web:evil.com%3F → host containing '?' (query injection)."""
    _fail_on_http(monkeypatch)
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did("did:web:evil.example%3Fpath")


def test_host_with_hash_rejected(monkeypatch):
    """did:web:evil.com%23x → host containing '#' (fragment injection)."""
    _fail_on_http(monkeypatch)
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did("did:web:evil.example%23frag")


def test_path_segment_with_dotdot_rejected(monkeypatch):
    """did:web:example.com:%2E%2E:secret → '..' in path traversal."""
    _fail_on_http(monkeypatch)
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did("did:web:example.com:%2E%2E:secret")


def test_path_segment_with_slash_rejected(monkeypatch):
    """did:web:example.com:foo%2Fbar → embedded slash in segment."""
    _fail_on_http(monkeypatch)
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did("did:web:example.com:foo%2Fbar")


# ─── M4: doc.id must match the requested DID ──────────────────────────


def test_doc_id_mismatch_rejected(monkeypatch):
    """Server returns a doc whose id ≠ the DID the caller requested.

    Attacker controls https://attacker.example/.well-known/did.json and
    serves a document claiming id: 'did:web:bank.example'. KYA must
    reject — otherwise downstream code that trusts doc.id (for issuer
    matching, audit, etc.) is lied to.
    """
    impostor_doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:bank.example",  # ≠ what we asked for
        "verificationMethod": [],
    }

    class MockResponse:
        status_code = 200

        def iter_content(self, chunk_size=8192, decode_unicode=False):
            yield json.dumps(impostor_doc).encode("utf-8")

    def fake_get(url, **kw):
        return MockResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    with pytest.raises(DIDResolutionFailed, match=r"(?i)id"):
        resolve_did("did:web:attacker.example")


def test_doc_id_matches_when_correct(monkeypatch, example_doc):
    """Sanity: when doc.id matches, resolution succeeds (regression guard)."""

    class MockResponse:
        status_code = 200

        def iter_content(self, chunk_size=8192, decode_unicode=False):
            yield json.dumps(example_doc).encode("utf-8")

    def fake_get(url, **kw):
        return MockResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    doc = resolve_did("did:web:example.com")
    assert doc.id == "did:web:example.com"


# ─── B1 escape hatch: KYA_DID_WEB_ALLOW_LOOPBACK for tests/dev ────────


# ─── V1: DNS rebinding (TOCTOU) — pin the IP between check and fetch ──


def test_dns_rebinding_pinning(monkeypatch):
    """getaddrinfo returns public IP first, then private IP on second call.

    Models: attacker controls authoritative DNS for `rebinding.example`,
    returns 8.8.8.8 (public) on the safety check and 127.0.0.1 (loopback)
    on the actual HTTP connection. The resolver must NOT connect to the
    private IP — either pin to the first lookup's IP or re-check on every
    DNS call.
    """
    import socket as _socket
    call_count = {"n": 0}
    orig_getaddrinfo = _socket.getaddrinfo

    def alternating_getaddrinfo(host, port, *a, **kw):
        call_count["n"] += 1
        if host == "rebinding.example":
            if call_count["n"] == 1:
                # First call: pretend to be public
                return [(_socket.AF_INET, _socket.SOCK_STREAM, 0, "",
                         ("8.8.8.8", port or 0))]
            else:
                # Rebound: now point at loopback
                return [(_socket.AF_INET, _socket.SOCK_STREAM, 0, "",
                         ("127.0.0.1", port or 0))]
        return orig_getaddrinfo(host, port, *a, **kw)

    monkeypatch.setattr(_socket, "getaddrinfo", alternating_getaddrinfo)

    # Capture which IP the HTTP layer actually connected to. urllib3 calls
    # getaddrinfo at connection-establishment time, so we simulate that
    # call here from inside the fake requests.get.
    connected_to: list[str] = []

    def fake_get(url, **kw):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        addrs = _socket.getaddrinfo(host, port)
        connected_to.append(addrs[0][4][0])

        class _R:
            status_code = 599

            def iter_content(self, *_a, **_kw):
                yield b""

        return _R()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)

    # Whether resolution succeeds or fails doesn't matter — what matters
    # is that the HTTP layer NEVER connected to 127.0.0.1.
    try:
        resolve_did("did:web:rebinding.example")
    except (DIDResolutionFailed, DIDInvalidIdentifier):
        pass

    assert "127.0.0.1" not in connected_to, (
        f"DNS rebinding succeeded — HTTP layer connected to {connected_to}"
    )


# ─── V3: IPv4-mapped IPv6 unwrap — `::ffff:127.0.0.1` is loopback ─────


def test_ssrf_rejects_ipv4_mapped_ipv6_loopback(monkeypatch):
    """A hostname whose AAAA record is `::ffff:127.0.0.1` must be rejected.

    On Python 3.10/3.11, `IPv6Address('::ffff:127.0.0.1').is_loopback` is
    False — the resolver must explicitly unmap before the safety check.
    The OS will unmap when connecting, so this IS a loopback target.
    """
    import socket as _socket
    state = _fail_on_http(monkeypatch)

    def aaaa_only(host, port, *a, **kw):
        if host == "v6evil.example":
            return [(_socket.AF_INET6, _socket.SOCK_STREAM, 0, "",
                     ("::ffff:127.0.0.1", port or 0, 0, 0))]
        return []

    monkeypatch.setattr(_socket, "getaddrinfo", aaaa_only)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:v6evil.example")
    assert state["called"] is False


def test_ssrf_rejects_ipv4_mapped_ipv6_metadata(monkeypatch):
    """`::ffff:169.254.169.254` (mapped AWS metadata IP) must be rejected."""
    import socket as _socket
    state = _fail_on_http(monkeypatch)

    def aaaa_only(host, port, *a, **kw):
        if host == "mappedmeta.example":
            return [(_socket.AF_INET6, _socket.SOCK_STREAM, 0, "",
                     ("::ffff:169.254.169.254", port or 0, 0, 0))]
        return []

    monkeypatch.setattr(_socket, "getaddrinfo", aaaa_only)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:mappedmeta.example")
    assert state["called"] is False


# ─── L3: CGNAT 100.64/10 not covered by is_private on Python <3.13 ────


def test_ssrf_rejects_cgnat_range(monkeypatch):
    """100.64.0.0/10 (carrier-grade NAT) must be rejected.

    `IPv4Address('100.64.0.1').is_private` is False on Python <3.13,
    so we need explicit network containment.
    """
    state = _fail_on_http(monkeypatch)
    with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
        resolve_did("did:web:100.64.0.1")
    assert state["called"] is False


def test_ssrf_rejects_documentation_subnets(monkeypatch):
    """TEST-NET-1/2/3 + benchmarking + class-E should all be rejected."""
    state = _fail_on_http(monkeypatch)
    for ip in ("192.0.2.10", "198.51.100.10", "203.0.113.10",
               "198.18.0.1", "240.0.0.1"):
        with pytest.raises((DIDResolutionFailed, DIDInvalidIdentifier)):
            resolve_did(f"did:web:{ip}")
    assert state["called"] is False


# ─── V4: reject `.` and empty path segments ──────────────────────────


def test_path_segment_single_dot_rejected(monkeypatch):
    """did:web:example.com:a:%2E:b decodes to `a/./b` — must reject."""
    _fail_on_http(monkeypatch)
    with pytest.raises(DIDInvalidIdentifier):
        resolve_did("did:web:example.com:a:%2E:b")


# ─── B1 escape hatch: KYA_DID_WEB_ALLOW_LOOPBACK for tests/dev ────────


def test_loopback_allowed_when_env_set(monkeypatch, example_doc):
    """Set KYA_DID_WEB_ALLOW_LOOPBACK=1 to permit 127.0.0.1 in dev/CI."""
    # Adjust the doc id to match the loopback request
    doc = dict(example_doc)
    doc["id"] = "did:web:127.0.0.1"

    class MockResponse:
        status_code = 200

        def iter_content(self, chunk_size=8192, decode_unicode=False):
            yield json.dumps(doc).encode("utf-8")

    def fake_get(url, **kw):
        return MockResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setenv("KYA_DID_WEB_ALLOW_LOOPBACK", "1")

    result = resolve_did("did:web:127.0.0.1")
    assert result.id == "did:web:127.0.0.1"


# ─── Phase 13b follow-up: KYA_DID_WEB_ALLOW_PRIVATE flag ───────────


def test_allow_loopback_permits_127_x(monkeypatch, example_doc):
    """### KYA_DID_WEB_ALLOW_LOOPBACK=1 lets loopback through.

    Pin the back-compat behavior: nothing about Phase 13b's new
    private-IP flag changes the existing loopback contract.
    """
    monkeypatch.setenv("KYA_DID_WEB_ALLOW_LOOPBACK", "1")

    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))
    ])
    # Stub the HTTP fetch so we don't actually hit 127.0.0.1.
    class _R:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = '{"id": "did:web:loopback.test"}'
        def json(self): import json; return json.loads(self.text)
        def iter_content(self, chunk_size, decode_unicode=False): yield self.text.encode("utf-8")

    import requests
    monkeypatch.setattr(
        requests, "get", lambda *a, **kw: _R(),
    )
    # Resolver finalises the doc.id via _resolve_and_check_host; we
    # care about whether it raises, not the doc content.
    try:
        resolve_did("did:web:loopback.test")
    except (DIDResolutionFailed, DIDInvalidIdentifier) as exc:
        pytest.fail(
            f"ALLOW_LOOPBACK=1 should permit loopback; got {exc!r}"
        )


def test_allow_loopback_alone_still_rejects_rfc1918(monkeypatch):
    """### Pre-fix bug: error message hinted at ALLOW_LOOPBACK as
    the fix for ANY refused IP. In reality LOOPBACK only relaxes
    127.x. A docker network IP (172.x) still gets refused with
    ALLOW_LOOPBACK=1 alone.
    """
    monkeypatch.setenv("KYA_DID_WEB_ALLOW_LOOPBACK", "1")
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_PRIVATE", raising=False)
    state = _fail_on_http(monkeypatch)
    with pytest.raises(
        (DIDResolutionFailed, DIDInvalidIdentifier),
    ) as exc_info:
        resolve_did("did:web:172.25.0.3")
    assert state["called"] is False
    # The new error message names the precise flag that would
    # unlock this IP -- ALLOW_PRIVATE, not ALLOW_LOOPBACK.
    msg = str(exc_info.value)
    assert "KYA_DID_WEB_ALLOW_PRIVATE" in msg, (
        f"error must point at ALLOW_PRIVATE, not LOOPBACK; got: {msg}"
    )


def test_allow_private_permits_rfc1918(monkeypatch, example_doc):
    """### Phase 13b new: ALLOW_PRIVATE=1 lets docker / k8s
    private IPs through for in-cluster testing.
    """
    monkeypatch.setenv("KYA_DID_WEB_ALLOW_PRIVATE", "1")
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_LOOPBACK", raising=False)

    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("172.25.0.3", 443))
    ])

    class _R:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = '{"id": "did:web:private.test"}'
        def json(self): import json; return json.loads(self.text)
        def iter_content(self, chunk_size, decode_unicode=False): yield self.text.encode("utf-8")

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **kw: _R())
    try:
        resolve_did("did:web:private.test")
    except (DIDResolutionFailed, DIDInvalidIdentifier) as exc:
        pytest.fail(
            f"ALLOW_PRIVATE=1 should permit RFC1918; got {exc!r}"
        )


def test_allow_private_implies_loopback(monkeypatch):
    """### Ergonomic shortcut: ALLOW_PRIVATE=1 alone covers BOTH
    127.x AND RFC1918 so customers running an in-cluster test
    don't have to set two flags."""
    monkeypatch.setenv("KYA_DID_WEB_ALLOW_PRIVATE", "1")
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_LOOPBACK", raising=False)

    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))
    ])

    class _R:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = '{"id": "did:web:lb.test"}'
        def json(self): import json; return json.loads(self.text)
        def iter_content(self, chunk_size, decode_unicode=False): yield self.text.encode("utf-8")

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **kw: _R())
    try:
        resolve_did("did:web:lb.test")
    except (DIDResolutionFailed, DIDInvalidIdentifier) as exc:
        pytest.fail(
            f"ALLOW_PRIVATE should cover loopback too; got {exc!r}"
        )


def test_no_flag_rejects_with_precise_hint_loopback(monkeypatch):
    """### Precise error: a 127.x IP refusal points at LOOPBACK,
    not PRIVATE."""
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_LOOPBACK", raising=False)
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_PRIVATE", raising=False)
    state = _fail_on_http(monkeypatch)
    with pytest.raises(
        (DIDResolutionFailed, DIDInvalidIdentifier),
    ) as exc_info:
        resolve_did("did:web:127.0.0.1")
    assert state["called"] is False
    msg = str(exc_info.value)
    assert "KYA_DID_WEB_ALLOW_LOOPBACK" in msg, (
        f"loopback refusal must name LOOPBACK flag; got: {msg}"
    )
    assert "KYA_DID_WEB_ALLOW_PRIVATE" not in msg, (
        f"loopback refusal must NOT name PRIVATE flag; got: {msg}"
    )


def test_no_flag_rejects_with_precise_hint_private(monkeypatch):
    """### Precise error: an RFC1918 refusal points at PRIVATE,
    not LOOPBACK -- the bug Phase 13b surfaced."""
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_LOOPBACK", raising=False)
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_PRIVATE", raising=False)
    state = _fail_on_http(monkeypatch)
    with pytest.raises(
        (DIDResolutionFailed, DIDInvalidIdentifier),
    ) as exc_info:
        resolve_did("did:web:192.168.1.50")
    assert state["called"] is False
    msg = str(exc_info.value)
    assert "KYA_DID_WEB_ALLOW_PRIVATE" in msg
    assert "KYA_DID_WEB_ALLOW_LOOPBACK" not in msg
    # Category name in the message ("RFC1918/ULA private") is the
    # actual user-facing breadcrumb -- pin it so a refactor of the
    # message text can't silently regress to the misleading
    # "internal IP" phrasing the pre-fix code used.
    assert "RFC1918" in msg or "private" in msg.lower()


def test_link_local_metadata_ip_no_flag_unlocks_it(monkeypatch):
    """### Safety pin: AWS metadata IP (169.254.169.254) and the
    rest of 169.254/16 link-local must NEVER be unlockable by a
    dev-mode flag. The error must say so explicitly so a customer
    misreading "internal" doesn't experiment with both flags
    looking for a way in.

    Cloud metadata endpoints in particular are the canonical SSRF
    target; the multi-flag scheme this PR introduces must not
    accidentally read as "set both flags and you're through."
    """
    monkeypatch.setenv("KYA_DID_WEB_ALLOW_LOOPBACK", "1")
    monkeypatch.setenv("KYA_DID_WEB_ALLOW_PRIVATE", "1")
    state = _fail_on_http(monkeypatch)
    with pytest.raises(
        (DIDResolutionFailed, DIDInvalidIdentifier),
    ) as exc_info:
        # AWS instance metadata IP -- the canonical SSRF target.
        resolve_did("did:web:169.254.169.254")
    assert state["called"] is False
    msg = str(exc_info.value)
    # Both flags are SET but neither unlocks link-local. The
    # error must say "non-routable" with neither flag named
    # as an escape hatch.
    assert "non-routable" in msg, (
        f"link-local refusal must call out 'non-routable' "
        f"category; got: {msg}"
    )
    assert "neither flag" in msg, (
        f"link-local refusal must explicitly say neither flag "
        f"unlocks it; got: {msg}"
    )


# ─── Live integration test: real HTTPS server on loopback ─────────


def test_live_loopback_resolve_against_real_https_server(
    monkeypatch, tmp_path,
):
    """### Live: actual HTTPS server on 127.0.0.1, self-signed
    cert with IPAddress SAN, real resolver fetch through the
    full HTTP + TLS stack. Catches drift the mock tests miss:
    HTTP client refactor (requests -> httpx), ssl.create_default_context
    semantics, REQUESTS_CA_BUNDLE handling.

    Belt-and-braces over the Phase 13b in-container live test;
    runs in-process without docker so CI catches regressions
    pre-merge.
    """
    import http.server
    import ipaddress as _ipaddr_mod
    import json as _json
    import socketserver
    import ssl
    import threading
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    # Self-signed cert. IPAddress SAN is the load-bearing piece --
    # strict TLS validators (the default in OpenSSL 3.x +
    # Python 3.12) refuse IP-literal hosts unless the IP is in
    # IPAddress SAN. CommonName fallback was deprecated by RFC 6125
    # and removed in modern stacks.
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048,
    )
    now = _dt.now(_tz.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _td(minutes=5))
        .not_valid_after(now + _td(minutes=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(_ipaddr_mod.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = tmp_path / "server.crt"
    key_pem = tmp_path / "server.key"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))

    # Doc root + did.json.
    import base64 as _b64
    doc_root = tmp_path / "www"
    wellknown = doc_root / ".well-known"
    wellknown.mkdir(parents=True)

    # Bind to an ephemeral port on 127.0.0.1 FIRST so the doc's
    # id can include the actual port. did:web spec ties the doc
    # id to the URL; resolver refuses any mismatch.
    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(doc_root), **kw)
        def log_message(self, *a, **kw):
            pass

    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]

    did_id_in_doc = f"did:web:127.0.0.1%3A{port}"
    pub_jwk_x = _b64.urlsafe_b64encode(b"\x00" * 32).rstrip(
        b"="
    ).decode("ascii")
    (wellknown / "did.json").write_text(_json.dumps({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/jws/v1",
        ],
        "id": did_id_in_doc,
        "verificationMethod": [{
            "id": f"{did_id_in_doc}#k1",
            "type": "JsonWebKey2020",
            "controller": did_id_in_doc,
            "publicKeyJwk": {
                "kty": "OKP", "crv": "Ed25519", "x": pub_jwk_x,
            },
        }],
        "authentication": [f"{did_id_in_doc}#k1"],
        "assertionMethod": [f"{did_id_in_doc}#k1"],
    }))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_pem), keyfile=str(key_pem))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    try:
        # Point ``requests`` (the resolver's HTTP client) at the
        # self-signed cert + open the SSRF guard for loopback.
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(cert_pem))
        monkeypatch.setenv("KYA_DID_WEB_ALLOW_LOOPBACK", "1")
        monkeypatch.delenv("KYA_DID_WEB_ALLOW_PRIVATE", raising=False)

        # Encode the ephemeral port in the DID per spec
        # (did:web:host%3Aport).
        suffix = f"127.0.0.1%3A{port}"
        doc = resolve_did(f"did:web:{suffix}")
        # Doc fetched + parsed end-to-end through the real
        # HTTP + TLS stack.
        assert doc is not None
        assert doc.id == did_id_in_doc, (
            f"unexpected doc id: {doc.id}"
        )
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_live_loopback_resolve_REJECTS_when_no_flag_set(
    monkeypatch, tmp_path,
):
    """### Live counterpart: same real HTTPS server, but WITHOUT
    ``KYA_DID_WEB_ALLOW_LOOPBACK`` set, the resolver must refuse
    BEFORE the HTTP fetch. Belt-and-braces against a refactor
    that reorders the SSRF check past the HTTP call.
    """
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_LOOPBACK", raising=False)
    monkeypatch.delenv("KYA_DID_WEB_ALLOW_PRIVATE", raising=False)
    state = _fail_on_http(monkeypatch)
    with pytest.raises(
        (DIDResolutionFailed, DIDInvalidIdentifier),
    ):
        resolve_did("did:web:127.0.0.1%3A8443")
    # The fetch must NOT have been attempted -- SSRF guard fires
    # first.
    assert state["called"] is False
