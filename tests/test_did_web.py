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
