"""did:web resolver (W3C did:web 0.6 spec).

did:web binds a DID to a DNS-controlled URL. The resolver fetches the DID
document from the well-known HTTPS path, parses it, and returns it.

URL derivation (per spec):
    did:web:example.com            -> https://example.com/.well-known/did.json
    did:web:example.com:path:to:id -> https://example.com/path/to/id/did.json
    did:web:example.com%3A8443     -> https://example.com:8443/.well-known/did.json

Security:
- HTTP (non-TLS) URLs are refused.
- Redirects are NOT followed — SSRF surface is too wide.
- Hosts that resolve to private / loopback / link-local / multicast /
  reserved IPs are rejected BEFORE any network request (B1 defense).
  Set ``KYA_DID_WEB_ALLOW_LOOPBACK=1`` for local dev / CI only.
- Segments are rejected if they contain pct-decoded characters that
  would break out of the host / path component (B2 defense).
- The resolved document's ``id`` MUST equal the requested DID URI.
  An attacker who controls a did.json file cannot claim to be a
  different DID (M4 defense).
- Response size is capped via ``KYA_DID_WEB_MAX_DOC_BYTES``.
- Request timeout via ``KYA_DID_WEB_TIMEOUT_S``.

Spec: https://w3c-ccg.github.io/did-method-web/
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import threading
from contextlib import contextmanager
from urllib.parse import unquote

import requests

from kya.did import (
    DIDDocumentTooLarge,
    DIDInvalidIdentifier,
    DIDResolutionFailed,
)
from kya.did_document import DIDDocument, ServiceEndpoint, VerificationMethod

_DEFAULT_MAX_BYTES = 262144  # 256 KB
_DEFAULT_TIMEOUT_S = 5.0
_USER_AGENT_FALLBACK = "kya-did-resolver/0.x"

# RFC 1123 hostname label: letters/digits/hyphens, 1-63 chars, no leading
# or trailing hyphen. Labels joined by dots; total ≤ 253 chars.
_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# Characters that, after pct-decode, would re-introduce URL-component
# boundaries into a host or path segment. Rejecting these prevents an
# attacker from smuggling "/", "@", "?", "#" through pct-encoding.
_FORBIDDEN_DECODED_CHARS = frozenset("/\\?#@\x00 \t\n\r\f\v")

# Path segments that collapse away or signal traversal — refuse rather
# than let the server normalize them into something the spec didn't say.
_FORBIDDEN_PATH_SEGMENTS = frozenset(("", ".", ".."))

# Networks not always covered by ipaddress.is_private / is_reserved on
# the Python versions we support (<3.13 misses CGNAT). Belt-and-suspenders.
_EXTRA_BLOCKED_V4 = [
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT (RFC 6598)
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking (RFC 2544)
]
_EXTRA_BLOCKED_V6 = [
    ipaddress.ip_network("64:ff9b::/96"),     # NAT64 (RFC 6052)
    ipaddress.ip_network("100::/64"),         # discard prefix
]


def _safe_unquote_segment(segment: str, *, context: str) -> str:
    """Pct-decode ``segment`` and reject if decoded form contains URL meta-chars.

    ``context`` is included in the error message ("host" / "path segment").
    """
    decoded = unquote(segment)
    for ch in _FORBIDDEN_DECODED_CHARS:
        if ch in decoded:
            raise DIDInvalidIdentifier(
                f"did:web {context} contains forbidden character "
                f"after pct-decode (ch={ch!r}): {segment!r}"
            )
    # Path-component signals (empty, ., ..) collapse on the server side
    # and break the 1:1 DID-to-URL invariant the spec wants. Refuse.
    if context == "path segment" and decoded in _FORBIDDEN_PATH_SEGMENTS:
        raise DIDInvalidIdentifier(
            f"did:web path segment resolves to {decoded!r}: {segment!r}"
        )
    if decoded == "..":
        raise DIDInvalidIdentifier(
            f"did:web {context} resolves to '..': {segment!r}"
        )
    return decoded


def _parse_host_port(decoded_host: str) -> tuple[str, int | None]:
    """Split ``host[:port]`` and validate shape.

    Accepts ASCII hostnames or IPv4 literals; rejects bracketed IPv6
    (uncommon in did:web). Returns (hostname, port_or_None).
    """
    if not decoded_host:
        raise DIDInvalidIdentifier("did:web host is empty")
    if len(decoded_host) > 253 + 6:  # hostname + ":65535"
        raise DIDInvalidIdentifier(f"did:web host too long: {decoded_host!r}")

    # Split off port if present.
    if decoded_host.count(":") == 1:
        host_part, port_str = decoded_host.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            raise DIDInvalidIdentifier(
                f"did:web port is not an integer: {decoded_host!r}"
            ) from None
        if not (1 <= port <= 65535):
            raise DIDInvalidIdentifier(
                f"did:web port out of range: {port}"
            )
    elif ":" in decoded_host:
        # Multiple colons → IPv6 literal (which we don't support) or junk.
        raise DIDInvalidIdentifier(
            f"did:web host has multiple colons (IPv6 not supported): "
            f"{decoded_host!r}"
        )
    else:
        host_part = decoded_host
        port = None

    if not host_part:
        raise DIDInvalidIdentifier(f"did:web host empty before port: {decoded_host!r}")

    # Validate hostname shape: IP literal OR DNS labels.
    try:
        ipaddress.ip_address(host_part)
        return host_part, port  # IP literal is shape-valid; SSRF check separate.
    except ValueError:
        pass

    if len(host_part) > 253:
        raise DIDInvalidIdentifier(f"did:web hostname too long: {host_part!r}")
    labels = host_part.split(".")
    for label in labels:
        if not _HOSTNAME_LABEL_RE.match(label):
            raise DIDInvalidIdentifier(
                f"did:web hostname has invalid label {label!r}: {host_part!r}"
            )
    return host_part, port


def _normalize_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Unwrap IPv6 tunneling forms so per-IP policy applies to the real target.

    The OS will unmap `::ffff:127.0.0.1` to `127.0.0.1` when connecting, and
    will route `6to4` / `teredo` to the embedded IPv4. We must apply policy
    to the post-unmap address — `IPv6Address('::ffff:127.0.0.1').is_loopback`
    is False on Python <3.12, which would otherwise let the safety check
    pass on a loopback target.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
        if ip.teredo is not None:
            return ip.teredo[1]
    return ip


def _is_ip_safe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP is publicly routable (not internal/metadata)."""
    ip = _normalize_ip(ip)
    if ip.is_loopback:
        return False
    if ip.is_link_local:  # 169.254/16 — incl. AWS/GCP/Azure metadata
        return False
    if ip.is_private:  # RFC1918 + ULA (CGNAT was added in 3.13)
        return False
    if ip.is_multicast:
        return False
    if ip.is_reserved:
        return False
    if ip.is_unspecified:  # 0.0.0.0, ::
        return False
    # Explicit blocklist for ranges ipaddress doesn't catch on every Python.
    blocklist = _EXTRA_BLOCKED_V4 if isinstance(ip, ipaddress.IPv4Address) else _EXTRA_BLOCKED_V6
    for net in blocklist:
        try:
            if ip in net:
                return False
        except TypeError:
            continue
    return True


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip() in ("1", "true", "yes")


def _resolve_and_check_host(host: str) -> list[str]:
    """Resolve ``host`` and return the list of safe IP strings to connect to.

    Raises DIDResolutionFailed if no safe IP remains. Two test-only
    relaxations are available, scoped to RFC ranges so each opens
    only what it advertises:

    - ``KYA_DID_WEB_ALLOW_LOOPBACK=1`` permits 127.0.0.0/8 + ::1
      (true loopback). Right for a single-host dev setup where
      the did-doc server runs on the same machine as the
      resolver.
    - ``KYA_DID_WEB_ALLOW_PRIVATE=1`` permits the RFC1918 private
      ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) + IPv6
      ULA fc00::/7. Right for in-cluster testing (docker
      networks, k8s pod IPs) where the did-doc server is on a
      private LAN reachable from the resolver. Implies loopback.

    Neither flag relaxes the multicast / reserved / unspecified /
    extra-blocklist guards. Default behavior (both flags unset)
    rejects every non-globally-routable address.
    """
    allow_loopback = _env_truthy("KYA_DID_WEB_ALLOW_LOOPBACK")
    allow_private = _env_truthy("KYA_DID_WEB_ALLOW_PRIVATE")

    candidate_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        candidate_ips.append(ipaddress.ip_address(host))
    except ValueError:
        try:
            addrs = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError) as exc:
            raise DIDResolutionFailed(
                f"did:web hostname {host!r} did not resolve: {exc}"
            ) from exc
        for entry in addrs:
            sockaddr = entry[4]
            try:
                candidate_ips.append(ipaddress.ip_address(sockaddr[0]))
            except (ValueError, IndexError):
                continue

    if not candidate_ips:
        raise DIDResolutionFailed(
            f"did:web hostname {host!r} resolved to zero IP addresses"
        )

    safe_ips: list[str] = []
    for ip in candidate_ips:
        if _is_ip_safe(ip):
            safe_ips.append(str(_normalize_ip(ip)))
            continue
        normalized = _normalize_ip(ip)
        # Loopback: covered by allow_loopback OR allow_private
        # (private implies loopback so customers don't have to
        # set both flags for the common dev setup).
        if (allow_loopback or allow_private) and normalized.is_loopback:
            safe_ips.append(str(normalized))
            continue
        # RFC1918 / ULA: covered only by allow_private. Phase 13b
        # established the need for this -- in-cluster docker /
        # k8s testing pulls a private IP that allow_loopback
        # alone would refuse.
        if allow_private and normalized.is_private and not normalized.is_loopback:
            safe_ips.append(str(normalized))
            continue
        # Precise error: name the category we hit and the flag
        # that would unlock it. Pre-fix message hinted at
        # ALLOW_LOOPBACK for every refused IP -- misleading
        # since LOOPBACK only covers 127.x.
        if normalized.is_loopback:
            hint = "KYA_DID_WEB_ALLOW_LOOPBACK=1"
            category = "loopback"
        elif normalized.is_private:
            hint = "KYA_DID_WEB_ALLOW_PRIVATE=1"
            category = "RFC1918/ULA private"
        else:
            hint = "neither flag relaxes this category"
            category = "non-routable"
        raise DIDResolutionFailed(
            f"did:web host {host!r} resolves to {category} IP {ip}; "
            f"refusing to fetch (set {hint} for dev/test ONLY)"
        )
    return safe_ips


# DNS-rebinding defense: between the safety check and the actual HTTP
# request, urllib3 calls getaddrinfo a second time. A malicious DNS server
# with TTL=0 can return a public IP to call #1 and a private IP to call #2.
# We close the gap by patching socket.getaddrinfo for the scope of the
# requests.get call to return only the pre-validated safe IPs. The lock
# serializes did:web fetches — acceptable since they're rare.
_DNS_PIN_LOCK = threading.Lock()


@contextmanager
def _pin_dns(hostname: str, safe_ips: list[str]):
    """While inside this block, getaddrinfo for ``hostname`` returns only safe IPs."""
    with _DNS_PIN_LOCK:
        orig = socket.getaddrinfo

        def pinned(host, port, *args, **kwargs):
            if host == hostname:
                results = []
                for ip_str in safe_ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                    except ValueError:
                        continue
                    family = socket.AF_INET if ip_obj.version == 4 else socket.AF_INET6
                    sockaddr = (ip_str, port or 0, 0, 0) if family == socket.AF_INET6 else (ip_str, port or 0)
                    results.append((family, socket.SOCK_STREAM, 0, "", sockaddr))
                if results:
                    return results
            return orig(host, port, *args, **kwargs)

        socket.getaddrinfo = pinned
        try:
            yield
        finally:
            socket.getaddrinfo = orig


def _suffix_to_url(suffix: str) -> str:
    """Translate a did:web suffix into an HTTPS URL per the spec.

    The first colon-separated segment is the host; remaining segments form a
    path. A bare host targets ``/.well-known/did.json``. URL-encoded colons
    in the host segment (``%3A``) are decoded.

    Raises ``DIDInvalidIdentifier`` if the suffix would inject URL-component
    boundaries (``/``, ``?``, ``#``, ``@``) after pct-decode, or if the host
    is not a valid hostname / IPv4 literal.
    """
    segments = suffix.split(":")
    if not segments or not segments[0]:
        raise DIDInvalidIdentifier(f"did:web suffix has no host: {suffix!r}")

    host_decoded = _safe_unquote_segment(segments[0], context="host")
    _parse_host_port(host_decoded)  # validates shape; raises on bad host
    path_segments = segments[1:]

    if path_segments:
        decoded_path = "/".join(
            _safe_unquote_segment(s, context="path segment")
            for s in path_segments
        )
        path = decoded_path + "/did.json"
    else:
        path = ".well-known/did.json"

    return f"https://{host_decoded}/{path}"


def _parse_doc(raw_doc: dict, *, requested_did: str) -> DIDDocument:
    """Convert a raw DID document JSON into a typed :class:`DIDDocument`.

    ``requested_did`` is the DID URI the caller asked us to resolve. The
    parsed document's ``id`` field MUST equal it — otherwise an attacker
    who controls a did.json file could claim to be a different DID.
    """
    did_id = raw_doc.get("id")
    if not isinstance(did_id, str) or not did_id.startswith("did:"):
        raise DIDResolutionFailed(
            f"DID document missing or has malformed 'id' field: {did_id!r}"
        )
    if did_id != requested_did:
        raise DIDResolutionFailed(
            f"DID document 'id' ({did_id!r}) does not match requested DID "
            f"({requested_did!r}); refusing to accept impostor document"
        )

    vms: list[VerificationMethod] = []
    for vm_raw in raw_doc.get("verificationMethod", []) or []:
        if not isinstance(vm_raw, dict):
            continue
        jwk = vm_raw.get("publicKeyJwk")
        if not isinstance(jwk, dict):
            # Some documents publish publicKeyMultibase instead; we don't
            # convert here, so we skip these methods. Downstream callers
            # will see "no usable key" and can fall back.
            continue
        vms.append(
            VerificationMethod(
                id=vm_raw.get("id", ""),
                type=vm_raw.get("type", ""),
                controller=vm_raw.get("controller", did_id),
                public_key_jwk=jwk,
            )
        )

    auth = [v if isinstance(v, str) else v.get("id", "") for v in raw_doc.get("authentication", [])]
    asser = [v if isinstance(v, str) else v.get("id", "") for v in raw_doc.get("assertionMethod", [])]

    services: list[ServiceEndpoint] = []
    for svc_raw in raw_doc.get("service", []) or []:
        if not isinstance(svc_raw, dict):
            continue
        services.append(
            ServiceEndpoint(
                id=svc_raw.get("id", ""),
                type=svc_raw.get("type", ""),
                service_endpoint=svc_raw.get("serviceEndpoint", ""),
            )
        )

    also = raw_doc.get("alsoKnownAs", []) or []
    if not isinstance(also, list):
        also = []

    return DIDDocument(
        id=did_id,
        verification_methods=vms,
        authentication=[a for a in auth if a],
        assertion_method=[a for a in asser if a],
        services=services,
        also_known_as=[a for a in also if isinstance(a, str)],
        raw=raw_doc,
    )


def resolve(suffix: str) -> DIDDocument:
    """Resolve ``did:web:<suffix>`` by fetching the DID document over HTTPS."""
    # URL derivation (also validates host + path segment shape).
    url = _suffix_to_url(suffix)

    # SSRF defense: resolve the host once, keep only safe IPs.
    host_with_port = _safe_unquote_segment(suffix.split(":", 1)[0], context="host")
    host_only, _port = _parse_host_port(host_with_port)
    safe_ips = _resolve_and_check_host(host_only)

    max_bytes = int(os.environ.get("KYA_DID_WEB_MAX_DOC_BYTES", str(_DEFAULT_MAX_BYTES)))
    timeout = float(os.environ.get("KYA_DID_WEB_TIMEOUT_S", str(_DEFAULT_TIMEOUT_S)))
    user_agent = os.environ.get("KYA_DID_REQUEST_USER_AGENT", _USER_AGENT_FALLBACK)

    # Pin DNS so urllib3's connection-time lookup cannot be rebound by a
    # malicious authoritative DNS server (V1 — DNS rebinding defense).
    try:
        with _pin_dns(host_only, safe_ips):
            resp = requests.get(
                url,
                headers={
                    "Accept": "application/did+json, application/json",
                    "User-Agent": user_agent,
                },
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
    except requests.RequestException as exc:
        raise DIDResolutionFailed(f"failed to fetch {url!r}: {exc}") from exc

    try:
        if resp.status_code != 200:
            raise DIDResolutionFailed(
                f"did:web fetch returned HTTP {resp.status_code} from {url!r}"
            )

        # Enforce size cap while streaming so we don't OOM on a malicious server.
        payload = bytearray()
        for chunk in resp.iter_content(chunk_size=8192, decode_unicode=False):
            if not chunk:
                continue
            payload.extend(chunk)
            if len(payload) > max_bytes:
                raise DIDDocumentTooLarge(
                    f"did:web document at {url!r} exceeds "
                    f"KYA_DID_WEB_MAX_DOC_BYTES={max_bytes}"
                )
    finally:
        # Release the urllib3 connection even when we abort mid-stream.
        try:
            resp.close()
        except Exception:  # pragma: no cover — close() can't normally fail
            pass

    try:
        raw_doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DIDResolutionFailed(
            f"did:web document at {url!r} is not valid JSON: {exc}"
        ) from exc

    if not isinstance(raw_doc, dict):
        raise DIDResolutionFailed(
            f"did:web document at {url!r} is not a JSON object"
        )

    return _parse_doc(raw_doc, requested_did=f"did:web:{suffix}")
