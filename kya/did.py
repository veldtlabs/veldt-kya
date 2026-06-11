"""KYA's W3C DID adapter.

Public facade. Importing this module gives you everything you need to resolve
a DID URI to a DIDDocument, verify Verifiable Credentials signed by a DID, and
bind a DID-rooted principal into KYA.

Quickstart:

    >>> from kya.did import resolve_did
    >>> doc = resolve_did("did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8")
    >>> vm = doc.verification_methods[0]
    >>> vm.public_key_jwk["kty"], vm.public_key_jwk["crv"]
    ('OKP', 'Ed25519')

Configuration (environment):
    KYA_DID_RESOLVERS         comma list of enabled methods. Unset → disabled.
                              Default when explicitly enabling: "key,web,jwk".
    KYA_DID_TRUSTED_ISSUERS   comma list of issuer DIDs allowed when verifying VCs.
    KYA_DID_WEB_MAX_DOC_BYTES upper bound on did:web document size (default 262144).
    KYA_DID_WEB_TIMEOUT_S     HTTP timeout for did:web fetches (default 5.0).

Custom DID methods can be registered at runtime:

    >>> from kya.did import register_did_method
    >>> def my_plc_resolver(suffix: str): ...
    >>> register_did_method("plc", my_plc_resolver)

Errors are all subclasses of ``DIDError`` and named after the failure mode so
callers can distinguish ``DIDMethodNotEnabled`` from ``DIDDocumentTooLarge``.
"""
from __future__ import annotations

import os
from collections.abc import Callable

from kya.did_document import DIDDocument

__all__ = [
    "DIDError",
    "DIDMethodNotEnabled",
    "DIDInvalidIdentifier",
    "DIDResolutionFailed",
    "DIDDocumentTooLarge",
    "resolve_did",
    "register_did_method",
    "enabled_methods",
    "trusted_issuers",
]


# ─── Errors ──────────────────────────────────────────────────────────


class DIDError(Exception):
    """Base class for all DID errors."""


class DIDMethodNotEnabled(DIDError):
    """The requested DID method is not in ``KYA_DID_RESOLVERS``."""


class DIDInvalidIdentifier(DIDError):
    """The DID URI is malformed."""


class DIDResolutionFailed(DIDError):
    """The DID couldn't be resolved (network error, malformed document, etc.)."""


class DIDDocumentTooLarge(DIDError):
    """did:web document exceeded ``KYA_DID_WEB_MAX_DOC_BYTES``."""


# ─── Registry ────────────────────────────────────────────────────────

# Each resolver takes the DID's method-specific identifier (the part after
# "did:<method>:") and returns a DIDDocument. Resolvers are added lazily by
# this module's import side and can be replaced via register_did_method().
_resolvers: dict[str, Callable[[str], DIDDocument]] = {}


def register_did_method(method: str, resolver: Callable[[str], DIDDocument]) -> None:
    """Register (or override) a DID method resolver.

    The ``method`` must match what appears in the DID URI (e.g., ``"key"`` for
    ``did:key:...``). The resolver callable takes the method-specific suffix
    and returns a :class:`~kya.did_document.DIDDocument`.
    """
    if not method or not isinstance(method, str):
        raise ValueError("method must be a non-empty string")
    _resolvers[method] = resolver


def _load_default_resolvers() -> None:
    """Lazy-import built-in resolvers on first use.

    Built-ins are only loaded when ``KYA_DID_RESOLVERS`` lists them, so a
    deployment that uses only ``did:web`` doesn't pull in multibase decoding
    machinery it doesn't need.
    """
    enabled = enabled_methods()
    if "key" in enabled and "key" not in _resolvers:
        from kya.did_methods.key import resolve as resolve_key
        register_did_method("key", resolve_key)
    if "web" in enabled and "web" not in _resolvers:
        from kya.did_methods.web import resolve as resolve_web
        register_did_method("web", resolve_web)
    if "jwk" in enabled and "jwk" not in _resolvers:
        from kya.did_methods.jwk import resolve as resolve_jwk
        register_did_method("jwk", resolve_jwk)


# ─── Configuration helpers ───────────────────────────────────────────


def enabled_methods() -> set[str]:
    """Return the set of DID methods enabled via env var.

    DID resolution is off by default — the env var must be set explicitly. This
    avoids surprises in existing KYA deployments.
    """
    raw = os.environ.get("KYA_DID_RESOLVERS", "").strip()
    if not raw:
        return set()
    return {m.strip().lower() for m in raw.split(",") if m.strip()}


def trusted_issuers() -> set[str]:
    """Return the set of issuer DIDs explicitly trusted for VC verification.

    Empty set means "trust any DID with a valid signature." For most production
    deployments this should be populated.
    """
    raw = os.environ.get("KYA_DID_TRUSTED_ISSUERS", "").strip()
    if not raw:
        return set()
    return {iss.strip() for iss in raw.split(",") if iss.strip()}


# ─── Public API ──────────────────────────────────────────────────────


def resolve_did(did_uri: str) -> DIDDocument:
    """Resolve a DID URI to its DID document.

    Args:
        did_uri: A DID URI like ``did:key:z6Mk...`` or ``did:web:example.com``.

    Returns:
        The resolved DID document.

    Raises:
        DIDInvalidIdentifier: If the URI doesn't start with ``did:<method>:``.
        DIDMethodNotEnabled: If the method isn't in ``KYA_DID_RESOLVERS``.
        DIDResolutionFailed: If resolution failed (network, malformed doc, etc.).
    """
    if not did_uri or not isinstance(did_uri, str):
        raise DIDInvalidIdentifier("did_uri must be a non-empty string")
    if not did_uri.startswith("did:"):
        raise DIDInvalidIdentifier(f"not a DID: {did_uri!r}")

    parts = did_uri.split(":", 2)
    if len(parts) < 3 or not parts[1] or not parts[2]:
        raise DIDInvalidIdentifier(f"malformed DID: {did_uri!r}")
    _, method, suffix = parts

    enabled = enabled_methods()
    if method not in enabled:
        raise DIDMethodNotEnabled(
            f"did:{method} resolution is not enabled. "
            f"Set KYA_DID_RESOLVERS to include {method!r}. Enabled: {sorted(enabled)}"
        )

    _load_default_resolvers()
    resolver = _resolvers.get(method)
    if resolver is None:
        raise DIDMethodNotEnabled(
            f"no resolver registered for did:{method}. "
            f"Call register_did_method({method!r}, fn) to add one."
        )

    try:
        return resolver(suffix)
    except DIDError:
        raise
    except Exception as exc:
        raise DIDResolutionFailed(f"failed to resolve {did_uri!r}: {exc}") from exc
