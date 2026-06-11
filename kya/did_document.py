"""DID document data model.

Minimal W3C DID Core 1.0 data shapes — enough for KYA's verifier to identify
the public key behind a DID URI and to capture a stable document hash for the
evidence chain.

Reference: https://www.w3.org/TR/did-core/
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VerificationMethod:
    """A public key in the DID document.

    The MVP cares about ``public_key_jwk`` — the JWK form of the verification
    key. Other forms (``publicKeyMultibase``, ``publicKeyBase58``) are converted
    to JWK by the resolver before this dataclass is built.
    """

    id: str
    type: str
    controller: str
    public_key_jwk: dict[str, Any]


@dataclass(frozen=True)
class ServiceEndpoint:
    """A DID service endpoint (e.g., a credential exchange URL)."""

    id: str
    type: str
    service_endpoint: str | dict[str, Any]


@dataclass(frozen=True)
class DIDDocument:
    """Resolved DID document.

    Notes:
        ``raw`` is the as-fetched (or as-derived) JSON object. It's preserved
        so the evidence chain can capture an exact hash of what was verified.
    """

    id: str
    verification_methods: list[VerificationMethod] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    assertion_method: list[str] = field(default_factory=list)
    services: list[ServiceEndpoint] = field(default_factory=list)
    also_known_as: list[str] = field(default_factory=list)
    raw: dict[str, Any] | None = None

    @property
    def doc_hash(self) -> str:
        """SHA-256 hex of the canonical DID document JSON.

        Used by the evidence chain to pin the verification context. If the
        DID's keys rotate after evidence is written, this hash still resolves
        to the document that *did* verify the original action.
        """
        if not self.raw:
            return ""
        canon = json.dumps(self.raw, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()

    def find_key(self, key_id: str | None = None) -> VerificationMethod | None:
        """Return a verification method by id, or the first one if ``key_id`` is None."""
        if not self.verification_methods:
            return None
        if key_id is None:
            return self.verification_methods[0]
        for vm in self.verification_methods:
            if vm.id == key_id or vm.id.endswith("#" + key_id):
                return vm
        return None
