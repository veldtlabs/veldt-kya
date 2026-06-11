"""W3C Verifiable Credentials verifier (JWT-VC profile).

KYA verifies Verifiable Credentials issued in the JWT-VC format (the most
widely deployed VC shape — used by Microsoft Entra Verified ID, Trinsic,
Indicio, mDL, etc.). The verifier:

1. Parses the JWT.
2. Resolves the issuer DID (from ``iss`` claim) via :mod:`kya.did`.
3. Verifies the signature against the DID document's verification method.
4. Validates standard claims: ``exp`` (required), ``iat`` (must not be future),
   ``nbf`` (if present).
5. Optionally checks the issuer DID against ``KYA_DID_TRUSTED_ISSUERS``.

JSON-LD VCs are out of scope for MVP — JWT-VC covers the practical ground.

Reference: https://www.w3.org/TR/vc-data-model-2.0/
JWT-VC profile: https://www.w3.org/TR/vc-jwt/
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import jwt as pyjwt

from kya.did import (
    DIDError,
    DIDResolutionFailed,
    resolve_did,
    trusted_issuers,
)
from kya.did_document import DIDDocument

__all__ = [
    "VCError",
    "VCSignatureInvalid",
    "VCExpired",
    "VCNotYetValid",
    "VCIssuerNotTrusted",
    "VCMalformed",
    "VerifiedCredential",
    "verify_vc",
]


# ─── Errors ──────────────────────────────────────────────────────────


class VCError(Exception):
    """Base class for Verifiable Credential errors."""


class VCSignatureInvalid(VCError):
    """The VC's JWT signature could not be verified against the issuer's DID."""


class VCExpired(VCError):
    """The VC has expired (``exp`` claim is in the past)."""


class VCNotYetValid(VCError):
    """The VC isn't valid yet (``nbf`` claim is in the future)."""


class VCIssuerNotTrusted(VCError):
    """Issuer DID is not in ``KYA_DID_TRUSTED_ISSUERS``."""


class VCMalformed(VCError):
    """The JWT-VC is not well-formed."""


@dataclass(frozen=True)
class VerifiedCredential:
    """A successfully verified VC.

    Fields:
        issuer_did: The ``iss`` claim from the JWT.
        subject_did: The ``sub`` claim (the holder/agent the credential is about).
        claims: The decoded JWT claim set.
        issuer_doc: The resolved issuer DID document used for verification.
        issuer_doc_hash: SHA-256 of the issuer DID document — capture this in
            the evidence chain so the verification context is reproducible.
    """

    issuer_did: str
    subject_did: str | None
    claims: dict[str, Any]
    issuer_doc: DIDDocument
    issuer_doc_hash: str


def _pick_verification_method(
    issuer_doc: DIDDocument, kid: str | None
) -> "VerificationMethod":
    """Pick the verification method that signed the VC.

    If ``kid`` is present in the JWS header, the VM with that id (matched
    by exact id OR by the fragment after ``#``) MUST be in the issuer's
    assertion-method list. If ``kid`` is absent and the issuer has exactly
    one VM, that VM is used (backward compat for single-key docs). If
    ``kid`` is absent and the issuer has multiple VMs, the verifier
    refuses — silently picking the first one is a footgun for key rotation.
    """
    if not issuer_doc.verification_methods:
        raise VCSignatureInvalid(
            f"issuer DID {issuer_doc.id!r} has no verification methods"
        )

    if kid is not None:
        # The VM must be referenced by assertionMethod for VC signing.
        # find_key matches exact id OR endswith #<fragment>.
        vm = issuer_doc.find_key(kid)
        if vm is None:
            raise VCSignatureInvalid(
                f"VC JWS header kid={kid!r} does not match any verification "
                f"method in issuer DID {issuer_doc.id!r}"
            )
        # Enforce assertion-method scope when the document declares one.
        # Full-id equality only — fragment-based fallbacks can match a VM
        # whose controller is a different DID than the one resolving here.
        if issuer_doc.assertion_method:
            if vm.id not in set(issuer_doc.assertion_method):
                raise VCSignatureInvalid(
                    f"VC kid={kid!r} resolves to VM {vm.id!r} but it is not "
                    f"in the issuer's assertionMethod set"
                )
        return vm

    # No kid in header.
    if len(issuer_doc.verification_methods) > 1:
        raise VCSignatureInvalid(
            f"issuer DID {issuer_doc.id!r} has multiple verification methods "
            f"and the VC JWS header has no kid — refusing to guess which key "
            f"signed (ambiguous)"
        )
    return issuer_doc.verification_methods[0]


def _algorithms_for_jwk(jwk: dict[str, Any], issuer_id: str) -> list[str]:
    """Return the single algorithm PyJWT should accept for this JWK.

    Honors ``jwk["alg"]`` when present (W3C VC-JWT recommends pinning).
    Otherwise picks the canonical single algorithm for the key type — never
    a family (which would be a downgrade surface).
    """
    explicit_alg = jwk.get("alg")
    kty = jwk.get("kty")
    crv = jwk.get("crv")

    _ALLOWED_FOR_KTY = {
        ("OKP", "Ed25519"): {"EdDSA"},
        ("EC", "secp256k1"): {"ES256K"},
        ("EC", "P-256"): {"ES256"},
        ("EC", "P-384"): {"ES384"},
        ("EC", "P-521"): {"ES512"},
    }
    rsa_allowed = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

    if explicit_alg is not None:
        if not isinstance(explicit_alg, str):
            raise VCSignatureInvalid(
                f"issuer DID {issuer_id!r} JWK has non-string 'alg' field"
            )
        if kty == "RSA":
            if explicit_alg not in rsa_allowed:
                raise VCSignatureInvalid(
                    f"issuer DID {issuer_id!r} RSA JWK declares unsupported "
                    f"alg={explicit_alg!r}"
                )
        else:
            allowed = _ALLOWED_FOR_KTY.get((kty, crv))
            if allowed is None or explicit_alg not in allowed:
                raise VCSignatureInvalid(
                    f"issuer DID {issuer_id!r} JWK alg={explicit_alg!r} does "
                    f"not match key type kty={kty!r} crv={crv!r}"
                )
        return [explicit_alg]

    # Default per kty/crv — single algorithm only.
    if (kty, crv) in _ALLOWED_FOR_KTY:
        return [next(iter(_ALLOWED_FOR_KTY[(kty, crv)]))]
    if kty == "RSA":
        # No explicit alg — pick RS256 as the conservative default.
        # If issuers want PS256 they must declare it in the JWK.
        return ["RS256"]

    raise VCSignatureInvalid(
        f"issuer DID {issuer_id!r} uses unsupported key type "
        f"kty={kty!r} crv={crv!r}"
    )


def verify_vc(
    jwt_vc: str,
    *,
    audience: str | None = None,
    trusted: set[str] | None = None,
    now: int | None = None,
    leeway_seconds: int = 30,
) -> VerifiedCredential:
    """Verify a Verifiable Credential in JWT-VC format.

    Args:
        jwt_vc: The JWT-VC string (three base64url segments separated by dots).
        audience: If set, the JWT's ``aud`` claim must match (defense against
            replay against a different relying party).
        trusted: Optional explicit allowlist of issuer DIDs. If omitted, falls
            back to ``KYA_DID_TRUSTED_ISSUERS``. An empty set after fallback
            means "trust any DID with a valid signature."
        now: Override the current time (seconds since epoch). Useful for tests.
        leeway_seconds: Clock skew tolerance on ``exp``/``nbf``/``iat``.

    Returns:
        A :class:`VerifiedCredential` with the issuer DID, subject DID, claim
        set, and a hash of the issuer document for evidence capture.

    Raises:
        VCMalformed: JWT is not parseable.
        VCSignatureInvalid: Signature check failed (or no usable key in issuer
            DID document).
        VCExpired / VCNotYetValid: Time-bound check failed.
        VCIssuerNotTrusted: Issuer is not in the trusted allowlist.
    """
    if not jwt_vc or not isinstance(jwt_vc, str):
        raise VCMalformed("jwt_vc must be a non-empty string")
    if jwt_vc.count(".") != 2:
        raise VCMalformed("jwt_vc is not a JWT (expected 3 base64url segments)")

    # Step 1 — extract the unverified issuer so we can fetch their key.
    try:
        unverified = pyjwt.decode(jwt_vc, options={"verify_signature": False})
    except pyjwt.InvalidTokenError as exc:
        raise VCMalformed(f"JWT decode failed: {exc}") from exc

    issuer = unverified.get("iss")
    if not isinstance(issuer, str) or not issuer.startswith("did:"):
        raise VCMalformed(f"VC issuer (iss) must be a DID, got {issuer!r}")

    # Step 2 — enforce the trusted-issuer allowlist (if configured).
    trust_set = trusted if trusted is not None else trusted_issuers()
    if trust_set and issuer not in trust_set:
        raise VCIssuerNotTrusted(
            f"issuer {issuer!r} not in trusted set ({sorted(trust_set)})"
        )

    # Step 3 — resolve the issuer's DID document.
    try:
        doc = resolve_did(issuer)
    except DIDError as exc:
        raise VCSignatureInvalid(
            f"could not resolve issuer DID {issuer!r}: {exc}"
        ) from exc

    # Step 3a — read the JWS header to learn which key signed.
    try:
        header = pyjwt.get_unverified_header(jwt_vc)
    except pyjwt.InvalidTokenError as exc:
        raise VCMalformed(f"JWT header decode failed: {exc}") from exc
    kid = header.get("kid") if isinstance(header, dict) else None
    if kid is not None and not isinstance(kid, str):
        raise VCMalformed(f"JWT header kid must be a string, got {type(kid).__name__}")
    if kid == "":
        kid = None  # Empty string is not a valid kid — treat as absent.

    vm = _pick_verification_method(doc, kid)
    jwk = vm.public_key_jwk
    algorithms = _algorithms_for_jwk(jwk, doc.id)

    # Step 4 — verify the signature + standard claims.
    try:
        verified_claims = pyjwt.decode(
            jwt_vc,
            key=pyjwt.PyJWK(jwk).key,
            algorithms=algorithms,
            audience=audience,
            leeway=leeway_seconds,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": audience is not None,
                "require": ["exp", "iss"],
            },
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise VCExpired(str(exc)) from exc
    except pyjwt.ImmatureSignatureError as exc:
        raise VCNotYetValid(str(exc)) from exc
    except pyjwt.InvalidSignatureError as exc:
        raise VCSignatureInvalid(f"VC signature failed verification: {exc}") from exc
    except pyjwt.InvalidTokenError as exc:
        raise VCSignatureInvalid(f"VC token invalid: {exc}") from exc

    # Optional belt-and-suspenders: explicit ``now`` override for tests.
    if now is not None:
        exp = verified_claims.get("exp")
        if isinstance(exp, (int, float)) and now > exp + leeway_seconds:
            raise VCExpired(f"VC expired at {exp}, now={now}")
        nbf = verified_claims.get("nbf")
        if isinstance(nbf, (int, float)) and now + leeway_seconds < nbf:
            raise VCNotYetValid(f"VC not valid before {nbf}, now={now}")

    subject = verified_claims.get("sub")
    if not isinstance(subject, str):
        subject = None

    return VerifiedCredential(
        issuer_did=issuer,
        subject_did=subject,
        claims=verified_claims,
        issuer_doc=doc,
        issuer_doc_hash=doc.doc_hash,
    )


def _now_seconds() -> int:
    return int(time.time())
