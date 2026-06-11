"""Identity binding for KYA Gateway.

Resolves the calling principal from one of the configured identity methods:

* ``bearer_jwt`` — bearer JWT in the ``Authorization`` header (KYA's existing
  ``kya.auth`` introspection).
* ``did`` — a DID URI passed as a custom header (default: ``X-KYA-DID``).
  Requires a proof-of-possession JWT in ``X-KYA-DID-Proof`` signed by a key
  in the DID document's authentication set, unless the deployment opts into
  ``identity.did.allow_header_trust = true`` (only safe behind a service
  mesh that has already authenticated the caller).
* ``spiffe`` — SPIFFE workload identity via SVID header.

Methods are tried in the order configured via ``identity.methods`` in
``gateway.yaml``. When a method's header is PRESENT but invalid, the
resolver hard-fails — it does NOT fall through to the next method (that
would let a malformed bearer token become a free pass to a self-claimed
DID header).

The resolver returns a typed ``BoundPrincipal`` dataclass — downstream
modules never look at raw headers.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from kya_gateway.config import IdentityConfig
from kya_gateway.errors import (
    IdentityBindingFailed,
    IdentityCredentialInvalid,
    RevocationBlocked,
)

logger = logging.getLogger(__name__)

# Header names the gateway recognizes. Documented in the requirements doc.
HEADER_AUTHORIZATION = "Authorization"
HEADER_DID = "X-KYA-DID"
HEADER_VC = "X-KYA-VC"
HEADER_DID_PROOF = "X-KYA-DID-Proof"
HEADER_SPIFFE_SVID = "X-SVID-JWT"

# Defaults applied when an unknown / untrusted issuer carries a
# `principal_kind` claim. The least-privileged principal kind wins.
_SAFE_DEFAULT_PRINCIPAL_KIND = "agent"
_SAFE_DEFAULT_PRINCIPAL_KIND_SPIFFE = "service_account"


def _extract_vc_principal_attr(vc_claims: dict, key: str) -> str | None:
    """Pull a custom principal-shaped attribute out of a verified VC.

    W3C VC-JWT spec: custom claims (anything the issuer adds beyond the
    standard JWT fields) live under ``vc.credentialSubject``. Some
    non-spec-compliant issuers stamp the same claim at the JWT top
    level instead -- we accept either location, preferring the spec-
    compliant nested form.

    Phase 12 surfaced that the gateway was reading ONLY the top level,
    so a VC issued by KYA's own JWTVCIssuer (which is W3C-correct and
    puts claims under credentialSubject) was never matched. Result:
    the gateway treated every agent's principal_id as the agent's
    DID, bypassing the operator-chosen stable id.

    Returns the string value or None if not present in either location.
    """
    if not isinstance(vc_claims, dict):
        return None
    vc_block = vc_claims.get("vc")
    if isinstance(vc_block, dict):
        cs = vc_block.get("credentialSubject")
        if isinstance(cs, dict):
            v = cs.get(key)
            if v is not None and v != "":
                return str(v)
    v = vc_claims.get(key)
    if v is not None and v != "":
        return str(v)
    return None


@dataclass(frozen=True)
class BoundPrincipal:
    """The principal calling the gateway."""

    principal_kind: str           # "agent" / "user" / "service_account" / etc.
    principal_id: str             # KYA's principal_id
    method: str                   # "bearer_jwt" | "did" | "spiffe"
    external_subject: str         # The IdP subject / DID / SVID
    external_issuer: str | None   # The issuer of the credential
    claims: dict | None = None    # Decoded claim set (for downstream policy)


class IdentityResolver:
    """Tries each configured method in order, returns the first match."""

    def __init__(self, config: IdentityConfig):
        self.config = config

    def resolve(self, headers: dict[str, str]) -> BoundPrincipal:
        """Inspect the request headers and return a BoundPrincipal.

        Raises:
            IdentityBindingFailed: No configured method produced a principal,
                OR a header was present but the credential was invalid (in
                the latter case, no fallthrough is attempted).
        """
        normalized = {k.lower(): v for k, v in headers.items()}

        last_missing: IdentityBindingFailed | None = None
        for method in self.config.methods:
            method = method.lower()
            try:
                if method == "bearer_jwt":
                    return self._try_jwt(normalized)
                if method == "did":
                    return self._try_did(normalized)
                if method == "spiffe":
                    return self._try_spiffe(normalized)
            except IdentityCredentialInvalid:
                # Header was present and credential failed — hard fail.
                raise
            except IdentityBindingFailed as exc:
                # Header was absent — try the next method.
                last_missing = exc
                continue

        if last_missing is not None:
            raise last_missing
        raise IdentityBindingFailed(
            f"no configured identity method produced a principal "
            f"(methods={self.config.methods})"
        )

    # ─── per-method handlers ────────────────────────────────────────

    def _try_jwt(self, h: dict[str, str]) -> BoundPrincipal:
        auth = h.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            # No header → not this method.
            raise IdentityBindingFailed("no bearer token in Authorization header")
        token = auth.split(" ", 1)[1].strip()
        if not token:
            # Header IS present but empty — invalid credential.
            raise IdentityCredentialInvalid("empty bearer token")

        try:
            from kya.auth import introspect_jwt  # type: ignore[attr-defined]
        except ImportError:
            raise IdentityCredentialInvalid(
                "kya.auth.introspect_jwt unavailable — install KYA core auth"
            )

        try:
            claims = introspect_jwt(token)
        except Exception as exc:
            # Header present + token invalid → HARD FAIL (no fallthrough).
            raise IdentityCredentialInvalid(
                f"bearer JWT failed verification: {exc}"
            ) from exc

        subject = str(claims.get("sub") or "")
        if not subject:
            raise IdentityCredentialInvalid("JWT has no 'sub' claim")
        issuer = claims.get("iss")

        # B13: only honor self-elevating claims (principal_kind / _id) if the
        # token was signed by an issuer the operator explicitly trusts.
        trusted = set((self.config.jwt.trusted_issuers if self.config.jwt else []) or [])
        if issuer in trusted:
            principal_kind = str(claims.get("principal_kind") or _SAFE_DEFAULT_PRINCIPAL_KIND)
            principal_id = str(claims.get("principal_id") or subject)
        else:
            principal_kind = _SAFE_DEFAULT_PRINCIPAL_KIND
            principal_id = subject

        return BoundPrincipal(
            principal_kind=principal_kind,
            principal_id=principal_id,
            method="bearer_jwt",
            external_subject=subject,
            external_issuer=issuer,
            claims=claims,
        )

    def _try_did(self, h: dict[str, str]) -> BoundPrincipal:
        did = h.get(HEADER_DID.lower())
        if not did:
            raise IdentityBindingFailed(f"no {HEADER_DID} header")

        try:
            from kya.did import resolve_did
        except ImportError:
            raise IdentityCredentialInvalid(
                "kya.did unavailable — install veldt-kya[did]"
            )

        try:
            doc = resolve_did(did)
        except Exception as exc:
            # DID header present but unresolvable — hard fail.
            raise IdentityCredentialInvalid(
                f"DID {did!r} could not be resolved: {exc}"
            ) from exc

        did_cfg = self.config.did
        allow_header_trust = bool(did_cfg and did_cfg.allow_header_trust)

        # B14: require a proof-of-possession JWT unless the operator
        # explicitly opted into header-trust mode.
        if not allow_header_trust:
            pop_jwt = h.get(HEADER_DID_PROOF.lower())
            if not pop_jwt:
                raise IdentityCredentialInvalid(
                    f"DID {did!r} requires a {HEADER_DID_PROOF} proof-of-possession "
                    f"JWT (or set identity.did.allow_header_trust=true)"
                )
            self._verify_did_pop(pop_jwt, did=did, doc=doc)

        # Optional VC for delegated claims.
        vc_claims: dict | None = None
        vc_issuer: str | None = None
        vc_header = h.get(HEADER_VC.lower())
        if vc_header:
            try:
                from kya.vc import verify_vc
                verified = verify_vc(vc_header)
                vc_claims = dict(verified.claims)
                vc_issuer = verified.issuer_did
            except Exception as exc:
                # VC header present but invalid — hard fail.
                raise IdentityCredentialInvalid(
                    f"VC verification failed: {exc}"
                ) from exc
            # Optional revocation check via pro. Lazy-imports kya_pro so
            # OSS-only deployments don't pay the import cost. Failure to
            # import (pro not installed) is silently a no-op — operators
            # who set revocation_check=true without pro installed get a
            # warning at startup but the gateway still serves.
            if did_cfg and did_cfg.revocation_check:
                self._maybe_check_revocation(verified)

        # B13: only trust principal_kind from a VC issued by a trusted DID.
        # Phase 12 fix: extract via _extract_vc_principal_attr so the
        # W3C-compliant `vc.credentialSubject.<key>` location is honored
        # (KYA's own JWTVCIssuer puts claims there; pre-fix gateway only
        # looked at top-level and never matched, so principal_id always
        # fell back to the agent's DID).
        trusted_did_issuers = set((did_cfg.trusted_issuers if did_cfg else []) or [])
        if vc_claims and vc_issuer and vc_issuer in trusted_did_issuers:
            principal_kind = (
                _extract_vc_principal_attr(vc_claims, "principal_kind")
                or _SAFE_DEFAULT_PRINCIPAL_KIND
            )
            principal_id = (
                _extract_vc_principal_attr(vc_claims, "principal_id")
                or did
            )
        else:
            principal_kind = _SAFE_DEFAULT_PRINCIPAL_KIND
            principal_id = did

        external_issuer = vc_issuer or did
        external_subject = did
        return BoundPrincipal(
            principal_kind=principal_kind,
            principal_id=principal_id,
            method="did",
            external_subject=external_subject,
            external_issuer=external_issuer,
            claims={"did_doc_hash": doc.doc_hash, **(vc_claims or {})},
        )

    def _try_spiffe(self, h: dict[str, str]) -> BoundPrincipal:
        svid = h.get(HEADER_SPIFFE_SVID.lower())
        if not svid:
            raise IdentityBindingFailed(f"no {HEADER_SPIFFE_SVID} header")
        try:
            from kya.spiffe import verify_svid_jwt  # type: ignore[attr-defined]
        except ImportError:
            raise IdentityCredentialInvalid(
                "kya.spiffe unavailable — install KYA core SPIFFE module"
            )

        try:
            claims = verify_svid_jwt(svid)
        except Exception as exc:
            raise IdentityCredentialInvalid(
                f"SPIFFE SVID failed verification: {exc}"
            ) from exc

        subject = str(claims.get("sub") or "")
        if not subject.startswith("spiffe://"):
            raise IdentityCredentialInvalid(
                f"SVID 'sub' is not a SPIFFE ID: {subject!r}"
            )

        # SPIFFE issuers (the SPIRE trust domain) are trusted by definition
        # because the SVID signature itself is the trust gate. Still default
        # principal_kind to service_account; don't honor self-elevation.
        principal_kind = _SAFE_DEFAULT_PRINCIPAL_KIND_SPIFFE
        principal_id = subject

        return BoundPrincipal(
            principal_kind=principal_kind,
            principal_id=principal_id,
            method="spiffe",
            external_subject=subject,
            external_issuer=claims.get("iss"),
            claims=claims,
        )

    # ─── proof-of-possession helper ─────────────────────────────────

    def _maybe_check_revocation(self, verified) -> None:
        """Run kya_pro.revocation.RevocationChecker if available.

        Constructed lazily on first call and cached on the resolver so we
        don't rebuild the cache+lock state per request. If kya_pro isn't
        installed, log once and no-op.
        """
        if getattr(self, "_revocation_checker_attempted", False):
            checker = getattr(self, "_revocation_checker", None)
        else:
            self._revocation_checker_attempted = True
            try:
                from urllib.error import URLError

                # Use urllib stdlib so we don't add httpx to the gateway.
                from urllib.request import urlopen

                from kya_pro.revocation import RevocationChecker, RevocationError

                def _fetch(url: str) -> bytes:
                    try:
                        with urlopen(url, timeout=10) as resp:
                            return resp.read()
                    except URLError as exc:
                        raise ConnectionError(str(exc))

                did_cfg = self.config.did
                checker = RevocationChecker(
                    http_fetch=_fetch,
                    trusted_issuers=set(did_cfg.trusted_issuers or []),
                    cache_ttl_seconds=did_cfg.revocation_cache_ttl_seconds,
                    fail_mode="closed",
                )
                self._revocation_checker = checker
                self._RevocationError = RevocationError
            except ImportError:
                logger.warning(
                    "[KYA-GATEWAY] revocation_check=true but kya_pro is not "
                    "installed — revocation checks are no-ops"
                )
                self._revocation_checker = None
                checker = None

        if checker is None:
            return
        try:
            checker.check(verified)
        except self._RevocationError as exc:
            # Phase 5g #3 — distinct subclass so the gateway can emit a
            # `revocation_blocked` security event when this fires,
            # separate from generic credential-invalid failures.
            raise RevocationBlocked(
                f"VC was revoked or status check failed: {exc}"
            ) from exc

    def _verify_did_pop(self, pop_jwt: str, *, did: str, doc) -> None:
        """Verify a DID proof-of-possession JWT.

        Requirements:
        - ``iss`` claim must equal ``did``.
        - ``aud`` claim must equal ``did_cfg.pop_audience`` if configured.
        - ``iat`` / ``exp`` must be present and valid (with leeway).
        - JWS must be signed by a verification method in the DID
          document's ``authentication`` list (not just any VM).
        """
        try:
            import jwt as pyjwt
        except ImportError as exc:
            raise IdentityCredentialInvalid(
                "pyjwt unavailable — install veldt-kya[did]"
            ) from exc

        did_cfg = self.config.did
        leeway = did_cfg.pop_leeway_seconds if did_cfg else 30

        try:
            header = pyjwt.get_unverified_header(pop_jwt)
        except pyjwt.InvalidTokenError as exc:
            raise IdentityCredentialInvalid(
                f"PoP JWT header invalid: {exc}"
            ) from exc

        kid = header.get("kid") if isinstance(header, dict) else None
        if not kid or not isinstance(kid, str):
            raise IdentityCredentialInvalid(
                "PoP JWT must include a 'kid' header pointing at a "
                "verification method in the DID document"
            )

        vm = doc.find_key(kid)
        if vm is None:
            raise IdentityCredentialInvalid(
                f"PoP JWT kid={kid!r} not found in DID document for {did!r}"
            )

        # PoP requires the signing key to be in the DID's `authentication`
        # set. A document with an EMPTY `authentication` array is rejected —
        # silently falling back to "any VM in document" would let a key
        # marked only for `assertionMethod` (i.e., a VC-signing key) act
        # as an authentication key.
        auth_ids = set(doc.authentication or [])
        if not auth_ids:
            raise IdentityCredentialInvalid(
                f"DID {did!r} document has no 'authentication' verification "
                f"methods declared — refusing to accept PoP"
            )
        if vm.id not in auth_ids:
            raise IdentityCredentialInvalid(
                f"PoP JWT kid={kid!r} resolves to VM {vm.id!r} which is "
                f"not in the DID's authentication set"
            )

        # Pick algorithm from the JWK (single-alg, no family acceptance).
        from kya.vc import _algorithms_for_jwk  # type: ignore[attr-defined]
        algorithms = _algorithms_for_jwk(vm.public_key_jwk, doc.id)

        # Audience binding is mandatory — without it, a PoP minted for
        # one gateway could be replayed against another. Operators who
        # want headerless trust set `allow_header_trust=True` instead.
        aud = did_cfg.pop_audience if did_cfg else None
        if not aud:
            raise IdentityCredentialInvalid(
                "identity.did.pop_audience is not configured; refusing to "
                "accept PoP without audience binding (set pop_audience to "
                "this gateway's externally visible URL, or set "
                "allow_header_trust=true for header-trust mode)"
            )
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_nbf": True,
            "verify_aud": True,
            "require": ["iss", "exp", "iat"],
        }
        try:
            claims = pyjwt.decode(
                pop_jwt,
                key=pyjwt.PyJWK(vm.public_key_jwk).key,
                algorithms=algorithms,
                audience=aud,
                leeway=leeway,
                options=options,
            )
        except pyjwt.InvalidTokenError as exc:
            raise IdentityCredentialInvalid(
                f"PoP JWT verification failed: {exc}"
            ) from exc

        if claims.get("iss") != did:
            raise IdentityCredentialInvalid(
                f"PoP JWT iss={claims.get('iss')!r} does not match DID {did!r}"
            )

        # Reject PoPs whose REMAINING lifetime exceeds the cap. Comparing
        # against `now` (not `exp - iat`) defeats the attacker who mints
        # iat=now+3600, exp=now+3700 — the iat-relative math sees a 100s
        # window but the PoP is actually usable from now until exp.
        exp = claims.get("exp")
        now = int(time.time())
        if isinstance(exp, (int, float)):
            if exp - now > 600 + leeway:  # 10 minutes max real-time window
                raise IdentityCredentialInvalid(
                    f"PoP JWT remaining lifetime {exp - now}s exceeds 600s "
                    f"cap (treat long-lived PoPs as stolen credentials)"
                )
