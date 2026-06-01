"""Phase 4c -- SPIFFE/OIDC workload identity tests.

Exercises:
  - parse_spiffe_id contract (valid + invalid shapes)
  - trust-domain allowlist resolution (kwarg > env > unrestricted)
  - verify_jwt_svid happy path + reject paths (no JWKS, missing sub,
    sub not a SPIFFE ID, trust domain not in allowlist)
  - bind_spiffe_id_to_principal validates format + allowlist
  - bind_principal_from_svid one-call verify+bind
  - lookup_principal_by_spiffe_id reverse lookup
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from kya import (
    SpiffeIdFormatError,
    bind_principal_from_svid,
    bind_spiffe_id_to_principal,
    init_storage,
    is_allowed_trust_domain,
    is_valid_spiffe_id,
    lookup_principal_by_spiffe_id,
    parse_spiffe_id,
    record_principal_signal,
    verify_jwt_svid,
)


TENANT = "11111111-2222-3333-4444-aaaaaaaa4c00"


@pytest.fixture(autouse=True)
def clean_env():
    keys = [k for k in list(os.environ.keys())
            if k.startswith("KYA_SPIFFE") or k.startswith("KYA_JWT")]
    saved = {k: os.environ.pop(k) for k in keys}
    yield
    for k, v in saved.items():
        os.environ[k] = v


@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:")
    session = sessionmaker(bind=eng)()
    init_storage(session)
    yield session
    session.close()
    eng.dispose()


# ── parse_spiffe_id contract ──────────────────────────────────────


def test_parse_spiffe_id_valid_basic():
    td, path = parse_spiffe_id("spiffe://example.org/ns/prod/sa/svc")
    assert td == "example.org"
    assert path == "/ns/prod/sa/svc"


def test_parse_spiffe_id_trust_domain_only():
    td, path = parse_spiffe_id("spiffe://example.org")
    assert td == "example.org"
    assert path == ""


def test_parse_spiffe_id_real_world_shapes():
    # AWS EKS-style
    td, path = parse_spiffe_id(
        "spiffe://acme.aws/eks/cluster-1/ns/payments/sa/billing")
    assert td == "acme.aws"
    assert path == "/eks/cluster-1/ns/payments/sa/billing"


def test_parse_spiffe_id_rejects_non_str():
    with pytest.raises(SpiffeIdFormatError, match="must be str"):
        parse_spiffe_id(b"spiffe://example.org")
    with pytest.raises(SpiffeIdFormatError, match="must be str"):
        parse_spiffe_id(None)


def test_parse_spiffe_id_rejects_empty():
    with pytest.raises(SpiffeIdFormatError, match="empty"):
        parse_spiffe_id("")


def test_parse_spiffe_id_rejects_oversized():
    big = "spiffe://example.org/" + ("a" * 2050)
    with pytest.raises(SpiffeIdFormatError, match="2048"):
        parse_spiffe_id(big)


def test_parse_spiffe_id_rejects_wrong_scheme():
    with pytest.raises(SpiffeIdFormatError, match="spiffe://"):
        parse_spiffe_id("https://example.org/path")
    with pytest.raises(SpiffeIdFormatError, match="spiffe://"):
        parse_spiffe_id("urn:spiffe:example.org")


def test_parse_spiffe_id_rejects_empty_trust_domain():
    with pytest.raises(SpiffeIdFormatError, match="trust domain"):
        parse_spiffe_id("spiffe:///path")


def test_parse_spiffe_id_rejects_uppercase_trust_domain():
    """Per spec, trust domain must be lowercase."""
    with pytest.raises(SpiffeIdFormatError, match="invalid char"):
        parse_spiffe_id("spiffe://EXAMPLE.ORG/path")


def test_parse_spiffe_id_rejects_invalid_trust_domain_chars():
    for bad in ["spiffe://exa_mple.org/p", "spiffe://exa mple.org/p",
                "spiffe://exa@mple.org/p"]:
        with pytest.raises(SpiffeIdFormatError, match="invalid char"):
            parse_spiffe_id(bad)


def test_parse_spiffe_id_rejects_dot_segments():
    with pytest.raises(SpiffeIdFormatError, match="\\.'"):
        parse_spiffe_id("spiffe://example.org/foo/./bar")
    with pytest.raises(SpiffeIdFormatError, match="\\.\\.'"):
        parse_spiffe_id("spiffe://example.org/foo/../bar")


def test_parse_spiffe_id_rejects_empty_path_segment():
    with pytest.raises(SpiffeIdFormatError, match="empty segment"):
        parse_spiffe_id("spiffe://example.org/foo//bar")


def test_parse_spiffe_id_rejects_query_or_fragment():
    with pytest.raises(SpiffeIdFormatError, match="query or fragment"):
        parse_spiffe_id("spiffe://example.org/p?x=1")
    with pytest.raises(SpiffeIdFormatError, match="query or fragment"):
        parse_spiffe_id("spiffe://example.org/p#frag")


def test_is_valid_spiffe_id():
    assert is_valid_spiffe_id("spiffe://example.org/sa/svc")
    assert not is_valid_spiffe_id("not-a-spiffe-id")
    assert not is_valid_spiffe_id("")


# ── Trust-domain allowlist ───────────────────────────────────────


def test_allowlist_unrestricted_default():
    """No env, no kwarg → all domains allowed."""
    assert is_allowed_trust_domain("anything.example") is True


def test_allowlist_env(monkeypatch):
    monkeypatch.setenv("KYA_SPIFFE_TRUST_DOMAINS",
                       "prod.example.org,staging.example.org")
    assert is_allowed_trust_domain("prod.example.org") is True
    assert is_allowed_trust_domain("staging.example.org") is True
    assert is_allowed_trust_domain("attacker.evil") is False


def test_allowlist_kwarg_overrides_env(monkeypatch):
    monkeypatch.setenv("KYA_SPIFFE_TRUST_DOMAINS", "only-env.example")
    # Explicit kwarg takes precedence
    assert is_allowed_trust_domain(
        "from-kwarg.example",
        allowed=["from-kwarg.example"]) is True
    assert is_allowed_trust_domain(
        "only-env.example",
        allowed=["from-kwarg.example"]) is False


def test_allowlist_handles_whitespace(monkeypatch):
    monkeypatch.setenv("KYA_SPIFFE_TRUST_DOMAINS",
                       "  one.example, two.example  ")
    assert is_allowed_trust_domain("one.example") is True
    assert is_allowed_trust_domain("two.example") is True


# ── verify_jwt_svid ──────────────────────────────────────────────


def test_verify_jwt_svid_returns_none_without_jwks_url():
    """No JWKS configured → fail-soft None."""
    assert verify_jwt_svid("dummy.jwt.signature") is None


def test_verify_jwt_svid_returns_none_on_empty_input():
    assert verify_jwt_svid("") is None
    assert verify_jwt_svid(None) is None  # type: ignore


def test_verify_jwt_svid_returns_none_when_jwt_verify_fails(monkeypatch):
    """When Phase 4a verify_jwt returns None (bad sig / expired /
    wrong audience), this should also return None."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    with patch("kya.auth.verify_jwt", return_value=None):
        assert verify_jwt_svid("bogus.jwt") is None


def test_verify_jwt_svid_returns_none_when_sub_missing(monkeypatch):
    """JWT verified but no `sub` claim → not a SPIFFE SVID."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    with patch("kya.auth.verify_jwt", return_value={"iss": "x"}):
        assert verify_jwt_svid("bogus.jwt") is None


def test_verify_jwt_svid_returns_none_when_sub_not_spiffe_id(monkeypatch):
    """JWT sub claim is not a valid SPIFFE ID."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    with patch("kya.auth.verify_jwt",
               return_value={"sub": "alice@example.com"}):
        assert verify_jwt_svid("bogus.jwt") is None


def test_verify_jwt_svid_rejects_trust_domain_not_in_allowlist(
        monkeypatch):
    """SVID's SPIFFE ID is for a trust domain NOT in the allowlist."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    monkeypatch.setenv("KYA_SPIFFE_TRUST_DOMAINS", "allowed.example")
    fake_claims = {
        "sub": "spiffe://attacker.evil/ns/x/sa/y",
        "iss": "spiffe://attacker.evil",
    }
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        assert verify_jwt_svid("bogus.jwt") is None


def test_verify_jwt_svid_happy_path(monkeypatch):
    """JWT verified, sub is a valid SPIFFE ID in allowlist."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    fake_claims = {
        "sub": "spiffe://example.org/ns/prod/sa/inference",
        "iss": "spiffe://example.org",
        "aud": "kya",
        "exp": 9999999999,
    }
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        result = verify_jwt_svid("ok.jwt")
    assert result is not None
    assert result["spiffe_id"] == "spiffe://example.org/ns/prod/sa/inference"
    assert result["trust_domain"] == "example.org"
    assert result["path"] == "/ns/prod/sa/inference"
    assert result["idp_issuer"] == "spiffe://example.org"
    assert result["claims"] == fake_claims


def test_verify_jwt_svid_allowed_via_kwarg_only(monkeypatch):
    """Trust domain allowlist passed as kwarg (no env)."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    fake_claims = {"sub": "spiffe://custom.td/sa/svc"}
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        result = verify_jwt_svid(
            "ok.jwt", allowed_trust_domains=["custom.td"])
    assert result is not None
    assert result["trust_domain"] == "custom.td"


def test_verify_jwt_svid_falls_back_to_kya_jwt_env(monkeypatch):
    """SPIFFE-specific env missing → falls back to KYA_JWT_* env."""
    monkeypatch.setenv("KYA_JWT_JWKS_URL", "https://generic/jwks")
    fake_claims = {"sub": "spiffe://example.org/sa/x"}
    with patch("kya.auth.verify_jwt", return_value=fake_claims) as m:
        result = verify_jwt_svid("ok.jwt")
    # Should have been called with the JWT_* JWKS URL
    assert m.called
    call_kwargs = m.call_args.kwargs
    assert call_kwargs.get("jwks_url") == "https://generic/jwks"
    assert result is not None


# ── bind_spiffe_id_to_principal ───────────────────────────────────


def test_bind_requires_tenant_and_principal(db):
    with pytest.raises(ValueError, match="tenant_id"):
        bind_spiffe_id_to_principal(
            db, tenant_id="", principal_kind="service_account",
            principal_id="svc-a",
            spiffe_id="spiffe://example.org/sa/svc-a")
    with pytest.raises(ValueError, match="principal_id"):
        bind_spiffe_id_to_principal(
            db, tenant_id=TENANT, principal_kind="service_account",
            principal_id="",
            spiffe_id="spiffe://example.org/sa/svc-a")


def test_bind_returns_false_on_invalid_spiffe_id(db):
    record_principal_signal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-a", signal_kind="clean_invocation")
    assert bind_spiffe_id_to_principal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-a",
        spiffe_id="not-a-spiffe-id") is False


def test_bind_returns_false_when_trust_domain_blocked(db, monkeypatch):
    monkeypatch.setenv("KYA_SPIFFE_TRUST_DOMAINS", "allowed.example")
    record_principal_signal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-a", signal_kind="clean_invocation")
    assert bind_spiffe_id_to_principal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-a",
        spiffe_id="spiffe://attacker.evil/sa/y") is False


def test_bind_happy_path_and_lookup(db):
    record_principal_signal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-a", signal_kind="clean_invocation")
    ok = bind_spiffe_id_to_principal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-a",
        spiffe_id="spiffe://example.org/ns/prod/sa/inference")
    assert ok is True

    found = lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT,
        spiffe_id="spiffe://example.org/ns/prod/sa/inference")
    assert found is not None
    assert found["principal_id"] == "svc-a"
    assert found["principal_kind"] == "service_account"


def test_bind_returns_false_when_principal_doesnt_exist(db):
    """Per Phase 4b semantics — bind only updates existing rows."""
    # No record_principal_signal first → no row to bind
    assert bind_spiffe_id_to_principal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="nonexistent",
        spiffe_id="spiffe://example.org/sa/x") is False


# ── lookup_principal_by_spiffe_id ─────────────────────────────────


def test_lookup_requires_tenant_id(db):
    with pytest.raises(ValueError, match="tenant_id"):
        lookup_principal_by_spiffe_id(
            db, tenant_id="",
            spiffe_id="spiffe://example.org/sa/x")


def test_lookup_returns_none_for_malformed_spiffe_id(db):
    assert lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT, spiffe_id="not-a-spiffe-id") is None


def test_lookup_returns_none_when_no_binding(db):
    assert lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT,
        spiffe_id="spiffe://example.org/sa/unbound") is None


# ── bind_principal_from_svid (one-call) ───────────────────────────


def test_bind_from_svid_verifies_then_binds(db, monkeypatch):
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    record_principal_signal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-b", signal_kind="clean_invocation")
    fake_claims = {"sub": "spiffe://example.org/ns/x/sa/svc-b"}
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        ok = bind_principal_from_svid(
            db, tenant_id=TENANT,
            principal_kind="service_account",
            principal_id="svc-b",
            svid="ok.jwt")
    assert ok is True
    assert lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT,
        spiffe_id="spiffe://example.org/ns/x/sa/svc-b") is not None


def test_bind_from_svid_returns_false_on_verify_failure(db, monkeypatch):
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    record_principal_signal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-c", signal_kind="clean_invocation")
    # verify_jwt returns None → bind is skipped
    with patch("kya.auth.verify_jwt", return_value=None):
        ok = bind_principal_from_svid(
            db, tenant_id=TENANT,
            principal_kind="service_account",
            principal_id="svc-c",
            svid="bad.jwt")
    assert ok is False
    # No binding created
    assert lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT,
        spiffe_id="spiffe://example.org/sa/svc-c") is None


# ── Security fixes from code review ──────────────────────────────


def test_parse_spiffe_id_rejects_invalid_path_chars():
    """Review fix #1: path segments must be [a-zA-Z0-9._-]."""
    for bad in ["spiffe://example.org/foo bar/sa/x",          # space
                "spiffe://example.org/foo%2fbar",              # %-encoded
                "spiffe://example.org/foo@bar",                # @
                "spiffe://example.org/foo:bar"]:               # :
        with pytest.raises(SpiffeIdFormatError, match="invalid char"):
            parse_spiffe_id(bad)


def test_parse_spiffe_id_accepts_spec_allowed_path_chars():
    """Review fix #1: a-z A-Z 0-9 . _ - all allowed."""
    parse_spiffe_id("spiffe://example.org/foo-bar.baz_v1/x")  # ok


def test_verify_jwt_svid_iss_sub_mismatch_rejected(monkeypatch):
    """Review fix #4: iss trust domain must match sub trust domain."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    fake_claims = {
        "sub": "spiffe://prod.example.org/sa/svc",
        "iss": "spiffe://attacker.evil",  # MISMATCH
    }
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        result = verify_jwt_svid("malicious.jwt")
    assert result is None


def test_verify_jwt_svid_iss_match_accepted(monkeypatch):
    """Review fix #4: matching iss is fine."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    fake_claims = {
        "sub": "spiffe://prod.example.org/sa/svc",
        "iss": "spiffe://prod.example.org",
    }
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        result = verify_jwt_svid("ok.jwt")
    assert result is not None


def test_verify_jwt_svid_no_iss_is_allowed(monkeypatch):
    """Review fix #4: iss is OPTIONAL in JWT-SVID spec; missing is OK."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    fake_claims = {"sub": "spiffe://example.org/sa/svc"}  # no iss
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        result = verify_jwt_svid("ok.jwt")
    assert result is not None


def test_verify_jwt_svid_iss_malformed_rejected(monkeypatch):
    """Review fix #4: garbage in iss is rejected."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    fake_claims = {
        "sub": "spiffe://example.org/sa/svc",
        "iss": "not-a-spiffe-id",
    }
    with patch("kya.auth.verify_jwt", return_value=fake_claims):
        result = verify_jwt_svid("malformed.jwt")
    assert result is None


def test_verify_jwt_svid_swallows_verify_jwt_exception(monkeypatch):
    """Review fix #3: if Phase 4a raises, we still return None."""
    monkeypatch.setenv("KYA_SPIFFE_JWKS_URL", "https://example.org/jwks")
    with patch("kya.auth.verify_jwt",
               side_effect=ValueError("simulated programmer error")):
        result = verify_jwt_svid("any.jwt")
    assert result is None


def test_lookup_filters_by_idp_kind(db):
    """Review fix #11: lookup_principal_by_spiffe_id refuses to return
    a row that was bound with a non-spiffe idp_kind."""
    from kya import bind_principal_to_idp
    record_principal_signal(
        db, tenant_id=TENANT, principal_kind="service_account",
        principal_id="svc-x", signal_kind="clean_invocation")
    # Sloppy caller stores a spiffe-looking string under idp_kind="okta"
    bind_principal_to_idp(
        db, tenant_id=TENANT,
        principal_kind="service_account",
        principal_id="svc-x",
        idp_subject="spiffe://example.org/sa/svc-x",
        idp_kind="okta")
    # lookup_principal_by_spiffe_id must NOT return this row.
    assert lookup_principal_by_spiffe_id(
        db, tenant_id=TENANT,
        spiffe_id="spiffe://example.org/sa/svc-x") is None


def test_unrestricted_allowlist_emits_warning(caplog):
    """Review fix #12: when no allowlist configured, emit warning."""
    import logging
    from kya import _reset_spiffe_warned_state
    _reset_spiffe_warned_state()
    with caplog.at_level(logging.WARNING, logger="kya.spiffe"):
        # First call should warn
        is_allowed_trust_domain("anything.example")
        # Second call should NOT warn again (one-time latch)
        is_allowed_trust_domain("other.example")
    warns = [r for r in caplog.records
             if "no trust-domain allowlist configured" in r.message]
    assert len(warns) == 1  # exactly once
