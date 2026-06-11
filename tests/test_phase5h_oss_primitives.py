"""Phase 5h — OSS-side primitives the pro issuer-API depends on.

- New evidence kinds registered in VALID_EVIDENCE_KINDS
- New security event kind in _HARDENING_EVENT_KINDS + realtime + SIGNAL_DELTAS
- `admin` principal kind extension
- DID-aware segment matcher (`_did_segment_match` + `_PATTERN_RE`)
- DID method-aware admin principal_id normalization
"""
from __future__ import annotations

# ─── New evidence kinds ─────────────────────────────────────────────


def test_phase5h_evidence_kinds_registered():
    from kya.evidence import VALID_EVIDENCE_KINDS
    new = {
        "vc_request_queued",
        "vc_request_approved",
        "vc_request_auto_approved",
        "vc_request_denied",
    }
    missing = new - set(VALID_EVIDENCE_KINDS)
    assert not missing, f"missing: {sorted(missing)}"


# ─── New security event kind in all three whitelists ────────────────


def test_phase5h_security_event_in_all_whitelists():
    """Phase 5g lesson — a security event kind must be registered in
    _HARDENING_EVENT_KINDS AND ALLOWED_SIGNAL_KINDS AND SIGNAL_DELTAS
    or it silently drops at the realtime / DB persistence path."""
    from kya._security_events import _HARDENING_EVENT_KINDS
    from kya.realtime import ALLOWED_SIGNAL_KINDS
    from kya.users import SIGNAL_DELTAS
    assert "vc_approval_denied" in _HARDENING_EVENT_KINDS
    assert "vc_approval_denied" in ALLOWED_SIGNAL_KINDS
    assert "vc_approval_denied" in SIGNAL_DELTAS


# ─── `admin` principal kind ─────────────────────────────────────────


def test_phase5h_admin_principal_kind_registered():
    from kya.principals import PRINCIPAL_KINDS
    assert "admin" in PRINCIPAL_KINDS


# ─── DID-aware segment matcher ──────────────────────────────────────


def test_did_segment_match_exact_no_wildcard():
    from kya.external_id import _did_segment_match
    assert _did_segment_match("did:key:z6Mk-x", "did:key:z6Mk-x")
    assert not _did_segment_match("did:key:z6Mk-x", "did:key:z6Mk-y")


def test_did_segment_match_one_segment_wildcard():
    from kya.external_id import _did_segment_match
    assert _did_segment_match(
        "did:web:fleet-a:drone-1234", "did:web:fleet-a:*"
    )


def test_did_segment_match_wildcard_does_not_cross_colon():
    """The whole point — `*` matches one segment, never multiple.
    Without this, `did:web:fleet-a:*` would allowlist arbitrary
    sub-namespaces an operator didn't intend."""
    from kya.external_id import _did_segment_match
    assert not _did_segment_match(
        "did:web:fleet-a:evil:drone", "did:web:fleet-a:*"
    )


def test_did_segment_match_wildcard_does_not_match_different_prefix():
    from kya.external_id import _did_segment_match
    assert not _did_segment_match(
        "did:web:fleet-a-evil:drone", "did:web:fleet-a:*"
    )


def test_pattern_regex_rejects_mid_pattern_wildcard():
    """Operators can't write `did:web:*.example` — only suffix `:*`
    is allowed. Config load must refuse the invalid form."""
    from kya.external_id import _PATTERN_RE
    assert _PATTERN_RE.match("did:web:fleet-a:*")
    assert _PATTERN_RE.match("did:key:z6Mk-abc")
    assert not _PATTERN_RE.match("did:web:*.example")
    assert not _PATTERN_RE.match("did:web:*:drone")
    assert not _PATTERN_RE.match("did:web:fleet*:drone")


def test_pattern_regex_validates_percent_encoding():
    """Round-3 NEW-2 — `%` must be followed by two hex digits."""
    from kya.external_id import _PATTERN_RE
    assert _PATTERN_RE.match("did:web:fleet%20a:*")   # well-formed
    assert not _PATTERN_RE.match("did:web:fleet%XY:*")
    assert not _PATTERN_RE.match("did:web:fleet%2:*")


# ─── DID admin principal_id normalization ──────────────────────────


def test_did_web_admin_normalization_case_folds_hostname_only():
    """did:web hostname is case-insensitive per RFC 3986 §3.2.2;
    path components are byte-exact."""
    from kya.external_id import normalize_admin_did
    assert (
        normalize_admin_did("did:web:Org.Example:users:alice")
        == normalize_admin_did("did:web:org.example:users:alice")
    )
    # Path case difference → DISTINCT
    assert (
        normalize_admin_did("did:web:org.example:USERS:alice")
        != normalize_admin_did("did:web:org.example:users:alice")
    )


def test_did_key_admin_normalization_is_byte_exact():
    """did:key multibase is case-sensitive; z6Mk ≠ z6mk."""
    from kya.external_id import normalize_admin_did
    assert (
        normalize_admin_did("did:key:z6MkABC")
        != normalize_admin_did("did:key:z6mkABC")
    )


def test_did_jwk_admin_normalization_is_byte_exact():
    from kya.external_id import normalize_admin_did
    a = "did:jwk:eyJhbGciOiJFZERTQSJ9"
    b = "did:jwk:eyjhbgcioijfzerteu5"
    assert normalize_admin_did(a) != normalize_admin_did(b)


def test_unknown_did_method_defaults_to_byte_exact():
    from kya.external_id import normalize_admin_did
    a = "did:future-method:ABC"
    b = "did:future-method:abc"
    assert normalize_admin_did(a) != normalize_admin_did(b)
