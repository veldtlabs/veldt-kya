"""Tests for the dev-fallback Fernet key in kya_redteam.targets.

The fallback lets `pip install veldt-kya` work end-to-end without the
operator setting KYA_REDTEAM_SECRET_KEY — but the threat model is only
acceptable if:

  1. The fallback ONLY fires for the current key_id (never for rotated
     ones — auto-generating a key for a historical id would silently
     break decryption).
  2. The warning logs exactly ONCE per process (not on every encrypt).
  3. Multiple threads first-calling concurrently get the SAME key (the
     TOCTOU window on the `hasattr` check is closed by a lock).
  4. The dev-key → env-var promotion failure mode produces an
     actionable error (not a raw cryptography.InvalidToken).
  5. `is_persistent_key_configured()` correctly distinguishes the
     ephemeral dev path from a real operator-set key.
"""
from __future__ import annotations

import concurrent.futures as cf
import logging

import pytest


@pytest.fixture(autouse=True)
def clean_redteam_module(monkeypatch):
    """Reset the dev-key cache + warning flag + env var on every test."""
    monkeypatch.delenv("KYA_REDTEAM_SECRET_KEY", raising=False)
    # Drop any prior tests' dev key + warning flag
    from kya_redteam import targets as t
    if hasattr(t._resolve_key, "_dev_key"):
        delattr(t._resolve_key, "_dev_key")
    t._DEV_KEY_WARNING_LOGGED = False
    yield
    if hasattr(t._resolve_key, "_dev_key"):
        delattr(t._resolve_key, "_dev_key")
    t._DEV_KEY_WARNING_LOGGED = False


def test_dev_fallback_fires_for_current_key_only():
    from kya_redteam.targets import _CURRENT_KEY_ID, _resolve_key
    assert _resolve_key(_CURRENT_KEY_ID) is not None, (
        "current key MUST have a dev fallback when env unset"
    )
    assert _resolve_key("some-old-key-id") is None, (
        "historical key_id MUST NOT auto-generate a dev key — "
        "would silently corrupt decryption"
    )
    assert _resolve_key("v0") is None
    assert _resolve_key("rotated-2025") is None


def test_dev_warning_logs_exactly_once(caplog):
    from kya_redteam.targets import _CURRENT_KEY_ID, _resolve_key
    with caplog.at_level(logging.WARNING, logger="kya_redteam.targets"):
        _resolve_key(_CURRENT_KEY_ID)
        _resolve_key(_CURRENT_KEY_ID)
        _resolve_key(_CURRENT_KEY_ID)
    hits = [r for r in caplog.records
            if "KYA_REDTEAM_SECRET_KEY not set" in r.getMessage()]
    assert len(hits) == 1, (
        f"warning should log exactly once per process; got {len(hits)} "
        "records"
    )


def test_dev_key_is_stable_across_calls():
    from kya_redteam.targets import _CURRENT_KEY_ID, _resolve_key
    k1 = _resolve_key(_CURRENT_KEY_ID)
    k2 = _resolve_key(_CURRENT_KEY_ID)
    assert k1 == k2, "dev key must be stable across repeat calls"


def test_dev_key_threadsafe_concurrent_first_call():
    """20 threads first-calling concurrently MUST observe one shared key.
    Pre-fix (no lock around the hasattr check) lets two threads each
    generate their own key and the second setattr clobbers the first,
    silently breaking ciphertext produced by the loser."""
    from kya_redteam.targets import _CURRENT_KEY_ID, _resolve_key
    keys: list[bytes] = []
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(_resolve_key, _CURRENT_KEY_ID)
                for _ in range(40)]
        for f in cf.as_completed(futs):
            keys.append(f.result())
    distinct = set(keys)
    assert len(distinct) == 1, (
        f"thread race produced {len(distinct)} distinct dev keys — "
        "lock around `_dev_key` init is not holding"
    )


def test_encrypt_then_decrypt_with_dev_fallback():
    """Round-trip via the dev fallback succeeds (same process, same key)."""
    from kya_redteam.targets import decrypt_secret, encrypt_secret
    ct, kid = encrypt_secret("my-bearer-token")
    pt = decrypt_secret(ct, kid)
    assert pt == "my-bearer-token"


def test_decrypt_after_env_set_gives_actionable_error(monkeypatch):
    """Dev-key promotion gotcha: encrypted under dev fallback, then env
    var set with a different key, then decrypt called → actionable
    SecretConfigError, NOT raw InvalidToken."""
    from kya_redteam.targets import (
        _CURRENT_KEY_ID,
        SecretConfigError,
        decrypt_secret,
        encrypt_secret,
    )
    # 1. Encrypt under dev fallback (env unset)
    ct, kid = encrypt_secret("token-v1")
    assert kid == _CURRENT_KEY_ID
    # 2. Operator sets env var to a DIFFERENT key
    from cryptography.fernet import Fernet
    monkeypatch.setenv("KYA_REDTEAM_SECRET_KEY",
                       Fernet.generate_key().decode())
    # 3. Decrypt of old dev-key ciphertext under the new env-supplied
    # key MUST raise SecretConfigError with an actionable hint, NOT a
    # raw cryptography.fernet.InvalidToken
    with pytest.raises(SecretConfigError) as ei:
        decrypt_secret(ct, kid)
    msg = str(ei.value).lower()
    assert "re-enroll" in msg or "dev key" in msg or "rotated" in msg


def test_is_persistent_key_configured_distinguishes_dev_from_env(
    monkeypatch,
):
    """The new helper MUST return False on the dev fallback and True
    when the env var is set."""
    from kya_redteam.targets import (
        is_encryption_configured,
        is_persistent_key_configured,
    )
    # Dev fallback — encryption WORKS but is_persistent says False
    assert is_encryption_configured() is True
    assert is_persistent_key_configured() is False

    # Now set the env var — persistent should flip True
    from cryptography.fernet import Fernet
    monkeypatch.setenv("KYA_REDTEAM_SECRET_KEY",
                       Fernet.generate_key().decode())
    assert is_persistent_key_configured() is True


# NB: A test for "cryptography missing → SecretConfigError" would need
# subprocess isolation (the module is already imported by the time the
# test runs). The path is exercised in CI's `Cleanroom · *` matrix and
# by the explicit error message in encrypt_secret/_fernet.
