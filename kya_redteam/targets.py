"""Persistent target registry + encrypted-token vault.

Production hardening over Phase 2's "target_endpoint + token in the
request body" path. Three problems with the ad-hoc approach:

  1. SSRF surface — a tenant admin could POST any URL (including
     internal cluster services) and the redteam runner would happily
     hit it. Persistent targets force the URL to be reviewed once
     when added; subsequent runs reference the registered target.
  2. Token exposure — the run request body carries the bearer token.
     It ends up in access logs, browser dev tools, and proxy
     intermediaries. Encrypted-at-rest storage + server-side join at
     run-time keeps the secret out of every API caller's history.
  3. Reusability — a tenant typically has 1-3 endpoints they want to
     red-team (prod, staging, customer-X-pilot). Targets let those
     be configured once and referenced from many campaigns.

Encryption
----------
Per-target tokens are encrypted using `cryptography.Fernet` (AES-128-CBC
+ HMAC) with a key supplied via env `KYA_REDTEAM_SECRET_KEY`. The
ciphertext + key_id are stored in `kya_redteam_target_secrets`.

Key rotation: at first read with a non-matching key_id, decrypt with
the old key (read from env `KYA_REDTEAM_SECRET_KEY_<key_id>`) and
re-encrypt under the current key. For the MVP we just support a
single key (key_id='v1') — multi-key rotation is a Phase 3.5 add.

Fail closed: when KYA_REDTEAM_SECRET_KEY is unset, the helper raises
`SecretConfigError` from the write path. Better to refuse than to
plaintext-store.

Response parsers
----------------
The dict serialization of the target row carries a `response_parser_kind`
string (one of `standard | openai_chat | anthropic_messages | text_only`).
HttpAgentTarget materializes this to a real callable at construction
time. Custom (tenant-defined) parsers come in Phase 3.5.
"""
from __future__ import annotations

import base64
import ipaddress as _ipaddress
import json as _json
import logging
import os
import socket as _socket
import time
import urllib.parse as _urlparse
from typing import Any, Optional

try:
    from sqlalchemy import text
except ImportError:
    def text(s):  # type: ignore
        raise RuntimeError("kya_redteam.targets requires SQLAlchemy")

from kya._migrations import apply_migrations

logger = logging.getLogger(__name__)


VALID_AUTH_KINDS = ("bearer", "header", "none")
VALID_PARSER_KINDS = ("standard", "openai_chat", "anthropic_messages", "text_only")
VALID_VERIFIED_STATUS = ("never", "ok", "failing")

# Current key id. Env-driven so a rotation can express "we're now on v2"
# without code changes. Each row in kya_redteam_target_secrets stores
# the key_id that encrypted it, so historical decryption stays available
# as long as `KYA_REDTEAM_SECRET_KEY_<old_id>` env vars are present.
# Validated: must be a short slug (alnum + underscore) so log lines /
# audit trails stay sane.
def _resolve_current_key_id() -> str:
    raw = os.environ.get("KYA_REDTEAM_CURRENT_KEY_ID", "").strip() or "v1"
    # Defensive: refuse pathological values that would break the env-var
    # naming convention (KYA_REDTEAM_SECRET_KEY_<id>).
    import re as _re
    if not _re.match(r"^[A-Za-z0-9_]{1,32}$", raw):
        logger.warning(
            "[REDTEAM-TARGETS] KYA_REDTEAM_CURRENT_KEY_ID='%s' is invalid; "
            "falling back to 'v1'. Allowed: alnum + underscore, ≤32 chars.",
            raw,
        )
        return "v1"
    return raw


_CURRENT_KEY_ID = _resolve_current_key_id()


# ── DDL ─────────────────────────────────────────────────────────────

_TARGETS_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_redteam_targets (
    id                   SERIAL PRIMARY KEY,
    tenant_id            UUID NOT NULL,
    agent_key            VARCHAR(50) NOT NULL,
    name                 TEXT NOT NULL,
    description          TEXT,
    endpoint_url         TEXT NOT NULL,
    auth_kind            TEXT NOT NULL DEFAULT 'bearer',
    auth_header_name     TEXT,
    body_template        JSONB,
    response_parser_kind TEXT NOT NULL DEFAULT 'standard',
    rate_limit_rps       NUMERIC(5,2) NOT NULL DEFAULT 1.0,
    enabled              BOOLEAN NOT NULL DEFAULT true,
    verified_at          TIMESTAMPTZ,
    verified_status      TEXT NOT NULL DEFAULT 'never',
    verified_error       TEXT,
    created_by           UUID,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
"""

_TARGETS_IDX = """
CREATE INDEX IF NOT EXISTS idx_kya_redteam_targets_tenant_agent
    ON prov_schema.kya_redteam_targets (tenant_id, agent_key);
"""

_SECRETS_DDL = """
CREATE TABLE IF NOT EXISTS prov_schema.kya_redteam_target_secrets (
    target_id     INT PRIMARY KEY REFERENCES prov_schema.kya_redteam_targets(id) ON DELETE CASCADE,
    tenant_id     UUID NOT NULL,
    ciphertext    BYTEA NOT NULL,
    key_id        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

_MIGRATIONS_TARGETS: list = []
_MIGRATIONS_SECRETS: list = []

_ENSURED_ENGINES: set[int] = set()


def ensure_tables(db) -> None:
    """Idempotent — dialect-aware via _legacy_tables. PG keeps the
    advisory lock; non-PG dialects skip it (no contention there)."""
    try:
        bind_for_id = db.get_bind()
        engine_key = id(bind_for_id.engine if hasattr(bind_for_id, "engine") else bind_for_id)
    except Exception:
        engine_key = -1

    if engine_key in _ENSURED_ENGINES:
        return
    try:
        bind = db.connection()
        if bind.dialect.name == "postgresql":
            lock_row = db.execute(
                text("SELECT pg_try_advisory_xact_lock(hashtext('kya_redteam_targets_ddl'))")
            ).fetchone()
            if not lock_row or not lock_row[0]:
                db.commit()
                return

        from kya._legacy_tables import (
            create_legacy_tables,
            kya_redteam_target_secrets,
            kya_redteam_targets,
        )

        create_legacy_tables(
            db,
            [kya_redteam_targets, kya_redteam_target_secrets],
        )
        apply_migrations(db, "kya_redteam_targets", _MIGRATIONS_TARGETS)
        apply_migrations(db, "kya_redteam_target_secrets", _MIGRATIONS_SECRETS)
        db.commit()
        _ENSURED_ENGINES.add(engine_key)
    except Exception as exc:
        logger.warning("[REDTEAM-TARGETS] ensure_tables failed: %s", exc)
        db.rollback()


# ── Encryption helpers ──────────────────────────────────────────────

class SecretConfigError(RuntimeError):
    """Raised when the redteam secret key isn't configured. Write paths
    fail closed rather than store plaintext."""


def _resolve_key(key_id: str) -> Optional[bytes]:
    """Find the Fernet key for a given key_id. Current key under
    KYA_REDTEAM_SECRET_KEY; rotated keys under
    KYA_REDTEAM_SECRET_KEY_<key_id>."""
    if key_id == _CURRENT_KEY_ID:
        raw = os.environ.get("KYA_REDTEAM_SECRET_KEY", "").strip()
    else:
        raw = os.environ.get(f"KYA_REDTEAM_SECRET_KEY_{key_id}", "").strip()
    if not raw:
        return None
    return raw.encode()


def _fernet(key: bytes):
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise SecretConfigError(
            "kya_redteam target encryption requires `pip install cryptography`"
        ) from exc
    return Fernet(key)


def encrypt_secret(plaintext: str) -> tuple[bytes, str]:
    """Encrypt under the current key. Returns (ciphertext, key_id)."""
    if not plaintext:
        raise ValueError("encrypt_secret called with empty plaintext")
    key = _resolve_key(_CURRENT_KEY_ID)
    if key is None:
        raise SecretConfigError(
            "KYA_REDTEAM_SECRET_KEY is not set — refusing to store target "
            "secret as plaintext. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\" and set the env var."
        )
    return _fernet(key).encrypt(plaintext.encode()), _CURRENT_KEY_ID


def decrypt_secret(ciphertext: bytes, key_id: str) -> str:
    key = _resolve_key(key_id)
    if key is None:
        raise SecretConfigError(
            f"Cannot decrypt redteam target secret: key_id='{key_id}' has "
            f"no matching env var (expected "
            f"{'KYA_REDTEAM_SECRET_KEY' if key_id == _CURRENT_KEY_ID else 'KYA_REDTEAM_SECRET_KEY_' + key_id})"
        )
    return _fernet(key).decrypt(ciphertext).decode()


def is_encryption_configured() -> bool:
    """Quick check for the health endpoint."""
    return _resolve_key(_CURRENT_KEY_ID) is not None


# ── Target CRUD ─────────────────────────────────────────────────────

def _validate_enum(value: str, valid: tuple, field: str) -> None:
    if value not in valid:
        raise ValueError(f"{field} must be one of {valid}, got '{value}'")


def create_target(
    db, tenant_id: str, agent_key: str, name: str,
    *,
    endpoint_url: str,
    auth_kind: str = "bearer",
    auth_header_name: Optional[str] = None,
    auth_secret: Optional[str] = None,
    body_template: Optional[dict] = None,
    response_parser_kind: str = "standard",
    rate_limit_rps: float = 1.0,
    description: Optional[str] = None,
    created_by: Optional[str] = None,
) -> dict:
    """Register a target. Encrypts auth_secret if provided.

    Raises ValueError on invalid enum / missing required field.
    Raises SecretConfigError when auth_secret is provided but
    KYA_REDTEAM_SECRET_KEY is unset.
    """
    _validate_enum(auth_kind, VALID_AUTH_KINDS, "auth_kind")
    _validate_enum(response_parser_kind, VALID_PARSER_KINDS, "response_parser_kind")
    if auth_kind == "header" and not auth_header_name:
        raise ValueError("auth_kind='header' requires auth_header_name")
    if auth_kind == "none" and auth_secret:
        raise ValueError("auth_kind='none' does not accept auth_secret")
    if auth_kind in ("bearer", "header") and not auth_secret:
        raise ValueError(f"auth_kind='{auth_kind}' requires auth_secret")
    # Endpoint allowlist guard — refuse private/loopback URLs by default.
    # Operators can bypass by setting KYA_REDTEAM_ALLOW_PRIVATE_URLS=1
    # (e.g. when the agent runs in the same VPC as vd-app).
    if not _endpoint_url_acceptable(endpoint_url):
        raise ValueError(
            f"endpoint_url '{endpoint_url}' is rejected — points at a "
            "private/loopback address. Set KYA_REDTEAM_ALLOW_PRIVATE_URLS=1 "
            "to permit (in-cluster targets) or use a public hostname."
        )
    ensure_tables(db)
    from kya._dialect_helpers import insert_returning_id
    from kya._legacy_tables import kya_redteam_targets, kya_redteam_target_secrets

    target_id = insert_returning_id(db, kya_redteam_targets, {
        "tenant_id": tenant_id,
        "agent_key": agent_key,
        "name": name,
        "description": description,
        "endpoint_url": endpoint_url,
        "auth_kind": auth_kind,
        "auth_header_name": auth_header_name,
        "body_template": body_template,
        "response_parser_kind": response_parser_kind,
        "rate_limit_rps": rate_limit_rps,
        "created_by": created_by,
    })

    if auth_secret:
        ciphertext, key_id = encrypt_secret(auth_secret)
        db.execute(kya_redteam_target_secrets.insert().values(
            target_id=target_id,
            tenant_id=tenant_id,
            ciphertext=ciphertext,
            key_id=key_id,
        ))
    db.commit()
    return get_target(db, tenant_id, target_id, include_secret=False)


def _is_private_or_local(addr: str) -> bool:
    """True when `addr` is a bare IP literal in a private/loopback/
    link-local/ULA range. Uses stdlib ipaddress for correctness instead
    of string-prefix matching (which falsely flagged 'fcdn.example.com'
    as IPv6 ULA in the prior implementation)."""
    try:
        ip = _ipaddress.ip_address(addr)
    except ValueError:
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _resolve_to_safe_ips(hostname: str) -> tuple[bool, list[str]]:
    """Resolve a hostname; return (all_safe, resolved_ips). Used to
    catch DNS rebinding at registration time and again before each
    send. An attacker who controls DNS can return a private IP after
    initial registration succeeds — re-resolving on each request
    closes that window.

    Returns (True, []) when resolution fails (fail-open at the DNS
    layer; the URL check + egress firewall are the other layers)."""
    try:
        infos = _socket.getaddrinfo(hostname, None)
    except _socket.gaierror as exc:
        # H3 — log the fail-open so audits can correlate DNS outages
        # with periods where SSRF didn't actually run at the DNS layer.
        logger.warning(
            "[REDTEAM-TARGETS] SSRF DNS check fail-open for host=%s: %s",
            hostname, exc,
        )
        return True, []
    ips = sorted({info[4][0] for info in infos})
    for ip in ips:
        if _is_private_or_local(ip):
            return False, ips
    return True, ips


def _endpoint_url_acceptable(url: str, *, resolve: bool = True) -> bool:
    """Reject loopback / link-local / private endpoints. Defense in
    depth — also configure egress firewalling at the network layer.

    Bypass via env KYA_REDTEAM_ALLOW_PRIVATE_URLS=1 for in-cluster
    targets where the agent runs on the same network as vd-app.

    Set resolve=False on the create/update path if a slow DNS
    resolver could block the request thread — the cheaper textual
    check still rejects bare-IP literals and "localhost".
    """
    if os.environ.get("KYA_REDTEAM_ALLOW_PRIVATE_URLS", "").strip() == "1":
        return True
    if not url:
        return False
    # urlparse handles bracketed IPv6 (e.g. [::1]:8080) correctly,
    # which the previous .split(":")[0] did not.
    try:
        parsed = _urlparse.urlparse(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    hostname = parsed.hostname  # already lowercased + bracket-stripped
    if not hostname:
        return False
    # Normalize trailing dot (DNS root) so "localhost." == "localhost".
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if hostname == "localhost":
        return False
    # Bare-IP check via stdlib — correctly distinguishes IP literal
    # from hostname-that-starts-with-a-digit-or-fc.
    if _is_private_or_local(hostname):
        return False
    # Hostname (not an IP literal) — optionally resolve to catch DNS
    # rebinding. Skip the resolution step when resolve=False.
    try:
        _ipaddress.ip_address(hostname)
        # It's an IP literal that wasn't private — accept.
        return True
    except ValueError:
        pass
    if resolve:
        safe, _ips = _resolve_to_safe_ips(hostname)
        if not safe:
            return False
    return True


_SELECT_TARGET_COLS = (
    "id, tenant_id, agent_key, name, description, endpoint_url, "
    "auth_kind, auth_header_name, body_template, response_parser_kind, "
    "rate_limit_rps, enabled, verified_at, verified_status, verified_error, "
    "created_by, created_at, updated_at"
)


def _row_to_target(r) -> dict:
    return {
        "id": r[0],
        "tenant_id": str(r[1]),
        "agent_key": r[2],
        "name": r[3],
        "description": r[4],
        "endpoint_url": r[5],
        "auth_kind": r[6],
        "auth_header_name": r[7],
        "body_template": r[8] or None,
        "response_parser_kind": r[9],
        "rate_limit_rps": float(r[10]) if r[10] is not None else None,
        "enabled": r[11],
        "verified_at": r[12],
        "verified_status": r[13],
        "verified_error": r[14],
        "created_by": str(r[15]) if r[15] else None,
        "created_at": r[16],
        "updated_at": r[17],
    }


def get_target(
    db, tenant_id: str, target_id: int, *, include_secret: bool = False,
) -> Optional[dict]:
    """Return target row. With include_secret=True, decrypts and includes
    the auth secret — only used in the run path (the dashboard list/view
    paths must NEVER set this flag).
    """
    ensure_tables(db)
    from kya._legacy_tables import kya_redteam_targets, kya_redteam_target_secrets
    schema = kya_redteam_targets.schema
    targets_ref = f"{schema}.kya_redteam_targets" if schema else "kya_redteam_targets"
    secrets_ref = f"{schema}.kya_redteam_target_secrets" if schema else "kya_redteam_target_secrets"
    row = db.execute(
        text(
            f"SELECT {_SELECT_TARGET_COLS} FROM {targets_ref} "
            f"WHERE tenant_id = :tid AND id = :id"
        ),
        {"tid": tenant_id, "id": target_id},
    ).fetchone()
    if not row:
        return None
    out = _row_to_target(row)
    if include_secret and out["auth_kind"] != "none":
        sec = db.execute(
            text(
                f"SELECT ciphertext, key_id FROM {secrets_ref} "
                f"WHERE target_id = :id AND tenant_id = :tid"
            ),
            {"id": target_id, "tid": tenant_id},
        ).fetchone()
        if sec:
            try:
                out["_auth_secret_decrypted"] = decrypt_secret(bytes(sec[0]), sec[1])
            except SecretConfigError as exc:
                raise
            except Exception as exc:
                # H5: do NOT mark this as None and continue — the caller
                # (verify_target / materialize_target) would then send a
                # request without auth, which can succeed on a public
                # endpoint and falsely flag the target healthy. Surface
                # the failure as a typed exception the caller can map to
                # an operator-actionable error.
                logger.warning(
                    "[REDTEAM-TARGETS] decrypt failed for target %s: %s",
                    target_id, exc,
                )
                raise SecretConfigError(
                    f"Cannot decrypt target {target_id} secret — key "
                    f"missing or ciphertext corrupted (key_id='{sec[1]}'). "
                    "Either restore the original key, rotate it via the "
                    "key-rotation flow, or delete and recreate the target."
                ) from exc
    return out


def list_targets(
    db, tenant_id: str, agent_key: Optional[str] = None,
) -> list[dict]:
    ensure_tables(db)
    if agent_key:
        rows = db.execute(
            text(
                f"SELECT {_SELECT_TARGET_COLS} "
                "FROM prov_schema.kya_redteam_targets "
                "WHERE tenant_id = (:tid)::uuid AND agent_key = :ak "
                "ORDER BY id DESC"
            ),
            {"tid": tenant_id, "ak": agent_key},
        ).fetchall()
    else:
        rows = db.execute(
            text(
                f"SELECT {_SELECT_TARGET_COLS} "
                "FROM prov_schema.kya_redteam_targets "
                "WHERE tenant_id = (:tid)::uuid "
                "ORDER BY id DESC"
            ),
            {"tid": tenant_id},
        ).fetchall()
    return [_row_to_target(r) for r in rows]


_MUTABLE_FIELDS = {
    "name", "description", "endpoint_url", "auth_kind", "auth_header_name",
    "body_template", "response_parser_kind", "rate_limit_rps", "enabled",
}


def update_target(
    db, tenant_id: str, target_id: int,
    *,
    auth_secret: Optional[str] = None,
    **patch,
) -> Optional[dict]:
    """Patch update. auth_secret=None means "leave the existing secret
    unchanged"; pass a string to rotate it.

    M3 — when auth_kind transitions to 'none', also DELETE the
    matching kya_redteam_target_secrets row. Otherwise an old
    encrypted token sits in the DB forever with no API to inspect or
    remove it (the get_target read path skips it for auth_kind='none').
    """
    ensure_tables(db)
    if "endpoint_url" in patch and not _endpoint_url_acceptable(patch["endpoint_url"]):
        raise ValueError("endpoint_url rejected (private/loopback)")
    if "auth_kind" in patch:
        _validate_enum(patch["auth_kind"], VALID_AUTH_KINDS, "auth_kind")
    if "response_parser_kind" in patch:
        _validate_enum(patch["response_parser_kind"], VALID_PARSER_KINDS,
                       "response_parser_kind")
    set_clauses = []
    params: dict[str, Any] = {"tid": tenant_id, "id": target_id}
    for k, v in patch.items():
        if k not in _MUTABLE_FIELDS:
            continue
        if k == "body_template":
            set_clauses.append(f"{k} = CAST(:{k} AS JSONB)")
            params[k] = _json.dumps(v) if v else None
        else:
            set_clauses.append(f"{k} = :{k}")
            params[k] = v
    if set_clauses:
        set_clauses.append("updated_at = now()")
        db.execute(
            text(
                "UPDATE prov_schema.kya_redteam_targets "
                f"SET {', '.join(set_clauses)} "
                "WHERE tenant_id = (:tid)::uuid AND id = :id"
            ),
            params,
        )
    if auth_secret is not None:
        ciphertext, key_id = encrypt_secret(auth_secret)
        # Upsert the secret row
        db.execute(
            text(
                "INSERT INTO prov_schema.kya_redteam_target_secrets "
                "  (target_id, tenant_id, ciphertext, key_id) "
                "VALUES (:id, (:tid)::uuid, :ct, :kid) "
                "ON CONFLICT (target_id) DO UPDATE "
                "  SET ciphertext = EXCLUDED.ciphertext, "
                "      key_id = EXCLUDED.key_id, "
                "      updated_at = now()"
            ),
            {"id": target_id, "tid": tenant_id, "ct": ciphertext, "kid": key_id},
        )
    # M3 — if auth_kind transitioned to 'none', clean up the orphaned
    # secret row. Otherwise it sits encrypted forever with no API to
    # inspect or remove it (read paths skip it for auth_kind='none').
    if patch.get("auth_kind") == "none":
        db.execute(
            text(
                "DELETE FROM prov_schema.kya_redteam_target_secrets "
                "WHERE target_id = :id AND tenant_id = (:tid)::uuid"
            ),
            {"id": target_id, "tid": tenant_id},
        )
    db.commit()
    return get_target(db, tenant_id, target_id, include_secret=False)


def delete_target(db, tenant_id: str, target_id: int) -> bool:
    ensure_tables(db)
    # ON DELETE CASCADE on the secrets table removes the secret row.
    result = db.execute(
        text(
            "DELETE FROM prov_schema.kya_redteam_targets "
            "WHERE tenant_id = (:tid)::uuid AND id = :id"
        ),
        {"tid": tenant_id, "id": target_id},
    )
    db.commit()
    return (result.rowcount or 0) > 0


# ── Verification (health check) ─────────────────────────────────────

def verify_target(db, tenant_id: str, target_id: int) -> dict:
    """POST a no-op probe to the target endpoint. Records the outcome
    on the target row (verified_at + verified_status). Reports back to
    the caller — doesn't raise on a failing probe; that's a normal
    outcome and we want the failed status persisted."""
    import requests
    target = get_target(db, tenant_id, target_id, include_secret=True)
    if not target:
        raise ValueError(f"target {target_id} not found")
    headers = {"Content-Type": "application/json"}
    secret = target.get("_auth_secret_decrypted")
    if target["auth_kind"] == "bearer" and secret:
        headers["Authorization"] = f"Bearer {secret}"
    elif target["auth_kind"] == "header" and secret:
        headers[target["auth_header_name"]] = secret

    body_template = target.get("body_template")
    probe_prompt = "[KYA-REDTEAM-PROBE] health check — please respond OK"
    if body_template:
        # Reuse the single-pass safe substituter from pyrit_target so
        # this path can't drift away from the security fix.
        from .pyrit_target import _substitute_template
        body = _substitute_template(
            body_template,
            {"prompt": probe_prompt, "session_id": "kya_probe"},
        )
    else:
        body = {"prompt": probe_prompt, "session_id": "kya_probe"}
    start = time.monotonic()
    try:
        resp = requests.post(
            target["endpoint_url"], headers=headers, json=body, timeout=10,
        )
        ok = resp.ok
        err = None if ok else f"http_{resp.status_code}: {resp.text[:200]}"
    except requests.RequestException as exc:
        ok = False
        err = f"transport: {exc}"
    duration_ms = int((time.monotonic() - start) * 1000)

    db.execute(
        text(
            "UPDATE prov_schema.kya_redteam_targets "
            "SET verified_at = now(), "
            "    verified_status = :st, "
            "    verified_error = :err, "
            "    updated_at = now() "
            "WHERE id = :id AND tenant_id = (:tid)::uuid"
        ),
        {
            "id": target_id, "tid": tenant_id,
            "st": "ok" if ok else "failing",
            "err": (err or "")[:500] if not ok else None,
        },
    )
    db.commit()
    return {
        "ok": ok,
        "duration_ms": duration_ms,
        "error": err,
        "target_id": target_id,
    }


# ── Response parsers (used by HttpAgentTarget) ──────────────────────

def get_response_parser(kind: str):
    """Resolve a parser_kind to a callable(payload_dict) -> normalized dict.

    Returns None for the standard kind (HttpAgentTarget already handles
    that case directly). For non-standard shapes, returns a function
    that the HttpAgentTarget can plug into its response_parser slot.
    """
    if kind == "standard" or not kind:
        return None
    if kind == "openai_chat":
        return _parse_openai_chat
    if kind == "anthropic_messages":
        return _parse_anthropic_messages
    if kind == "text_only":
        return _parse_text_only
    return None


def _parse_openai_chat(payload):
    try:
        choices = payload.get("choices") or []
        if choices:
            msg = (choices[0] or {}).get("message") or {}
            return {"output": msg.get("content") or "",
                    "tools_used": [tc.get("function", {}).get("name", "")
                                   for tc in (msg.get("tool_calls") or [])],
                    "events": []}
    except Exception:
        pass
    return {"output": str(payload)[:2000], "tools_used": [], "events": []}


def _parse_anthropic_messages(payload):
    try:
        content_blocks = payload.get("content") or []
        text_parts = [b.get("text", "") for b in content_blocks
                      if b.get("type") == "text"]
        tool_uses = [b.get("name", "") for b in content_blocks
                     if b.get("type") == "tool_use"]
        return {"output": "\n".join(text_parts),
                "tools_used": tool_uses, "events": []}
    except Exception:
        pass
    return {"output": str(payload)[:2000], "tools_used": [], "events": []}


def _parse_text_only(payload):
    if isinstance(payload, dict):
        return {"output": payload.get("output") or str(payload)[:2000],
                "tools_used": [], "events": []}
    return {"output": str(payload)[:2000], "tools_used": [], "events": []}


# ── Target → HttpAgentTarget materializer ───────────────────────────

def rotate_target_secret(
    db, tenant_id: str, target_id: int, new_auth_secret: str,
) -> dict:
    """Rotate ONE target's auth_secret. Re-encrypts under the current
    Fernet key. Used when the customer's bearer token expires or gets
    rotated upstream.

    Returns the target row (without the secret).
    """
    ensure_tables(db)
    if not new_auth_secret:
        raise ValueError("new_auth_secret is required and must be non-empty")
    # Confirm the target exists + auth_kind supports a secret
    t = get_target(db, tenant_id, target_id, include_secret=False)
    if not t:
        raise ValueError(f"target {target_id} not found")
    if t["auth_kind"] == "none":
        raise ValueError(
            f"target {target_id} has auth_kind='none'; nothing to rotate. "
            "Update auth_kind first via PUT /redteam/targets/{tid}."
        )
    ciphertext, key_id = encrypt_secret(new_auth_secret)
    db.execute(
        text(
            "INSERT INTO prov_schema.kya_redteam_target_secrets "
            "  (target_id, tenant_id, ciphertext, key_id) "
            "VALUES (:id, (:tid)::uuid, :ct, :kid) "
            "ON CONFLICT (target_id) DO UPDATE "
            "  SET ciphertext = EXCLUDED.ciphertext, "
            "      key_id = EXCLUDED.key_id, "
            "      updated_at = now()"
        ),
        {"id": target_id, "tid": tenant_id, "ct": ciphertext, "kid": key_id},
    )
    # Force the target row's updated_at to bump too, so audit trails
    # show "something changed" even though the visible columns didn't.
    db.execute(
        text(
            "UPDATE prov_schema.kya_redteam_targets "
            "SET updated_at = now() "
            "WHERE id = :id AND tenant_id = (:tid)::uuid"
        ),
        {"id": target_id, "tid": tenant_id},
    )
    db.commit()
    return t


def rotate_encryption_key_for_tenant(
    db, tenant_id: str, *, dry_run: bool = False,
) -> dict:
    """Re-encrypt every target secret for `tenant_id` under the CURRENT
    Fernet key. Used after rotating `KYA_REDTEAM_SECRET_KEY`:

      1. Operator generates new Fernet key
      2. Renames the OLD key to env `KYA_REDTEAM_SECRET_KEY_<old_id>`
         (where <old_id> matches the key_id column on existing rows)
      3. Sets the NEW key on `KYA_REDTEAM_SECRET_KEY`
      4. Calls this endpoint per tenant (or all tenants in a loop)

    For each row, decrypts with the OLD key_id (looking up the matching
    env var) and re-encrypts under the CURRENT key_id. After successful
    rotation across all tenants, the old env vars can be removed.

    `dry_run=True` returns the count of rows that WOULD be rotated and
    any decryption failures, without writing.

    Returns (C3 — dry-run uses a separate field so callers can't
    confuse "would have rotated" with "actually rotated"):
      Always:    {"checked": N, "failed": [target_ids], "errors": [...],
                  "skipped_already_current": K, "dry_run": bool}
      dry_run:   + {"would_rotate": M}
      live:      + {"rotated": M}
    """
    ensure_tables(db)
    rows = db.execute(
        text(
            "SELECT target_id, ciphertext, key_id "
            "FROM prov_schema.kya_redteam_target_secrets "
            "WHERE tenant_id = (:tid)::uuid"
        ),
        {"tid": tenant_id},
    ).fetchall()
    report: dict = {
        "checked": len(rows),
        "failed": [],
        "errors": [],
        "skipped_already_current": 0,
        "dry_run": dry_run,
    }
    if dry_run:
        report["would_rotate"] = 0
    else:
        report["rotated"] = 0

    for target_id, ciphertext, old_key_id in rows:
        if old_key_id == _CURRENT_KEY_ID:
            report["skipped_already_current"] += 1
            continue
        try:
            plaintext = decrypt_secret(bytes(ciphertext), old_key_id)
        except Exception as exc:
            report["failed"].append(int(target_id))
            report["errors"].append(f"target {target_id}: decrypt: {exc}")
            logger.warning(
                "[REDTEAM-ROTATE] target %s decrypt failed under key_id=%s: %s",
                target_id, old_key_id, exc,
            )
            continue
        if dry_run:
            report["would_rotate"] += 1
            continue
        try:
            new_ciphertext, new_key_id = encrypt_secret(plaintext)
        except Exception as exc:
            report["failed"].append(int(target_id))
            report["errors"].append(f"target {target_id}: encrypt: {exc}")
            logger.warning(
                "[REDTEAM-ROTATE] target %s encrypt failed: %s",
                target_id, exc,
            )
            continue
        # H1 — commit per-row so a failure on row N doesn't roll back
        # rows 1..N-1 that already succeeded. The report's "rotated"
        # count then matches durably-written rows.
        try:
            db.execute(
                text(
                    "UPDATE prov_schema.kya_redteam_target_secrets "
                    "SET ciphertext = :ct, key_id = :kid, updated_at = now() "
                    "WHERE target_id = :id AND tenant_id = (:tid)::uuid"
                ),
                {"ct": new_ciphertext, "kid": new_key_id,
                 "id": int(target_id), "tid": tenant_id},
            )
            db.commit()
            report["rotated"] += 1
        except Exception as exc:
            report["failed"].append(int(target_id))
            report["errors"].append(f"target {target_id}: write: {exc}")
            logger.warning(
                "[REDTEAM-ROTATE] target %s write failed: %s",
                target_id, exc,
            )
            try:
                db.rollback()
            except Exception:
                pass
    return report


def materialize_target(db, tenant_id: str, target_id: int):
    """Read a target row + its secret, return an HttpAgentTarget ready
    to send. Used by the campaign run path.

    M9: re-checks the endpoint URL against _endpoint_url_acceptable at
    materialize time so a DNS-rebinding attack that swapped a public
    hostname's resolution to a private IP between target creation and
    campaign run gets caught here. Refuses to materialize when the URL
    no longer passes the check.
    """
    from .pyrit_target import HttpAgentTarget
    t = get_target(db, tenant_id, target_id, include_secret=True)
    if not t:
        raise ValueError(f"target {target_id} not found")
    if not t.get("enabled", True):
        raise ValueError(f"target {target_id} is disabled")
    # Re-run the SSRF guard (resolve=True triggers DNS lookup) so a
    # rebound hostname gets rejected before any prompt is sent.
    if not _endpoint_url_acceptable(t["endpoint_url"], resolve=True):
        raise ValueError(
            f"target {target_id} endpoint_url is no longer acceptable "
            "(resolves to private/loopback or scheme/host invalid). "
            "Check DNS resolution and KYA_REDTEAM_ALLOW_PRIVATE_URLS."
        )
    token = t.get("_auth_secret_decrypted") or ""
    extra_headers: dict[str, str] = {}
    if t["auth_kind"] == "header" and token and t["auth_header_name"]:
        extra_headers[t["auth_header_name"]] = token
        token = ""   # don't pass it as Bearer too
    return HttpAgentTarget(
        endpoint_url=t["endpoint_url"],
        token=token if t["auth_kind"] == "bearer" else "",
        agent_key=t["agent_key"],
        extra_headers=extra_headers,
        body_template=t.get("body_template"),
        response_parser=get_response_parser(t.get("response_parser_kind") or "standard"),
        rate_limit_rps=float(t.get("rate_limit_rps") or 0.0),
        rate_limit_key=f"{tenant_id}:{target_id}",
    )
