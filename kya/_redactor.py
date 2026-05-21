"""PII redaction + payload truncation for dual-write.

The customer's local DB always gets the raw row. Only the
collector-bound *copy* is redacted by this module. The defaults are:

  • Fields whose name matches the PII allowlist (case-insensitive) get
    sha256-hashed with a per-deployment salt; the original value never
    leaves the process.
  • Text fields longer than 200 chars are truncated with a marker.
  • Bytes / binary fields are replaced with a length-only stub.
  • Nested dicts and lists are walked recursively up to max_depth.

The salt is read once at module import from KYA_DUALWRITE_SALT; if not
set, a random per-process salt is used so emitted hashes are not
correlatable across restarts. Customers that want stable cross-day
hashes (e.g. for cohort counts on the collector) must pin the salt
themselves.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Iterable

DEFAULT_PII_FIELDS: tuple[str, ...] = (
    "email", "phone", "ssn", "address", "ip_address",
    "user_id", "principal_id", "actor_id", "actor_email", "actor_name",
    "subject_email", "subject_name", "patient_id", "customer_id",
    "session_token", "api_key", "bearer", "authorization",
)

_SALT = os.environ.get("KYA_DUALWRITE_SALT") or os.urandom(16).hex()


def _hash(value: Any) -> str:
    s = str(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(_SALT.encode() + s).hexdigest()[:16]


class Redactor:
    def __init__(
        self,
        pii_fields: Iterable[str] = DEFAULT_PII_FIELDS,
        truncate_text_at: int = 200,
        max_depth: int = 6,
    ):
        self.pii_fields = frozenset(f.lower() for f in pii_fields)
        self.truncate_at = truncate_text_at
        self.max_depth = max_depth

    def redact(self, payload: Any, depth: int = 0) -> Any:
        if depth > self.max_depth:
            return {"__truncated__": "depth"}
        if isinstance(payload, dict):
            return {
                k: (
                    _hash(v)
                    if isinstance(k, str) and k.lower() in self.pii_fields and v is not None
                    else self.redact(v, depth + 1)
                )
                for k, v in payload.items()
            }
        if isinstance(payload, list):
            return [self.redact(item, depth + 1) for item in payload]
        if isinstance(payload, tuple):
            return [self.redact(item, depth + 1) for item in payload]
        if isinstance(payload, (bytes, bytearray)):
            return {"__redacted__": "bytes", "len": len(payload)}
        if isinstance(payload, str) and len(payload) > self.truncate_at:
            return payload[: self.truncate_at] + f"…[+{len(payload) - self.truncate_at}ch]"
        return payload


_TRUNCATE_ONLY = Redactor(pii_fields=())


def passthrough_redactor() -> Redactor:
    """Permissive redactor — keeps PII but still truncates oversized text."""
    return _TRUNCATE_ONLY
