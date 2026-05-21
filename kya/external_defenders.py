"""External-defender integrations — orthogonal runtime defenders that
augment KYA's 3-layer governance gate.

Two patterns:

  1. **In-process defenders** (NeMo Guardrails)
     Called from inside the action_gate path. Configurable via env;
     lazy-imports the SDK so the dep is optional.

  2. **Webhook detectors** (Lakera Guard, Prompt Security, custom)
     External SaaS detectors post verdicts via a KYA HTTP endpoint.
     We map their verdicts into KYA event types (data_leak,
     policy_violation, oos_tool) and credit them to the principal
     trust signal-counts. Same record_* path the Hooks SDK uses, so
     ALL detector sources flow into the same trust score.

Activation
----------
NeMo Guardrails:
  - pip install nemoguardrails
  - KYA_NEMO_GUARDRAILS_CONFIG=/path/to/config.yml (Colang flows + LLM)
  - Defender is consulted by the action_gate on the next request.

Webhook detectors:
  - Endpoint: POST /api/v1/admin/agents/external-detector/verdict
  - Header: `Authorization: Bearer <tenant JWT>`
  - Body: see ExternalDetectorVerdict pydantic model below
  - No SDK dep; the detector calls KYA, not the other way around.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ── NeMo Guardrails defender ────────────────────────────────────────

_NEMO_DISABLE_ENV = "KYA_DISABLE_NEMO_GUARDRAILS"
_NEMO_CONFIG_ENV = "KYA_NEMO_GUARDRAILS_CONFIG"

_NEMO_RAILS = None  # lazy-cached LLMRails instance
_NEMO_LOAD_ATTEMPTED = False


@dataclass
class NemoStatus:
    installed: bool = False
    import_ok: bool = False
    enabled_by_env: bool = False
    config_path: str | None = None
    config_loaded: bool = False
    version: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "installed": self.installed,
            "import_ok": self.import_ok,
            "enabled_by_env": self.enabled_by_env,
            "config_path": self.config_path,
            "config_loaded": self.config_loaded,
            "version": self.version,
            "error": self.error,
            "env_disable_var": _NEMO_DISABLE_ENV,
            "env_config_var": _NEMO_CONFIG_ENV,
            "default": "on (when installed + configured)",
        }


def nemo_status() -> NemoStatus:
    disabled = os.environ.get(_NEMO_DISABLE_ENV, "").lower() in ("1", "true", "yes")
    cfg_path = os.environ.get(_NEMO_CONFIG_ENV, "").strip() or None
    out = NemoStatus(enabled_by_env=not disabled, config_path=cfg_path)
    spec = importlib.util.find_spec("nemoguardrails")
    if spec is None:
        return out
    out.installed = True
    try:
        m = importlib.import_module("nemoguardrails")
        out.version = getattr(m, "__version__", "unknown")
        out.import_ok = True
    except Exception as exc:
        out.error = f"{type(exc).__name__}: {exc}"
    out.config_loaded = _NEMO_RAILS is not None
    return out


def _load_nemo_rails():
    """Lazy-load the configured rails. Returns None if unavailable.
    Cached after first successful load; load failures retry only when
    the config env var changes."""
    global _NEMO_RAILS, _NEMO_LOAD_ATTEMPTED
    if _NEMO_RAILS is not None:
        return _NEMO_RAILS
    if _NEMO_LOAD_ATTEMPTED:
        return None
    _NEMO_LOAD_ATTEMPTED = True
    if os.environ.get(_NEMO_DISABLE_ENV, "").lower() in ("1", "true", "yes"):
        return None
    cfg_path = os.environ.get(_NEMO_CONFIG_ENV, "").strip()
    if not cfg_path:
        return None
    try:
        from nemoguardrails import LLMRails, RailsConfig  # type: ignore

        config = RailsConfig.from_path(cfg_path)
        _NEMO_RAILS = LLMRails(config)
        logger.info("[KYA-NEMO] loaded rails from %s", cfg_path)
        return _NEMO_RAILS
    except ImportError:
        return None
    except Exception as exc:
        logger.warning("[KYA-NEMO] rails load failed: %s", exc)
        return None


def check_with_nemo(
    user_input: str,
    agent_output: str | None = None,
) -> dict:
    """Run a request through the configured NeMo rails. Returns:
        {"verdict": "allow"|"block"|"redact"|"unavailable",
         "reason": str, "redacted": Optional[str]}

    The action_gate calls this BEFORE dispatching to a handler. When
    NeMo isn't loaded, returns 'unavailable' and the action_gate falls
    back to its native rule evaluation.
    """
    rails = _load_nemo_rails()
    if rails is None:
        return {"verdict": "unavailable", "reason": "not_configured", "redacted": None}
    try:
        messages = [{"role": "user", "content": user_input or ""}]
        if agent_output:
            messages.append({"role": "assistant", "content": agent_output})
        result = rails.generate(messages=messages)
        # NeMo returns the (possibly-redacted) response; if the rails
        # decided to refuse, the content will include the refusal text.
        content = (
            result.get("content")
            if isinstance(result, dict)
            else getattr(result, "content", None) or str(result)
        )
        refusal_markers = [
            "I can't",
            "I cannot",
            "unable to",
            "blocked",
            "against policy",
        ]
        if content and any(m.lower() in content.lower() for m in refusal_markers):
            return {"verdict": "block", "reason": "nemo_refusal", "redacted": content}
        return {"verdict": "allow", "reason": "nemo_passed", "redacted": content}
    except Exception as exc:
        logger.warning("[KYA-NEMO] check failed: %s", exc)
        return {
            "verdict": "unavailable",
            "reason": f"runtime_error: {exc}",
            "redacted": None,
        }


# ── Webhook detector verdict ingest ─────────────────────────────────
# Lakera Guard, Prompt Security, AWS Bedrock Guardrails, Azure Content
# Safety, custom in-house detectors — all of them follow the same
# shape: receive a request, return a verdict. KYA accepts those
# verdicts via this endpoint and rolls them into the same principal
# trust + signal_counts the Hooks SDK uses.

# Map vendor verdict strings to KYA event types
_VENDOR_VERDICT_MAP = {
    # Lakera Guard typical categories
    "prompt_injection": "policy_violation",
    "jailbreak": "policy_violation",
    "pii": "data_leak",
    "moderated": "policy_violation",
    "data_leak": "data_leak",
    "violence": "policy_violation",
    "sexual": "policy_violation",
    # Prompt Security
    "prompt_attack": "policy_violation",
    "sensitive_data": "data_leak",
    "secret": "data_leak",
    # AWS Bedrock Guardrails
    "PII_FOUND": "data_leak",
    "PROMPT_ATTACK": "policy_violation",
    "CONTENT_FILTER": "policy_violation",
    "TOPIC": "policy_violation",
    # Azure Content Safety
    "HateSeverity": "policy_violation",
    "ViolenceSeverity": "policy_violation",
    "SexualSeverity": "policy_violation",
    "SelfHarmSeverity": "policy_violation",
}


def map_vendor_verdict_to_kya(
    vendor: str,
    category: str,
    severity: str | None = None,
) -> dict:
    """Map a vendor detector's verdict into the KYA event-type space.

    Returns:
        {"kya_event_type": str, "violation_kind": str,
         "data_class": str, "severity": str}
    """
    et = _VENDOR_VERDICT_MAP.get(category) or _VENDOR_VERDICT_MAP.get(category.lower())
    if not et:
        # Unknown category — default to policy_violation, attribute to vendor
        et = "policy_violation"
    out = {"kya_event_type": et, "vendor": vendor, "vendor_category": category}
    if et == "data_leak":
        # Heuristic mapping for the data_class field
        cl = (
            "pii"
            if "pii" in category.lower()
            else "secret"
            if "secret" in category.lower()
            else "phi"
            if "phi" in category.lower()
            else "internal"
        )
        out["data_class"] = cl
    else:
        out["violation_kind"] = (
            "prompt_injection"
            if "injection" in category.lower()
            else "jailbreak"
            if "jail" in category.lower()
            else "harmful_output"
        )
    out["severity"] = (severity or "medium").lower()
    if out["severity"] not in ("low", "medium", "high", "critical"):
        out["severity"] = "medium"
    return out
