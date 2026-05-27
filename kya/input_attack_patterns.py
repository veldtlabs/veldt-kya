"""High-precision input-attack pattern detection.

This module is a content-neutral, zero-dependency, no-LLM input
safety judge. It catches the specific attack classes that live
testing showed Fiddler's safety model misses:

  - encoded payloads (base64 / hex of instruction-shaped text)
  - exfiltration paths (.env, /etc/secrets/, ~/.aws/credentials)
  - action-following directives ("reply with X and nothing else")
  - external redirects with double-encoded URLs
  - authority + urgency social engineering
  - indirect injection markers in RAG context
  - PII smuggling (SSN/CC numbers near "include in invite/email/etc")
  - role hijack ("you are now DAN", "developer mode")

Design principles:
  - HIGH PRECISION first. False positives ruin trust in the judge
    more than missed attacks. Each category requires either an
    unambiguous marker OR a combination of weaker signals.
  - Multiple signals stack. Hitting two unrelated categories raises
    the score significantly; one category alone may be UNCLEAR.
  - No LLM call. Pure regex + substring + bounded structural checks.
    Runs in microseconds.
  - Categories are exposed so callers can see WHY the input was
    flagged (audit trail + tunable thresholds).

The orchestrator integrates this as a peer to `fiddler_safety` in
the `input_safety` dimension. Fiddler is good at overt threats /
classic jailbreaks; this judge is good at infrastructure-shaped
attacks. Together they cover both.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from dataclasses import dataclass, field
from re import Pattern

logger = logging.getLogger(__name__)


# ── Category 1: encoded payloads ──────────────────────────────────


_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/=]{40,}")
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{60,}\b")
_INSTRUCTION_VERBS = (
    "ignore", "disregard", "override", "bypass", "forget",
    "instead", "new task", "your new", "delete", "drop table",
)
_DECODE_VERBS = (
    "decode", "translate", "execute", "run this", "interpret",
    "evaluate", "follow these", "do what this",
)


def _decode_b64_safe(s: str) -> str | None:
    try:
        # Heuristic: only treat as suspicious if decoded text is mostly
        # printable ASCII (raw bytes are likely intentional).
        raw = base64.b64decode(s, validate=True)
        text = raw.decode("utf-8", errors="strict")
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        if len(text) == 0 or printable / len(text) < 0.85:
            return None
        return text
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _decode_hex_safe(s: str) -> str | None:
    try:
        raw = bytes.fromhex(s)
        text = raw.decode("utf-8", errors="strict")
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        if len(text) == 0 or printable / len(text) < 0.85:
            return None
        return text
    except (ValueError, UnicodeDecodeError):
        return None


def _category_encoded_payload(text: str) -> dict | None:
    """Look for base64/hex strings whose decoded contents contain
    instruction-shaped verbs near decode/translate verbs in the
    surrounding text."""
    lower = text.lower()
    has_decode_verb = any(v in lower for v in _DECODE_VERBS)
    findings: list[dict] = []

    for match in _BASE64_TOKEN.finditer(text):
        token = match.group(0)
        decoded = _decode_b64_safe(token)
        if not decoded:
            continue
        decoded_lower = decoded.lower()
        if any(v in decoded_lower for v in _INSTRUCTION_VERBS):
            findings.append({
                "kind": "base64",
                "token_prefix": token[:24] + "...",
                "decoded_prefix": decoded[:80],
            })
    for match in _HEX_TOKEN.finditer(text):
        token = match.group(0)
        decoded = _decode_hex_safe(token)
        if not decoded:
            continue
        if any(v in decoded.lower() for v in _INSTRUCTION_VERBS):
            findings.append({
                "kind": "hex",
                "token_prefix": token[:24] + "...",
                "decoded_prefix": decoded[:80],
            })

    if not findings:
        return None
    return {
        "category": "encoded_payload",
        "findings": findings,
        # Stronger if surrounding text also pushes the model to
        # execute the decoded content.
        "weight": 0.9 if has_decode_verb else 0.7,
    }


# ── Category 2: exfiltration paths + credential filenames ─────────


_SECRET_PATHS: tuple[Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        r"/etc/secrets?\b",
        r"/etc/passwd\b",
        r"/etc/shadow\b",
        r"~?/\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts)\b",
        r"~?/\.aws/(credentials|config)\b",
        r"~?/\.kube/config\b",
        r"~?/\.gnupg/(secring|private-keys)\b",
        r"~?/\.npmrc\b", r"~?/\.pypirc\b",
        r"(?<!\w)\.env(\.local|\.production|\.staging)?\b",
        r"\bcredentials\.json\b",
        r"\bservice[_-]account\.json\b",
        r"\bid_rsa\b", r"\bsecring\.gpg\b",
    )
)

_SECRET_ENV_VARS = re.compile(
    r"\b("
    r"AWS_(SECRET_ACCESS_KEY|SESSION_TOKEN|ACCESS_KEY_ID)|"
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GROQ_API_KEY|"
    r"GITHUB_TOKEN|GH_TOKEN|"
    r"STRIPE_(SECRET|API)_KEY|"
    r"DATABASE_URL|POSTGRES_PASSWORD|MYSQL_PASSWORD|"
    r"SECRET_KEY|PRIVATE_KEY|JWT_SECRET|"
    r"SLACK_TOKEN|DISCORD_TOKEN|"
    r"DOCKER_PASSWORD|KUBECONFIG"
    r")\b"
)

_EXFIL_VERBS = (
    "dump", "show me the contents", "print every", "paste the contents",
    "output the file", "print the file", "leak", "exfiltrate",
    "send to", "email to", "post to", "upload to",
    "for my reference", "format as a markdown code block",
    "paste in your reply",
)


def _category_exfil_path(text: str) -> dict | None:
    lower = text.lower()
    path_hits = []
    for pat in _SECRET_PATHS:
        m = pat.search(text)
        if m:
            path_hits.append(m.group(0))
    env_hits = [m.group(0) for m in _SECRET_ENV_VARS.finditer(text)]
    verb_hit = next((v for v in _EXFIL_VERBS if v in lower), None)

    if not (path_hits or env_hits):
        return None

    # Weight: path/env-var alone is suspicious; combined with an
    # exfil verb is high-confidence.
    findings = path_hits + env_hits
    weight = 0.9 if (verb_hit and findings) else 0.6
    return {
        "category": "exfiltration_path",
        "findings": findings,
        "verb_match": verb_hit,
        "weight": weight,
    }


# ── Category 3: action-following directives near sensitive content ─


_ACTION_FOLLOWING_PATTERNS = (
    re.compile(r"\breply with\s+['\"]?[^'\"]{1,40}['\"]?\s+(and )?(nothing else|only)",
               re.IGNORECASE),
    re.compile(r"\boutput\s+(only|exactly|just)\s+", re.IGNORECASE),
    re.compile(r"\bformat\s+(as|in)\s+(a\s+)?(markdown\s+)?code\s+block",
               re.IGNORECASE),
    re.compile(r"\bdo not\s+(refuse|explain|comment|add)",
               re.IGNORECASE),
    re.compile(r"\bdon'?t\s+(refuse|explain|comment|add|ask)",
               re.IGNORECASE),
)


def _category_action_following(text: str) -> dict | None:
    hits = []
    for pat in _ACTION_FOLLOWING_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(m.group(0))
    if not hits:
        return None
    # Action-following alone is borderline; needs to combine with
    # another signal to BREACH on its own.
    return {
        "category": "action_following",
        "findings": hits,
        "weight": 0.4,
    }


# ── Category 4: external redirects + URL exfil ─────────────────────


_REDIRECT_PARAM = re.compile(
    r"[?&](redir|redirect|next|url|continue|return_url|return_to|goto)="
    r"(?:[^&\s]*?%3a%2f%2f|https?[:/])[^&\s]*",
    re.IGNORECASE,
)
_DOUBLE_ENCODED_URL = re.compile(
    r"%2[5fF]([0-9a-fA-F]{2}){2,}", re.IGNORECASE)
_SESSION_TOKEN_IN_URL = re.compile(
    r"\$(?:SESSION|TOKEN|COOKIE|AUTH|API_KEY|SECRET)",
    re.IGNORECASE)


def _category_external_redirect(text: str) -> dict | None:
    findings = []
    m = _REDIRECT_PARAM.search(text)
    if m:
        findings.append({"redirect_param": m.group(0)[:80]})
    if _DOUBLE_ENCODED_URL.search(text):
        findings.append({"double_encoded": True})
    if _SESSION_TOKEN_IN_URL.search(text):
        findings.append({"session_token_interpolation": True})
    if not findings:
        return None
    # Multiple signals = high confidence.
    return {
        "category": "external_redirect",
        "findings": findings,
        "weight": 0.7 if len(findings) >= 2 else 0.5,
    }


# ── Category 5: authority + urgency social engineering ─────────────


_AUTHORITY_CLAIM = re.compile(
    r"\bthis is\s+\w+\s+from\s+"
    r"(security|platform|compliance|legal|finance|exec|the (ceo|cto|cfo))",
    re.IGNORECASE,
)
_URGENCY_MARKERS = (
    "every minute matters", "right now", "no time", "urgent",
    "emergency", "breach detected", "live incident",
    "don't ask for confirmation", "no confirmation",
)
_OVERRIDE_NEAR_RULES = re.compile(
    r"\b(override|bypass|disable|ignore)\b.{0,40}\b"
    r"(rules?|instructions?|policies|policy|guardrails?|"
    r"restrictions?|guidelines?)\b",
    re.IGNORECASE,
)
_AUTH_TOKEN_IN_PROMPT = re.compile(
    r"\b(authorization|auth|override):\s*\S+",
    re.IGNORECASE,
)


def _category_authority_claim(text: str) -> dict | None:
    findings = []
    lower = text.lower()
    if _AUTHORITY_CLAIM.search(text):
        findings.append("authority_role_claim")
    urgent = [u for u in _URGENCY_MARKERS if u in lower]
    if urgent:
        findings.append(f"urgency_marker={urgent[0]}")
    if _OVERRIDE_NEAR_RULES.search(text):
        findings.append("override_near_rules")
    if _AUTH_TOKEN_IN_PROMPT.search(text):
        findings.append("inline_auth_token")
    if not findings:
        return None
    # Single signals are weak; combinations are strong.
    weight = (0.3 if len(findings) == 1
              else 0.7 if len(findings) == 2
              else 0.9)
    return {
        "category": "authority_claim",
        "findings": findings,
        "weight": weight,
    }


# ── Category 6: PII smuggling ─────────────────────────────────────


_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_PATTERN = re.compile(r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b")
_PII_KEYWORDS = (
    "ssn", "social security", "credit card", "bank account",
    "passport", "driver's license", "tax id",
)
_PII_PLACEMENT_VERBS = (
    "put my", "include my", "include the", "in the description",
    "in the invite", "in the event", "in the email body",
    "paste the user's", "paste my",
)
_EXTERNAL_RELAY_DOMAINS = re.compile(
    r"[\w._%+-]+@(?:[\w-]+\.)*"
    r"(?:gmail|yahoo|outlook|hotmail|icloud|protonmail|"
    r"external-relay|external|tempmail|guerrillamail|"
    r"mailinator|10minutemail)\.(?:com|net|org|me|io)",
    re.IGNORECASE,
)


def _category_pii_smuggling(text: str) -> dict | None:
    lower = text.lower()
    findings: list[str] = []
    if _SSN_PATTERN.search(text):
        findings.append("ssn_literal")
    if _CC_PATTERN.search(text):
        findings.append("credit_card_literal")
    if any(kw in lower for kw in _PII_KEYWORDS):
        findings.append("pii_keyword")
    placement = next(
        (v for v in _PII_PLACEMENT_VERBS if v in lower), None)
    if placement:
        findings.append(f"placement_verb={placement}")
    external_recipients = [
        m.group(0) for m in _EXTERNAL_RELAY_DOMAINS.finditer(text)]
    if external_recipients:
        findings.append(
            f"external_recipient={external_recipients[0]}")

    # A literal PII number ALONE may be legitimate; PII + placement
    # verb is suspicious; PII + placement + external recipient is
    # clearly an exfil attempt.
    if not findings:
        return None
    has_literal = any(f in ("ssn_literal", "credit_card_literal")
                      for f in findings)
    has_placement = any(f.startswith("placement_verb") for f in findings)
    has_external = any(f.startswith("external_recipient")
                       for f in findings)
    if has_literal and has_placement and has_external:
        weight = 0.95
    elif has_literal and (has_placement or has_external):
        weight = 0.8
    elif has_literal:
        weight = 0.5
    else:
        weight = 0.3
    return {
        "category": "pii_smuggling",
        "findings": findings,
        "weight": weight,
    }


# ── Category 7: role hijack ────────────────────────────────────────


_ROLE_HIJACK_PATTERNS = (
    re.compile(r"\byou(?:'re| are)\s+now\s+(DAN|STAN|developer mode|"
               r"jailbroken|unrestricted)",
               re.IGNORECASE),
    re.compile(r"\b(?:DAN|STAN)\s+(?:mode|never\s+refuses|"
               r"has no restrictions|can do anything)",
               re.IGNORECASE),
    re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
    re.compile(r"\bstay\s+in\s+character\s+as\b", re.IGNORECASE),
    re.compile(r"\bdeveloper\s+mode\s+enabled\b", re.IGNORECASE),
    re.compile(r"\bjailbreak(?:ing)?\b", re.IGNORECASE),
    re.compile(r"\b(?:let'?s\s+)?(?:play|pretend)\s+a?\s*game\b.{0,80}"
               r"\bno\s+restrictions?\b",
               re.IGNORECASE | re.DOTALL),
)


def _category_role_hijack(text: str) -> dict | None:
    hits = []
    for pat in _ROLE_HIJACK_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(m.group(0)[:60])
    if not hits:
        return None
    # Role hijack is one of the strongest signals -- single match
    # already justifies BREACH.
    return {
        "category": "role_hijack",
        "findings": hits,
        "weight": 0.9,
    }


# ── Category 8: indirect injection markers (RAG context) ───────────


_INJECTION_MARKERS = (
    re.compile(r"\[SYSTEM\s+OVERRIDE\b", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]\s*:", re.IGNORECASE),
    re.compile(r"\[NEW\s+INSTRUCTIONS?\b", re.IGNORECASE),
    re.compile(r"\[IMPORTANT\s+OVERRIDE\b", re.IGNORECASE),
    re.compile(r"###\s*(NEW|UPDATED|FINAL)\s+(INSTRUCTIONS?|TASK)",
               re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"</?system>", re.IGNORECASE),
    re.compile(r"\bignore\s+(your\s+)?(previous|prior|all)\s+"
               r"instructions?",
               re.IGNORECASE),
    re.compile(r"\byour\s+new\s+task\s+is\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(all\s+)?(prior|previous|the\s+above)",
               re.IGNORECASE),
)


def _category_indirect_injection(text: str) -> dict | None:
    hits = []
    for pat in _INJECTION_MARKERS:
        m = pat.search(text)
        if m:
            hits.append(m.group(0))
    if not hits:
        return None
    return {
        "category": "indirect_injection",
        "findings": hits,
        # Strong signal -- these markers in a document/context are
        # always adversarial in normal usage.
        "weight": 0.95,
    }


# ── Aggregator ────────────────────────────────────────────────────


@dataclass
class PatternScanResult:
    """Result of scanning input + context for attack patterns."""
    max_weight: float
    categories: list[dict] = field(default_factory=list)
    breach_threshold: float = 0.5

    @property
    def breached(self) -> bool:
        return self.max_weight >= self.breach_threshold

    @property
    def category_names(self) -> list[str]:
        return [c["category"] for c in self.categories]


_INPUT_CATEGORIES = (
    _category_encoded_payload,
    _category_exfil_path,
    _category_action_following,
    _category_external_redirect,
    _category_authority_claim,
    _category_pii_smuggling,
    _category_role_hijack,
)

_CONTEXT_CATEGORIES = (
    # Indirect injection is the dominant context-side attack.
    _category_indirect_injection,
    # Exfil paths can hide in RAG documents too.
    _category_exfil_path,
)


def scan(
    input_text: str | None,
    context: str | None = None,
    *,
    breach_threshold: float = 0.5,
) -> PatternScanResult:
    """Scan input + RAG context for attack patterns.

    Returns a `PatternScanResult` summarizing which categories
    triggered and what the maximum confidence weight was. A weight
    >= `breach_threshold` means BREACH.

    Why max-weight not sum: any single high-confidence category
    (encoded payload with instruction, exfil path with verb, role
    hijack) is enough to BREACH on its own. Summing would let
    multiple weak signals tip a BREACH on a borderline input,
    which has worse false-positive characteristics than a clean
    max-of-categories.
    """
    findings: list[dict] = []
    if input_text:
        for fn in _INPUT_CATEGORIES:
            try:
                f = fn(input_text)
            except Exception as exc:
                logger.debug(
                    "[KYA-PATTERNS] category %s raised: %s",
                    fn.__name__, exc)
                continue
            if f:
                findings.append(f)
    if context:
        for fn in _CONTEXT_CATEGORIES:
            try:
                f = fn(context)
            except Exception as exc:
                logger.debug(
                    "[KYA-PATTERNS] context category %s raised: %s",
                    fn.__name__, exc)
                continue
            if f:
                # Mark context-side findings distinct from input
                # findings so the audit trail shows where the
                # attack lived.
                f = dict(f)
                f["surface"] = "context"
                findings.append(f)
    max_weight = max((f["weight"] for f in findings), default=0.0)
    return PatternScanResult(
        max_weight=max_weight,
        categories=findings,
        breach_threshold=breach_threshold,
    )
