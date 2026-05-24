"""
Data-leak scanner — reusable content classifier for KYA hooks.

Pure regex-based + Luhn check for card numbers (no deps beyond stdlib).
Used by every framework adapter so behavior stays consistent: same
input -> same KYA event regardless of which SDK is in front.

Customize via:
  scanner = DataLeakScanner()
  scanner.add_pattern("custom_class", r"\\bPROJ-\\d{5}\\b", "internal project id")

Card-number detection (fix C3): requires Luhn checksum + recognized
BIN prefix (Visa 4xxx, MasterCard 5xxx/2xxx, AmEx 34/37, Discover 6xxx,
Diners 30/36/38, JCB 35). Eliminates the false-positive flood on order
IDs / tracking numbers / MRN strings that the naive 13-19 digit pattern
caused in healthcare and e-commerce tenants.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanMatch:
    """One leak finding produced by the scanner."""
    data_class: str
    pattern_label: str
    matched_text: str  # truncated to 80 chars for safety


# A validator takes the matched text and returns True to keep, False to drop.
PatternValidator = Callable[[str], bool]


# ── Validators ──────────────────────────────────────────────────────

def _luhn_check(digits: str) -> bool:
    """Classic Luhn mod-10 — used for credit card numbers (and many other
    financial IDs)."""
    n = [int(d) for d in digits if d.isdigit()]
    if len(n) < 13:
        return False
    s = 0
    parity = len(n) % 2
    for i, d in enumerate(n):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


_CARD_BIN_RE = re.compile(
    r"^(?:"
    r"4\d{12}(?:\d{3})?"     # Visa: 13 or 16 digits, starts 4
    r"|5[1-5]\d{14}"          # MasterCard: 16 digits, starts 51-55
    r"|2(?:2[2-9]|[3-6]\d|7[01]|720)\d{12}"  # MC 2-series: 16 digits
    r"|3[47]\d{13}"           # AmEx: 15 digits, starts 34 or 37
    r"|6(?:011|5\d{2}|4[4-9]\d|22(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5])))\d{12}"
    # Discover: 16 digits, complex prefix
    r"|3(?:0[0-5]|[68]\d)\d{11}"             # Diners: 14 digits
    r"|35(?:2[89]|[3-8]\d)\d{12}"             # JCB: 16 digits
    r")$"
)


def _valid_card_number(matched: str) -> bool:
    """Combined check: Luhn passes AND prefix matches a known BIN range."""
    digits = re.sub(r"[ -]", "", matched)
    if not digits.isdigit():
        return False
    if not _CARD_BIN_RE.match(digits):
        return False
    return _luhn_check(digits)


# ── Scanner ─────────────────────────────────────────────────────────

@dataclass
class DataLeakScanner:
    """Regex + validator based scanner for PHI / PII / financial / secret.

    Each pattern: (data_class, regex, label, optional validator).
    Returns ScanMatch list per call to `scan(text)`.

    Defaults cover:
      - phi: SSN-shape (XXX-XX-XXXX), MRN/PatientID prefix
      - pii: email addresses, US phone shapes
      - financial: credit card numbers (Luhn + BIN verified)
      - secret: AWS access key, Anthropic key, OpenAI key shapes
    """
    patterns: list = field(default_factory=list)

    def __post_init__(self):
        if not self.patterns:
            self.patterns = list(_DEFAULT_PATTERNS)

    def add_pattern(
        self, data_class: str, regex: str, label: str,
        validator: PatternValidator | None = None,
    ) -> None:
        """Register an additional pattern. `validator` (optional) is run on
        each match — returning False drops the match (validates without
        the false-positive cost of pure regex)."""
        self.patterns.append((data_class, regex, label, validator))

    def scan(self, text: str) -> list[ScanMatch]:
        """Run all patterns over `text`. Returns matches in pattern order.

        For each regex hit, if a validator is attached and returns False,
        the match is silently dropped. This is what saves the card pattern
        from false-positiving on MRN runs.
        """
        if not text:
            return []
        out: list[ScanMatch] = []
        for entry in self.patterns:
            # Allow 3-tuple (legacy) or 4-tuple (with validator)
            if len(entry) == 4:
                data_class, regex, label, validator = entry
            else:
                data_class, regex, label = entry
                validator = None
            for m in re.finditer(regex, text, flags=re.IGNORECASE):
                matched = m.group(0)
                if validator is not None and not validator(matched):
                    continue
                out.append(ScanMatch(
                    data_class=data_class,
                    pattern_label=label,
                    matched_text=matched[:80],
                ))
        return out

    def scan_unique_classes(self, text: str) -> list[ScanMatch]:
        """At most ONE match per data_class to avoid event spam."""
        seen: set[str] = set()
        out: list[ScanMatch] = []
        for match in self.scan(text):
            if match.data_class not in seen:
                seen.add(match.data_class)
                out.append(match)
        return out


# ── Default patterns ─────────────────────────────────────────────────
# (data_class, regex, label, validator)
# Conservative — better to false-negative than false-positive in real prod
# where every alert pages someone. Strict shapes + validators.

_DEFAULT_PATTERNS = (
    ("phi",       r"\b\d{3}-\d{2}-\d{4}\b",                            "ssn-shape",         None),
    ("phi",       r"\b(?:MRN|PatientID)[:\s]*\d+",                     "mrn-prefix",        None),
    ("pii",       r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",   "email-shape",       None),
    ("pii",       r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                                                                       "us-phone-shape",    None),
    # Fix C3: Luhn + BIN validation — no false positives on MRN/order IDs.
    ("financial", r"\b(?:\d[ -]*?){13,19}\b",                          "card-number-shape", _valid_card_number),
    ("secret",    r"\bAKIA[0-9A-Z]{16}\b",                             "aws-access-key",    None),
    ("secret",    r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",                    "anthropic-key",     None),
    ("secret",    r"\bsk-[A-Za-z0-9]{30,}\b",                          "openai-key",        None),
)
