"""Secret and PII detection with checksum validators, plus redaction.

Raw values are never stored: a SecretHit keeps offsets (for redaction) and a masked preview.
Detector order is priority order - earlier detectors win when spans overlap.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .verhoeff import validate as verhoeff_valid

SAFE_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}
SAFE_EMAIL_TLDS = {"test", "example", "invalid", "localhost"}
_PLACEHOLDERS = {
    "null", "none", "true", "false", "undefined", "string", "password", "yourpassword",
    "your_password", "changeme_placeholder", "example", "value",
}


@dataclass(frozen=True)
class SecretHit:
    kind: str
    start: int
    end: int
    preview: str
    confidence: str
    checksum_ok: bool | None = None
    source: str = ""


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: re.Pattern
    group: int = 0
    validator: Callable[[str], bool] | None = None
    confidence: str = "high"
    mask: str = "prefix"  # prefix | last4 | block


# ---------------------------------------------------------------- validators
def _not_placeholder(value: str) -> bool:
    low = value.strip("*<>[]{}()\"'").lower()
    if not low or "redacted" in low:
        return False
    if set(low) <= {"*", "x", ".", "\u2022"}:
        return False
    return low not in _PLACEHOLDERS


def _real_email(value: str) -> bool:
    domain = value.rsplit("@", 1)[-1].lower()
    return domain not in SAFE_EMAIL_DOMAINS and domain.rsplit(".", 1)[-1] not in SAFE_EMAIL_TLDS


def _aadhaar_ok(value: str) -> bool:
    return verhoeff_valid(re.sub(r"\D", "", value))


def _pan_ok(value: str) -> bool:
    return value[3] in "ABCFGHLJPTK"


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _card_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 13 <= len(digits) <= 19 and digits[0] in "3456" and luhn_ok(digits)


def _c(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


DETECTORS: list[Detector] = [
    Detector(
        "private_key",
        _c(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:[\s\S]{0,6000}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)?"),
        mask="block",
    ),
    Detector("aws_access_key_id", _c(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Detector(
        "aws_secret_access_key",
        _c(r"(?i)(?<![A-Za-z0-9])(?:aws_?)?secret_?access_?key(?![A-Za-z0-9])[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
        group=1,
    ),
    Detector("github_token", _c(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    Detector("slack_token", _c(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    Detector("google_api_key", _c(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Detector("stripe_key", _c(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    Detector(
        "jwt",
        _c(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    Detector(
        "bearer_token",
        _c(r"(?i)\bauthorization\s*:\s*(?:bearer|token)\s+([A-Za-z0-9._~+/=\-]{12,})"),
        group=1,
    ),
    Detector(
        "url_credentials",
        _c(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^/\s:@]+:([^/\s@]+)@"),
        group=1,
        validator=_not_placeholder,
    ),
    Detector(
        "session_id",
        _c(r"(?i)\b(?:phpsessid|jsessionid|sessionid|session_id|sid|connect\.sid|session)\s*=\s*([A-Za-z0-9%._\-]{16,})"),
        group=1,
        validator=_not_placeholder,
        confidence="medium",
    ),
    Detector(
        "password",
        _c(
            r"(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|passphrase|client_secret|secret|api[_-]?key|apikey|access_token|auth_token|token)"
            r"(?![A-Za-z0-9])[\"']?\s*[:=]\s*[\"']?([^\s\"',;&<>]{4,})"
        ),
        group=1,
        validator=_not_placeholder,
        confidence="medium",
    ),
    Detector(
        "email",
        _c(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        validator=_real_email,
        confidence="medium",
    ),
    Detector(
        "aadhaar",
        _c(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),
        validator=_aadhaar_ok,
        mask="last4",
    ),
    Detector("pan", _c(r"\b[A-Z]{5}\d{4}[A-Z]\b"), validator=_pan_ok, confidence="medium"),
    Detector(
        "payment_card",
        _c(r"\b(?:\d[ -]?){13,19}\b"),
        validator=_card_ok,
        confidence="medium",
        mask="last4",
    ),
]


def _preview(value: str, style: str) -> str:
    if style == "block":
        return "[private key]"
    digits = re.sub(r"\D", "", value)
    if style == "last4" and len(digits) >= 4:
        return "**** " + digits[-4:]
    v = value.strip()
    if len(v) < 8:
        return "*" * len(v)
    return v[:2] + "******"


def scan_text(text: str, source: str = "") -> list[SecretHit]:
    """Find secrets/PII in `text`. Returns non-overlapping hits sorted by position."""
    candidates = []
    for priority, det in enumerate(DETECTORS):
        for m in det.pattern.finditer(text):
            start, end = (m.start(det.group), m.end(det.group)) if det.group else m.span()
            if start < 0 or end <= start:
                continue
            value = text[start:end]
            if det.validator and not det.validator(value):
                continue
            checksum = True if det.kind in ("aadhaar", "payment_card") else None
            candidates.append((priority, start, end, det, value, checksum))
    candidates.sort(key=lambda c: (c[0], c[1]))
    chosen: list[tuple] = []
    for cand in candidates:
        _, start, end, *_ = cand
        if any(start < c[2] and end > c[1] for c in chosen):
            continue
        chosen.append(cand)
    chosen.sort(key=lambda c: c[1])
    return [
        SecretHit(
            kind=det.kind,
            start=start,
            end=end,
            preview=_preview(value, det.mask),
            confidence=det.confidence,
            checksum_ok=checksum,
            source=source,
        )
        for _, start, end, det, value, checksum in chosen
    ]


def redact_text(text: str, hits: list[SecretHit]) -> str:
    out = text
    for hit in sorted(hits, key=lambda h: h.start, reverse=True):
        out = out[: hit.start] + f"[REDACTED:{hit.kind}]" + out[hit.end :]
    return out


def redact(text: str, source: str = "") -> tuple[str, list[SecretHit]]:
    hits = scan_text(text, source)
    return redact_text(text, hits), hits
