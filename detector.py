
"""Detection engine for identifying sensitive information in text."""

import math
import re
from collections import Counter


# -------------------------------------------------------------------
# Validation helpers
# -------------------------------------------------------------------

def luhn_ok(number: str) -> bool:
    """Check whether a number passes the Luhn checksum."""
    digits = [int(char) for char in re.sub(r"\D", "", number)][::-1]

    if not 13 <= len(digits) <= 19:
        return False

    total = 0

    for index, digit in enumerate(digits):
        if index % 2 == 1:
            digit *= 2

            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0


# Tables used by the Verhoeff checksum algorithm.
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_ok(number: str) -> bool:
    """Validate a number using the Verhoeff checksum."""
    digits = [int(char) for char in re.sub(r"\D", "", number)]
    checksum = 0

    for index, digit in enumerate(reversed(digits)):
        checksum = _D[checksum][_P[index % 8][digit]]

    return checksum == 0


def aadhaar_ok(value: str) -> bool:
    """Check the format and checksum of an Aadhaar number."""
    digits = re.sub(r"\D", "", value)

    return (
        len(digits) == 12
        and digits[0] in "23456789"
        and len(set(digits)) > 1
        and verhoeff_ok(digits)
    )


def card_ok(value: str) -> bool:
    """Check whether a card number passes basic validation."""
    digits = re.sub(r"\D", "", value)

    return (
        digits[:1] in "3456"
        and len(set(digits)) > 1
        and luhn_ok(digits)
    )


def iban_ok(value: str) -> bool:
    """Validate an IBAN using the modulo 97 check."""
    iban = re.sub(r"\s", "", value).upper()

    if not 15 <= len(iban) <= 34:
        return False

    rearranged = iban[4:] + iban[:4]

    try:
        numeric_iban = "".join(
            str(int(char, 36)) for char in rearranged
        )
        return int(numeric_iban) % 97 == 1
    except ValueError:
        return False


def ssn_ok(value: str) -> bool:
    """Reject invalid US Social Security number groups."""
    area, group, serial = value.split("-")

    return (
        area not in ("000", "666")
        and not area.startswith("9")
        and group != "00"
        and serial != "0000"
    )


def ip_ok(value: str) -> bool:
    """Check IPv4 octets and reject selected special addresses."""
    parts = value.split(".")

    if len(parts) != 4:
        return False

    try:
        if not all(0 <= int(part) <= 255 for part in parts):
            return False
    except ValueError:
        return False

    return not (
        value.startswith(("0.", "127."))
        or value == "255.255.255.255"
    )


PLACEHOLDER = re.compile(
    r"^(\*+|x+|null|none|true|false|changeme|your[_-].*|"
    r"<.*>|\$\{.*\}|\{\{.*\}\}|%.*%)$",
    re.IGNORECASE,
)


def password_ok(value: str) -> bool:
    """Ignore obvious placeholder values."""
    return not PLACEHOLDER.match(value)


# -------------------------------------------------------------------
# Masking helpers
# -------------------------------------------------------------------

def mask_partial(value: str, keep: int = 2) -> str:
    """Keep a few characters at each end and mask the rest."""
    if len(value) <= keep * 2:
        return "*" * len(value)

    hidden_length = len(value) - keep * 2
    return value[:keep] + "*" * hidden_length + value[-keep:]


def mask_email(value: str) -> str:
    """Hide the local part of an email address."""
    local, separator, domain = value.partition("@")

    if not local or not separator:
        return "*" * len(value)

    return local[:1] + "***@" + domain


def mask_full(value: str) -> str:
    """Replace a value with a fixed-length mask."""
    return "*" * min(max(len(value), 6), 12)


def mask_last4(value: str) -> str:
    """Keep only the last four digits."""
    digits = re.sub(r"\D", "", value)

    if len(digits) <= 4:
        return "*" * len(digits)

    return "*" * (len(digits) - 4) + digits[-4:]


# -------------------------------------------------------------------
# Detection rules
# Each rule contains:
# type, label, severity, pattern, capture group,
# validator, masking function, and priority.
# -------------------------------------------------------------------

RULES = [
    (
        "private_key", "Private key", "high",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        0, None, mask_full, 100,
    ),
    (
        "aws_key", "AWS access key", "high",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        0, None, mask_partial, 95,
    ),
    (
        "google_key", "Google API key", "high",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        0, None, mask_partial, 95,
    ),
    (
        "github_token", "GitHub token", "high",
        r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        0, None, mask_partial, 95,
    ),
    (
        "slack_token", "Slack token", "high",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
        0, None, mask_partial, 95,
    ),
    (
        "jwt", "JWT token", "high",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        0, None, mask_partial, 90,
    ),
    (
        "password", "Password / secret", "high",
        r"""(?i)\b(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|token)\b["']?\s*[:=]\s*["']?([^\s"',;]{4,})""",
        1, password_ok, mask_full, 85,
    ),
    (
        "cvv", "CVV", "high",
        r"(?i)\bcvv2?\b\W{0,3}(\d{3,4})(?!\d)",
        1, None, mask_full, 85,
    ),
    (
        "credit_card", "Credit / debit card", "high",
        r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])",
        0, card_ok, mask_last4, 80,
    ),
    (
        "aadhaar", "Aadhaar number", "high",
        r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)",
        0, aadhaar_ok, mask_last4, 80,
    ),
    (
        "ssn", "US SSN", "high",
        r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])",
        0, ssn_ok, mask_last4, 75,
    ),
    (
        "pan", "PAN (India)", "high",
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
        0, None, mask_partial, 75,
    ),
    (
        "iban", "IBAN", "high",
        r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b",
        0, iban_ok, mask_partial, 70,
    ),
    (
        "bank_account", "Bank account number", "high",
        r"(?i)\baccount\s*(?:no|number|num|#)?\.?\W{0,4}(\d{9,18})(?!\d)",
        1, None, mask_last4, 70,
    ),
    (
        "email", "Email address", "medium",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
        0, None, mask_email, 60,
    ),
    (
        "phone", "Phone number", "medium",
        r"(?<![\w+.-])(?:\+91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)|(?<![\w+.-])\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)",
        0, None, mask_last4, 55,
    ),
    (
        "dob", "Date of birth", "medium",
        r"(?i)(?:\bdob\b|date of birth|birth ?date)\W{0,4}(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2})",
        1, None, mask_full, 55,
    ),
    (
        "ip", "IP address", "low",
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        0, ip_ok, mask_partial, 40,
    ),
]

COMPILED_RULES = [
    (
        key,
        label,
        severity,
        re.compile(pattern),
        group,
        validator,
        masker,
        priority,
    )
    for (
        key,
        label,
        severity,
        pattern,
        group,
        validator,
        masker,
        priority,
    ) in RULES
]

ENTROPY_PATTERN = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")


def shannon(value: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


# -------------------------------------------------------------------
# Scanning
# -------------------------------------------------------------------

def scan_line(line: str):
    """Find sensitive values in a line without overlapping results."""
    candidates = []

    for (
        key,
        label,
        severity,
        pattern,
        group,
        validator,
        masker,
        priority,
    ) in COMPILED_RULES:
        for match in pattern.finditer(line):
            start, end = match.span(group)

            if start == end:
                continue

            raw_value = match.group(group)

            if validator and not validator(raw_value):
                continue

            candidates.append(
                (
                    priority,
                    end - start,
                    start,
                    end,
                    key,
                    label,
                    severity,
                    masker(raw_value),
                )
            )

    # Look for long strings that may be randomly generated secrets.
    for match in ENTROPY_PATTERN.finditer(line):
        value = match.group()

        has_digits = re.search(r"\d", value)
        has_letters = re.search(r"[A-Za-z]", value)
        looks_like_url = value.lower().startswith(("http", "www"))

        if (
            has_digits
            and has_letters
            and shannon(value) >= 4.0
            and not looks_like_url
            and value.count("/") < 3
        ):
            candidates.append(
                (
                    10,
                    len(value),
                    match.start(),
                    match.end(),
                    "high_entropy",
                    "Possible secret (high entropy)",
                    "medium",
                    mask_partial(value),
                )
            )

    # Prefer higher-priority matches when results overlap.
    candidates.sort(key=lambda item: (-item[0], -item[1], item[2]))

    occupied_ranges = []
    findings = []

    for (
        priority,
        _,
        start,
        end,
        key,
        label,
        severity,
        masked_value,
    ) in candidates:
        overlaps = any(
            start < previous_end and end > previous_start
            for previous_start, previous_end in occupied_ranges
        )

        if overlaps:
            continue

        occupied_ranges.append((start, end))

        findings.append(
            {
                "type": key,
                "label": label,
                "severity": severity,
                "start": start,
                "end": end,
                "masked": masked_value,
            }
        )

    return sorted(findings, key=lambda item: item["start"])


def masked_context(line: str, findings, width: int = 90) -> str:
    """Create a context preview without exposing detected raw values."""
    parts = []
    position = 0
    first_match_position = None

    for finding in findings:
        start = finding["start"]
        end = finding["end"]

        parts.append(line[position:start])

        if first_match_position is None:
            first_match_position = sum(len(part) for part in parts)

        parts.append(finding["masked"])
        position = end

    parts.append(line[position:])
    context = "".join(parts).strip()

    if len(context) > width * 2:
        start = max(0, (first_match_position or 0) - width)
        end = start + width * 2

        prefix = "…" if start else ""
        suffix = "…" if end < len(context) else ""

        context = prefix + context[start:end] + suffix

    return context


MAX_FINDINGS = 5000


def scan_units(units):
    """Scan text units and return a summary of detected sensitive data."""
    findings = []
    truncated = False

    for location, text in units:
        if not text or not text.strip():
            continue

        line_findings = scan_line(text)

        if not line_findings:
            continue

        context = masked_context(text, line_findings)

        for finding in line_findings:
            findings.append(
                {
                    "type": finding["type"],
                    "label": finding["label"],
                    "severity": finding["severity"],
                    "location": location,
                    "masked": finding["masked"],
                    "context": context,
                }
            )

            if len(findings) >= MAX_FINDINGS:
                truncated = True
                break

        if truncated:
            break

    severity_counts = Counter(
        finding["severity"] for finding in findings
    )
    type_counts = Counter(
        finding["label"] for finding in findings
    )

    score = (
        severity_counts["high"] * 10
        + severity_counts["medium"] * 3
        + severity_counts["low"]
    )

    if not findings:
        risk = "Clean"
    elif severity_counts["high"] >= 10 or score >= 100:
        risk = "Critical"
    elif severity_counts["high"]:
        risk = "High"
    elif severity_counts["medium"]:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk": risk,
        "score": score,
        "total": len(findings),
        "truncated": truncated,
        "by_severity": {
            severity: severity_counts.get(severity, 0)
            for severity in ("high", "medium", "low")
        },
        "by_type": dict(type_counts.most_common()),
        "findings": findings,
    }
