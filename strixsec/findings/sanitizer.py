"""
Evidence Sanitizer and Secret Redaction Module for StrixSec.
"""

from __future__ import annotations

import re

# Regex patterns for sensitive credentials
SENSITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Set-Cookie values
    (re.compile(r"(set-cookie\s*:\s*[^=;]+)=([^;\r\n]+)", re.IGNORECASE), r"\1=<REDACTED>"),
    # Generic cookie key=val
    (re.compile(r"(cookie\s*:\s*[^=;]+)=([^;\r\n]+)", re.IGNORECASE), r"\1=<REDACTED>"),
    # Bearer / Auth tokens
    (re.compile(r"(authorization\s*:\s*bearer\s+)[^\s\r\n]+", re.IGNORECASE), r"\1<REDACTED>"),
    (re.compile(r"(authorization\s*:\s*basic\s+)[^\s\r\n]+", re.IGNORECASE), r"\1<REDACTED>"),
    # Passwords & Secret parameters in strings/queries
    (
        re.compile(
            r"((?:password|passwd|secret|api_key|apikey|token|access_token)\s*[:=]\s*)[^\s;&,\"]+",
            re.IGNORECASE,
        ),
        r"\1<REDACTED>",
    ),
    # RSA / PEM Private keys
    (
        re.compile(r"-----BEGIN[A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]+PRIVATE KEY-----"),
        "[PRIVATE KEY REDACTED]",
    ),
)


def sanitize_evidence(raw_value: str) -> str:
    """Sanitize and redact sensitive credentials from evidence strings.

    Args:
        raw_value: Raw input evidence string.

    Returns:
        Sanitized evidence string with sensitive secrets replaced by <REDACTED>.
    """
    if not raw_value or not isinstance(raw_value, str):
        return ""

    sanitized = raw_value
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized
