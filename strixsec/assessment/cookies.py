"""
Cookie Security Analysis Module for StrixSec with Mandatory Value Redaction.
"""

from __future__ import annotations

import re

from strixsec.assessment.models import CookieAttributeCheck, CookieResult
from strixsec.recon.models import HTTPResult

COOKIE_KV_REGEX = re.compile(r"^([^=;]+)=([^;]*)")


def evaluate_cookies(http_result: HTTPResult) -> CookieResult:
    """Analyze Set-Cookie headers for security attributes and apply mandatory value redaction.

    Args:
        http_result: HTTPResult model containing response headers.

    Returns:
        CookieResult model populated with REDACTED CookieAttributeCheck entries.
    """
    evaluated_cookies: list[CookieAttributeCheck] = []

    # Collect Set-Cookie headers (httpx may combine or expose via headers.get_list)
    raw_cookie_headers: list[str] = []

    for k, v in http_result.headers.items():
        if k.lower() == "set-cookie":
            # Split if multiple cookies separated by newlines or comma
            raw_cookie_headers.append(v)

    for cookie_str in raw_cookie_headers:
        cookie_check = _parse_and_redact_cookie(cookie_str)
        if cookie_check:
            evaluated_cookies.append(cookie_check)

    return CookieResult(
        target=http_result.url,
        cookies=evaluated_cookies,
    )


def _parse_and_redact_cookie(cookie_header: str) -> CookieAttributeCheck | None:
    """Parse a Set-Cookie string, evaluate security flags, and REDACT the secret value."""
    if not cookie_header or not cookie_header.strip():
        return None

    parts = [p.strip() for p in cookie_header.split(";")]
    if not parts:
        return None

    first_part = parts[0]
    match = COOKIE_KV_REGEX.match(first_part)
    if not match:
        cookie_name = first_part
        redacted_first_part = f"{cookie_name}=<REDACTED>"
    else:
        cookie_name = match.group(1).strip()
        redacted_first_part = f"{cookie_name}=<REDACTED>"

    # Evaluate flags
    secure = False
    httponly = False
    samesite_value: str | None = None

    redacted_parts = [redacted_first_part]

    for part in parts[1:]:
        part_lower = part.lower()
        if part_lower == "secure":
            secure = True
            redacted_parts.append("Secure")
        elif part_lower == "httponly":
            httponly = True
            redacted_parts.append("HttpOnly")
        elif part_lower.startswith("samesite"):
            if "=" in part:
                val = part.split("=", 1)[1].strip()
                samesite_value = val.capitalize()
                redacted_parts.append(f"SameSite={samesite_value}")
            else:
                samesite_value = "Default"
                redacted_parts.append("SameSite")
        else:
            # Preserve other non-sensitive flags (Path, Domain, Max-Age, Expires)
            redacted_parts.append(part)

    redacted_header_str = "; ".join(redacted_parts)

    return CookieAttributeCheck(
        cookie_name=cookie_name,
        redacted_header=redacted_header_str,
        secure=secure,
        httponly=httponly,
        samesite=samesite_value,
    )
