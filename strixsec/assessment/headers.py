"""
Security Headers Assessment Module for StrixSec.
"""

from __future__ import annotations

from strixsec.assessment.models import SecurityHeaderCheck, SecurityHeaderResult
from strixsec.recon.models import HTTPResult

RECOMMENDED_HEADERS: dict[str, dict[str, str]] = {
    "Strict-Transport-Security": {
        "implication": (
            "HSTS forces browsers to communicate over HTTPS only, mitigating "
            "man-in-the-middle and protocol downgrade attacks."
        ),
        "recommendation": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
            "to response headers."
        ),
    },
    "Content-Security-Policy": {
        "implication": (
            "CSP restricts resource loading sources, providing strong defense against "
            "Cross-Site Scripting (XSS) and data injection."
        ),
        "recommendation": (
            "Implement a strict Content-Security-Policy header restricting script-src, "
            "style-src, and object-src."
        ),
    },
    "X-Content-Type-Options": {
        "implication": (
            "Prevents MIME-sniffing where browsers interpret files as a different "
            "MIME type than declared."
        ),
        "recommendation": "Set 'X-Content-Type-Options: nosniff' on all HTTP responses.",
    },
    "X-Frame-Options": {
        "implication": (
            "Controls whether page can be embedded in <frame>, <iframe>, or <object>, "
            "protecting against Clickjacking."
        ),
        "recommendation": (
            "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or use CSP frame-ancestors)."
        ),
    },
    "Referrer-Policy": {
        "implication": (
            "Controls how much referrer information (URL paths) is included "
            "with requests initiated from the site."
        ),
        "recommendation": (
            "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
        ),
    },
    "Permissions-Policy": {
        "implication": (
            "Allows site operators to restrict browser features and APIs "
            "(e.g. camera, microphone, geolocation)."
        ),
        "recommendation": (
            "Define a Permissions-Policy header explicitly disabling unused browser features."
        ),
    },
}


def evaluate_security_headers(http_result: HTTPResult) -> SecurityHeaderResult:
    """Analyze HTTP response headers for presence and security implications.

    Args:
        http_result: HTTPResult model from Phase 3 recon module.

    Returns:
        SecurityHeaderResult model populated with header checks.
    """
    headers = {k.lower(): (v, k) for k, v in http_result.headers.items()}
    checks: list[SecurityHeaderCheck] = []

    for header_name, meta in RECOMMENDED_HEADERS.items():
        key_lower = header_name.lower()
        if key_lower in headers:
            val, original_key = headers[key_lower]
            checks.append(
                SecurityHeaderCheck(
                    header_name=original_key,
                    is_present=True,
                    value=val,
                    implication=meta["implication"],
                    recommendation=(
                        "Header is present. Ensure configured parameters match "
                        "security best practices."
                    ),
                )
            )
        else:
            checks.append(
                SecurityHeaderCheck(
                    header_name=header_name,
                    is_present=False,
                    value=None,
                    implication=meta["implication"],
                    recommendation=meta["recommendation"],
                )
            )

    return SecurityHeaderResult(
        target=http_result.url,
        checks=checks,
    )
