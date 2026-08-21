"""
Passive Technology Fingerprinting Engine for StrixSec.
"""

from __future__ import annotations

from strixsec.recon.models import (
    ConfidenceLevel,
    HTTPResult,
    TechnologyMatch,
    TechnologyResult,
)


def detect_technologies(http_res: HTTPResult) -> TechnologyResult:
    """Passively detect technologies based on HTTP response headers and title.

    Args:
        http_res: HTTPResult model from analyze_http.

    Returns:
        TechnologyResult containing list of passive matches with confidence scores.
    """
    matches: list[TechnologyMatch] = []
    headers = {k.lower(): v for k, v in http_res.headers.items()}
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    generator = headers.get("x-generator", "")

    # 1. Web Servers (from Server Header)
    if "nginx" in server.lower():
        matches.append(
            TechnologyMatch(
                name="Nginx",
                category="Web Server",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"Server: {server}",
            )
        )
    elif "apache" in server.lower():
        matches.append(
            TechnologyMatch(
                name="Apache HTTP Server",
                category="Web Server",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"Server: {server}",
            )
        )
    elif "cloudflare" in server.lower():
        matches.append(
            TechnologyMatch(
                name="Cloudflare",
                category="CDN / Reverse Proxy",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"Server: {server}",
            )
        )
    elif "caddy" in server.lower():
        matches.append(
            TechnologyMatch(
                name="Caddy Web Server",
                category="Web Server",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"Server: {server}",
            )
        )
    elif "microsoft-iis" in server.lower():
        matches.append(
            TechnologyMatch(
                name="Microsoft IIS",
                category="Web Server",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"Server: {server}",
            )
        )

    # 2. Frameworks & Backend Technologies (from X-Powered-By / Cookies)
    if "express" in powered_by.lower():
        matches.append(
            TechnologyMatch(
                name="Express.js",
                category="Framework",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"X-Powered-By: {powered_by}",
            )
        )
    elif "php" in powered_by.lower():
        matches.append(
            TechnologyMatch(
                name="PHP",
                category="Programming Language",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"X-Powered-By: {powered_by}",
            )
        )
    elif "asp.net" in powered_by.lower():
        matches.append(
            TechnologyMatch(
                name="ASP.NET",
                category="Framework",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"X-Powered-By: {powered_by}",
            )
        )
    elif "next.js" in powered_by.lower() or "x-nextjs-cache" in headers:
        matches.append(
            TechnologyMatch(
                name="Next.js",
                category="Framework",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator="Next.js Header Indicator",
            )
        )

    # Cookie based indicators
    cookies = headers.get("set-cookie", "")
    if "laravel_session" in cookies.lower():
        matches.append(
            TechnologyMatch(
                name="Laravel",
                category="Framework",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator="Set-Cookie: laravel_session",
            )
        )
    elif "csrftoken" in cookies.lower() or "sessionid" in cookies.lower():
        matches.append(
            TechnologyMatch(
                name="Django",
                category="Framework",
                confidence=ConfidenceLevel.MEDIUM,
                matched_indicator="Set-Cookie: django csrf/session pattern",
            )
        )

    # 3. CMS Fingerprints (from Meta Generator or Header)
    if "wordpress" in generator.lower() or "wp-content" in generator.lower():
        matches.append(
            TechnologyMatch(
                name="WordPress",
                category="CMS",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"Generator: {generator}",
            )
        )
    elif "drupal" in generator.lower():
        matches.append(
            TechnologyMatch(
                name="Drupal",
                category="CMS",
                confidence=ConfidenceLevel.HIGH,
                matched_indicator=f"Generator: {generator}",
            )
        )

    return TechnologyResult(
        target=http_res.url,
        detected_technologies=matches,
    )
