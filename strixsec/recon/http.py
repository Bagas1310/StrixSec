"""
Safe HTTP/HTTPS Inspection Engine for StrixSec.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from strixsec.core.logging import setup_logger
from strixsec.recon.models import HTTPResult, Redirect
from strixsec.scope.normalizer import normalize_target
from strixsec.scope.storage import ScopeStorage
from strixsec.scope.validator import ScopeValidator

logger = setup_logger("strixsec.recon.http")

USER_AGENT = "StrixSec/0.1.0 (Security Assessment Toolkit; Authorized Audit)"
MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MB limit
TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def analyze_http(
    target: str,
    timeout: float = 5.0,
    max_redirects: int = 5,
    client: httpx.Client | None = None,
) -> HTTPResult:
    """Safely inspect HTTP/HTTPS service for an in-scope target.

    Args:
        target: Target domain, IP, or URL string.
        timeout: Request timeout in seconds.
        max_redirects: Maximum allowed redirect hops.
        client: Optional pre-configured httpx Client (useful for unit test mocking).

    Returns:
        HTTPResult containing headers, title, server, and redirect chain.
    """
    # Format initial candidate target URL
    initial_url = f"https://{target}" if not target.startswith(("http://", "https://")) else target

    storage = ScopeStorage()
    validator = ScopeValidator(storage.load_scope())

    # Try HTTPS first, fall back to HTTP if HTTPS fails
    res = _execute_http_analysis(initial_url, timeout, max_redirects, validator, client)

    if res.error and initial_url.startswith("https://"):
        http_fallback_url = f"http://{target.removeprefix('https://')}"
        logger.debug(
            f"HTTPS analysis failed for '{target}'. Trying HTTP fallback: '{http_fallback_url}'"
        )
        fallback_res = _execute_http_analysis(
            http_fallback_url, timeout, max_redirects, validator, client
        )
        if not fallback_res.error:
            return fallback_res

    return res


def _execute_http_analysis(
    url: str,
    timeout: float,
    max_redirects: int,
    validator: ScopeValidator,
    custom_client: httpx.Client | None = None,
) -> HTTPResult:
    """Internal helper to execute HTTP request flow and redirect chain inspection."""
    redirect_chain: list[Redirect] = []
    current_url = url
    https_available = current_url.startswith("https://")
    final_response = None
    last_error = None

    headers_send = {"User-Agent": USER_AGENT, "Accept": "*/*"}

    # Use provided client or create a fresh custom client
    own_client = custom_client is None
    client = custom_client or httpx.Client(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=False,  # Don't crash on self-signed certs during passive recon
    )

    try:
        redirect_count = 0
        while redirect_count <= max_redirects:
            # Security Requirement: Validate hostname of current_url against ScopeValidator
            try:
                hostname = urlparse(current_url).hostname or current_url
                norm_host, _ = normalize_target(hostname)
                val_res = validator.validate(norm_host)
                if not val_res.is_in_scope:
                    logger.warning(
                        f"Redirect boundary blocked: Hostname '{hostname}' is OUT OF SCOPE. "
                        "Halting redirect chain."
                    )
                    last_error = f"Redirect halted: '{hostname}' is out of scope."
                    break
            except Exception as val_err:
                last_error = f"Scope validation failed on redirect URL '{current_url}': {val_err}"
                break

            try:
                # Perform GET request with streaming to enforce MAX_RESPONSE_SIZE limit
                with client.stream("GET", current_url, headers=headers_send) as response:
                    final_response = response
                    status_code = response.status_code

                    # Check for redirect (3xx)
                    if response.is_redirect and "location" in response.headers:
                        if redirect_count >= max_redirects:
                            logger.warning(
                                f"Max redirect limit of {max_redirects} "
                                f"reached for '{current_url}'."
                            )
                            last_error = f"Maximum redirect limit of {max_redirects} exceeded."
                            break

                        redirect_chain.append(
                            Redirect(
                                url=current_url,
                                status_code=status_code,
                                headers=dict(response.headers),
                            )
                        )
                        location = response.headers["location"]
                        # Resolve relative redirect URLs
                        current_url = str(response.url.join(location))
                        redirect_count += 1
                        continue

                    # Read body up to max cap
                    content_bytes = bytearray()
                    for chunk in response.iter_bytes(chunk_size=8192):
                        content_bytes.extend(chunk)
                        if len(content_bytes) >= MAX_RESPONSE_SIZE:
                            logger.warning(
                                f"Response body truncated for '{current_url}' at limit "
                                f"{MAX_RESPONSE_SIZE} bytes."
                            )
                            break

                    body_text = content_bytes.decode("utf-8", errors="replace")

                    # Extract page details
                    headers_dict = dict(response.headers)
                    content_type = headers_dict.get("content-type")
                    server = headers_dict.get("server")
                    page_title = (
                        _extract_title(body_text)
                        if "text/html" in (content_type or "").lower() or not content_type
                        else None
                    )

                    return HTTPResult(
                        url=url,
                        final_url=current_url,
                        status_code=status_code,
                        headers=headers_dict,
                        content_type=content_type,
                        page_title=page_title,
                        server=server,
                        redirect_chain=redirect_chain,
                        https_available=https_available or current_url.startswith("https://"),
                        error=None,
                    )
            except httpx.TimeoutException:
                last_error = f"Connection to '{current_url}' timed out."
                break
            except httpx.ConnectError as err:
                last_error = f"Connection refused or failed for '{current_url}': {err}"
                break
            except httpx.HTTPError as err:
                last_error = f"HTTP error occurred for '{current_url}': {err}"
                break

    finally:
        if own_client:
            client.close()

    # Return error result if failed
    return HTTPResult(
        url=url,
        final_url=current_url,
        status_code=final_response.status_code if final_response else 0,
        headers=dict(final_response.headers) if final_response else {},
        redirect_chain=redirect_chain,
        https_available=False,
        error=last_error or "HTTP inspection failed.",
    )


def _extract_title(html_content: str) -> str | None:
    """Extract and sanitize HTML <title> text."""
    match = TITLE_REGEX.search(html_content)
    if match:
        raw_title = match.group(1).strip()
        # Clean up whitespace and line breaks
        cleaned = " ".join(raw_title.split())
        return cleaned[:200]  # Cap title length
    return None
