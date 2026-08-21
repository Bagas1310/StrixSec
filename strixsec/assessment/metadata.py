"""
Safe Public Security Metadata Inspector for StrixSec.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from strixsec.assessment.models import MetadataResult
from strixsec.core.logging import setup_logger
from strixsec.recon.http import MAX_RESPONSE_SIZE, USER_AGENT
from strixsec.scope.normalizer import normalize_target
from strixsec.scope.storage import ScopeStorage
from strixsec.scope.validator import ScopeValidator

logger = setup_logger("strixsec.assessment.metadata")


def inspect_metadata(
    target: str,
    timeout: float = 5.0,
    client: httpx.Client | None = None,
) -> MetadataResult:
    """Safely check public security metadata files (robots.txt, security.txt).

    Args:
        target: Target domain or URL string.
        timeout: Request timeout in seconds.
        client: Optional custom httpx.Client instance for testing.

    Returns:
        MetadataResult model populated with metadata findings.
    """
    base_url = f"https://{target}" if not target.startswith(("http://", "https://")) else target

    storage = ScopeStorage()
    validator = ScopeValidator(storage.load_scope())

    # Check /robots.txt
    robots_found, robots_content = _fetch_public_file(
        f"{base_url.rstrip('/')}/robots.txt", timeout, validator, client
    )

    # Check /.well-known/security.txt then /security.txt
    sec_found, sec_content = _fetch_public_file(
        f"{base_url.rstrip('/')}/.well-known/security.txt", timeout, validator, client
    )
    if not sec_found:
        sec_found, sec_content = _fetch_public_file(
            f"{base_url.rstrip('/')}/security.txt", timeout, validator, client
        )

    return MetadataResult(
        target=target,
        robots_found=robots_found,
        robots_content=robots_content,
        security_txt_found=sec_found,
        security_txt_content=sec_content,
    )


def _fetch_public_file(
    file_url: str,
    timeout: float,
    validator: ScopeValidator,
    custom_client: httpx.Client | None = None,
) -> tuple[bool, str | None]:
    """Internal helper to safely fetch a public text file using GET requests only."""
    hostname = urlparse(file_url).hostname or file_url
    try:
        norm_host, _ = normalize_target(hostname)
        val_res = validator.validate(norm_host)
        if not val_res.is_in_scope:
            logger.warning(f"Metadata check blocked: '{hostname}' is OUT OF SCOPE.")
            return False, None
    except Exception as err:
        logger.warning(f"Scope validation failed for '{file_url}': {err}")
        return False, None

    headers_send = {"User-Agent": USER_AGENT, "Accept": "text/plain, */*"}
    own_client = custom_client is None
    client = custom_client or httpx.Client(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=False,
    )

    try:
        with client.stream("GET", file_url, headers=headers_send) as response:
            if response.status_code == 200:
                content_bytes = bytearray()
                for chunk in response.iter_bytes(chunk_size=8192):
                    content_bytes.extend(chunk)
                    if len(content_bytes) >= MAX_RESPONSE_SIZE:
                        logger.warning(
                            f"Public metadata file '{file_url}' exceeded 2 MB size limit."
                        )
                        break

                text = content_bytes.decode("utf-8", errors="replace").strip()
                # Return truncated snippet for display
                snippet = text[:500] if len(text) > 500 else text
                return True, snippet
    except Exception as err:
        logger.debug(f"Failed to fetch public metadata file '{file_url}': {err}")
    finally:
        if own_client:
            client.close()

    return False, None
