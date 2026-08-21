"""
Normalization and Target Parsing Engine for StrixSec Scope System.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from strixsec.core.errors import ScopeValidationError
from strixsec.scope.models import TargetType

# RFC 1123 domain label pattern
DOMAIN_LABEL_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def normalize_target(raw_input: str) -> tuple[str, TargetType]:
    """Normalize a target string (URL, IP, CIDR, Domain, Wildcard) and determine its type.

    Args:
        raw_input: Raw target string from user input or file.

    Returns:
        Tuple of (normalized_target_string, TargetType).

    Raises:
        ScopeValidationError: If target is malformed or invalid.
    """
    if not raw_input or not isinstance(raw_input, str):
        raise ScopeValidationError("Target input must be a non-empty string.")

    cleaned = raw_input.strip()
    if not cleaned:
        raise ScopeValidationError("Target string cannot be blank or whitespace.")

    # 1. Handle URL schemes (e.g. http://example.com:8080/path -> example.com)
    if "://" in cleaned:
        try:
            parsed = urlparse(cleaned)
            hostname = parsed.hostname
            if not hostname:
                raise ScopeValidationError(f"Invalid URL structure in target '{raw_input}'.")
            cleaned = hostname
        except Exception as err:
            raise ScopeValidationError(f"Failed to parse URL target '{raw_input}': {err}") from err
    else:
        # Strip path or query if passed without scheme (e.g. example.com/path)
        if "/" in cleaned and not _is_cidr(cleaned):
            cleaned = cleaned.split("/")[0]

        # Strip port if present (e.g. example.com:8080 or 192.168.1.1:8080)
        if ":" in cleaned:
            # Check if it's not an IPv6 address
            parts = cleaned.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                cleaned = parts[0]

    # Lowercase and remove trailing FQDN dot (e.g. EXAMPLE.COM. -> example.com)
    cleaned = cleaned.lower().rstrip(".")

    if not cleaned:
        raise ScopeValidationError(f"Normalized target is empty for input '{raw_input}'.")

    # 2. Check for Wildcard Domain (*.example.com)
    if cleaned.startswith("*."):
        domain_part = cleaned[2:]
        if not DOMAIN_LABEL_REGEX.match(domain_part):
            raise ScopeValidationError(
                f"Invalid wildcard domain '{raw_input}'. Main domain '{domain_part}' is invalid."
            )
        return cleaned, TargetType.WILDCARD_DOMAIN

    # Reject wildcard in other positions (e.g., ex*ample.com or *example.com)
    if "*" in cleaned:
        raise ScopeValidationError(
            f"Invalid wildcard placement in target '{raw_input}'. "
            "Wildcard is only supported as prefix '*.'."
        )

    # 3. Check for IPv4 Address
    try:
        ip = ipaddress.IPv4Address(cleaned)
        return str(ip), TargetType.IPV4
    except ValueError:
        pass

    # 4. Check for CIDR Range
    if "/" in cleaned:
        try:
            net = ipaddress.IPv4Network(cleaned, strict=False)
            return str(net), TargetType.CIDR
        except ValueError as err:
            raise ScopeValidationError(f"Invalid CIDR network range '{raw_input}': {err}") from err

    # 5. Check for Exact Domain
    # Allow single label hostnames in local contexts or strict domain validation
    if DOMAIN_LABEL_REGEX.match(cleaned) or (cleaned.isalnum() and not cleaned.isdigit()):
        return cleaned, TargetType.EXACT_DOMAIN

    raise ScopeValidationError(
        f"Invalid target format '{raw_input}'. "
        "Must be a valid domain, wildcard domain (*.domain.com), IPv4, or CIDR."
    )


def _is_cidr(target: str) -> bool:
    """Internal helper to test if target resembles a CIDR notation."""
    if "/" not in target:
        return False
    parts = target.split("/")
    return len(parts) == 2 and parts[1].isdigit()
