"""
Safe TLS/SSL Inspection Module for StrixSec.
"""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from strixsec.assessment.models import CertificateInfo, TLSResult
from strixsec.core.logging import setup_logger

logger = setup_logger("strixsec.assessment.tls")


def inspect_tls(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
) -> TLSResult:
    """Safely inspect TLS certificate and protocol attributes for target hostname.

    Args:
        hostname: Target domain or IP string.
        port: TLS port number (default 443).
        timeout: Socket connection timeout in seconds.

    Returns:
        TLSResult model with certificate and protocol status.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with (
            socket.create_connection((hostname, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert = ssock.getpeercert()
            tls_version = ssock.version()

            if not cert:
                return TLSResult(
                    target=hostname,
                    port=port,
                    status="FAILED",
                    error="No peer certificate returned by server.",
                )

            cert_info = _parse_certificate(cert, hostname)
            status = "EXPIRED" if cert_info.is_expired else "SUCCESS"

            return TLSResult(
                target=hostname,
                port=port,
                tls_version=tls_version,
                cert_info=cert_info,
                status=status,
                error=None,
            )

    except ssl.SSLCertVerificationError as err:
        logger.debug(f"TLS certificate verification failed for '{hostname}': {err}")
        cert_info = _try_fetch_unverified_cert_info(hostname, port, timeout)
        return TLSResult(
            target=hostname,
            port=port,
            cert_info=cert_info,
            status="VERIFICATION_FAILED",
            error=f"TLS certificate verification failed: {err.verify_message or err}",
        )
    except TimeoutError:
        logger.debug(f"TLS connection to '{hostname}:{port}' timed out after {timeout}s.")
        return TLSResult(
            target=hostname,
            port=port,
            status="TIMEOUT",
            error=f"TLS connection timed out after {timeout} seconds.",
        )
    except ConnectionRefusedError:
        logger.debug(f"TLS connection to '{hostname}:{port}' refused.")
        return TLSResult(
            target=hostname,
            port=port,
            status="FAILED",
            error=f"Connection refused on port {port}.",
        )
    except Exception as err:
        logger.debug(f"TLS inspection for '{hostname}:{port}' failed: {err}")
        return TLSResult(
            target=hostname,
            port=port,
            status="FAILED",
            error=f"TLS handshake failed: {err}",
        )


def _parse_certificate(cert: dict[str, Any], hostname: str) -> CertificateInfo:
    """Parse raw ssl peer certificate dictionary into CertificateInfo model."""
    subject_dict = _dn_tuples_to_dict(cert.get("subject", ()))
    issuer_dict = _dn_tuples_to_dict(cert.get("issuer", ()))

    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")

    # Parse UTC date strings (e.g. "May 20 12:00:00 2026 GMT")
    date_fmt = "%b %d %H:%M:%S %Y GMT"
    now_utc = datetime.now(UTC)

    try:
        valid_to_dt = datetime.strptime(not_after_str, date_fmt).replace(tzinfo=UTC)
        days_until_exp = (valid_to_dt - now_utc).days
        is_expired = now_utc > valid_to_dt
    except ValueError:
        days_until_exp = 0
        is_expired = False

    # Extract Subject Alternative Names
    sans: list[str] = []
    for san_type, san_val in cert.get("subjectAltName", ()):
        if san_type.lower() == "dns":
            sans.append(san_val)

    # Check hostname match
    hostname_lower = hostname.lower()
    hostname_matches = any(
        _match_hostname_pattern(hostname_lower, san.lower()) for san in sans
    ) or _match_hostname_pattern(hostname_lower, subject_dict.get("commonName", "").lower())

    return CertificateInfo(
        subject=subject_dict,
        issuer=issuer_dict,
        valid_from=not_before_str,
        valid_to=not_after_str,
        days_until_expiration=days_until_exp,
        is_expired=is_expired,
        hostname_matches=hostname_matches,
        sans=sans,
    )


def _try_fetch_unverified_cert_info(
    hostname: str, port: int, timeout: float
) -> CertificateInfo | None:
    """Diagnostic helper to fetch cert details when verification fails."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((hostname, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert = ssock.getpeercert(binary_form=False)
            if cert:
                info = _parse_certificate(cert, hostname)
                info.hostname_matches = False
                return info
    except Exception:
        pass
    return None


def _dn_tuples_to_dict(dn_tuples: tuple[Any, ...]) -> dict[str, str]:
    """Convert nested DN tuples into a flat key-value dictionary."""
    res: dict[str, str] = {}
    for item in dn_tuples:
        for key, val in item:
            res[key] = str(val)
    return res


def _match_hostname_pattern(hostname: str, pattern: str) -> bool:
    """Check if hostname matches pattern (exact or wildcard *.domain)."""
    if not pattern:
        return False
    if hostname == pattern:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname.endswith(f".{suffix}")
    return False
