"""
DNS Reconnaissance Module for StrixSec.
"""

from __future__ import annotations

import dns.exception
import dns.resolver

from strixsec.core.logging import setup_logger
from strixsec.recon.models import DNSRecord, DNSResult

logger = setup_logger("strixsec.recon.dns")

DEFAULT_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def query_dns(
    target: str,
    record_types: tuple[str, ...] | list[str] = DEFAULT_RECORD_TYPES,
    timeout: float = 3.0,
    lifetime: float = 5.0,
) -> DNSResult:
    """Perform non-destructive DNS queries for target domain.

    Args:
        target: Target domain or hostname string.
        record_types: Iterable of DNS record types to query.
        timeout: Query timeout per DNS server attempt in seconds.
        lifetime: Total query lifetime in seconds.

    Returns:
        DNSResult model populated with resolved records and status details.
    """
    result_records: list[DNSRecord] = []
    errors: list[str] = []
    has_nxdomain = False

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            for rdata in answers:
                r_ttl = getattr(answers, "ttl", None)
                val_str = str(rdata).strip()
                result_records.append(
                    DNSRecord(
                        record_type=rtype.upper(),
                        value=val_str,
                        ttl=r_ttl,
                    )
                )
        except dns.resolver.NXDOMAIN:
            has_nxdomain = True
            logger.debug(f"DNS query {rtype} for '{target}': NXDOMAIN")
        except dns.resolver.NoAnswer:
            logger.debug(f"DNS query {rtype} for '{target}': NoAnswer")
        except dns.resolver.Timeout:
            err_msg = f"DNS query {rtype} for '{target}' timed out after {timeout}s."
            logger.warning(err_msg)
            errors.append(err_msg)
        except dns.exception.DNSException as err:
            err_msg = f"DNS query {rtype} for '{target}' failed: {err}"
            logger.debug(err_msg)
            errors.append(err_msg)
        except Exception as err:
            err_msg = f"Unexpected error during DNS query {rtype} for '{target}': {err}"
            logger.error(err_msg)
            errors.append(err_msg)

    # Determine overall status
    if has_nxdomain and not result_records:
        status = "NXDOMAIN"
    elif errors and not result_records:
        status = "TIMEOUT" if any("timed out" in e for e in errors) else "ERROR"
    else:
        status = "SUCCESS"

    return DNSResult(
        target=target,
        records=result_records,
        status=status,
        errors=errors,
    )
