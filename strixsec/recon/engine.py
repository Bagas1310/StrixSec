"""
Unified Reconnaissance Engine Orchestrator for StrixSec.
"""

from __future__ import annotations

from urllib.parse import urlparse

from strixsec.core.errors import ScopeValidationError
from strixsec.core.logging import setup_logger
from strixsec.recon.dns import query_dns
from strixsec.recon.http import analyze_http
from strixsec.recon.models import Asset, DNSResult, HTTPResult, TechnologyResult
from strixsec.recon.tech import detect_technologies
from strixsec.scope.normalizer import normalize_target
from strixsec.scope.storage import ScopeStorage
from strixsec.scope.validator import ScopeValidator

logger = setup_logger("strixsec.recon.engine")


class ReconEngine:
    """Orchestrator for executing safe, authorized reconnaissance pipelines."""

    def __init__(self, validator: ScopeValidator | None = None) -> None:
        if validator is None:
            storage = ScopeStorage()
            self.validator = ScopeValidator(storage.load_scope())
        else:
            self.validator = validator

    def validate_and_normalize(self, target: str) -> str:
        """Mandatory security gate: Normalize target and enforce scope validation.

        Args:
            target: Input domain, IP, or URL string.

        Returns:
            Normalized target host string if IN SCOPE.

        Raises:
            ScopeValidationError: If target is malformed or OUT OF SCOPE.
        """
        # Extract hostname if target is a URL
        if "://" in target:
            hostname = urlparse(target).hostname or target
        else:
            hostname = target.split("/")[0].split(":")[0]

        norm_target, _ = normalize_target(hostname)
        val_result = self.validator.validate(norm_target)

        if not val_result.is_in_scope:
            logger.warning(
                f"Security Gate Blocked: Target '{target}' "
                f"(normalized: '{norm_target}') is OUT OF SCOPE."
            )
            raise ScopeValidationError(
                f"Target '{target}' is OUT OF SCOPE. Network operation blocked."
            )

        logger.info(f"Target validated: {norm_target}")
        return norm_target

    def run_dns(self, target: str) -> DNSResult:
        """Run safe DNS queries for authorized target."""
        norm_target = self.validate_and_normalize(target)
        logger.info(f"Starting DNS analysis for '{norm_target}'")
        return query_dns(norm_target)

    def run_http(self, target: str) -> HTTPResult:
        """Run safe HTTP/HTTPS inspection for authorized target."""
        norm_target = self.validate_and_normalize(target)
        logger.info(f"Starting HTTP analysis for '{norm_target}'")
        return analyze_http(norm_target)

    def run_tech(self, target: str) -> TechnologyResult:
        """Run passive technology fingerprinting for authorized target."""
        norm_target = self.validate_and_normalize(target)
        logger.info(f"Starting technology detection for '{norm_target}'")
        http_res = analyze_http(norm_target)
        return detect_technologies(http_res)

    def run_full_recon(self, target: str) -> Asset:
        """Run complete safe reconnaissance suite (DNS, HTTP, Tech) for authorized target."""
        norm_target = self.validate_and_normalize(target)

        dns_res = query_dns(norm_target)
        http_res = analyze_http(norm_target)
        tech_res = detect_technologies(http_res)

        return Asset(
            target=norm_target,
            dns_info=dns_res,
            http_info=http_res,
            tech_info=tech_res,
        )
