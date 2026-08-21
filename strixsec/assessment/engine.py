"""
Unified Assessment Engine Orchestrator for StrixSec.
"""

from __future__ import annotations

from urllib.parse import urlparse

from strixsec.assessment.cookies import evaluate_cookies
from strixsec.assessment.headers import evaluate_security_headers
from strixsec.assessment.metadata import inspect_metadata
from strixsec.assessment.models import (
    AssessmentResult,
    CookieResult,
    MetadataResult,
    SecurityHeaderResult,
    TLSResult,
)
from strixsec.assessment.tls import inspect_tls
from strixsec.core.errors import ScopeValidationError
from strixsec.core.logging import setup_logger
from strixsec.recon.http import analyze_http
from strixsec.scope.normalizer import normalize_target
from strixsec.scope.storage import ScopeStorage
from strixsec.scope.validator import ScopeValidator

logger = setup_logger("strixsec.assessment.engine")


class AssessmentEngine:
    """Orchestrator for executing safe, authorized security assessment modules."""

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

        logger.info(f"Target validated for assessment: {norm_target}")
        return norm_target

    def run_headers(self, target: str) -> SecurityHeaderResult:
        """Run safe security headers evaluation for authorized target."""
        norm_target = self.validate_and_normalize(target)
        logger.info(f"Starting security headers assessment for '{norm_target}'")
        http_res = analyze_http(norm_target)
        return evaluate_security_headers(http_res)

    def run_tls(self, target: str, port: int = 443) -> TLSResult:
        """Run safe TLS certificate and protocol inspection for authorized target."""
        norm_target = self.validate_and_normalize(target)
        logger.info(f"Starting TLS assessment for '{norm_target}:{port}'")
        return inspect_tls(norm_target, port=port)

    def run_cookies(self, target: str) -> CookieResult:
        """Run safe cookie security evaluation with mandatory value redaction."""
        norm_target = self.validate_and_normalize(target)
        logger.info(f"Starting cookie security assessment for '{norm_target}'")
        http_res = analyze_http(norm_target)
        return evaluate_cookies(http_res)

    def run_metadata(self, target: str) -> MetadataResult:
        """Run safe public security metadata inspection (robots.txt, security.txt)."""
        norm_target = self.validate_and_normalize(target)
        logger.info(f"Starting public metadata assessment for '{norm_target}'")
        return inspect_metadata(norm_target)

    def run_full_assessment(self, target: str) -> AssessmentResult:
        """Run complete safe security assessment suite for authorized target."""
        norm_target = self.validate_and_normalize(target)

        headers_res = self.run_headers(norm_target)
        tls_res = self.run_tls(norm_target)
        cookies_res = self.run_cookies(norm_target)
        meta_res = self.run_metadata(norm_target)

        return AssessmentResult(
            target=norm_target,
            headers_result=headers_res,
            tls_result=tls_res,
            cookie_result=cookies_res,
            metadata_result=meta_res,
        )
