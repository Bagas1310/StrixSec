"""
Security Assessment Subsystem for StrixSec.
"""

from __future__ import annotations

from strixsec.assessment.cookies import evaluate_cookies
from strixsec.assessment.engine import AssessmentEngine
from strixsec.assessment.headers import evaluate_security_headers
from strixsec.assessment.metadata import inspect_metadata
from strixsec.assessment.models import (
    AssessmentResult,
    CertificateInfo,
    CookieAttributeCheck,
    CookieResult,
    MetadataResult,
    SecurityHeaderCheck,
    SecurityHeaderResult,
    TLSResult,
)
from strixsec.assessment.tls import inspect_tls

__all__ = [
    "AssessmentEngine",
    "AssessmentResult",
    "CertificateInfo",
    "CookieAttributeCheck",
    "CookieResult",
    "MetadataResult",
    "SecurityHeaderCheck",
    "SecurityHeaderResult",
    "TLSResult",
    "evaluate_cookies",
    "evaluate_security_headers",
    "inspect_metadata",
    "inspect_tls",
]
