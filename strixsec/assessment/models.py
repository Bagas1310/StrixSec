"""
Assessment Data Models for StrixSec Assessment Subsystem.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SecurityHeaderCheck(BaseModel):
    """Model representing an individual security header evaluation."""

    header_name: str = Field(..., description="Name of the security header evaluated")
    is_present: bool = Field(..., description="True if header is present in HTTP response")
    value: str | None = Field(default=None, description="Raw header value if present")
    implication: str = Field(..., description="Security context or risk implications")
    recommendation: str = Field(..., description="Actionable recommendation for defense")


class SecurityHeaderResult(BaseModel):
    """Model representing overall security headers assessment for a target."""

    target: str = Field(..., description="Target domain or URL analyzed")
    checks: list[SecurityHeaderCheck] = Field(
        default_factory=list, description="List of evaluated header checks"
    )


class CertificateInfo(BaseModel):
    """Model representing X.509 TLS certificate attributes."""

    subject: dict[str, str] = Field(
        default_factory=dict, description="Certificate Subject DN fields"
    )
    issuer: dict[str, str] = Field(default_factory=dict, description="Certificate Issuer DN fields")
    valid_from: str = Field(..., description="Certificate validity start date (Not Before)")
    valid_to: str = Field(..., description="Certificate expiration date (Not After)")
    days_until_expiration: int = Field(
        ..., description="Remaining valid days until cert expiration"
    )
    is_expired: bool = Field(..., description="True if certificate has expired")
    hostname_matches: bool = Field(..., description="True if target hostname matches cert SAN/CN")
    sans: list[str] = Field(default_factory=list, description="Subject Alternative Names")


class TLSResult(BaseModel):
    """Model representing TLS/SSL inspection findings for a target."""

    target: str = Field(..., description="Target domain or host analyzed")
    port: int = Field(default=443, description="Target port number")
    tls_version: str | None = Field(
        default=None, description="Negotiated TLS protocol version (e.g. TLSv1.3)"
    )
    cert_info: CertificateInfo | None = Field(
        default=None, description="TLS Certificate details if retrieved"
    )
    status: str = Field(
        default="SUCCESS", description="TLS assessment status (SUCCESS, EXPIRED, MISMATCH, FAILED)"
    )
    error: str | None = Field(
        default=None, description="Error message if TLS handshake or validation failed"
    )


class CookieAttributeCheck(BaseModel):
    """Model representing a Set-Cookie security evaluation with mandatory value redaction."""

    cookie_name: str = Field(..., description="Cookie identifier name")
    redacted_header: str = Field(..., description="Set-Cookie header with secret value REDACTED")
    secure: bool = Field(..., description="True if Secure flag is present")
    httponly: bool = Field(..., description="True if HttpOnly flag is present")
    samesite: str | None = Field(
        default=None, description="SameSite flag value (Strict, Lax, None, or None/Missing)"
    )


class CookieResult(BaseModel):
    """Model representing cookie security analysis for a target."""

    target: str = Field(..., description="Target domain or URL analyzed")
    cookies: list[CookieAttributeCheck] = Field(
        default_factory=list, description="List of evaluated cookies with REDACTED values"
    )


class MetadataResult(BaseModel):
    """Model representing public security metadata findings."""

    target: str = Field(..., description="Target domain analyzed")
    robots_found: bool = Field(default=False, description="True if /robots.txt exists")
    robots_content: str | None = Field(default=None, description="Truncated content of /robots.txt")
    security_txt_found: bool = Field(default=False, description="True if /security.txt exists")
    security_txt_content: str | None = Field(
        default=None, description="Truncated content of /security.txt"
    )


class AssessmentResult(BaseModel):
    """Unified Result aggregating all Phase 4 Security Assessment findings."""

    target: str = Field(..., description="Target domain or URL analyzed")
    headers_result: SecurityHeaderResult | None = Field(default=None)
    tls_result: TLSResult | None = Field(default=None)
    cookie_result: CookieResult | None = Field(default=None)
    metadata_result: MetadataResult | None = Field(default=None)
    custom_metadata: dict[str, Any] = Field(default_factory=dict)
