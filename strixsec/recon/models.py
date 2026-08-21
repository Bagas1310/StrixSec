"""
Reconnaissance Data Models for StrixSec Recon Subsystem.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ConfidenceLevel(StrEnum):
    """Confidence rating for passive technology fingerprinting."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DNSRecord(BaseModel):
    """Model representing a single DNS resource record."""

    record_type: str = Field(..., description="DNS query type (A, AAAA, CNAME, MX, NS, TXT)")
    value: str = Field(..., description="Parsed record rdata content string")
    ttl: int | None = Field(default=None, description="Time to Live in seconds")


class DNSResult(BaseModel):
    """Model representing DNS reconnaissance findings for a target."""

    target: str = Field(..., description="Target domain or hostname queried")
    records: list[DNSRecord] = Field(
        default_factory=list, description="List of resolved DNS records"
    )
    status: str = Field(
        default="SUCCESS",
        description="DNS resolution status (SUCCESS, NXDOMAIN, TIMEOUT, SERVFAIL, ERROR)",
    )
    errors: list[str] = Field(
        default_factory=list, description="List of error messages if any queries failed"
    )


class Redirect(BaseModel):
    """Model representing a single HTTP redirect step."""

    url: str = Field(..., description="Origin URL of redirect hop")
    status_code: int = Field(..., description="HTTP redirect status code (e.g. 301, 302, 307, 308)")
    headers: dict[str, str] = Field(
        default_factory=dict, description="Response headers for redirect hop"
    )


class HTTPResult(BaseModel):
    """Model representing HTTP inspection results for a target."""

    url: str = Field(..., description="Initial requested target URL")
    final_url: str = Field(..., description="Final URL after following allowed redirects")
    status_code: int = Field(..., description="Final HTTP response status code")
    headers: dict[str, str] = Field(default_factory=dict, description="HTTP response headers")
    content_type: str | None = Field(default=None, description="Response Content-Type header value")
    page_title: str | None = Field(
        default=None, description="Extracted HTML <title> text if available"
    )
    server: str | None = Field(default=None, description="Server header string if present")
    redirect_chain: list[Redirect] = Field(
        default_factory=list, description="List of intermediate redirect hops"
    )
    https_available: bool = Field(
        default=False, description="True if target responded successfully over HTTPS"
    )
    error: str | None = Field(default=None, description="Error message if HTTP request failed")


class TechnologyMatch(BaseModel):
    """Model representing a passively detected technology fingerprint."""

    name: str = Field(..., description="Detected technology name (e.g. Nginx, React, WordPress)")
    category: str = Field(..., description="Category (Web Server, Framework, CMS, Frontend)")
    confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.MEDIUM, description="Detection confidence rating"
    )
    matched_indicator: str = Field(
        ..., description="Header, tag, or pattern indicator triggering match"
    )


class TechnologyResult(BaseModel):
    """Model representing all technology fingerprinting findings for a target."""

    target: str = Field(..., description="Target domain or URL analyzed")
    detected_technologies: list[TechnologyMatch] = Field(
        default_factory=list, description="List of detected technologies"
    )


class Asset(BaseModel):
    """Unified Asset representation aggregating scope and reconnaissance findings."""

    target: str = Field(..., description="Target domain, URL, or IP address")
    dns_info: DNSResult | None = Field(default=None, description="DNS resolution findings")
    http_info: HTTPResult | None = Field(default=None, description="HTTP inspection findings")
    tech_info: TechnologyResult | None = Field(
        default=None, description="Passive technology fingerprint findings"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional custom metadata")
