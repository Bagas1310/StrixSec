"""
Finding, Evidence, and Scan History Models for StrixSec.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SeverityLevel(StrEnum):
    """Vulnerability severity levels based on CVSS standard scales."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFORMATIONAL"


class FindingCategory(StrEnum):
    """Categories for security assessment findings."""

    SECURITY_HEADER = "SECURITY_HEADER"
    TLS = "TLS"
    COOKIE = "COOKIE"
    METADATA = "METADATA"
    CONFIGURATION = "CONFIGURATION"


class FindingStatus(StrEnum):
    """Lifecycle status for security findings."""

    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED = "ACCEPTED"
    FIXED = "FIXED"


class Evidence(BaseModel):
    """Model representing sanitized evidence supporting a finding."""

    type: str = Field(..., description="Evidence type (e.g. Header, Cookie, Cert, Response)")
    source: str = Field(..., description="Source location or header name")
    description: str = Field(..., description="Contextual explanation of evidence")
    sanitized_value: str = Field(..., description="Sanitized/redacted evidence payload string")
    timestamp: str = Field(..., description="Timestamp when evidence was captured")


class Finding(BaseModel):
    """Security finding model representing an identified issue or observation."""

    id: str = Field(..., description="Unique finding identifier (e.g. STRX-0001)")
    title: str = Field(..., description="Short descriptive title of the finding")
    asset: str = Field(..., description="Target asset hostname or IP")
    category: FindingCategory = Field(..., description="Finding category")
    severity: SeverityLevel = Field(default=SeverityLevel.INFO, description="Severity rating")
    confidence: str = Field(
        default="HIGH", description="Finding confidence rating (HIGH, MEDIUM, LOW)"
    )
    description: str = Field(..., description="Detailed explanation of the finding")
    evidence: list[Evidence] = Field(
        default_factory=list, description="List of supporting evidence items"
    )
    impact: str = Field(default="", description="Potential security impact description")
    remediation: str | None = Field(default=None, description="Recommended remediation guidance")
    references: list[str] = Field(default_factory=list, description="Reference URLs or CVE tags")
    status: FindingStatus = Field(default=FindingStatus.OPEN, description="Lifecycle status")
    created_at: str = Field(..., description="Creation timestamp (ISO-8601 UTC)")
    updated_at: str = Field(..., description="Last updated timestamp (ISO-8601 UTC)")


class ScanRecord(BaseModel):
    """Model representing scan execution history."""

    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Target domain, IP, or scope evaluated")
    scan_type: str = Field(..., description="Type of scan executed (Recon, Assessment, Full)")
    started_at: str = Field(..., description="Scan start timestamp")
    completed_at: str | None = Field(default=None, description="Scan completion timestamp")
    status: str = Field(default="RUNNING", description="Scan execution status")
    num_findings: int = Field(default=0, description="Total findings identified during scan")
    metadata: dict[str, Any] = Field(default_factory=dict)
