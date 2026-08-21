"""
Report Data Models for StrixSec Professional Reporting Subsystem.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from strixsec.findings.models import Finding, ScanRecord


class SeveritySummary(BaseModel):
    """Aggregated count of findings per severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total: int = 0


class ReportMetadata(BaseModel):
    """Report header metadata block."""

    title: str = Field(default="StrixSec Security Assessment Report")
    strixsec_version: str
    generated_at: str = Field(..., description="ISO-8601 UTC generation timestamp")
    scope: list[str] = Field(default_factory=list, description="Target scope entries")
    assets: list[str] = Field(default_factory=list, description="Unique assessed assets")
    methodology: str = Field(
        default=(
            "This assessment was performed using StrixSec, an open-source, non-destructive "
            "cybersecurity assessment toolkit. All findings are based solely on passive "
            "observation and safe inspection techniques. No exploitation was attempted."
        )
    )


class ReportContext(BaseModel):
    """Complete assembled report context ready for rendering."""

    metadata: ReportMetadata
    executive_summary: str = Field(
        default="", description="Auto-generated summary prose from finding counts"
    )
    severity_summary: SeveritySummary = Field(default_factory=SeveritySummary)
    findings: list[Finding] = Field(default_factory=list)
    scan_records: list[ScanRecord] = Field(default_factory=list)
