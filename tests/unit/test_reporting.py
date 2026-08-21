"""
Unit tests for Phase 6 reporting subsystem.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from strixsec.findings.models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    ScanRecord,
    SeverityLevel,
)
from strixsec.reporting.builder import ReportBuilder
from strixsec.reporting.html_renderer import render_html
from strixsec.reporting.markdown_renderer import render_markdown
from strixsec.reporting.models import ReportContext, ReportMetadata, SeveritySummary
from strixsec.storage.database import DatabaseManager


@pytest.fixture
def sample_finding() -> Finding:
    """Return a sample finding for testing."""
    return Finding(
        id="STRIX-001",
        title="XSS in login form",
        category=FindingCategory.SECURITY_HEADER,
        severity=SeverityLevel.HIGH,
        confidence="HIGH",
        asset="https://example.com",
        description="XSS vulnerability detected.",
        impact="User session hijacking.",
        remediation="Sanitize inputs.",
        status=FindingStatus.OPEN,
        evidence=[
            Evidence(
                type="HTTP_RESPONSE",
                source="https://example.com/login",
                description="Reflected XSS",
                sanitized_value="&lt;script&gt;alert(1)&lt;/script&gt;",
                timestamp=datetime.now(UTC).isoformat(),
            )
        ],
        references=["https://owasp.org/xss"],
        created_at=datetime.now(UTC).isoformat(),
        updated_at=datetime.now(UTC).isoformat(),
    )


@pytest.fixture
def sample_scan_record() -> ScanRecord:
    """Return a sample scan record."""
    return ScanRecord(
        scan_id="scan-123",
        target="https://example.com",
        scan_type="web",
        started_at=datetime.now(UTC).isoformat(),
        completed_at=datetime.now(UTC).isoformat(),
        status="completed",
        num_findings=1,
    )


def test_severity_summary_model() -> None:
    """Test SeveritySummary model."""
    summary = SeveritySummary(critical=1, high=2, medium=3, low=4, informational=5, total=15)
    assert summary.critical == 1
    assert summary.high == 2
    assert summary.total == 15


def test_report_metadata_model() -> None:
    """Test ReportMetadata model."""
    meta = ReportMetadata(
        title="Test Report",
        strixsec_version="0.1.0",
        generated_at=datetime.now(UTC).isoformat(),
        scope=["https://example.com"],
        assets=["example.com"],
    )
    assert meta.title == "Test Report"
    assert "https://example.com" in meta.scope


def test_report_context_model(sample_finding: Finding, sample_scan_record: ScanRecord) -> None:
    """Test ReportContext model."""
    ctx = ReportContext(
        metadata=ReportMetadata(
            title="Test",
            strixsec_version="0.1.0",
            generated_at=datetime.now(UTC).isoformat(),
        ),
        executive_summary="Test summary.",
        severity_summary=SeveritySummary(high=1, total=1),
        findings=[sample_finding],
        scan_records=[sample_scan_record],
    )
    assert len(ctx.findings) == 1
    assert ctx.severity_summary.total == 1


def test_report_builder_empty_db(tmp_path) -> None:
    """Test ReportBuilder with empty database."""
    db_path = tmp_path / "test.db"
    db = DatabaseManager(db_path=db_path)
    builder = ReportBuilder(db=db)

    ctx = builder.build(title="Empty Test Report")

    assert ctx.metadata.title == "Empty Test Report"
    assert ctx.severity_summary.total == 0
    assert len(ctx.findings) == 0
    assert "No findings" in ctx.executive_summary


def test_report_builder_with_findings(tmp_path, sample_finding: Finding) -> None:
    """Test ReportBuilder with findings in database."""
    db_path = tmp_path / "test.db"
    db = DatabaseManager(db_path=db_path)
    db.save_finding(sample_finding)

    builder = ReportBuilder(db=db)
    ctx = builder.build()

    assert ctx.severity_summary.total == 1
    assert ctx.severity_summary.high == 1
    assert len(ctx.findings) == 1
    assert "1 finding" in ctx.executive_summary.lower()


def test_markdown_renderer_empty() -> None:
    """Test Markdown renderer with empty context."""
    ctx = ReportContext(
        metadata=ReportMetadata(
            title="Empty",
            strixsec_version="0.1.0",
            generated_at=datetime.now(UTC).isoformat(),
        ),
        executive_summary="Nothing found.",
    )

    md = render_markdown(ctx)

    assert "# Empty" in md
    assert "Nothing found." in md
    assert "No findings recorded" in md


def test_markdown_renderer_with_findings(sample_finding: Finding) -> None:
    """Test Markdown renderer with findings."""
    ctx = ReportContext(
        metadata=ReportMetadata(
            title="Test Report",
            strixsec_version="0.1.0",
            generated_at=datetime.now(UTC).isoformat(),
            scope=["https://example.com"],
            assets=["example.com"],
        ),
        executive_summary="Found issues.",
        severity_summary=SeveritySummary(high=1, total=1),
        findings=[sample_finding],
    )

    md = render_markdown(ctx)

    assert "# Test Report" in md
    assert "STRIX-001" in md
    assert "XSS in login form" in md
    assert "https://example.com" in md
    assert "Sanitize inputs" in md


def test_html_renderer_empty() -> None:
    """Test HTML renderer with empty context."""
    ctx = ReportContext(
        metadata=ReportMetadata(
            title="Empty HTML",
            strixsec_version="0.1.0",
            generated_at=datetime.now(UTC).isoformat(),
        ),
        executive_summary="Nothing here.",
    )

    html = render_html(ctx)

    assert "<!DOCTYPE html>" in html
    assert "<title>Empty HTML</title>" in html
    assert "Nothing here." in html
    assert "No findings recorded" in html


def test_html_renderer_with_findings(sample_finding: Finding) -> None:
    """Test HTML renderer with findings."""
    ctx = ReportContext(
        metadata=ReportMetadata(
            title="HTML Test",
            strixsec_version="0.1.0",
            generated_at=datetime.now(UTC).isoformat(),
        ),
        severity_summary=SeveritySummary(high=1, total=1),
        findings=[sample_finding],
    )

    html = render_html(ctx)

    assert "<!DOCTYPE html>" in html
    assert "STRIX-001" in html
    assert "XSS in login form" in html


def test_html_escaping() -> None:
    """Test HTML renderer escapes dangerous content."""
    dangerous = Finding(
        id="STRIX-XSS",
        title='<script>alert("xss")</script>',
        category=FindingCategory.SECURITY_HEADER,
        severity=SeverityLevel.HIGH,
        confidence="HIGH",
        asset="https://evil.com",
        description='<img src=x onerror="alert(1)">',
        impact="",
        remediation="",
        status=FindingStatus.OPEN,
        evidence=[],
        references=[],
        created_at=datetime.now(UTC).isoformat(),
        updated_at=datetime.now(UTC).isoformat(),
    )

    ctx = ReportContext(
        metadata=ReportMetadata(
            title="Escape Test",
            strixsec_version="0.1.0",
            generated_at=datetime.now(UTC).isoformat(),
        ),
        findings=[dangerous],
    )

    html = render_html(ctx)

    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "<script>alert" not in html
    assert 'onerror="alert' not in html
