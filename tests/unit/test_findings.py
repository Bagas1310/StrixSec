"""
Comprehensive Unit Tests for StrixSec Finding Engine, SQLite Persistence, and Sanitization.
"""

from __future__ import annotations

from pathlib import Path

from strixsec.assessment.models import (
    AssessmentResult,
    CookieAttributeCheck,
    CookieResult,
    SecurityHeaderCheck,
    SecurityHeaderResult,
)
from strixsec.findings.generator import generate_findings_from_assessment
from strixsec.findings.models import (
    Evidence,
    Finding,
    FindingCategory,
    SeverityLevel,
)
from strixsec.findings.sanitizer import sanitize_evidence
from strixsec.storage.database import DatabaseManager

# --- Evidence Sanitizer Tests ---


def test_sanitize_evidence_redacts_cookies_and_auth_tokens() -> None:
    raw_cookie = "Set-Cookie: session_id=SECRET_RAW_COOKIE_12345; Secure; HttpOnly"
    sanitized_cookie = sanitize_evidence(raw_cookie)
    assert "SECRET_RAW_COOKIE_12345" not in sanitized_cookie
    assert "<REDACTED>" in sanitized_cookie

    raw_auth = "Authorization: Bearer secret_api_token_abc123"
    sanitized_auth = sanitize_evidence(raw_auth)
    assert "secret_api_token_abc123" not in sanitized_auth
    assert "<REDACTED>" in sanitized_auth

    raw_pem = "-----BEGIN PRIVATE KEY-----\nSecretKeyData\n-----END PRIVATE KEY-----"
    sanitized_pem = sanitize_evidence(raw_pem)
    assert "SecretKeyData" not in sanitized_pem
    assert "[PRIVATE KEY REDACTED]" in sanitized_pem


# --- Database Persistence & Transaction Tests ---


def test_db_init_and_crud_operations(tmp_path: Path) -> None:
    db_file = tmp_path / "test_strixsec.db"
    db = DatabaseManager(db_path=db_file)

    # Create Scan Record
    scan = db.create_scan("SCAN-001", "example.com", "Assessment")
    assert scan.scan_id == "SCAN-001"
    assert scan.status == "RUNNING"

    # Save Finding
    ev = Evidence(
        type="Header",
        source="example.com",
        description="Missing HSTS",
        sanitized_value="Set-Cookie: token=<REDACTED>",
        timestamp="2026-08-20T00:00:00Z",
    )
    finding = Finding(
        id="STRX-0001",
        title="Missing Strict-Transport-Security",
        asset="example.com",
        category=FindingCategory.SECURITY_HEADER,
        severity=SeverityLevel.MEDIUM,
        confidence="HIGH",
        description="HSTS header missing",
        evidence=[ev],
        created_at="2026-08-20T00:00:00Z",
        updated_at="2026-08-20T00:00:00Z",
    )

    saved = db.save_finding(finding)
    assert saved.id == "STRX-0001"

    # Retrieve Finding
    retrieved = db.get_finding("STRX-0001")
    assert retrieved is not None
    assert retrieved.title == "Missing Strict-Transport-Security"
    assert len(retrieved.evidence) == 1
    assert retrieved.evidence[0].sanitized_value == "Set-Cookie: token=<REDACTED>"

    # Complete Scan
    db.complete_scan("SCAN-001", num_findings=1)
    scans = db.list_scans()
    assert len(scans) == 1
    assert scans[0].status == "COMPLETED"
    assert scans[0].num_findings == 1


def test_db_sql_injection_protection(tmp_path: Path) -> None:
    """Security Test: Verify parameterized queries resist SQL injection payloads."""
    db_file = tmp_path / "test_strixsec.db"
    db = DatabaseManager(db_path=db_file)

    malicious_asset = "example.com'; DROP TABLE findings; --"
    finding = Finding(
        id="STRX-SQLI",
        title="SQL Injection Test",
        asset=malicious_asset,
        category=FindingCategory.SECURITY_HEADER,
        severity=SeverityLevel.INFO,
        confidence="HIGH",
        description="Testing parameter safety",
        created_at="2026-08-20T00:00:00Z",
        updated_at="2026-08-20T00:00:00Z",
    )

    saved = db.save_finding(finding)
    assert saved.id == "STRX-SQLI"

    # Assert findings table still exists and finding is safely stored
    retrieved = db.get_finding("STRX-SQLI")
    assert retrieved is not None
    assert retrieved.asset == malicious_asset


def test_db_deduplication(tmp_path: Path) -> None:
    """Test automatic finding deduplication on asset + category + title."""
    db_file = tmp_path / "test_strixsec.db"
    db = DatabaseManager(db_path=db_file)

    finding1 = Finding(
        id="STRX-0001",
        title="Missing CSP",
        asset="example.com",
        category=FindingCategory.SECURITY_HEADER,
        severity=SeverityLevel.MEDIUM,
        confidence="HIGH",
        description="Initial finding description",
        created_at="2026-08-20T00:00:00Z",
        updated_at="2026-08-20T00:00:00Z",
    )

    db.save_finding(finding1)

    # Save second finding with same asset + category + title
    finding2 = Finding(
        id="STRX-0002",
        title="Missing CSP",
        asset="example.com",
        category=FindingCategory.SECURITY_HEADER,
        severity=SeverityLevel.MEDIUM,
        confidence="HIGH",
        description="Updated description from second scan",
        created_at="2026-08-20T01:00:00Z",
        updated_at="2026-08-20T01:00:00Z",
    )

    saved2 = db.save_finding(finding2)
    # Must update existing finding (retaining STRX-0001 stable ID)
    assert saved2.id == "STRX-0001"

    all_findings = db.list_findings()
    assert len(all_findings) == 1
    assert all_findings[0].description == "Updated description from second scan"


def test_db_filtering_and_status_update(tmp_path: Path) -> None:
    db_file = tmp_path / "test_strixsec.db"
    db = DatabaseManager(db_path=db_file)

    f1 = Finding(
        id="STRX-0001",
        title="HSTS Missing",
        asset="example.com",
        category=FindingCategory.SECURITY_HEADER,
        severity=SeverityLevel.MEDIUM,
        created_at="2026-08-20T00:00:00Z",
        updated_at="2026-08-20T00:00:00Z",
        description="HSTS issue",
    )
    f2 = Finding(
        id="STRX-0002",
        title="Cookie Unsecure",
        asset="example.com",
        category=FindingCategory.COOKIE,
        severity=SeverityLevel.HIGH,
        created_at="2026-08-20T00:00:00Z",
        updated_at="2026-08-20T00:00:00Z",
        description="Cookie issue",
    )

    db.save_finding(f1)
    db.save_finding(f2)

    # Filter by category
    headers_list = db.list_findings(category="SECURITY_HEADER")
    assert len(headers_list) == 1
    assert headers_list[0].id == "STRX-0001"

    # Filter by severity
    high_list = db.list_findings(severity="HIGH")
    assert len(high_list) == 1
    assert high_list[0].id == "STRX-0002"

    # Update status to FIXED
    updated = db.update_finding_status("STRX-0001", "FIXED")
    assert updated is True

    fixed_list = db.list_findings(status="FIXED")
    assert len(fixed_list) == 1
    assert fixed_list[0].id == "STRX-0001"


# --- Finding Generator Tests ---


def test_finding_generator_from_assessment_result() -> None:
    header_check = SecurityHeaderCheck(
        header_name="Strict-Transport-Security",
        is_present=False,
        value=None,
        implication="Missing HSTS",
        recommendation="Add HSTS header",
    )
    cookie_check = CookieAttributeCheck(
        cookie_name="session_id",
        redacted_header="session_id=<REDACTED>; Path=/",
        secure=False,
        httponly=False,
        samesite=None,
    )
    assessment = AssessmentResult(
        target="example.com",
        headers_result=SecurityHeaderResult(target="example.com", checks=[header_check]),
        cookie_result=CookieResult(target="example.com", cookies=[cookie_check]),
    )

    generated = generate_findings_from_assessment(assessment)
    assert len(generated) >= 3  # HSTS + Cookie Secure + Cookie HttpOnly

    titles = {f.title for f in generated}
    assert "Missing Strict-Transport-Security (HSTS) Header" in titles
    assert "Cookie Missing Secure Flag: session_id" in titles
    assert "Cookie Missing HttpOnly Flag: session_id" in titles
