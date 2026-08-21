"""
Integration tests: assessment-to-finding persistence wiring.

Proves that `strixsec assess all <target>` converts the AssessmentResult via
generate_findings_from_assessment() and persists each Finding via
DatabaseManager.save_finding(), after which `findings list` retrieves them.
"""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from strixsec.assessment.engine import AssessmentEngine
from strixsec.assessment.models import (
    CookieAttributeCheck,
    CookieResult,
    MetadataResult,
    SecurityHeaderCheck,
    SecurityHeaderResult,
    TLSResult,
)
from strixsec.cli.main import app
from strixsec.scope.storage import ScopeStorage

runner = CliRunner()


def _mock_full_assessment(sid_value: str = "RAWTOKEN123") -> None:
    """Patch all engine module runners so no network activity is required."""
    mock_headers = SecurityHeaderResult(
        target="example.com",
        checks=[
            SecurityHeaderCheck(
                header_name="Strict-Transport-Security",
                is_present=False,
                value=None,
                implication="Clients may connect over unencrypted HTTP.",
                recommendation="Enable HSTS.",
            )
        ],
    )
    mock_tls = TLSResult(target="example.com")
    mock_cookies = CookieResult(
        target="example.com",
        cookies=[
            CookieAttributeCheck(
                cookie_name="sid",
                redacted_header=f"Set-Cookie: sid={sid_value}; Path=/",
                secure=False,
                httponly=False,
                samesite=None,
            )
        ],
    )
    mock_meta = MetadataResult(
        target="example.com",
        security_txt_found=True,
        security_txt_content="Contact: security@example.com",
    )

    engine_patcher = [
        patch.object(AssessmentEngine, "run_headers", return_value=mock_headers),
        patch.object(AssessmentEngine, "run_tls", return_value=mock_tls),
        patch.object(AssessmentEngine, "run_cookies", return_value=mock_cookies),
        patch.object(AssessmentEngine, "run_metadata", return_value=mock_meta),
    ]
    for patcher in engine_patcher:
        patcher.start()
    for patcher in engine_patcher:
        patcher.stop()


def test_assess_all_persists_and_lists_findings(monkeypatch, tmp_path) -> None:
    """assess all persists findings; `findings list` retrieves them."""
    monkeypatch.chdir(tmp_path)
    ScopeStorage().add_target("example.com")

    mock_headers = SecurityHeaderResult(
        target="example.com",
        checks=[
            SecurityHeaderCheck(
                header_name="Strict-Transport-Security",
                is_present=False,
                value=None,
                implication="Clients may connect over unencrypted HTTP.",
                recommendation="Enable HSTS.",
            )
        ],
    )
    mock_tls = TLSResult(target="example.com")
    mock_cookies = CookieResult(
        target="example.com",
        cookies=[
            CookieAttributeCheck(
                cookie_name="sid",
                redacted_header="Set-Cookie: sid=<REDACTED>; Path=/",
                secure=False,
                httponly=False,
                samesite=None,
            )
        ],
    )
    mock_meta = MetadataResult(
        target="example.com",
        security_txt_found=True,
        security_txt_content="Contact: security@example.com",
    )

    with (
        patch.object(AssessmentEngine, "run_headers", return_value=mock_headers),
        patch.object(AssessmentEngine, "run_tls", return_value=mock_tls),
        patch.object(AssessmentEngine, "run_cookies", return_value=mock_cookies),
        patch.object(AssessmentEngine, "run_metadata", return_value=mock_meta),
    ):
        res = runner.invoke(app, ["assess", "all", "example.com"], env={"COLUMNS": "200"})

    assert res.exit_code == 0
    # Expected: missing HSTS header, cookie Secure flag, cookie HttpOnly flag, security.txt
    assert "Finding stored" in res.stdout

    res_list = runner.invoke(app, ["findings", "list"], env={"COLUMNS": "200"})
    assert res_list.exit_code == 0
    assert "STRX-" in res_list.stdout


def test_assess_all_dedup_on_rerun(monkeypatch, tmp_path) -> None:
    """Re-running assess all does not duplicate persisted findings."""
    monkeypatch.chdir(tmp_path)
    ScopeStorage().add_target("example.com")

    mock_headers = SecurityHeaderResult(
        target="example.com",
        checks=[
            SecurityHeaderCheck(
                header_name="Strict-Transport-Security",
                is_present=False,
                value=None,
                implication="Clients may connect over unencrypted HTTP.",
                recommendation="Enable HSTS.",
            )
        ],
    )
    mock_tls = TLSResult(target="example.com")
    mock_cookies = CookieResult(target="example.com", cookies=[])
    mock_meta = MetadataResult(target="example.com")

    with (
        patch.object(AssessmentEngine, "run_headers", return_value=mock_headers),
        patch.object(AssessmentEngine, "run_tls", return_value=mock_tls),
        patch.object(AssessmentEngine, "run_cookies", return_value=mock_cookies),
        patch.object(AssessmentEngine, "run_metadata", return_value=mock_meta),
    ):
        runner.invoke(app, ["assess", "all", "example.com"], env={"COLUMNS": "200"})
        runner.invoke(app, ["assess", "all", "example.com"], env={"COLUMNS": "200"})

    from strixsec.storage.database import DatabaseManager

    db = DatabaseManager()
    findings = db.list_findings()
    # Same HSTS finding exists exactly once after two runs.
    hsts = [f for f in findings if "Strict-Transport-Security" in f.title]
    assert len(hsts) == 1


def test_no_secrets_persisted(monkeypatch, tmp_path) -> None:
    """Raw cookie secrets never reach SQLite, even if a result is mislabeled."""
    monkeypatch.chdir(tmp_path)
    ScopeStorage().add_target("example.com")

    # Deliberately simulate an un-redacted value flowing out of the mock.
    raw_secret = "SECRET_VALUE_42"
    mock_headers = SecurityHeaderResult(target="example.com", checks=[])
    mock_tls = TLSResult(target="example.com")
    mock_cookies = CookieResult(
        target="example.com",
        cookies=[
            CookieAttributeCheck(
                cookie_name="sid",
                redacted_header=f"Set-Cookie: sid={raw_secret}; Path=/",
                secure=False,
                httponly=False,
                samesite=None,
            )
        ],
    )
    mock_meta = MetadataResult(target="example.com")

    with (
        patch.object(AssessmentEngine, "run_headers", return_value=mock_headers),
        patch.object(AssessmentEngine, "run_tls", return_value=mock_tls),
        patch.object(AssessmentEngine, "run_cookies", return_value=mock_cookies),
        patch.object(AssessmentEngine, "run_metadata", return_value=mock_meta),
    ):
        runner.invoke(app, ["assess", "all", "example.com"], env={"COLUMNS": "200"})

    from strixsec.storage.database import DatabaseManager

    db = DatabaseManager()
    for finding in db.list_findings():
        for ev in finding.evidence:
            assert raw_secret not in ev.sanitized_value
            assert "<REDACTED>" in ev.sanitized_value


def test_report_generates_from_persisted_findings(monkeypatch, tmp_path) -> None:
    """Report generation succeeds with findings persisted by assess all."""
    monkeypatch.chdir(tmp_path)
    ScopeStorage().add_target("example.com")

    mock_headers = SecurityHeaderResult(
        target="example.com",
        checks=[
            SecurityHeaderCheck(
                header_name="X-Content-Type-Options",
                is_present=False,
                value=None,
                implication="MIME-sniffing risk.",
                recommendation="Set X-Content-Type-Options: nosniff.",
            )
        ],
    )
    mock_tls = TLSResult(target="example.com")
    mock_cookies = CookieResult(target="example.com", cookies=[])
    mock_meta = MetadataResult(target="example.com")

    with (
        patch.object(AssessmentEngine, "run_headers", return_value=mock_headers),
        patch.object(AssessmentEngine, "run_tls", return_value=mock_tls),
        patch.object(AssessmentEngine, "run_cookies", return_value=mock_cookies),
        patch.object(AssessmentEngine, "run_metadata", return_value=mock_meta),
    ):
        runner.invoke(app, ["assess", "all", "example.com"], env={"COLUMNS": "200"})

    out_md = tmp_path / "report.md"
    res_md = runner.invoke(
        app,
        ["report", "generate", "--output", str(out_md), "--format", "markdown"],
    )
    assert res_md.exit_code == 0
    assert out_md.exists()
    content = out_md.read_text(encoding="utf-8")
    assert "X-Content-Type-Options" in content
