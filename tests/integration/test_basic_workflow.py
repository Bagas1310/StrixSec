"""
Integration tests for StrixSec Phase 1 foundation workflow.
"""

from __future__ import annotations

from typer.testing import CliRunner

from strixsec.cli.main import app
from strixsec.core.config import get_default_config
from strixsec.findings.models import Finding, SeverityLevel

runner = CliRunner()


def test_basic_cli_to_core_integration() -> None:
    """Test integration between CLI, core settings, and finding models."""
    config = get_default_config()
    assert config.app_name == "StrixSec"

    finding = Finding(
        id="STRIX-TEST-001",
        title="Test Integration Finding",
        asset="192.168.1.100",
        category="SECURITY_HEADER",
        description="Sample integration description",
        severity=SeverityLevel.HIGH,
        created_at="2026-08-20T00:00:00Z",
        updated_at="2026-08-20T00:00:00Z",
    )
    assert finding.id == "STRIX-TEST-001"
    assert finding.severity == SeverityLevel.HIGH

    cli_result = runner.invoke(app, ["version"])
    assert cli_result.exit_code == 0
    assert "v0.1.0" in cli_result.stdout
