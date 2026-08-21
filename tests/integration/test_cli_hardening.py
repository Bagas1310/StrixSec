"""
CLI hardening tests: invalid commands, corrupted state, graceful errors.
"""

from __future__ import annotations

from typer.testing import CliRunner

from strixsec.cli.main import app

runner = CliRunner()


def test_invalid_command() -> None:
    """Invalid command shows helpful error."""
    result = runner.invoke(app, ["invalid-command"])
    assert result.exit_code != 0
    # Typer may output to stderr or stdout
    output = result.stdout + result.stderr
    assert "No such command" in output or "Usage:" in output or result.exit_code == 2


def test_invalid_finding_id(tmp_path, monkeypatch) -> None:
    """Invalid finding ID returns graceful error."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["findings", "get", "INVALID-ID-999"])
    assert result.exit_code != 0 or "not found" in result.stdout.lower()


def test_empty_database(tmp_path, monkeypatch) -> None:
    """Empty database returns empty results, not crash."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["findings", "list"])
    # Should succeed with empty list
    assert result.exit_code == 0
    assert "0" in result.stdout or "No findings" in result.stdout or result.stdout == ""


def test_corrupted_database(tmp_path, monkeypatch) -> None:
    """Corrupted database returns error, not crash."""
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / ".strixsec.db"
    db_path.write_bytes(b"CORRUPTED DATA NOT SQLITE")

    result = runner.invoke(app, ["findings", "list"])
    # Should fail gracefully
    assert result.exit_code != 0 or "error" in result.stdout.lower()


def test_missing_scope_file(tmp_path, monkeypatch) -> None:
    """Missing scope file returns helpful error."""
    monkeypatch.chdir(tmp_path)
    # Try to run recon without scope
    result = runner.invoke(app, ["recon", "dns", "example.com"])
    # Should fail with scope error
    assert result.exit_code != 0 or "scope" in result.stdout.lower()


def test_invalid_report_format(tmp_path, monkeypatch) -> None:
    """Report with invalid format falls back to Markdown and writes output."""
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "report.md"
    result = runner.invoke(app, ["report", "generate", "-f", "invalid", "-o", str(out)])
    # Unknown format falls back to markdown rendering
    assert result.exit_code == 0
    assert out.exists()


def test_cli_help_commands() -> None:
    """All help commands work."""
    commands = [
        ["--help"],
        ["scope", "--help"],
        ["recon", "--help"],
        ["assess", "--help"],
        ["findings", "--help"],
        ["report", "--help"],
    ]

    for cmd in commands:
        result = runner.invoke(app, cmd)
        assert result.exit_code == 0
        assert "Usage:" in result.stdout or "help" in result.stdout.lower()
