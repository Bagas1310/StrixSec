"""
Unit tests for StrixSec CLI interface.
"""

from __future__ import annotations

from typer.testing import CliRunner

from strixsec.cli.main import app

runner = CliRunner()


def test_cli_help() -> None:
    """Test `strixsec --help` output."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "StrixSec" in result.stdout
    assert "Open-Source Cybersecurity Assessment Toolkit" in result.stdout
    assert "version" in result.stdout


def test_cli_version_command() -> None:
    """Test `strixsec version` subcommand."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "StrixSec" in result.stdout
    assert "v0.1.0" in result.stdout
    assert "Python Runtime" in result.stdout
    assert "OS Platform" in result.stdout


def test_cli_version_flag() -> None:
    """Test `strixsec --version` flag."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "StrixSec" in result.stdout
    assert "v0.1.0" in result.stdout
