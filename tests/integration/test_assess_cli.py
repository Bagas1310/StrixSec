"""
Integration tests for StrixSec Assessment CLI subcommands.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from strixsec.cli.main import app
from strixsec.scope.storage import DEFAULT_SCOPE_FILE, ScopeStorage

runner = CliRunner()


def setup_function() -> None:
    if DEFAULT_SCOPE_FILE.exists():
        DEFAULT_SCOPE_FILE.unlink()


def teardown_function() -> None:
    if DEFAULT_SCOPE_FILE.exists():
        DEFAULT_SCOPE_FILE.unlink()


def test_assess_cli_out_of_scope_rejection() -> None:
    # Scope is empty
    res_headers = runner.invoke(app, ["assess", "headers", "forbidden.com"])
    assert res_headers.exit_code == 1
    assert "OUT OF SCOPE" in res_headers.stdout
    assert "Network operation blocked" in res_headers.stdout

    res_tls = runner.invoke(app, ["assess", "tls", "forbidden.com"])
    assert res_tls.exit_code == 1
    assert "OUT OF SCOPE" in res_tls.stdout

    res_cookies = runner.invoke(app, ["assess", "cookies", "forbidden.com"])
    assert res_cookies.exit_code == 1
    assert "OUT OF SCOPE" in res_cookies.stdout

    res_meta = runner.invoke(app, ["assess", "metadata", "forbidden.com"])
    assert res_meta.exit_code == 1
    assert "OUT OF SCOPE" in res_meta.stdout


@patch("strixsec.assessment.engine.analyze_http")
def test_assess_cli_in_scope_headers(mock_http: MagicMock) -> None:
    storage = ScopeStorage()
    storage.add_target("example.com")

    from strixsec.recon.models import HTTPResult

    mock_http.return_value = HTTPResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={"Strict-Transport-Security": "max-age=31536000"},
    )

    res = runner.invoke(app, ["assess", "headers", "example.com"])
    assert res.exit_code == 0
    assert "Target validated: example.com" in res.stdout
    assert "Strict-Transport-Security" in res.stdout
    assert "PRESENT" in res.stdout
