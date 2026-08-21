"""
Integration tests for StrixSec Recon CLI subcommands.
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


def test_recon_cli_out_of_scope_rejection() -> None:
    # Scope is empty
    res_dns = runner.invoke(app, ["recon", "dns", "forbidden.com"])
    assert res_dns.exit_code == 1
    assert "OUT OF SCOPE" in res_dns.stdout
    assert "Network operation blocked" in res_dns.stdout

    res_http = runner.invoke(app, ["recon", "http", "forbidden.com"])
    assert res_http.exit_code == 1
    assert "OUT OF SCOPE" in res_http.stdout

    res_tech = runner.invoke(app, ["recon", "tech", "forbidden.com"])
    assert res_tech.exit_code == 1
    assert "OUT OF SCOPE" in res_tech.stdout


@patch("dns.resolver.Resolver.resolve")
def test_recon_cli_in_scope_dns(mock_resolve: MagicMock) -> None:
    storage = ScopeStorage()
    storage.add_target("example.com")

    mock_a = MagicMock()
    mock_a.__str__.return_value = "93.184.216.34"
    mock_answers = MagicMock()
    mock_answers.__iter__.return_value = [mock_a]
    mock_answers.ttl = 3600
    mock_resolve.return_value = mock_answers

    res = runner.invoke(app, ["recon", "dns", "example.com"])
    assert res.exit_code == 0
    assert "Target validated: example.com" in res.stdout
    assert "93.184.216.34" in res.stdout
