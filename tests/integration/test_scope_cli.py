"""
Integration tests for StrixSec Scope CLI subcommands and exit codes.
"""

from __future__ import annotations

from typer.testing import CliRunner

from strixsec.cli.main import app
from strixsec.scope.storage import DEFAULT_SCOPE_FILE, ScopeStorage

runner = CliRunner()


def setup_function() -> None:
    """Clean up scope file before each test."""
    if DEFAULT_SCOPE_FILE.exists():
        DEFAULT_SCOPE_FILE.unlink()


def teardown_function() -> None:
    """Clean up scope file after each test."""
    if DEFAULT_SCOPE_FILE.exists():
        DEFAULT_SCOPE_FILE.unlink()


def test_cli_scope_add_and_list() -> None:
    # Add allowed domain
    res_add = runner.invoke(app, ["scope", "add", "example.com"])
    assert res_add.exit_code == 0
    assert "[+] Scope allowed target added: example.com" in res_add.stdout

    # Add exclusion
    res_ex = runner.invoke(app, ["scope", "add", "admin.example.com", "--exclude"])
    assert res_ex.exit_code == 0
    assert "[+] Scope exclusion added: admin.example.com" in res_ex.stdout

    # List scope
    res_list = runner.invoke(app, ["scope", "list"])
    assert res_list.exit_code == 0
    assert "ALLOWED" in res_list.stdout
    assert "EXCLUDED" in res_list.stdout
    assert "example.com" in res_list.stdout
    assert "admin.example.com" in res_list.stdout


def test_cli_scope_validate_in_and_out_of_scope() -> None:
    # Configure scope
    storage = ScopeStorage()
    storage.add_target("example.com")
    storage.add_target("admin.example.com", is_exclusion=True)

    # Validate allowed target -> Exit code 0
    res_valid = runner.invoke(app, ["scope", "validate", "api.example.com"])
    assert res_valid.exit_code == 0
    assert "[+] Target is IN SCOPE" in res_valid.stdout

    # Validate excluded target -> Exit code 1
    res_ex = runner.invoke(app, ["scope", "validate", "admin.example.com"])
    assert res_ex.exit_code == 1
    assert "[-] Target is OUT OF SCOPE" in res_ex.stdout

    # Validate unlisted domain -> Exit code 1
    res_out = runner.invoke(app, ["scope", "validate", "evil.com"])
    assert res_out.exit_code == 1
    assert "[-] Target is OUT OF SCOPE" in res_out.stdout


def test_cli_scope_remove() -> None:
    storage = ScopeStorage()
    storage.add_target("example.com")

    # Remove target
    res_rem = runner.invoke(app, ["scope", "remove", "example.com"])
    assert res_rem.exit_code == 0
    assert "[+] Scope entry removed: example.com" in res_rem.stdout

    # Try removing non-existent target
    res_rem_absent = runner.invoke(app, ["scope", "remove", "nonexistent.com"])
    assert res_rem_absent.exit_code == 0
    assert "not found in scope" in res_rem_absent.stdout
