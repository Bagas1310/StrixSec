"""
Integration tests for StrixSec Findings CLI subcommands.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from strixsec.cli.main import app
from strixsec.findings.models import (
    Finding,
    FindingCategory,
    SeverityLevel,
)
from strixsec.storage.database import DatabaseManager

# Use wide terminal env flag to prevent Rich from truncating table columns
runner = CliRunner()


def test_findings_cli_list_show_and_update(tmp_path: Path) -> None:
    test_db = tmp_path / "test_cli.db"
    db = DatabaseManager(db_path=test_db)

    # Insert sample finding into the test database
    finding = Finding(
        id="STRX-0001",
        title="Missing Strict-Transport-Security",
        asset="example.com",
        category=FindingCategory.SECURITY_HEADER,
        severity=SeverityLevel.MEDIUM,
        confidence="HIGH",
        description="HSTS header missing",
        created_at="2026-08-20T00:00:00Z",
        updated_at="2026-08-20T00:00:00Z",
    )
    db.save_finding(finding)

    # Patch DatabaseManager to always use the test DB
    original_init = DatabaseManager.__init__

    def patched_init(self: DatabaseManager, db_path: Path = test_db) -> None:
        original_init(self, db_path=test_db)

    with patch.object(DatabaseManager, "__init__", patched_init):
        # 1. List findings - assert ID present (title may be truncated in narrow env)
        res_list = runner.invoke(app, ["findings", "list"], env={"COLUMNS": "200"})
        assert res_list.exit_code == 0
        assert "STRX-0001" in res_list.stdout

        # 2. Filter findings by category
        res_filt = runner.invoke(
            app, ["findings", "list", "--category", "SECURITY_HEADER"], env={"COLUMNS": "200"}
        )
        assert res_filt.exit_code == 0
        assert "STRX-0001" in res_filt.stdout

        # 3. Show specific finding (panel output is not truncated)
        res_show = runner.invoke(app, ["findings", "show", "STRX-0001"])
        assert res_show.exit_code == 0
        assert "STRX-0001" in res_show.stdout
        assert "HSTS header missing" in res_show.stdout

        # 4. Update finding status
        res_upd = runner.invoke(app, ["findings", "update", "STRX-0001", "--status", "FIXED"])
        assert res_upd.exit_code == 0
        assert "FIXED" in res_upd.stdout

        # 5. Show non-existent finding ID
        res_err = runner.invoke(app, ["findings", "show", "STRX-9999"])
        assert res_err.exit_code == 1
        assert "not found" in res_err.stdout
