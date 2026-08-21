"""
Pytest Fixtures for StrixSec.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from strixsec.core.config import AppConfig


@pytest.fixture
def cli_runner() -> CliRunner:
    """Fixture providing Typer CliRunner for CLI integration testing."""
    return CliRunner()


@pytest.fixture
def default_config() -> AppConfig:
    """Fixture providing default AppConfig instance."""
    return AppConfig()
