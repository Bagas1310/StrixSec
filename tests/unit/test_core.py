"""
Unit tests for StrixSec core configuration, logging, and error handling.
"""

from __future__ import annotations

import logging

import pytest

from strixsec.core.config import AppConfig, get_default_config
from strixsec.core.errors import ConfigurationError, StrixSecError
from strixsec.core.logging import JSONFormatter, setup_logger


def test_default_config() -> None:
    """Test default application configuration initialization."""
    config = get_default_config()
    assert isinstance(config, AppConfig)
    assert config.app_name == "StrixSec"
    assert config.version == "0.1.0"
    assert config.safety.strict_mode is True


def test_config_from_dict_valid() -> None:
    """Test AppConfig parsing from valid dictionary."""
    data = {
        "app_name": "CustomStrix",
        "debug": True,
        "log_level": "DEBUG",
    }
    config = AppConfig.from_dict(data)
    assert config.app_name == "CustomStrix"
    assert config.debug is True
    assert config.log_level == "DEBUG"


def test_config_from_dict_invalid() -> None:
    """Test AppConfig error handling on invalid data."""
    with pytest.raises(ConfigurationError):
        # Invalid type handling if non-coercible or failing validation
        AppConfig.from_dict({"output_dir": 12345})


def test_strixsec_error_formatting() -> None:
    """Test custom exception message and details string conversion."""
    err = StrixSecError("Failed action", details={"code": 404})
    assert "Failed action" in str(err)
    assert "404" in str(err)
    assert err.message == "Failed action"
    assert err.details == {"code": 404}


def test_logger_setup() -> None:
    """Test setup_logger creates a valid logger instance."""
    logger = setup_logger(name="test_logger", level="DEBUG")
    assert logger.name == "test_logger"
    assert logger.level == logging.DEBUG


def test_json_formatter() -> None:
    """Test structured JSON log formatter."""
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test log entry",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert '"level": "INFO"' in formatted
    assert '"message": "Test log entry"' in formatted
