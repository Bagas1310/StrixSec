"""
Core Configuration Models and Settings Manager for StrixSec.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from strixsec.core.errors import ConfigurationError


class SafetyConfig(BaseModel):
    """Safety guardrail configuration settings."""

    strict_mode: bool = Field(
        default=True,
        description="Enforce strict authorization and scope boundaries.",
    )
    allow_localhost: bool = Field(
        default=False,
        description="Explicitly allow scanning localhost/127.0.0.1 targets.",
    )
    blocked_subnets: list[str] = Field(
        default_factory=lambda: ["169.254.169.254/32", "224.0.0.0/4", "255.255.255.255/32"],
        description="CIDR ranges strictly forbidden from assessment.",
    )


class AppConfig(BaseModel):
    """Global StrixSec Application Configuration."""

    app_name: str = "StrixSec"
    version: str = "0.1.0"
    debug: bool = False
    log_level: str = "INFO"
    json_logs: bool = False
    output_dir: Path = Field(default_factory=lambda: Path("reports"))
    safety: SafetyConfig = Field(default_factory=SafetyConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppConfig:
        """Create AppConfig instance from dictionary with validation."""
        try:
            return cls.model_validate(data)
        except Exception as err:
            raise ConfigurationError(
                f"Failed to load application configuration: {err}",
                details={"raw_data": data},
            ) from err


def get_default_config() -> AppConfig:
    """Return default application configuration."""
    return AppConfig()
