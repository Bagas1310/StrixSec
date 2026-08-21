"""
Scope Models and Data Structures for StrixSec Scope System.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TargetType(StrEnum):
    """Classification of target types in scope."""

    EXACT_DOMAIN = "EXACT_DOMAIN"
    WILDCARD_DOMAIN = "WILDCARD_DOMAIN"
    IPV4 = "IPV4"
    CIDR = "CIDR"


class ScopeEntry(BaseModel):
    """Model representing a single target rule in scope configuration."""

    raw_target: str = Field(..., description="Original raw target input string")
    normalized_target: str = Field(..., description="Normalized target representation")
    target_type: TargetType = Field(..., description="Target type classification")
    is_exclusion: bool = Field(default=False, description="True if target is an exclusion rule")


class ScopeConfig(BaseModel):
    """Pydantic model representing complete scope configuration."""

    allowed_targets: list[ScopeEntry] = Field(default_factory=list)
    excluded_targets: list[ScopeEntry] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize scope config to dictionary."""
        return self.model_dump()


class ValidationResult(BaseModel):
    """Model representing result of a scope validation check."""

    target: str = Field(..., description="Target string evaluated")
    normalized_target: str = Field(..., description="Normalized target representation")
    is_in_scope: bool = Field(..., description="True if target is permitted in scope")
    reason: str = Field(..., description="Detailed explanation of validation result")
    matched_rule: ScopeEntry | None = Field(
        default=None, description="Scope rule that matched the target"
    )
