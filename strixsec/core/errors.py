"""
Custom Exception Hierarchy for StrixSec.
"""

from __future__ import annotations


class StrixSecError(Exception):
    """Base exception class for all StrixSec errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class ConfigurationError(StrixSecError):
    """Raised when there is an invalid or missing configuration."""


class ScopeValidationError(StrixSecError):
    """Raised when target scope validation fails or target is out-of-scope."""


class SafetyGuardrailError(StrixSecError):
    """Raised when a safety policy check fails or unauthorized action is blocked."""


class AssessmentError(StrixSecError):
    """Raised during assessment module failures."""


class StorageError(StrixSecError):
    """Raised when finding persistence or database operations fail."""


class ReportingError(StrixSecError):
    """Raised when report generation fails."""
