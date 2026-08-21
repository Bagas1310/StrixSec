"""
Unit tests for StrixSec safety guardrails.
"""

from __future__ import annotations

import pytest

from strixsec.core.errors import SafetyGuardrailError
from strixsec.safety.guardrails import SafetyGuardrail


def test_guardrail_valid_ip() -> None:
    """Test safety guardrail validation with allowed external IP."""
    guard = SafetyGuardrail()
    assert guard.validate_target_ip("8.8.8.8") is True


def test_guardrail_localhost_blocked_by_default() -> None:
    """Test safety guardrail blocks loopback IP by default."""
    guard = SafetyGuardrail(allow_localhost=False)
    with pytest.raises(SafetyGuardrailError, match="loopback/localhost"):
        guard.validate_target_ip("127.0.0.1")


def test_guardrail_localhost_allowed_when_configured() -> None:
    """Test safety guardrail permits localhost when allow_localhost is True."""
    guard = SafetyGuardrail(allow_localhost=True)
    assert guard.validate_target_ip("127.0.0.1") is True


def test_guardrail_forbidden_cloud_metadata_ip() -> None:
    """Test safety guardrail strictly blocks AWS/GCP cloud metadata IP."""
    guard = SafetyGuardrail()
    with pytest.raises(SafetyGuardrailError, match="forbidden range"):
        guard.validate_target_ip("169.254.169.254")
