"""
Comprehensive Unit Tests for StrixSec Scope Validation System.
"""

from __future__ import annotations

import pytest

from strixsec.core.errors import ScopeValidationError
from strixsec.scope.models import ScopeConfig, TargetType
from strixsec.scope.normalizer import normalize_target
from strixsec.scope.storage import ScopeStorage
from strixsec.scope.validator import ScopeValidator

# --- Normalizer Tests ---


def test_normalize_exact_domain() -> None:
    target, t_type = normalize_target("example.com")
    assert target == "example.com"
    assert t_type == TargetType.EXACT_DOMAIN


def test_normalize_uppercase_and_trailing_dot() -> None:
    target, t_type = normalize_target("EXAMPLE.COM.")
    assert target == "example.com"
    assert t_type == TargetType.EXACT_DOMAIN


def test_normalize_url_with_scheme_port_path() -> None:
    target, t_type = normalize_target("https://api.example.com:8443/v1/scan?q=test#ref")
    assert target == "api.example.com"
    assert t_type == TargetType.EXACT_DOMAIN


def test_normalize_wildcard_domain() -> None:
    target, t_type = normalize_target("*.example.com")
    assert target == "*.example.com"
    assert t_type == TargetType.WILDCARD_DOMAIN


def test_normalize_ipv4() -> None:
    target, t_type = normalize_target("192.168.1.100")
    assert target == "192.168.1.100"
    assert t_type == TargetType.IPV4


def test_normalize_cidr() -> None:
    target, t_type = normalize_target("192.168.1.0/24")
    assert target == "192.168.1.0/24"
    assert t_type == TargetType.CIDR


def test_normalize_malformed_ip() -> None:
    with pytest.raises(ScopeValidationError, match="Invalid target format"):
        normalize_target("999.999.999.999")


def test_normalize_invalid_wildcard_placement() -> None:
    with pytest.raises(ScopeValidationError, match="Invalid wildcard placement"):
        normalize_target("ex*ample.com")


def test_normalize_empty_input() -> None:
    with pytest.raises(ScopeValidationError, match="non-empty string"):
        normalize_target("")


# --- Scope Validator Engine Tests ---


def test_empty_scope_rejects_all() -> None:
    validator = ScopeValidator(ScopeConfig())
    res = validator.validate("example.com")
    assert res.is_in_scope is False
    assert "Scope is empty" in res.reason


def test_exact_domain_matching() -> None:
    storage = ScopeStorage()
    config = ScopeConfig()

    # Add exact domain rule example.com
    config.allowed_targets.append(storage.add_target("example.com").model_copy())

    validator = ScopeValidator(config)

    # Allowed
    assert validator.validate("example.com").is_in_scope is True
    assert validator.validate("www.example.com").is_in_scope is True
    assert validator.validate("api.sub.example.com").is_in_scope is True
    assert validator.validate("http://example.com:8080/path").is_in_scope is True

    # Out of scope
    assert validator.validate("example.org").is_in_scope is False
    assert validator.validate("notexample.com").is_in_scope is False


def test_suffix_confusion_security_protection() -> None:
    """Critical Security Requirement: Prevent domain suffix confusion attacks."""
    config = ScopeConfig()

    # Allow exact domain rule example.com
    norm, t_type = normalize_target("example.com")
    from strixsec.scope.models import ScopeEntry

    config.allowed_targets.append(
        ScopeEntry(raw_target="example.com", normalized_target=norm, target_type=t_type)
    )

    validator = ScopeValidator(config)

    # Must NOT allow suffix confusion domains!
    assert validator.validate("example.com.evil.com").is_in_scope is False
    assert validator.validate("evilexample.com").is_in_scope is False
    assert validator.validate("fake-example.com").is_in_scope is False


def test_wildcard_matching_security_protection() -> None:
    """Security Requirement: Wildcard *.example.com must NOT match root example.com."""
    config = ScopeConfig()
    from strixsec.scope.models import ScopeEntry

    norm, t_type = normalize_target("*.example.com")
    config.allowed_targets.append(
        ScopeEntry(raw_target="*.example.com", normalized_target=norm, target_type=t_type)
    )

    validator = ScopeValidator(config)

    # Allowed subdomains
    assert validator.validate("api.example.com").is_in_scope is True
    assert validator.validate("dev.test.example.com").is_in_scope is True

    # REJECTED: Root domain example.com is NOT allowed by *.example.com wildcard rule alone!
    assert validator.validate("example.com").is_in_scope is False

    # REJECTED: Suffix confusion or sibling domains
    assert validator.validate("evil-example.com").is_in_scope is False
    assert validator.validate("example.org").is_in_scope is False


def test_exclusion_rule_precedence() -> None:
    """Test that exclusions override allowed rules."""
    config = ScopeConfig()
    from strixsec.scope.models import ScopeEntry

    # Allow *.example.com
    norm_wild, t_wild = normalize_target("*.example.com")
    config.allowed_targets.append(
        ScopeEntry(raw_target="*.example.com", normalized_target=norm_wild, target_type=t_wild)
    )

    # Exclude admin.example.com
    norm_ex, t_ex = normalize_target("admin.example.com")
    config.excluded_targets.append(
        ScopeEntry(
            raw_target="admin.example.com",
            normalized_target=norm_ex,
            target_type=t_ex,
            is_exclusion=True,
        )
    )

    validator = ScopeValidator(config)

    # api.example.com is in scope
    assert validator.validate("api.example.com").is_in_scope is True

    # admin.example.com is OUT OF SCOPE due to exclusion
    res_admin = validator.validate("admin.example.com")
    assert res_admin.is_in_scope is False
    assert "exclusion rule" in res_admin.reason


def test_ipv4_and_cidr_matching() -> None:
    config = ScopeConfig()
    from strixsec.scope.models import ScopeEntry

    # Add single IP 10.0.0.5
    norm_ip, t_ip = normalize_target("10.0.0.5")
    config.allowed_targets.append(
        ScopeEntry(raw_target="10.0.0.5", normalized_target=norm_ip, target_type=t_ip)
    )

    # Add CIDR range 192.168.1.0/24
    norm_cidr, t_cidr = normalize_target("192.168.1.0/24")
    config.allowed_targets.append(
        ScopeEntry(raw_target="192.168.1.0/24", normalized_target=norm_cidr, target_type=t_cidr)
    )

    validator = ScopeValidator(config)

    # In scope
    assert validator.validate("10.0.0.5").is_in_scope is True
    assert validator.validate("192.168.1.50").is_in_scope is True
    assert validator.validate("192.168.1.254").is_in_scope is True
    assert validator.validate("https://192.168.1.10:8443").is_in_scope is True

    # Out of scope
    assert validator.validate("10.0.0.6").is_in_scope is False
    assert validator.validate("192.168.2.1").is_in_scope is False


def test_storage_duplicate_entries(tmp_path) -> None:
    scope_file = tmp_path / ".strixsec_scope.json"
    storage = ScopeStorage(file_path=scope_file)

    storage.add_target("example.com")
    storage.add_target("EXAMPLE.COM.")  # Duplicate normalized entry

    config = storage.load_scope()
    assert len(config.allowed_targets) == 1
    assert config.allowed_targets[0].normalized_target == "example.com"
