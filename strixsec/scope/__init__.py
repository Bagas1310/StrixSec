"""
Scope Subsystem for StrixSec.
"""

from __future__ import annotations

from strixsec.scope.models import ScopeConfig, ScopeEntry, TargetType, ValidationResult
from strixsec.scope.normalizer import normalize_target
from strixsec.scope.storage import ScopeStorage
from strixsec.scope.validator import ScopeValidator

__all__ = [
    "ScopeConfig",
    "ScopeEntry",
    "ScopeStorage",
    "ScopeValidator",
    "TargetType",
    "ValidationResult",
    "normalize_target",
]
