"""
Security-Hardened Scope Validation Engine for StrixSec.
"""

from __future__ import annotations

import ipaddress

from strixsec.scope.models import ScopeConfig, ScopeEntry, TargetType, ValidationResult
from strixsec.scope.normalizer import normalize_target


class ScopeValidator:
    """Validator engine for testing targets against scope rules without network operations."""

    def __init__(self, config: ScopeConfig | None = None) -> None:
        self.config = config or ScopeConfig()

    def validate(self, target: str) -> ValidationResult:
        """Validate if a target string is permitted under the current scope configuration.

        Args:
            target: Candidate target string (domain, URL, IP).

        Returns:
            ValidationResult containing status, matched rule, and explanation.
        """
        try:
            norm_target, target_type = normalize_target(target)
        except Exception as err:
            return ValidationResult(
                target=target,
                normalized_target=target,
                is_in_scope=False,
                reason=f"Target normalization failed: {err}",
            )

        # 1. Check Exclusion Rules (Exclusions always take precedence)
        for exclusion in self.config.excluded_targets:
            if self._matches_rule(norm_target, target_type, exclusion):
                return ValidationResult(
                    target=target,
                    normalized_target=norm_target,
                    is_in_scope=False,
                    reason=f"Target matches exclusion rule '{exclusion.raw_target}'",
                    matched_rule=exclusion,
                )

        # 2. Check Allowed Rules
        if not self.config.allowed_targets:
            return ValidationResult(
                target=target,
                normalized_target=norm_target,
                is_in_scope=False,
                reason="Scope is empty. No targets are permitted.",
            )

        for allowed in self.config.allowed_targets:
            if self._matches_rule(norm_target, target_type, allowed):
                return ValidationResult(
                    target=target,
                    normalized_target=norm_target,
                    is_in_scope=True,
                    reason=f"Target matches allowed rule '{allowed.raw_target}'",
                    matched_rule=allowed,
                )

        return ValidationResult(
            target=target,
            normalized_target=norm_target,
            is_in_scope=False,
            reason="Target does not match any allowed scope rules.",
        )

    def _matches_rule(self, norm_target: str, target_type: TargetType, rule: ScopeEntry) -> bool:
        """Evaluate if normalized candidate target matches a specific scope rule."""
        rule_target = rule.normalized_target
        rule_type = rule.target_type

        # Case A: Rule is Exact Domain (e.g. example.com)
        if rule_type == TargetType.EXACT_DOMAIN:
            if target_type in (TargetType.EXACT_DOMAIN, TargetType.WILDCARD_DOMAIN):
                # Exact match
                if norm_target == rule_target:
                    return True
                # Subdomain match: e.g. api.example.com ends with .example.com
                if norm_target.endswith(f".{rule_target}"):
                    return True

        # Case B: Rule is Wildcard Domain (e.g. *.example.com)
        elif rule_type == TargetType.WILDCARD_DOMAIN:
            base_domain = rule_target[2:]  # Strip *. prefix -> example.com
            # Must be a subdomain (e.g. api.example.com ends with .example.com)
            # Note: Root domain (example.com) will NOT match .example.com
            if target_type in (
                TargetType.EXACT_DOMAIN,
                TargetType.WILDCARD_DOMAIN,
            ) and norm_target.endswith(f".{base_domain}"):
                return True

        # Case C: Rule is IPv4 Address (e.g. 192.168.1.10)
        elif rule_type == TargetType.IPV4:
            if target_type == TargetType.IPV4 and norm_target == rule_target:
                return True

        # Case D: Rule is CIDR Range (e.g. 192.168.1.0/24)
        elif rule_type == TargetType.CIDR:
            if target_type == TargetType.IPV4:
                try:
                    ip = ipaddress.IPv4Address(norm_target)
                    network = ipaddress.IPv4Network(rule_target, strict=False)
                    if ip in network:
                        return True
                except ValueError:
                    pass
            elif target_type == TargetType.CIDR:
                try:
                    sub_net = ipaddress.IPv4Network(norm_target, strict=False)
                    parent_net = ipaddress.IPv4Network(rule_target, strict=False)
                    if sub_net.subnet_of(parent_net):
                        return True
                except ValueError:
                    pass

        return False
