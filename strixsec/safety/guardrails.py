"""
Safety Guardrails and Scope Authorization Verification Engine.
"""

from __future__ import annotations

import ipaddress

from strixsec.core.errors import SafetyGuardrailError


class SafetyGuardrail:
    """Enforces safety guardrails to ensure targets are authorized and safe to scan."""

    FORBIDDEN_NETWORKS: tuple[str, ...] = (
        "169.254.169.254/32",  # Cloud Instance Metadata (AWS/GCP/Azure)
        "224.0.0.0/4",  # Multicast
        "255.255.255.255/32",  # Broadcast
    )

    def __init__(self, allow_localhost: bool = False) -> None:
        self.allow_localhost = allow_localhost

    def validate_target_ip(self, ip_str: str) -> bool:
        """Validate whether an IP address is permissible under safety rules.

        Args:
            ip_str: Target IP address string.

        Returns:
            True if IP is permitted.

        Raises:
            SafetyGuardrailError: If target violates safety rules.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as err:
            raise SafetyGuardrailError(f"Invalid IP address format: '{ip_str}'") from err

        if ip.is_loopback and not self.allow_localhost:
            raise SafetyGuardrailError(
                f"Target IP '{ip_str}' is a loopback/localhost address. "
                "Scanning localhost is restricted."
            )

        for forbidden_cidr in self.FORBIDDEN_NETWORKS:
            net = ipaddress.ip_network(forbidden_cidr)
            if ip in net:
                raise SafetyGuardrailError(
                    f"Target IP '{ip_str}' belongs to forbidden range '{forbidden_cidr}' "
                    "(Cloud Metadata/Broadcast)."
                )

        return True
