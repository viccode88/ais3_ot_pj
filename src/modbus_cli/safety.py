"""Fail-closed laboratory target and resource limits."""

import ipaddress
import socket
from dataclasses import dataclass, field

from .exceptions import SafetyPolicyError


@dataclass(frozen=True)
class SafetyPolicy:
    allowed_networks: tuple[str, ...] = field(
        default_factory=lambda: ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )
    allow_public_targets: bool = False
    allow_write_functions: bool = False
    max_requests: int = 10_000
    max_rate: float = 50.0
    max_concurrency: int = 4

    def validate_target(self, host: str) -> str:
        try:
            address = ipaddress.ip_address(socket.gethostbyname(host))
        except (ValueError, OSError) as exc:
            raise SafetyPolicyError(f"cannot resolve target {host!r}") from exc
        allowed = any(address in ipaddress.ip_network(network) for network in self.allowed_networks)
        if not allowed and not self.allow_public_targets:
            raise SafetyPolicyError(f"target {address} is outside allowed laboratory networks")
        return str(address)

    def validate_fuzz(self, requests: int, rate: float, concurrency: int) -> None:
        if not 1 <= requests <= self.max_requests:
            raise SafetyPolicyError(f"requests must be 1..{self.max_requests}")
        if not 0 < rate <= self.max_rate:
            raise SafetyPolicyError(f"rate must be >0 and <= {self.max_rate}")
        if not 1 <= concurrency <= self.max_concurrency:
            raise SafetyPolicyError(f"concurrency must be 1..{self.max_concurrency}")
