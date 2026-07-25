from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    original: str
    address: str
    family: socket.AddressFamily


def resolve_target(target: str, *, allow_public: bool = False) -> ResolvedTarget:
    infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    if not infos:
        raise ValueError(f"cannot resolve target: {target}")
    candidates: list[ResolvedTarget] = []
    for family, _, _, _, sockaddr in infos:
        address = str(sockaddr[0])
        ip = ipaddress.ip_address(address)
        if not allow_public and not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
        ):
            continue
        candidates.append(ResolvedTarget(target, address, family))
    if candidates:
        return candidates[0]
    raise ValueError(
        "target resolves only to public addresses; pass --allow-public only with authorization"
    )


def socket_address(target: ResolvedTarget, port: int) -> tuple[object, ...]:
    if target.family == socket.AF_INET6:
        return (target.address, port, 0, 0)
    return (target.address, port)
