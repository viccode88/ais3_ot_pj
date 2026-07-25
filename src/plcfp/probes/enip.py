from __future__ import annotations

import socket
import struct
import time
from typing import Any

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget, socket_address
from plcfp.scheduler import ProbeScheduler, ScanProfile


def _header(command: int, payload: bytes = b"", session: int = 0) -> bytes:
    return struct.pack("<HHII8sI", command, len(payload), session, 0, b"\0" * 8, 0) + payload


def _parse_header(data: bytes) -> dict[str, Any]:
    if len(data) < 24:
        raise ValueError("short EtherNet/IP encapsulation header")
    command, length, session, status, context, options = struct.unpack("<HHII8sI", data[:24])
    if len(data) < 24 + length:
        raise ValueError("short EtherNet/IP encapsulation payload")
    return {
        "command": command,
        "length": length,
        "session_handle": session,
        "status": status,
        "sender_context": context.hex(),
        "options": options,
        "payload": data[24 : 24 + length],
    }


def _parse_identity(payload: bytes) -> dict[str, Any]:
    if len(payload) < 4:
        raise ValueError("short ListIdentity payload")
    count = struct.unpack_from("<H", payload, 0)[0]
    offset = 2
    identities: list[dict[str, Any]] = []
    for _ in range(count):
        if offset + 4 > len(payload):
            break
        item_type, item_length = struct.unpack_from("<HH", payload, offset)
        offset += 4
        item = payload[offset : offset + item_length]
        offset += item_length
        identity: dict[str, Any] = {"item_type": item_type}
        # Identity item: protocol(2), sockaddr(16), identity object fields.
        if item_type == 0x000C and len(item) >= 33:
            base = 18
            vendor, device_type, product_code = struct.unpack_from("<HHH", item, base)
            major, minor = item[base + 6], item[base + 7]
            status = struct.unpack_from("<H", item, base + 8)[0]
            serial = struct.unpack_from("<I", item, base + 10)[0]
            name_length = item[base + 14]
            name = item[base + 15 : base + 15 + name_length].decode("utf-8", errors="replace")
            identity.update(
                {
                    "vendor_id": vendor,
                    "device_type": device_type,
                    "product_code": product_code,
                    "revision": f"{major}.{minor}",
                    "status": status,
                    "serial_number": serial,
                    "product_name": name,
                }
            )
        identities.append(identity)
    return {"item_count": count, "identities": identities}


def _udp_list_identity(target: ResolvedTarget, scheduler: ProbeScheduler, port: int) -> Observation:
    request = _header(0x0063)

    def action() -> tuple[bytes, float]:
        started = time.monotonic()
        with socket.socket(target.family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(scheduler.timeout)
            sock.sendto(request, socket_address(target, port))
            response, _ = sock.recvfrom(65535)
        return response, round((time.monotonic() - started) * 1000, 3)

    try:
        response, latency = scheduler.run(action)
        parsed = _parse_header(response)
        value = _parse_identity(parsed.pop("payload"))
        value["encapsulation"] = parsed
        return Observation(
            probe_id="enip.list_identity",
            feature="enip.list_identity",
            value=value,
            latency_ms=latency,
            raw=response,
            metadata={"request_hex": request.hex()},
        )
    except (OSError, ValueError) as exc:
        return Observation(
            probe_id="enip.list_identity",
            feature="enip.list_identity",
            state=ProbeState.UNAVAILABLE,
            error=str(exc),
            metadata={"request_hex": request.hex()},
        )


def _tcp_command(
    target: ResolvedTarget,
    scheduler: ProbeScheduler,
    command: int,
    payload: bytes,
    port: int,
) -> Observation:
    request = _header(command, payload)

    def action() -> tuple[bytes, float]:
        started = time.monotonic()
        with socket.socket(target.family, socket.SOCK_STREAM) as sock:
            sock.settimeout(scheduler.timeout)
            sock.connect(socket_address(target, port))
            sock.sendall(request)
            response = sock.recv(65535)
        return response, round((time.monotonic() - started) * 1000, 3)

    name = {
        0x0000: "nop",
        0x0004: "list_services",
        0x0064: "list_interfaces",
        0x0065: "register_session",
    }.get(command, f"command_{command:04x}")
    try:
        response, latency = scheduler.run(action)
        parsed = _parse_header(response)
        parsed["payload_hex"] = parsed.pop("payload").hex()
        return Observation(
            probe_id=f"enip.{name}",
            feature=f"enip.{name}",
            value=parsed,
            latency_ms=latency,
            raw=response,
            metadata={"request_hex": request.hex()},
        )
    except (OSError, ValueError) as exc:
        return Observation(
            probe_id=f"enip.{name}",
            feature=f"enip.{name}",
            state=ProbeState.UNAVAILABLE,
            error=str(exc),
            metadata={"request_hex": request.hex()},
        )


def probe_enip(
    target: ResolvedTarget,
    scheduler: ProbeScheduler,
    *,
    profile: ScanProfile,
    port: int = 44818,
) -> list[Observation]:
    observations = [_udp_list_identity(target, scheduler, port)]
    if profile in {ScanProfile.STANDARD, ScanProfile.LAB}:
        observations.extend(
            [
                _tcp_command(target, scheduler, 0x0065, struct.pack("<HH", 1, 0), port),
                _tcp_command(target, scheduler, 0x0004, b"", port),
                _tcp_command(target, scheduler, 0x0064, b"", port),
                _tcp_command(target, scheduler, 0x0000, b"", port),
            ]
        )
    return observations
