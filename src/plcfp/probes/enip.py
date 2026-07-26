from __future__ import annotations

import socket
import struct
import time
from typing import Any

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget, socket_address
from plcfp.scheduler import ProbeScheduler, ScanProfile


def _header(
    command: int,
    payload: bytes = b"",
    session: int = 0,
    *,
    context: bytes = b"\0" * 8,
) -> bytes:
    if len(context) != 8:
        raise ValueError("EtherNet/IP sender context must be exactly 8 bytes")
    return struct.pack("<HHII8sI", command, len(payload), session, 0, context, 0) + payload


def _request_context(command: int) -> bytes:
    return struct.pack("<II", 0x504C4346, command)


def _parse_header(data: bytes) -> dict[str, Any]:
    if len(data) < 24:
        raise ValueError("short EtherNet/IP encapsulation header")
    command, length, session, status, context, options = struct.unpack("<HHII8sI", data[:24])
    if len(data) != 24 + length:
        raise ValueError("EtherNet/IP encapsulation length does not match received bytes")
    return {
        "command": command,
        "length": length,
        "session_handle": session,
        "status": status,
        "sender_context": context.hex(),
        "options": options,
        "payload": data[24 : 24 + length],
    }


def _correlate_response(response: bytes, request: bytes, command: int) -> dict[str, Any]:
    if response == request:
        raise ValueError("EtherNet/IP response echoed the request")
    parsed = _parse_header(response)
    request_header = _parse_header(request)
    if parsed["command"] != command:
        raise ValueError("EtherNet/IP response command does not match request")
    if parsed["sender_context"] != request_header["sender_context"]:
        raise ValueError("EtherNet/IP sender context mismatch")
    if parsed["status"] != 0 or parsed["options"] != 0:
        raise ValueError("EtherNet/IP response has invalid status or options")
    return parsed


def _parse_identity(payload: bytes) -> dict[str, Any]:
    if len(payload) < 2:
        raise ValueError("short ListIdentity payload")
    count = struct.unpack_from("<H", payload, 0)[0]
    if count < 1:
        raise ValueError("ListIdentity response contained no identity items")
    offset = 2
    identities: list[dict[str, Any]] = []
    for _ in range(count):
        if offset + 4 > len(payload):
            raise ValueError("truncated ListIdentity item header")
        item_type, item_length = struct.unpack_from("<HH", payload, offset)
        offset += 4
        if offset + item_length > len(payload):
            raise ValueError("truncated ListIdentity item")
        item = payload[offset : offset + item_length]
        offset += item_length
        if item_type != 0x000C or len(item) < 34:
            raise ValueError("invalid ListIdentity identity item")
        if struct.unpack_from("<H", item, 0)[0] != 1:
            raise ValueError("unsupported ListIdentity protocol version")
        base = 18
        vendor, device_type, product_code = struct.unpack_from("<HHH", item, base)
        major, minor = item[base + 6], item[base + 7]
        status = struct.unpack_from("<H", item, base + 8)[0]
        serial = struct.unpack_from("<I", item, base + 10)[0]
        name_length = item[base + 14]
        name_end = base + 15 + name_length
        if name_end + 1 != len(item):
            raise ValueError("invalid ListIdentity product-name length")
        name = item[base + 15 : name_end].decode("utf-8", errors="replace")
        identity: dict[str, Any] = {
            "item_type": item_type,
            "vendor_id": vendor,
            "device_type": device_type,
            "product_code": product_code,
            "revision": f"{major}.{minor}",
            "status": status,
            "serial_number": serial,
            "product_name": name,
            "state": item[name_end],
        }
        identities.append(identity)
    if offset != len(payload):
        raise ValueError("unexpected trailing ListIdentity bytes")
    return {"item_count": count, "identities": identities, "protocol_valid": True}


def _parse_item_list(
    payload: bytes,
    *,
    expected_type: int | None = None,
    allow_empty: bool = True,
) -> list[tuple[int, bytes]]:
    if len(payload) < 2:
        raise ValueError("short EtherNet/IP item list")
    count = struct.unpack_from("<H", payload, 0)[0]
    if not allow_empty and count == 0:
        raise ValueError("EtherNet/IP item list must not be empty")
    offset = 2
    items: list[tuple[int, bytes]] = []
    for _ in range(count):
        if offset + 4 > len(payload):
            raise ValueError("truncated EtherNet/IP item header")
        item_type, item_length = struct.unpack_from("<HH", payload, offset)
        offset += 4
        if expected_type is not None and item_type != expected_type:
            raise ValueError("unexpected EtherNet/IP item type")
        if offset + item_length > len(payload):
            raise ValueError("truncated EtherNet/IP item payload")
        items.append((item_type, payload[offset : offset + item_length]))
        offset += item_length
    if offset != len(payload):
        raise ValueError("unexpected trailing EtherNet/IP item bytes")
    return items


def _validate_command_response(
    command: int,
    parsed: dict[str, Any],
    request_payload: bytes,
) -> None:
    payload = parsed["payload"]
    if not isinstance(payload, bytes):
        raise TypeError("invalid EtherNet/IP response payload")
    session = parsed["session_handle"]
    if command == 0x0065:
        if session == 0 or payload != request_payload:
            raise ValueError("invalid EtherNet/IP RegisterSession response")
        return
    if session != 0:
        raise ValueError("unexpected EtherNet/IP session handle")
    if command == 0x0004:
        items = _parse_item_list(payload, expected_type=0x0100, allow_empty=False)
        if any(len(item) != 20 or struct.unpack_from("<H", item, 0)[0] != 1 for _, item in items):
            raise ValueError("invalid EtherNet/IP ListServices item")
        return
    if command == 0x0064:
        _parse_item_list(payload)
        return
    if command == 0x0000:
        raise ValueError("EtherNet/IP NOP response is not identity evidence")
    raise ValueError(f"unsupported EtherNet/IP command 0x{command:04x}")


def _udp_list_identity(target: ResolvedTarget, scheduler: ProbeScheduler, port: int) -> Observation:
    command = 0x0063
    request = _header(command, context=_request_context(command))

    def action() -> tuple[bytes, float]:
        started = time.monotonic()
        with socket.socket(target.family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(scheduler.timeout)
            sock.sendto(request, socket_address(target, port))
            response, _ = sock.recvfrom(65535)
        return response, round((time.monotonic() - started) * 1000, 3)

    try:
        response, latency = scheduler.run(action)
        parsed = _correlate_response(response, request, command)
        if parsed["session_handle"] != 0:
            raise ValueError("unexpected ListIdentity session handle")
        value = _parse_identity(parsed.pop("payload"))
        value["encapsulation"] = parsed
        return Observation(
            probe_id="enip.list_identity",
            feature="enip.list_identity",
            value=value,
            latency_ms=latency,
            raw=response,
            metadata={
                "request_hex": request.hex(),
                "transport": "udp",
                "protocol_valid": True,
            },
        )
    except (OSError, ValueError) as exc:
        return Observation(
            probe_id="enip.list_identity",
            feature="enip.list_identity",
            state=ProbeState.UNAVAILABLE,
            error=str(exc),
            metadata={
                "request_hex": request.hex(),
                "transport": "udp",
                "protocol_valid": False,
            },
        )


def _tcp_command(
    target: ResolvedTarget,
    scheduler: ProbeScheduler,
    command: int,
    payload: bytes,
    port: int,
) -> Observation:
    request = _header(command, payload, context=_request_context(command))

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
        parsed = _correlate_response(response, request, command)
        _validate_command_response(command, parsed, payload)
        parsed["payload_hex"] = parsed.pop("payload").hex()
        parsed["protocol_valid"] = True
        return Observation(
            probe_id=f"enip.{name}",
            feature=f"enip.{name}",
            value=parsed,
            latency_ms=latency,
            raw=response,
            metadata={
                "request_hex": request.hex(),
                "transport": "tcp",
                "protocol_valid": True,
            },
        )
    except (OSError, ValueError) as exc:
        return Observation(
            probe_id=f"enip.{name}",
            feature=f"enip.{name}",
            state=ProbeState.UNAVAILABLE,
            error=str(exc),
            metadata={
                "request_hex": request.hex(),
                "transport": "tcp",
                "protocol_valid": False,
            },
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
