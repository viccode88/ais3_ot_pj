from __future__ import annotations

import socket
import struct
import time

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget, socket_address
from plcfp.scheduler import ProbeScheduler


def _dnp3_crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def _link_status_request(destination: int, source: int = 0xFFFE) -> bytes:
    header = b"\x05\x64\x05\xc9" + struct.pack("<HH", destination, source)
    return header + struct.pack("<H", _dnp3_crc(header))


def _parse_link_status_response(data: bytes, *, destination: int, source: int) -> dict[str, object]:
    if len(data) != 10:
        raise ValueError("DNP3 link-status response must be exactly one link header")
    if data[:2] != b"\x05\x64" or data[2] != 5:
        raise ValueError("invalid DNP3 link header")
    expected_crc = _dnp3_crc(data[:8])
    received_crc = struct.unpack_from("<H", data, 8)[0]
    if received_crc != expected_crc:
        raise ValueError("invalid DNP3 link-header CRC")

    control = data[3]
    if control not in {0x0B, 0x1B}:
        raise ValueError("DNP3 response is not a secondary link-status frame")
    response_destination, response_source = struct.unpack_from("<HH", data, 4)
    if response_destination != source or response_source != destination:
        raise ValueError("DNP3 response addresses do not correlate with request")

    return {
        "responded": True,
        "valid_start": True,
        "protocol_valid": True,
        "destination": destination,
        "response_destination": response_destination,
        "response_source": response_source,
        "control": control,
        "data_flow_control": bool(control & 0x10),
    }


def probe_dnp3(
    target: ResolvedTarget,
    scheduler: ProbeScheduler,
    *,
    destination: int,
    port: int = 20000,
) -> list[Observation]:
    if not 0 <= destination <= 0xFFFF:
        raise ValueError("DNP3 destination must be between 0 and 65535")
    source = 0xFFFE
    request = _link_status_request(destination, source)

    def action() -> tuple[bytes, float]:
        started = time.monotonic()
        with socket.socket(target.family, socket.SOCK_STREAM) as sock:
            sock.settimeout(scheduler.timeout)
            sock.connect(socket_address(target, port))
            sock.sendall(request)
            response = sock.recv(65535)
        return response, round((time.monotonic() - started) * 1000, 3)

    try:
        response, latency = scheduler.run(action)
        value = _parse_link_status_response(response, destination=destination, source=source)
        return [
            Observation(
                probe_id="dnp3.link_status",
                feature="dnp3.link_status_response",
                value=value,
                latency_ms=latency,
                raw=response,
                metadata={
                    "request_hex": request.hex(),
                    "transport": "tcp",
                    "protocol_valid": True,
                },
            )
        ]
    except (OSError, ValueError) as exc:
        return [
            Observation(
                probe_id="dnp3.link_status",
                feature="dnp3.link_status_response",
                state=ProbeState.UNAVAILABLE,
                error=str(exc),
                metadata={
                    "request_hex": request.hex(),
                    "destination": destination,
                    "transport": "tcp",
                    "protocol_valid": False,
                },
            )
        ]
