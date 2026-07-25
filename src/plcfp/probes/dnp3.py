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


def probe_dnp3(
    target: ResolvedTarget,
    scheduler: ProbeScheduler,
    *,
    destination: int,
    port: int = 20000,
) -> list[Observation]:
    if not 0 <= destination <= 0xFFFF:
        raise ValueError("DNP3 destination must be between 0 and 65535")
    request = _link_status_request(destination)

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
        valid_start = response.startswith(b"\x05\x64")
        return [
            Observation(
                probe_id="dnp3.link_status",
                feature="dnp3.link_status_response",
                value={
                    "responded": True,
                    "valid_start": valid_start,
                    "destination": destination,
                },
                latency_ms=latency,
                raw=response,
                metadata={"request_hex": request.hex()},
            )
        ]
    except OSError as exc:
        return [
            Observation(
                probe_id="dnp3.link_status",
                feature="dnp3.link_status_response",
                state=ProbeState.UNAVAILABLE,
                error=str(exc),
                metadata={"request_hex": request.hex(), "destination": destination},
            )
        ]
