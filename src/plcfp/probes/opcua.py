from __future__ import annotations

import socket
import struct
import time
from typing import Any

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget, socket_address
from plcfp.scheduler import ProbeScheduler


def _ua_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<i", len(encoded)) + encoded


def _hello(endpoint: str) -> bytes:
    body = struct.pack("<IIIII", 0, 65536, 65536, 16 * 1024 * 1024, 0) + _ua_string(endpoint)
    return b"HELF" + struct.pack("<I", len(body) + 8) + body


def _parse_ack(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        raise ValueError("short OPC UA TCP response")
    message_type = data[:3].decode("ascii", errors="replace")
    chunk_type = chr(data[3])
    size = struct.unpack_from("<I", data, 4)[0]
    result: dict[str, Any] = {
        "message_type": message_type,
        "chunk_type": chunk_type,
        "message_size": size,
    }
    if message_type == "ACK" and len(data) >= 28:
        protocol, receive, send, maximum, chunks = struct.unpack_from("<IIIII", data, 8)
        result.update(
            {
                "protocol_version": protocol,
                "receive_buffer_size": receive,
                "send_buffer_size": send,
                "max_message_size": maximum,
                "max_chunk_count": chunks,
            }
        )
    elif message_type == "ERR" and len(data) >= 12:
        result["error_code"] = struct.unpack_from("<I", data, 8)[0]
    return result


def probe_opcua(
    target: ResolvedTarget, scheduler: ProbeScheduler, port: int = 4840
) -> list[Observation]:
    endpoint = f"opc.tcp://{target.original}:{port}"
    request = _hello(endpoint)

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
        parsed = _parse_ack(response)
        return [
            Observation(
                probe_id="opcua.hello",
                feature="opcua.hello_ack",
                value=parsed,
                latency_ms=latency,
                raw=response,
                metadata={"request_hex": request.hex(), "endpoint": endpoint},
            )
        ]
    except (OSError, ValueError) as exc:
        return [
            Observation(
                probe_id="opcua.hello",
                feature="opcua.hello_ack",
                state=ProbeState.UNAVAILABLE,
                error=str(exc),
                metadata={"request_hex": request.hex(), "endpoint": endpoint},
            )
        ]
