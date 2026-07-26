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
    try:
        message_type = data[:3].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid OPC UA TCP message type") from exc
    chunk_type = chr(data[3])
    size = struct.unpack_from("<I", data, 4)[0]
    if message_type not in {"ACK", "ERR"}:
        raise ValueError(f"unexpected OPC UA response type {message_type!r}")
    if chunk_type != "F":
        raise ValueError("OPC UA connection response must be a final chunk")
    if size != len(data):
        raise ValueError("OPC UA message size does not match received bytes")
    result: dict[str, Any] = {
        "message_type": message_type,
        "chunk_type": chunk_type,
        "message_size": size,
        "protocol_valid": True,
    }
    if message_type == "ACK":
        if size != 28:
            raise ValueError("OPC UA ACK must contain the complete 28-byte structure")
        protocol, receive, send, maximum, chunks = struct.unpack_from("<IIIII", data, 8)
        if protocol != 0:
            raise ValueError("unsupported OPC UA protocol version in ACK")
        if not 8192 <= receive <= 65536 or not 8192 <= send <= 65536:
            raise ValueError("invalid OPC UA ACK buffer sizes")
        result.update(
            {
                "protocol_version": protocol,
                "receive_buffer_size": receive,
                "send_buffer_size": send,
                "max_message_size": maximum,
                "max_chunk_count": chunks,
            }
        )
    else:
        if size < 16:
            raise ValueError("short OPC UA ERR response")
        result["error_code"] = struct.unpack_from("<I", data, 8)[0]
        reason_size = struct.unpack_from("<i", data, 12)[0]
        if reason_size < -1:
            raise ValueError("invalid OPC UA ERR reason length")
        expected_size = 16 if reason_size == -1 else 16 + reason_size
        if size != expected_size:
            raise ValueError("OPC UA ERR reason length does not match message size")
        if reason_size >= 0:
            try:
                result["reason"] = data[16:].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("invalid UTF-8 in OPC UA ERR reason") from exc
        else:
            result["reason"] = None
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
                metadata={
                    "request_hex": request.hex(),
                    "endpoint": endpoint,
                    "transport": "tcp",
                    "protocol_valid": True,
                },
            )
        ]
    except (OSError, ValueError) as exc:
        return [
            Observation(
                probe_id="opcua.hello",
                feature="opcua.hello_ack",
                state=ProbeState.UNAVAILABLE,
                error=str(exc),
                metadata={
                    "request_hex": request.hex(),
                    "endpoint": endpoint,
                    "transport": "tcp",
                    "protocol_valid": False,
                },
            )
        ]
