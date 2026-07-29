"""Transport abstraction and framed Modbus TCP implementation."""

from __future__ import annotations

import socket
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class TransportResult:
    response: bytes | None
    elapsed_ms: float
    status: str
    error: str | None = None


class Transport(ABC):
    name: str

    @abstractmethod
    def exchange(self, payload: bytes, *, expect_response: bool = True) -> TransportResult:
        """Send one payload and optionally receive one response."""


class TCPTransport(Transport):
    name = "tcp"

    def __init__(self, host: str, port: int = 502, timeout: float = 1.5) -> None:
        self.host, self.port, self.timeout = host, port, timeout

    def exchange(
        self, payload: bytes, *, expect_response: bool = True, tolerant: bool = False
    ) -> TransportResult:
        started = time.monotonic()
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as stream:
                stream.settimeout(self.timeout)
                stream.sendall(payload)
                if not expect_response:
                    return TransportResult(None, (time.monotonic() - started) * 1000, "sent")
                header = _recv_exact(stream, 7) if not tolerant else _recv_upto(stream, 7)
                if len(header) < 7:
                    return TransportResult(
                        header if tolerant else header,
                        (time.monotonic() - started) * 1000,
                        "disconnect" if header else "timeout",
                        "partial MBAP header" if header else None,
                    )
                length = struct.unpack(">H", header[4:6])[0]
                declared = max(0, length - 1)
                if tolerant:
                    body = _recv_upto(stream, declared)
                    response = header + body
                    # Fuzz targets routinely misdeclare the MBAP length (debug
                    # function codes on OpenPLC v3 both over- and under-count), so
                    # drain whatever else the peer already sent as evidence.
                    response += _drain_available(stream, min(0.2, self.timeout))
                    note = (
                        None
                        if len(body) == declared
                        else f"partial MBAP body: declared {declared + 1}, received {len(body) + 1}"
                    )
                    return TransportResult(
                        response, (time.monotonic() - started) * 1000, "response", note
                    )
                body = _recv_exact(stream, declared)
                response = header + body
                status = "response" if len(body) == declared else "disconnect"
                return TransportResult(response, (time.monotonic() - started) * 1000, status)
        except TimeoutError as exc:
            return TransportResult(None, (time.monotonic() - started) * 1000, "timeout", str(exc))
        except ConnectionRefusedError as exc:
            return TransportResult(
                None, (time.monotonic() - started) * 1000, "connection-refused", str(exc)
            )
        except (ConnectionResetError, BrokenPipeError, OSError) as exc:
            return TransportResult(
                None, (time.monotonic() - started) * 1000, "transport-error", str(exc)
            )


def _recv_exact(stream: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        part = stream.recv(count - len(chunks))
        if not part:
            break
        chunks.extend(part)
    return bytes(chunks)


def _recv_upto(stream: socket.socket, count: int) -> bytes:
    """Read up to ``count`` bytes; a read timeout keeps the partial bytes."""
    chunks = bytearray()
    while len(chunks) < count:
        try:
            part = stream.recv(count - len(chunks))
        except TimeoutError:
            break
        if not part:
            break
        chunks.extend(part)
    return bytes(chunks)


def _drain_available(stream: socket.socket, window: float) -> bytes:
    """Slurp bytes the peer already queued beyond the declared MBAP frame."""
    chunks = bytearray()
    stream.settimeout(max(0.01, window))
    while len(chunks) < 65536:
        try:
            part = stream.recv(4096)
        except TimeoutError:
            break
        if not part:
            break
        chunks.extend(part)
    return bytes(chunks)
