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

    def exchange(self, payload: bytes, *, expect_response: bool = True) -> TransportResult:
        started = time.monotonic()
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as stream:
                stream.settimeout(self.timeout)
                stream.sendall(payload)
                if not expect_response:
                    return TransportResult(None, (time.monotonic() - started) * 1000, "sent")
                header = _recv_exact(stream, 7)
                if len(header) < 7:
                    return TransportResult(
                        header,
                        (time.monotonic() - started) * 1000,
                        "disconnect",
                        "partial MBAP header",
                    )
                length = struct.unpack(">H", header[4:6])[0]
                body = _recv_exact(stream, max(0, length - 1))
                response = header + body
                status = "response" if len(body) == max(0, length - 1) else "disconnect"
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
