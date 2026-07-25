from __future__ import annotations

import socket
import struct
from typing import Self

import pytest

from plcfp.net import ResolvedTarget
from plcfp.probes.dnp3 import _dnp3_crc, _link_status_request
from plcfp.probes.http import _murmur3_32
from plcfp.probes.modbus import ModbusClient
from plcfp.scan import ScanOptions
from plcfp.scheduler import BudgetExceeded, ProbeScheduler, ScanProfile


def test_scheduler_enforces_hard_budget() -> None:
    scheduler = ProbeScheduler(ScanProfile.SAFE, interval=0, packet_budget=1)
    assert scheduler.run(lambda: "ok") == "ok"
    try:
        scheduler.run(lambda: "never")
    except BudgetExceeded:
        pass
    else:
        raise AssertionError("hard packet budget was not enforced")


def test_scan_options_support_isolated_lab_port_mappings() -> None:
    options = ScanOptions(modbus_port=1502, v3_http_port=18080, enip_port=14418)
    assert options.ports == (1502, 18080, 8443, 14418, 20000, 4840)
    with pytest.raises(ValueError, match="ports"):
        _ = ScanOptions(modbus_port=0).ports


def test_murmur3_matches_known_vectors() -> None:
    assert _murmur3_32(b"") == 0
    assert _murmur3_32(b"hello") == 613153351


def test_dnp3_link_status_frame_has_valid_header_crc() -> None:
    frame = _link_status_request(1)
    assert frame[:4] == b"\x05\x64\x05\xc9"
    assert struct.unpack("<H", frame[-2:])[0] == _dnp3_crc(frame[:-2])


def test_modbus_client_parses_exception_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeSocket:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.request = b""

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, _address: object) -> None:
            return None

        def sendall(self, request: bytes) -> None:
            self.request = request

        def recv(self, size: int) -> bytes:
            transaction, protocol, _length, unit = struct.unpack(">HHHB", self.request[:7])
            response_pdu = bytes([self.request[7] | 0x80, 1])
            response = (
                struct.pack(">HHHB", transaction, protocol, len(response_pdu) + 1, unit)
                + response_pdu
            )
            return response[:7] if size == 7 else response[7:]

    monkeypatch.setattr("plcfp.probes.modbus.socket.socket", FakeSocket)
    target = ResolvedTarget("127.0.0.1", "127.0.0.1", socket.AF_INET)
    scheduler = ProbeScheduler(ScanProfile.SAFE, interval=0, timeout=1)
    result = ModbusClient(target, scheduler, 1502).exchange(b"\x2b\x0e\x01\x00")
    assert result.function == 0xAB
    assert result.exception_code == 1
    assert scheduler.sent == 1
