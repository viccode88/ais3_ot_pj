from __future__ import annotations

import socket
import struct
from collections.abc import Callable
from typing import Self, TypeVar, cast

import pytest

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget
from plcfp.port_services import build_port_findings
from plcfp.probes.dnp3 import (
    _dnp3_crc,
    _link_status_request,
    _parse_link_status_response,
    probe_dnp3,
)
from plcfp.probes.enip import (
    _correlate_response,
    _header,
    _parse_identity,
    _request_context,
    _tcp_command,
    _udp_list_identity,
    _validate_command_response,
)
from plcfp.probes.modbus import ModbusClient, _validate_response_pdu
from plcfp.probes.opcua import _hello, _parse_ack, probe_opcua
from plcfp.scheduler import ProbeScheduler, ScanProfile

T = TypeVar("T")


class StaticScheduler:
    timeout = 1.0

    def __init__(self, result: object) -> None:
        self.result = result

    def run(self, _action: Callable[[], T]) -> T:
        return cast(T, self.result)


def _scheduler(response: bytes) -> ProbeScheduler:
    return cast(ProbeScheduler, StaticScheduler((response, 0.25)))


def _target() -> ResolvedTarget:
    return ResolvedTarget("127.0.0.1", "127.0.0.1", socket.AF_INET)


def _tcp_open(port: int) -> Observation:
    return Observation(
        probe_id=f"network.tcp.{port}",
        feature=f"tcp.port.{port}.open",
        value=True,
        metadata={"port": port, "transport": "tcp"},
    )


def _dnp3_response(destination: int, source: int = 0xFFFE) -> bytes:
    header = b"\x05\x64\x05\x0b" + struct.pack("<HH", source, destination)
    return header + struct.pack("<H", _dnp3_crc(header))


def _enip_identity_payload(name: bytes = b"PLC") -> bytes:
    sockaddr = b"\0" * 16
    identity = (
        struct.pack("<H", 1)
        + sockaddr
        + struct.pack("<HHH", 1, 2, 3)
        + bytes((1, 0))
        + struct.pack("<H", 0)
        + struct.pack("<I", 123)
        + bytes((len(name),))
        + name
        + b"\0"
    )
    return struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(identity)) + identity


def test_modbus_rejects_echo_and_malformed_read_response() -> None:
    request = b"\x03\x00\x00\x00\x01"

    with pytest.raises(ValueError, match="echoed"):
        _validate_response_pdu(request, request)
    with pytest.raises(ValueError, match="byte count"):
        _validate_response_pdu(request, b"\x03\x01\x00")

    _validate_response_pdu(request, b"\x03\x02\x00\x01")
    _validate_response_pdu(request, b"\x83\x02")


def test_modbus_client_rejects_full_mbap_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    class EchoSocket:
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
            return self.request[:7] if size == 7 else self.request[7:]

    monkeypatch.setattr("plcfp.probes.modbus.socket.socket", EchoSocket)
    scheduler = ProbeScheduler(ScanProfile.SAFE, interval=0, timeout=1)
    client = ModbusClient(_target(), scheduler)

    with pytest.raises(ValueError, match="echoed"):
        client.exchange(b"\x03\x00\x00\x00\x01")


def test_opcua_only_accepts_complete_ack_or_error_response() -> None:
    ack = b"ACKF" + struct.pack("<I", 28) + struct.pack("<IIIII", 0, 65536, 65536, 0, 0)

    assert _parse_ack(ack)["protocol_valid"] is True
    with pytest.raises(ValueError, match="unexpected OPC UA response type"):
        _parse_ack(_hello("opc.tcp://127.0.0.1:4840"))
    with pytest.raises(ValueError, match="message size"):
        _parse_ack(ack[:-1])


def test_opcua_probe_marks_echo_invalid_and_ack_valid() -> None:
    endpoint = "opc.tcp://127.0.0.1:4840"
    echo = probe_opcua(_target(), _scheduler(_hello(endpoint)))[0]
    assert echo.state == ProbeState.UNAVAILABLE
    assert echo.metadata["protocol_valid"] is False
    assert echo.metadata["transport"] == "tcp"

    ack = b"ACKF" + struct.pack("<I", 28) + struct.pack("<IIIII", 0, 65536, 65536, 0, 0)
    valid = probe_opcua(_target(), _scheduler(ack))[0]
    assert valid.state == ProbeState.OBSERVED
    assert valid.metadata["protocol_valid"] is True


def test_dnp3_requires_crc_control_and_swapped_addresses() -> None:
    destination = 7
    valid = _dnp3_response(destination)

    assert (
        _parse_link_status_response(valid, destination=destination, source=0xFFFE)["protocol_valid"]
        is True
    )
    with pytest.raises(ValueError, match="secondary link-status"):
        _parse_link_status_response(
            _link_status_request(destination), destination=destination, source=0xFFFE
        )
    with pytest.raises(ValueError, match="addresses"):
        _parse_link_status_response(valid, destination=8, source=0xFFFE)
    with pytest.raises(ValueError, match="CRC"):
        _parse_link_status_response(valid[:-1] + b"\0", destination=destination, source=0xFFFE)


def test_dnp3_probe_exposes_protocol_valid() -> None:
    invalid = probe_dnp3(_target(), _scheduler(b"arbitrary"), destination=7)[0]
    assert invalid.state == ProbeState.UNAVAILABLE
    assert invalid.metadata["protocol_valid"] is False
    assert invalid.metadata["transport"] == "tcp"

    valid = probe_dnp3(_target(), _scheduler(_dnp3_response(7)), destination=7)[0]
    assert valid.metadata["protocol_valid"] is True
    assert valid.value["protocol_valid"] is True


def test_enip_register_session_rejects_echo_and_correlates_response() -> None:
    command = 0x0065
    payload = struct.pack("<HH", 1, 0)
    context = _request_context(command)
    request = _header(command, payload, context=context)

    with pytest.raises(ValueError, match="echoed"):
        _correlate_response(request, request, command)

    response = _header(command, payload, session=0x1234, context=context)
    parsed = _correlate_response(response, request, command)
    _validate_command_response(command, parsed, payload)

    wrong_command = _header(0x0004, b"\0\0", context=context)
    with pytest.raises(ValueError, match="command"):
        _correlate_response(wrong_command, request, command)


def test_enip_tcp_probe_marks_correlated_response_valid() -> None:
    command = 0x0065
    payload = struct.pack("<HH", 1, 0)
    response = _header(
        command,
        payload,
        session=0x1234,
        context=_request_context(command),
    )

    observation = _tcp_command(_target(), _scheduler(response), command, payload, 44818)

    assert observation.state == ProbeState.OBSERVED
    assert observation.metadata["transport"] == "tcp"
    assert observation.metadata["protocol_valid"] is True


def test_enip_udp_identity_is_valid_udp_evidence_but_not_tcp_confirmation() -> None:
    command = 0x0063
    payload = _enip_identity_payload()
    response = _header(command, payload, context=_request_context(command))
    observation = _udp_list_identity(_target(), _scheduler(response), 44818)
    observation.metadata.update({"port": 44818, "service_id": "ethernet-ip"})

    assert _parse_identity(payload)["protocol_valid"] is True
    assert observation.metadata["transport"] == "udp"
    assert observation.metadata["protocol_valid"] is True
    finding = build_port_findings(
        [_tcp_open(44818), observation],
        {"ethernet-ip": 44818},
    )[0]
    assert finding.identification == "configured"


@pytest.mark.parametrize(
    ("service_id", "port", "probe_id", "feature", "value"),
    [
        ("modbus-tcp", 502, "modbus.unit_ids", "modbus.unit_id.response_matrix", {}),
        ("opc-ua", 4840, "opcua.hello", "opcua.hello_ack", {}),
        ("dnp3", 20000, "dnp3.link_status", "dnp3.link_status_response", {"valid_start": True}),
        ("ethernet-ip", 44818, "enip.register_session", "enip.register_session", {}),
    ],
)
def test_arbitrary_raw_bytes_never_confirm_without_protocol_valid(
    service_id: str,
    port: int,
    probe_id: str,
    feature: str,
    value: dict[str, object],
) -> None:
    arbitrary = Observation(
        probe_id,
        feature,
        value=value,
        raw=b"arbitrary bytes",
        metadata={"port": port, "transport": "tcp", "service_id": service_id},
    )

    finding = build_port_findings([_tcp_open(port), arbitrary], {service_id: port})[0]
    assert finding.identification == "configured"
