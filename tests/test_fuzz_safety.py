import json
import struct
from pathlib import Path

import pytest

from modbus_cli.exceptions import SafetyPolicyError
from modbus_cli.fuzzing import (
    STRATEGIES,
    CaseGenerator,
    FuzzCase,
    build_huge_payload,
    execute_cases,
    fuzz_payload_safety_reason,
    save_cases,
)
from modbus_cli.protocol import encode_adu
from modbus_cli.safety import SafetyPolicy
from modbus_cli.transport import TransportResult


def test_seed_is_reproducible() -> None:
    first = CaseGenerator(123)
    second = CaseGenerator(123)
    assert [
        first.generate(i, strategy, 1, "127.0.0.1", 502).request_hex
        for i, strategy in enumerate(STRATEGIES)
    ] == [
        second.generate(i, strategy, 1, "127.0.0.1", 502).request_hex
        for i, strategy in enumerate(STRATEGIES)
    ]


def test_report_serialization(tmp_path: Path) -> None:
    case = CaseGenerator(1).generate(1, "boundary", 1, "127.0.0.1", 502)
    output = tmp_path / "report.json"
    save_cases(output, [case])
    assert json.loads(output.read_text())[0]["seed"] == 1


def test_safety_limits_and_public_target() -> None:
    policy = SafetyPolicy()
    assert policy.validate_target("127.0.0.1") == "127.0.0.1"
    with pytest.raises(SafetyPolicyError):
        policy.validate_target("8.8.8.8")
    with pytest.raises(SafetyPolicyError):
        policy.validate_fuzz(1, 51, 1)


def test_seed_17_33rd_random_case_sends_fc06_to_virtual_lab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generator = CaseGenerator(17)
    case = [generator.generate(index, "random", 1, "127.0.0.1", 502) for index in range(1, 34)][-1]
    assert bytes.fromhex(case.request_hex)[7] == 6

    transport_calls: list[tuple[object, ...]] = []

    class RecordingTransport:
        def __init__(self, *args: object) -> None:
            transport_calls.append(args)

        def exchange(self, payload: bytes) -> TransportResult:
            transport_calls.append((payload,))
            return TransportResult(None, 0.0, "sent")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", RecordingTransport)
    execute_cases([case], timeout=1.5, interval=0)

    assert transport_calls[-1] == (bytes.fromhex(case.request_hex),)
    assert case.sent_at is not None
    assert case.status == "sent"
    assert case.safety_reason is None

    output = tmp_path / "sent-report.json"
    save_cases(output, [case])
    report_case = json.loads(output.read_text())[0]
    assert report_case["status"] == "sent"
    assert report_case["safety_reason"] is None


def test_read_only_fc03_is_still_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = CaseGenerator(17).generate(1, "boundary", 1, "127.0.0.1", 502)
    assert bytes.fromhex(case.request_hex)[7] == 3
    payloads: list[bytes] = []
    progress_events: list[str] = []

    class RecordingTransport:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert (host, port, timeout) == ("127.0.0.1", 502, 1.5)

        def exchange(self, payload: bytes) -> TransportResult:
            payloads.append(payload)
            return TransportResult(None, 0.25, "sent")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", RecordingTransport)
    execute_cases(
        [case],
        timeout=1.5,
        interval=0,
        progress=lambda event, _case: progress_events.append(event),
    )

    assert payloads == [bytes.fromhex(case.request_hex)]
    assert progress_events == ["sending", "result"]
    assert case.status == "sent"
    assert case.classification == "normal-or-exception-response"
    assert case.safety_reason is None


def test_concatenated_read_and_write_adus_are_sent_to_virtual_lab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = encode_adu(3, 0, 1) + encode_adu(6, 0, values=[1])
    case = FuzzCase(
        "case-concatenated",
        1,
        ["replay"],
        {"host": "127.0.0.1", "port": 502},
        payload.hex(),
        [],
    )
    sent_payloads: list[bytes] = []

    class RecordingTransport:
        def __init__(self, *args: object) -> None:
            pass

        def exchange(self, payload: bytes) -> TransportResult:
            sent_payloads.append(payload)
            return TransportResult(None, 0.0, "sent")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", RecordingTransport)

    execute_cases([case], timeout=1.5, interval=0)

    assert sent_payloads == [payload]
    assert case.status == "sent"
    assert case.safety_reason is None


def test_fc43_allows_any_mei_for_virtual_lab_testing() -> None:
    read_device_id = bytes.fromhex("000100000005012B0E0100")
    canopen_write_capable_mei = bytes.fromhex("000100000004012B0D00")

    assert fuzz_payload_safety_reason(read_device_id) is None
    assert fuzz_payload_safety_reason(canopen_write_capable_mei) is None


@pytest.mark.parametrize(
    "payload",
    (
        bytes.fromhex("000100010006010300000001"),
        bytes.fromhex("000100000005010300000001"),
        bytes.fromhex("00010000000601030000"),
    ),
)
def test_invalid_mbap_framing_is_sent_to_virtual_lab(payload: bytes) -> None:
    assert fuzz_payload_safety_reason(payload) is None


def test_empty_payload_is_the_only_transport_boundary_block() -> None:
    assert fuzz_payload_safety_reason(b"") is not None


def test_huge_payload_strategy_matches_legacy_fc16_shape() -> None:
    case = CaseGenerator(7).generate(1, "huge-payload", 1, "127.0.0.1", 502)
    payload = bytes.fromhex(case.request_hex)
    register_count = struct.unpack(">H", payload[10:12])[0]

    assert "huge-payload" in STRATEGIES
    assert payload[7] == 16
    assert 200 <= register_count <= 2000
    assert payload[12] == (register_count * 2) & 0xFF
    assert len(payload) == 7 + 1 + 2 + 2 + 1 + (register_count * 2)
    assert struct.unpack(">H", payload[4:6])[0] == len(payload) - 6
    assert case.mutations == [f"fc16-huge-payload:quantity={register_count}"]


def test_build_huge_payload_wraps_byte_count() -> None:
    payload, modbus = build_huge_payload(transaction_id=0xD000, unit_id=1, register_count=2000)

    assert payload[7] == 16
    assert modbus["byte_count_mismatch"] is True
    assert modbus["legacy_huge_payload_shape"] is True
    assert "byte count mismatch" in modbus["decoded_request"]["warnings"]


def test_huge_payload_is_sent_through_virtual_lab_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = CaseGenerator(11).generate(1, "huge-payload", 1, "127.0.0.1", 502)
    sent_payloads: list[bytes] = []

    class RecordingTransport:
        def __init__(self, *args: object) -> None:
            pass

        def exchange(self, payload: bytes) -> TransportResult:
            sent_payloads.append(payload)
            return TransportResult(None, 0.25, "sent")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", RecordingTransport)
    execute_cases([case], timeout=1.5, interval=0)

    assert sent_payloads == [bytes.fromhex(case.request_hex)]
    assert case.status == "sent"
    assert case.safety_reason is None
