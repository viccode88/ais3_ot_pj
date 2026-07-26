import json
from pathlib import Path

import pytest

from modbus_cli.exceptions import SafetyPolicyError
from modbus_cli.fuzzing import (
    STRATEGIES,
    CaseGenerator,
    FuzzCase,
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


def test_seed_17_33rd_random_case_blocks_fc06_before_transport(
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

    assert transport_calls == []
    assert case.sent_at is None
    assert case.status == "blocked"
    assert case.classification == "blocked-by-safety-policy"
    assert case.safety_reason is not None
    assert "0x06" in case.safety_reason

    output = tmp_path / "blocked-report.json"
    save_cases(output, [case])
    report_case = json.loads(output.read_text())[0]
    assert report_case["status"] == "blocked"
    assert report_case["classification"] == "blocked-by-safety-policy"
    assert "0x06" in report_case["safety_reason"]


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


def test_concatenated_read_and_write_adus_are_blocked_before_transport(
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
    transport_calls: list[object] = []
    monkeypatch.setattr(
        "modbus_cli.fuzzing.TCPTransport",
        lambda *_args, **_kwargs: transport_calls.append(object()),
    )

    execute_cases([case], timeout=1.5, interval=0)

    assert transport_calls == []
    assert case.status == "blocked"
    assert case.safety_reason is not None
    assert "concatenated" in case.safety_reason


def test_fc43_allows_only_read_device_identification_mei() -> None:
    read_device_id = bytes.fromhex("000100000005012B0E0100")
    canopen_write_capable_mei = bytes.fromhex("000100000004012B0D00")

    assert fuzz_payload_safety_reason(read_device_id) is None
    reason = fuzz_payload_safety_reason(canopen_write_capable_mei)
    assert reason is not None
    assert "MEI 0x0E" in reason


@pytest.mark.parametrize(
    "payload",
    (
        bytes.fromhex("000100010006010300000001"),
        bytes.fromhex("000100000005010300000001"),
        bytes.fromhex("00010000000601030000"),
    ),
)
def test_invalid_mbap_framing_is_blocked(payload: bytes) -> None:
    assert fuzz_payload_safety_reason(payload) is not None
