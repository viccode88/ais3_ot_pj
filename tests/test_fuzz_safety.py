import json
import struct
from pathlib import Path
from typing import Self

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


HEALTH_RESPONSE = bytes.fromhex("C0DE00000005010302002A")


def test_health_check_runs_every_n_sent_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    generator = CaseGenerator(3)
    cases = [generator.generate(index, "boundary", 1, "127.0.0.1", 502) for index in range(1, 6)]
    probes: list[bytes] = []

    class RecordingTransport:
        def __init__(self, *args: object) -> None:
            pass

        def exchange(self, payload: bytes, **kwargs: object) -> TransportResult:
            if payload.startswith(b"\xc0\xde"):
                probes.append(payload)
                return TransportResult(HEALTH_RESPONSE, 0.5, "response")
            return TransportResult(None, 0.1, "sent")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", RecordingTransport)
    execute_cases(cases, timeout=1.5, interval=0, health_check_interval=2, health_unit_id=1)

    assert len(probes) == 2
    assert [case.health_after is not None for case in cases] == [False, True, False, True, False]
    assert cases[1].health_after == {
        "ok": True,
        "status": "response",
        "elapsed_ms": 0.5,
        "error": None,
    }


def test_health_check_failure_is_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    case = CaseGenerator(3).generate(1, "boundary", 1, "127.0.0.1", 502)

    class DegradedTransport:
        def __init__(self, *args: object) -> None:
            pass

        def exchange(self, payload: bytes, **kwargs: object) -> TransportResult:
            if payload.startswith(b"\xc0\xde"):
                return TransportResult(None, 1500.0, "timeout", "timed out")
            return TransportResult(None, 0.1, "sent")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", DegradedTransport)
    execute_cases([case], timeout=1.5, interval=0, health_check_interval=1)

    assert case.health_after is not None
    assert case.health_after["ok"] is False
    assert case.health_after["status"] == "timeout"


def test_blocked_cases_do_not_count_toward_health_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = [
        FuzzCase("case-blocked", 1, ["replay"], {"host": "127.0.0.1", "port": 502}, "zz", []),
        CaseGenerator(3).generate(1, "boundary", 1, "127.0.0.1", 502),
    ]
    probes = 0

    class RecordingTransport:
        def __init__(self, *args: object) -> None:
            pass

        def exchange(self, payload: bytes, **kwargs: object) -> TransportResult:
            nonlocal probes
            if payload.startswith(b"\xc0\xde"):
                probes += 1
                return TransportResult(HEALTH_RESPONSE, 0.5, "response")
            return TransportResult(None, 0.1, "sent")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", RecordingTransport)
    execute_cases(cases, timeout=1.5, interval=0, health_check_interval=1)

    assert probes == 1
    assert cases[0].health_after is None
    assert cases[1].health_after is not None and cases[1].health_after["ok"] is True


def _fc03_response(transaction_id: int) -> bytes:
    return struct.pack(">HHHB", transaction_id, 0, 5, 1) + b"\x03\x02\x00\x2a"


class FakeStream:
    """Minimal socket stand-in recording sends and replaying a fixed rx buffer."""

    def __init__(self, rx: bytes):
        self.sent: list[bytes] = []
        self._rx = bytearray(rx)

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, count: int) -> bytes:
        chunk = bytes(self._rx[:count])
        del self._rx[:count]
        return chunk

    def close(self) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


def _patch_socket(monkeypatch: pytest.MonkeyPatch, stream: FakeStream) -> None:
    monkeypatch.setattr(
        "modbus_cli.fuzzing.socket.create_connection", lambda *_args: stream
    )


def test_fragmented_send_splits_one_adu_over_one_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = CaseGenerator(5).generate(2, "fragmented-send", 1, "127.0.0.1", 502)
    assert case.send_plan is not None and case.send_plan["mode"] == "fragmented"
    stream = FakeStream(_fc03_response(2))
    _patch_socket(monkeypatch, stream)

    execute_cases([case], timeout=1.5, interval=0)

    assert b"".join(stream.sent) == bytes.fromhex(case.request_hex)
    assert len(stream.sent) == len(case.send_plan["segments"])
    assert case.status == "response"
    assert case.execution is not None and case.execution["mode"] == "fragmented"
    assert case.classification == "normal-or-exception-response"


def test_repeat_storm_sends_n_times_on_one_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = CaseGenerator(9).generate(1, "repeat-storm", 1, "127.0.0.1", 502)
    assert case.send_plan is not None and case.send_plan["mode"] == "repeat"
    count = case.send_plan["count"]
    stream = FakeStream(_fc03_response(1) * count)
    _patch_socket(monkeypatch, stream)

    execute_cases([case], timeout=1.5, interval=0)

    payload = bytes.fromhex(case.request_hex)
    assert stream.sent == [payload] * count
    assert case.execution is not None
    read_step = case.execution["steps"][-1]
    assert read_step == {"action": "read-responses", "received": count}
    assert case.status == "response"


def test_session_sequence_records_per_step_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = CaseGenerator(4).generate(3, "session-sequence", 1, "127.0.0.1", 502)
    assert case.send_plan is not None and case.send_plan["mode"] == "session"
    payloads = case.send_plan["payloads"]
    assert len(payloads) == 3 and payloads[0] == payloads[2]
    # Each payload gets a response in order.
    stream = FakeStream(_fc03_response(3) * 3)
    _patch_socket(monkeypatch, stream)

    execute_cases([case], timeout=1.5, interval=0)

    assert [bytes.fromhex(p) for p in payloads] == stream.sent
    assert case.execution is not None
    steps = case.execution["steps"]
    assert [step["response"] for step in steps] == [_fc03_response(3).hex().upper()] * 3
    assert case.status == "response"


def test_send_plan_cases_are_deterministic_and_serializable(tmp_path: Path) -> None:
    first = [CaseGenerator(11).generate(i, s, 1, "127.0.0.1", 502) for i, s in enumerate(
        ("fragmented-send", "repeat-storm", "session-sequence"), start=1
    )]
    second = [CaseGenerator(11).generate(i, s, 1, "127.0.0.1", 502) for i, s in enumerate(
        ("fragmented-send", "repeat-storm", "session-sequence"), start=1
    )]
    assert [c.send_plan for c in first] == [c.send_plan for c in second]
    output = tmp_path / "plan.json"
    save_cases(output, first)
    loaded = json.loads(output.read_text())
    assert all(case["send_plan"] for case in loaded)


def test_length_strategy_keeps_mbap_length_consistent() -> None:
    for seed in range(25):
        case = CaseGenerator(seed).generate(seed, "length", 1, "127.0.0.1", 502)
        payload = bytes.fromhex(case.request_hex)
        declared = struct.unpack(">H", payload[4:6])[0]

        assert 2 <= declared <= 254
        assert len(payload) == 6 + declared
        assert case.mutations == [f"length={declared}"]
        assert fuzz_payload_safety_reason(payload) is None


def _generated_payloads(strategy: str, count: int = 25) -> list[bytes]:
    return [
        bytes.fromhex(CaseGenerator(seed).generate(seed, strategy, 1, "127.0.0.1", 502).request_hex)
        for seed in range(count)
    ]


def _declared_length(payload: bytes) -> int:
    return struct.unpack(">H", payload[4:6])[0]


def test_protocol_id_strategy_sets_nonzero_protocol_id() -> None:
    for payload in _generated_payloads("protocol-id"):
        assert payload[2:4] != b"\x00\x00"
        assert len(payload) == 12
        assert fuzz_payload_safety_reason(payload) is None


def test_address_wrap_strategy_uses_overflowing_ranges() -> None:
    seen = set()
    for payload in _generated_payloads("address-wrap"):
        start, quantity = struct.unpack(">HH", payload[8:12])
        seen.add((start, quantity))
        assert start + quantity > 0xFFFF or (start, quantity) == (0, 0)
        assert payload[7] == 3
    assert len(seen) > 1


def test_truncated_mbap_strategy_sends_partial_header() -> None:
    lengths = set()
    for payload in _generated_payloads("truncated-mbap"):
        assert 1 <= len(payload) <= 6
        lengths.add(len(payload))
        assert fuzz_payload_safety_reason(payload) is None
    assert len(lengths) > 1


def test_concatenated_adu_strategy_appends_second_frame() -> None:
    for index, payload in enumerate(_generated_payloads("concatenated-adu")):
        base = encode_adu(3, 0, 1, transaction_id=index & 0xFFFF, unit_id=1)
        assert payload.startswith(base)
        assert len(payload) > len(base)
        assert fuzz_payload_safety_reason(payload) is None


def test_pdu_mismatch_strategy_keeps_consistent_framing() -> None:
    functions = set()
    for payload in _generated_payloads("pdu-mismatch"):
        assert len(payload) == 6 + _declared_length(payload)
        functions.add(payload[7])
        assert payload[7] in {3, 5, 15, 16}
    assert functions == {3, 5, 15, 16}


def test_exception_shape_strategy_builds_exception_shaped_requests() -> None:
    for payload in _generated_payloads("exception-shape"):
        assert len(payload) == 6 + _declared_length(payload)
        assert payload[7] & 0x80
        assert len(payload[7:]) == 2


def test_mei_subtype_strategy_stays_on_fc43_with_consistent_framing() -> None:
    meis = set()
    for payload in _generated_payloads("mei-subtype"):
        assert len(payload) == 6 + _declared_length(payload)
        assert payload[7] == 43
        if len(payload[7:]) > 1:
            meis.add(payload[8])
    assert meis


def test_rtu_over_tcp_strategy_carries_valid_crc() -> None:
    from modbus_cli.fuzzing import _crc16_modbus

    for payload in _generated_payloads("rtu-over-tcp"):
        assert len(payload) == 8
        body, crc = payload[:-2], struct.unpack("<H", payload[-2:])[0]
        assert crc == _crc16_modbus(body)
        assert body[1] == 3
        assert fuzz_payload_safety_reason(payload) is None


def test_fill_strategy_fills_unit_and_pdu_with_one_byte() -> None:
    fills = set()
    for payload in _generated_payloads("fill"):
        assert len(payload) == 12
        assert _declared_length(payload) == 6
        assert len(set(payload[6:])) == 1
        fills.add(payload[6])
    assert fills == {0x00, 0xFF}


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
