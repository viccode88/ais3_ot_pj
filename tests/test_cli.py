import json
import struct
from pathlib import Path

import pytest

from modbus_cli.cli import main
from modbus_cli.transport import TransportResult


def test_build_json(capsys: object) -> None:
    assert (
        main(["build", "--function", "3", "--address", "0", "--quantity", "10", "--output", "json"])
        == 0
    )
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output["hex"] == "00010000000601030000000A"


def test_decode_invalid_hex(capsys: object) -> None:
    assert main(["decode", "--hex", "zz"]) == 2
    assert "error:" in capsys.readouterr().err  # type: ignore[attr-defined]


def test_write_dry_run(capsys: object) -> None:
    code = main(
        [
            "write",
            "single-register",
            "--target",
            "127.0.0.1",
            "--address",
            "1",
            "--values",
            "12",
            "--dry-run",
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True  # type: ignore[attr-defined]


def test_offline_fuzz(tmp_path: Path, capsys: object) -> None:
    output = tmp_path / "cases.json"
    assert main(["fuzz", "--target", "127.0.0.1", "--requests", "2", "--output", str(output)]) == 0
    assert len(json.loads(output.read_text())) == 2
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert json.loads(captured.out)["executed"] is False
    assert captured.err == ""


def test_fuzz_interval_is_reported(tmp_path: Path, capsys: object) -> None:
    output = tmp_path / "cases.json"
    assert (
        main(
            [
                "fuzz",
                "--target",
                "127.0.0.1",
                "--requests",
                "1",
                "--interval",
                "0.5",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["interval"] == 0.5  # type: ignore[attr-defined]


def test_fuzz_rejects_non_positive_interval(capsys: object) -> None:
    assert main(["fuzz", "--target", "127.0.0.1", "--interval", "0"]) == 2
    assert "interval must be > 0" in capsys.readouterr().err  # type: ignore[attr-defined]


@pytest.mark.parametrize("option,value", (("--port", "0"), ("--timeout", "0")))
def test_fuzz_rejects_invalid_transport_options(option: str, value: str, capsys: object) -> None:
    assert main(["fuzz", "--target", "127.0.0.1", option, value]) == 2
    assert "invalid port or timeout" in capsys.readouterr().err  # type: ignore[attr-defined]


def test_fuzz_execute_reports_actual_request_and_response_types(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeTransport:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert (host, port, timeout) == ("127.0.0.1", 502, 1.5)

        def exchange(self, payload: bytes) -> TransportResult:
            transaction_id = struct.unpack(">H", payload[:2])[0]
            response_pdu = bytes((0x84, 0x02))
            response = (
                struct.pack(">HHHB", transaction_id, 0, len(response_pdu) + 1, payload[6])
                + response_pdu
            )
            return TransportResult(response, 1.25, "response")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", FakeTransport)
    report = tmp_path / "executed.json"
    assert (
        main(
            [
                "fuzz",
                "--target",
                "127.0.0.1",
                "--requests",
                "1",
                "--output",
                str(report),
                "--execute",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert json.loads(captured.out)["executed"] is True
    assert "[case-000001] TX request-type=read-holding-registers (FC 0x03)" in captured.err
    assert "target=127.0.0.1:502; strategy=boundary" in captured.err
    assert (
        "[case-000001] RX response-type=exception-response/read-input-registers "
        "(FC 0x84, exception=illegal-data-address 0x02)" in captured.err
    )
    assert (
        "status=response; elapsed_ms=1.250; "
        "classification=normal-or-exception-response" in captured.err
    )


def test_fuzz_execute_reports_when_target_returns_no_packet(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    class TimeoutTransport:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            pass

        def exchange(self, payload: bytes) -> TransportResult:
            return TransportResult(None, 1500.0, "timeout", "timed out")

    monkeypatch.setattr("modbus_cli.fuzzing.TCPTransport", TimeoutTransport)
    report = tmp_path / "timeout.json"
    assert (
        main(
            [
                "fuzz",
                "--target",
                "127.0.0.1",
                "--requests",
                "1",
                "--strategy",
                "function-code",
                "--output",
                str(report),
                "--execute",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert json.loads(captured.out)["executed"] is True
    assert "TX request-type=unknown (FC 0x07)" in captured.err
    assert "RX response-type=no-packet; status=timeout; elapsed_ms=1500.000" in captured.err
    assert "classification=possible-service-degradation" in captured.err
