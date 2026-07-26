import json
from pathlib import Path

import pytest

from modbus_cli.exceptions import ConfigurationError, SafetyPolicyError
from modbus_cli.transport import TransportResult
from modbus_cli.workflow import ScanTarget, load_scan_target, verify_modbus_endpoint


def _finding(port: object = 502, **overrides: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "port": port,
        "state": "open",
        "service_id": "modbus-tcp",
        "identification": "confirmed",
        "fuzz_eligible": True,
    }
    finding.update(overrides)
    return finding


def _write_report(
    path: Path,
    *,
    resolved_address: object = "127.0.0.1",
    port_findings: object = None,
    **overrides: object,
) -> Path:
    report: dict[str, object] = {
        "target": "plc-lab.local",
        "resolved_address": resolved_address,
        "status": "complete",
        "port_summary": {"scan_complete": True},
        "port_findings": [_finding()] if port_findings is None else port_findings,
        "observations": [
            {
                "probe_id": "modbus.fc43.device_id",
                "feature": "modbus.fc43.device_identification",
                "state": "observed",
                "metadata": {
                    "port": finding["port"],
                    "transport": "tcp",
                    "service_id": "modbus-tcp",
                    "protocol_valid": True,
                },
            }
            for finding in ([_finding()] if port_findings is None else port_findings)
            if isinstance(finding, dict)
            and finding.get("service_id") == "modbus-tcp"
            and isinstance(finding.get("port"), int)
            and not isinstance(finding.get("port"), bool)
        ],
    }
    report.update(overrides)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_loads_unique_confirmed_modbus_target(tmp_path: Path) -> None:
    path = _write_report(tmp_path / "scan.json")

    assert load_scan_target(path) == ScanTarget(
        host="127.0.0.1",
        port=502,
        report_target="plc-lab.local",
    )


def test_rejects_report_without_eligible_port(tmp_path: Path) -> None:
    path = _write_report(
        tmp_path / "scan.json",
        port_findings=[
            _finding(state="closed"),
            _finding(1502, identification="probable"),
            _finding(2502, service_id="unknown"),
            _finding(3502, fuzz_eligible=False),
        ],
    )

    with pytest.raises(ConfigurationError, match="no open, confirmed, fuzz-eligible"):
        load_scan_target(path)


def test_rejects_multiple_ports_without_selection(tmp_path: Path) -> None:
    path = _write_report(
        tmp_path / "scan.json",
        port_findings=[_finding(502), _finding(1502)],
    )

    with pytest.raises(ConfigurationError, match="multiple eligible.*requested_port is required"):
        load_scan_target(path)


def test_requested_port_selects_matching_eligible_candidate(tmp_path: Path) -> None:
    path = _write_report(
        tmp_path / "scan.json",
        port_findings=[_finding(502), _finding(1502)],
    )

    assert load_scan_target(path, requested_port=1502).port == 1502
    with pytest.raises(
        ConfigurationError, match="requested_port 2502 is not an eligible candidate"
    ):
        load_scan_target(path, requested_port=2502)


@pytest.mark.parametrize("port", [0, 65536, True])
def test_rejects_invalid_candidate_port(tmp_path: Path, port: object) -> None:
    path = _write_report(tmp_path / "scan.json", port_findings=[_finding(port)])

    with pytest.raises(ConfigurationError, match=r"port_findings\[0\]\.port.*1\.\.65535"):
        load_scan_target(path)


@pytest.mark.parametrize("port", [0, 65536, True])
def test_rejects_invalid_requested_port(tmp_path: Path, port: int) -> None:
    path = _write_report(tmp_path / "scan.json")

    with pytest.raises(ConfigurationError, match=r"requested_port.*1\.\.65535"):
        load_scan_target(path, requested_port=port)


def test_revalidates_and_rejects_public_resolved_address(tmp_path: Path) -> None:
    path = _write_report(tmp_path / "scan.json", resolved_address="8.8.8.8")

    with pytest.raises(SafetyPolicyError, match="outside allowed laboratory networks"):
        load_scan_target(path)


@pytest.mark.parametrize("contents", ["{", "[]"])
def test_rejects_bad_json_or_non_object(tmp_path: Path, contents: str) -> None:
    path = tmp_path / "scan.json"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(ConfigurationError, match="invalid scan report"):
        load_scan_target(path)


@pytest.mark.parametrize(
    "report, message",
    [
        ({"port_findings": []}, "resolved_address"),
        ({"resolved_address": "127.0.0.1"}, "port_findings"),
        (
            {
                "resolved_address": "127.0.0.1",
                "port_findings": [_finding()],
                "status": "BUDGET_EXCEEDED",
            },
            "BUDGET_EXCEEDED",
        ),
    ],
)
def test_rejects_incomplete_report(tmp_path: Path, report: dict[str, object], message: str) -> None:
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ConfigurationError, match=message):
        load_scan_target(path)


@pytest.mark.parametrize("status", ["complete", "CONFLICT", "INCONCLUSIVE", "FORKED"])
def test_accepts_classification_status_when_scan_execution_is_complete(
    tmp_path: Path, status: object
) -> None:
    path = _write_report(tmp_path / "scan.json", status=status)

    assert load_scan_target(path).port == 502


@pytest.mark.parametrize("status", [None, "unknown", "running"])
def test_rejects_unknown_or_missing_classification_status(tmp_path: Path, status: object) -> None:
    path = _write_report(tmp_path / "scan.json", status=status)

    with pytest.raises(ConfigurationError, match="unknown or missing"):
        load_scan_target(path)


@pytest.mark.parametrize("summary", [None, {}, {"scan_complete": False}])
def test_rejects_unknown_or_incomplete_scan_execution(tmp_path: Path, summary: object) -> None:
    path = _write_report(tmp_path / "scan.json", port_summary=summary)

    with pytest.raises(ConfigurationError, match="scan_complete"):
        load_scan_target(path)


def test_rejects_self_asserted_finding_without_protocol_valid_observation(
    tmp_path: Path,
) -> None:
    path = _write_report(tmp_path / "scan.json", observations=[])

    with pytest.raises(ConfigurationError, match="no open, confirmed, fuzz-eligible"):
        load_scan_target(path)


@pytest.mark.parametrize("transport", [None, "udp"])
def test_rejects_modbus_confirmation_not_bound_to_tcp(tmp_path: Path, transport: object) -> None:
    observation = {
        "probe_id": "modbus.fc43.device_id",
        "feature": "modbus.fc43.device_identification",
        "state": "observed",
        "metadata": {
            "port": 502,
            "transport": transport,
            "service_id": "modbus-tcp",
            "protocol_valid": True,
        },
    }
    path = _write_report(tmp_path / "scan.json", observations=[observation])

    with pytest.raises(ConfigurationError, match="no open, confirmed, fuzz-eligible"):
        load_scan_target(path)


def test_verify_modbus_endpoint_rejects_echo_and_accepts_correlated_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = ScanTarget("127.0.0.1", 502, "plc-lab.local")
    responses = [
        bytes.fromhex("C0DE00000006010300000001"),
        bytes.fromhex("C0DE000000050103020001"),
    ]

    class FakeTransport:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert (host, port, timeout) == ("127.0.0.1", 502, 1.5)

        def exchange(self, _payload: bytes) -> TransportResult:
            return TransportResult(responses.pop(0), 0.1, "response")

    monkeypatch.setattr("modbus_cli.workflow.TCPTransport", FakeTransport)
    with pytest.raises(ConfigurationError, match="preflight failed"):
        verify_modbus_endpoint(target, 1.5)
    verify_modbus_endpoint(target, 1.5)


def test_verify_modbus_endpoint_uses_requested_unit_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = ScanTarget("127.0.0.1", 502, "plc-lab.local")

    class FakeTransport:
        def __init__(self, _host: str, _port: int, _timeout: float) -> None:
            pass

        def exchange(self, payload: bytes) -> TransportResult:
            assert payload[6] == 247
            response = bytes.fromhex("C0DE00000005F703020001")
            return TransportResult(response, 0.1, "response")

    monkeypatch.setattr("modbus_cli.workflow.TCPTransport", FakeTransport)
    verify_modbus_endpoint(target, 1.5, unit_id=247)


def test_verify_modbus_endpoint_accepts_fc03_exception_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = ScanTarget("127.0.0.1", 502, "plc-lab.local")

    class FakeTransport:
        def __init__(self, _host: str, _port: int, _timeout: float) -> None:
            pass

        def exchange(self, _payload: bytes) -> TransportResult:
            return TransportResult(bytes.fromhex("C0DE00000003018302"), 0.1, "response")

    monkeypatch.setattr("modbus_cli.workflow.TCPTransport", FakeTransport)
    verify_modbus_endpoint(target, 1.5)
