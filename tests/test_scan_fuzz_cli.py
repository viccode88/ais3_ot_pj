from __future__ import annotations

import json
from pathlib import Path

import pytest

from modbus_cli.cli import main
from plcfp.model import Observation, PortFinding, ScanReport


def _scan_report() -> ScanReport:
    finding = PortFinding(
        port=1502,
        transport="tcp",
        state="open",
        service_id="modbus-tcp",
        service_name="Modbus/TCP (configured port)",
        plc_relevance="high",
        identification="confirmed",
        evidence=["valid MBAP response"],
        latency_ms=0.5,
        fuzz_eligible=True,
    )
    return ScanReport(
        target="127.0.0.1",
        resolved_address="127.0.0.1",
        product="OpenPLC Runtime",
        major="v3",
        version_range={"min": None, "max": None},
        point_estimate=None,
        build_epoch=None,
        confidence=0.9,
        lifecycle="end-of-life",
        cpe=[],
        cpe_note="",
        evidence=[],
        conflicts=[],
        config_findings=[],
        observations=[
            Observation(
                probe_id="modbus.fc43.device_id",
                feature="modbus.fc43.device_identification",
                value={"protocol_valid": True},
                metadata={
                    "port": 1502,
                    "transport": "tcp",
                    "service_id": "modbus-tcp",
                    "protocol_valid": True,
                },
            )
        ],
        scan_profile="safe",
        max_layer=2,
        packets_sent=3,
        signature_db={},
        started_at="2026-01-01T00:00:00+00:00",
        completed_at="2026-01-01T00:00:01+00:00",
        port_findings=[finding],
        port_summary={
            "scan_complete": True,
            "scanned": 2,
            "open": 1,
            "closed": 1,
            "unavailable": 0,
            "high_relevance_open": [1502],
            "fuzz_candidates": [1502],
        },
    )


def test_unified_scan_command_renders_clear_text(
    capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("modbus_cli.cli.scan_target", lambda _target, _options: _scan_report())
    assert main(["scan", "--target", "127.0.0.1", "--format", "text"]) == 0
    output = capsys.readouterr().out  # type: ignore[attr-defined]
    assert "HIGH  1502" in output
    assert "Modbus/TCP (configured port)" in output


def test_unified_scan_writes_fuzz_compatible_json(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("modbus_cli.cli.scan_target", lambda _target, _options: _scan_report())
    output = tmp_path / "scan.json"
    assert (
        main(
            [
                "scan",
                "--target",
                "127.0.0.1",
                "--output",
                str(output),
                "--no-raw",
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["port_findings"][0]["fuzz_eligible"] is True
    summary = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert summary["port_summary"]["fuzz_candidates"] == [1502]


def test_unified_scan_returns_incomplete_status_exit_code(
    capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _scan_report()
    report.status = "BUDGET_EXCEEDED"
    monkeypatch.setattr("modbus_cli.cli.scan_target", lambda _target, _options: report)

    assert main(["scan", "--target", "127.0.0.1"]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "BUDGET_EXCEEDED"  # type: ignore[attr-defined]


def test_fuzz_uses_confirmed_port_from_scan_report(tmp_path: Path, capsys: object) -> None:
    scan_report = tmp_path / "scan.json"
    scan_report.write_text(json.dumps(_scan_report().to_dict()))
    fuzz_report = tmp_path / "fuzz.json"

    assert (
        main(
            [
                "fuzz",
                "--scan-report",
                str(scan_report),
                "--requests",
                "1",
                "--output",
                str(fuzz_report),
            ]
        )
        == 0
    )

    cases = json.loads(fuzz_report.read_text())
    assert cases[0]["target"] == {"host": "127.0.0.1", "port": 1502}
    summary = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert summary["executed"] is False
    assert summary["target"] == {
        "host": "127.0.0.1",
        "port": 1502,
        "source": "scan-report",
    }


def test_report_execute_paces_first_case_after_preflight(
    tmp_path: Path, capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_report = tmp_path / "scan.json"
    scan_report.write_text(json.dumps(_scan_report().to_dict()))
    fuzz_report = tmp_path / "fuzz.json"
    events: list[object] = []

    monkeypatch.setattr(
        "modbus_cli.cli.verify_modbus_endpoint",
        lambda target, timeout, unit_id: events.append(
            ("preflight", target.port, timeout, unit_id)
        ),
    )
    monkeypatch.setattr(
        "modbus_cli.cli.time.sleep", lambda interval: events.append(("sleep", interval))
    )

    def fake_execute(_cases: object, _timeout: float, interval: float, _progress: object) -> None:
        events.append(("execute", interval))

    monkeypatch.setattr("modbus_cli.cli.execute_cases", fake_execute)

    assert (
        main(
            [
                "fuzz",
                "--scan-report",
                str(scan_report),
                "--requests",
                "1",
                "--interval",
                "0.25",
                "--output",
                str(fuzz_report),
                "--execute",
            ]
        )
        == 0
    )

    assert events == [
        ("preflight", 1502, 1.5, 1),
        ("sleep", 0.25),
        ("execute", 0.25),
    ]
    assert json.loads(capsys.readouterr().out)["preflight_verified"] is True  # type: ignore[attr-defined]
