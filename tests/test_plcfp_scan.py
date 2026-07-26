from __future__ import annotations

import socket

import pytest

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget
from plcfp.scan import ScanOptions, scan_target
from plcfp.scheduler import ProbeScheduler, ScanProfile


def test_scan_tags_custom_modbus_probe_and_builds_fuzz_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = ResolvedTarget("lab-plc", "127.0.0.1", socket.AF_INET)
    monkeypatch.setattr("plcfp.scan.resolve_target", lambda *_args, **_kwargs: target)

    def fake_ports(
        _target: ResolvedTarget, _scheduler: object, ports: tuple[int, ...]
    ) -> list[Observation]:
        observations = []
        for port in ports:
            is_open = port in {22, 1502}
            observations.append(
                Observation(
                    probe_id=f"network.tcp.{port}",
                    feature=f"tcp.port.{port}.open",
                    value=is_open,
                    state=ProbeState.OBSERVED if is_open else ProbeState.ABSENT,
                    latency_ms=0.25,
                    metadata={"port": port, "transport": "tcp"},
                )
            )
        return observations

    monkeypatch.setattr("plcfp.scan.probe_tcp_ports", fake_ports)
    monkeypatch.setattr(
        "plcfp.scan.probe_modbus",
        lambda *_args, **_kwargs: [
            Observation(
                probe_id="modbus.fc43.device_id",
                feature="modbus.fc43.device_identification",
                raw=b"validated MBAP response",
                metadata={"protocol_valid": True},
            )
        ],
    )

    report = scan_target(
        "lab-plc",
        ScanOptions(
            profile=ScanProfile.SAFE,
            max_layer=2,
            interval=0,
            modbus_port=1502,
            additional_ports=(65000,),
        ),
    )

    findings = {finding.port: finding for finding in report.port_findings}
    assert findings[1502].identification == "confirmed"
    assert findings[1502].fuzz_eligible is True
    assert findings[22].service_id == "ssh"
    assert findings[22].plc_relevance == "low"
    assert findings[65000].service_id == "unknown"
    assert report.port_summary["fuzz_candidates"] == [1502]

    modbus_observation = next(
        observation
        for observation in report.observations
        if observation.probe_id.startswith("modbus.")
    )
    assert modbus_observation.metadata == {
        "port": 1502,
        "transport": "tcp",
        "service_id": "modbus-tcp",
        "protocol_valid": True,
    }


def test_port_results_survive_a_partial_scan_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = ResolvedTarget("lab-plc", "127.0.0.1", socket.AF_INET)
    monkeypatch.setattr("plcfp.scan.resolve_target", lambda *_args, **_kwargs: target)

    def budgeted_port(
        _target: ResolvedTarget, scheduler: ProbeScheduler, ports: tuple[int, ...]
    ) -> list[Observation]:
        port = ports[0]
        scheduler.run(lambda: None)
        return [
            Observation(
                probe_id=f"network.tcp.{port}",
                feature=f"tcp.port.{port}.open",
                value=False,
                state=ProbeState.ABSENT,
                metadata={"port": port, "transport": "tcp"},
            )
        ]

    monkeypatch.setattr("plcfp.scan.probe_tcp_ports", budgeted_port)
    report = scan_target(
        "lab-plc",
        ScanOptions(
            profile=ScanProfile.SAFE,
            max_layer=1,
            interval=0,
            packet_budget=2,
        ),
    )

    assert report.status == "BUDGET_EXCEEDED"
    assert report.port_summary["requested"] == len(ScanOptions().ports)
    assert report.port_summary["scanned"] == 2
    assert report.port_summary["not_scanned"] == len(ScanOptions().ports) - 2
    assert report.port_summary["unavailable"] == 0
    assert len(report.port_findings) == len(ScanOptions().ports)
    not_scanned_findings = [
        finding for finding in report.port_findings if finding.state == "not-scanned"
    ]
    assert len(not_scanned_findings) == len(ScanOptions().ports) - 2
    assert all(
        finding.evidence == [f"not-scanned: TCP/{finding.port} was not probed"]
        or finding.evidence[0] == f"not-scanned: TCP/{finding.port} was not probed"
        for finding in not_scanned_findings
    )
    skipped = [
        observation
        for observation in report.observations
        if observation.state == ProbeState.SKIPPED and observation.feature.startswith("tcp.port.")
    ]
    assert len(skipped) == len(ScanOptions().ports) - 2


def test_explicit_role_and_additional_ports_are_scanned_before_catalog_defaults() -> None:
    options = ScanOptions(
        modbus_port=1502,
        v3_http_port=18080,
        v4_https_port=18443,
        enip_port=14418,
        dnp3_port=12000,
        opcua_port=14840,
        additional_ports=(65000,),
    )

    assert options.ports[:7] == (1502, 18080, 18443, 14418, 12000, 14840, 65000)
