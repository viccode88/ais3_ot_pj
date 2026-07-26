from __future__ import annotations

import pytest

from plcfp.model import Observation, PortFinding, ProbeState, ScanReport
from plcfp.port_services import (
    DEFAULT_DISCOVERY_TCP_PORTS,
    build_port_findings,
    parse_port_spec,
)


def _tcp_port(
    port: int,
    *,
    value: bool | None = True,
    state: ProbeState = ProbeState.OBSERVED,
    latency_ms: float | None = 1.25,
) -> Observation:
    return Observation(
        probe_id=f"network.tcp.{port}",
        feature=f"tcp.port.{port}.open",
        value=value,
        state=state,
        latency_ms=latency_ms,
    )


def _finding(findings: list[PortFinding], port: int) -> PortFinding:
    return next(item for item in findings if item.port == port)


def test_default_discovery_catalog_covers_common_plc_ports() -> None:
    assert set(DEFAULT_DISCOVERY_TCP_PORTS) == {
        22,
        80,
        102,
        443,
        502,
        802,
        1217,
        1883,
        1962,
        2404,
        2455,
        4840,
        4843,
        5094,
        8080,
        8443,
        9600,
        11740,
        18245,
        20000,
        44818,
    }


def test_parse_port_spec_supports_ranges_deduplication_and_boundaries() -> None:
    assert parse_port_spec("1, 502,500-503,65535") == (1, 502, 500, 501, 503, 65535)


@pytest.mark.parametrize(
    "spec",
    [
        "",
        " ",
        "0",
        "65536",
        "100-90",
        "22,",
        ",22",
        "22,,80",
        "one",
        "22-23-24",
        "-1",
    ],
)
def test_parse_port_spec_rejects_invalid_input(spec: str) -> None:
    with pytest.raises(ValueError):
        parse_port_spec(spec)


def test_parse_port_spec_rejects_too_many_unique_ports() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        parse_port_spec("1-4,2", max_ports=3)


def test_catalog_port_is_only_a_hint_and_unknown_port_remains_unknown() -> None:
    findings = build_port_findings([_tcp_port(502), _tcp_port(65000)], {})

    modbus = _finding(findings, 502)
    assert modbus.service_id == "modbus-tcp"
    assert modbus.identification == "port-hint"
    assert modbus.plc_relevance == "high"
    assert not modbus.fuzz_eligible

    unknown = _finding(findings, 65000)
    assert unknown.service_id == "unknown"
    assert unknown.identification == "unknown"
    assert unknown.plc_relevance == "unknown"


def test_bound_modbus_active_evidence_confirms_and_enables_fuzzing() -> None:
    observations = [
        _tcp_port(1502, latency_ms=2.5),
        Observation(
            "modbus.unit_ids",
            "modbus.unit_id.response_matrix",
            value={"1": {"responded": True}},
            metadata={
                "port": 1502,
                "transport": "tcp",
                "service_id": "modbus-tcp",
                "protocol_valid": True,
            },
        ),
    ]

    finding = build_port_findings(observations, {"modbus-tcp": 1502})[0]

    assert finding.port == 1502
    assert finding.state == "open"
    assert finding.identification == "confirmed"
    assert finding.fuzz_eligible
    assert finding.latency_ms == 2.5
    assert any(item.startswith("active-confirmation:") for item in finding.evidence)


def test_active_evidence_without_endpoint_metadata_does_not_confirm() -> None:
    observations = [
        _tcp_port(502),
        Observation(
            "modbus.fc43.device_id",
            "modbus.fc43.device_identification",
            raw=b"parsed Modbus response",
        ),
    ]

    finding = build_port_findings(observations, {"modbus-tcp": 502})[0]

    assert finding.identification == "configured"
    assert not finding.fuzz_eligible


def test_mismatched_metadata_cannot_confirm_another_port() -> None:
    observations = [
        _tcp_port(502),
        _tcp_port(1502),
        Observation(
            "modbus.fc43.device_id",
            "modbus.fc43.device_identification",
            raw=b"parsed Modbus response",
            metadata={
                "port": 1502,
                "transport": "tcp",
                "service_id": "modbus-tcp",
                "protocol_valid": True,
            },
        ),
    ]

    findings = build_port_findings(observations, {"modbus-tcp": 1502})

    assert _finding(findings, 1502).identification == "confirmed"
    assert _finding(findings, 502).identification == "port-hint"


@pytest.mark.parametrize(
    ("service_id", "port", "probe_id", "feature"),
    [
        ("ethernet-ip", 44818, "enip.register_session", "enip.register_session"),
        ("opc-ua", 4840, "opcua.hello", "opcua.hello_ack"),
    ],
)
def test_enip_and_opcua_require_correlated_raw_active_evidence(
    service_id: str, port: int, probe_id: str, feature: str
) -> None:
    base = [_tcp_port(port)]
    empty = Observation(
        probe_id,
        feature,
        value={"responded": True},
        metadata={
            "port": port,
            "transport": "tcp",
            "service_id": service_id,
            "protocol_valid": True,
        },
    )
    unvalidated_raw = Observation(
        probe_id,
        feature,
        raw=b"validated response",
        metadata={"port": port, "transport": "tcp", "service_id": service_id},
    )
    validated_raw = Observation(
        probe_id,
        feature,
        raw=b"validated response",
        metadata={
            "port": port,
            "transport": "tcp",
            "service_id": service_id,
            "protocol_valid": True,
        },
    )

    assert build_port_findings([*base, empty], {service_id: port})[0].identification == (
        "configured"
    )
    assert (
        build_port_findings([*base, unvalidated_raw], {service_id: port})[0].identification
        == "configured"
    )
    assert (
        build_port_findings([*base, validated_raw], {service_id: port})[0].identification
        == "confirmed"
    )


def test_dnp3_requires_a_valid_start_marker() -> None:
    invalid = Observation(
        "dnp3.link_status",
        "dnp3.link_status_response",
        value={"responded": True, "valid_start": False},
        metadata={
            "port": 20000,
            "transport": "tcp",
            "service_id": "dnp3",
            "protocol_valid": True,
        },
    )
    valid = Observation(
        "dnp3.link_status",
        "dnp3.link_status_response",
        value={"responded": True, "valid_start": True},
        metadata={
            "port": 20000,
            "transport": "tcp",
            "service_id": "dnp3",
            "protocol_valid": True,
        },
    )

    assert (
        build_port_findings([_tcp_port(20000), invalid], {"dnp3": 20000})[0].identification
        == "configured"
    )
    assert (
        build_port_findings([_tcp_port(20000), valid], {"dnp3": 20000})[0].identification
        == "confirmed"
    )


def test_openplc_web_port_requires_matching_detected_major() -> None:
    active = Observation(
        "http.v3.login",
        "http.v3.login",
        value={"status": 200, "mentions_openplc": True},
        metadata={"port": 8080, "transport": "tcp", "service_id": "openplc-v3-http"},
    )

    without_major = build_port_findings([_tcp_port(8080), active], {"openplc-v3-http": 8080})[0]
    with_major = build_port_findings(
        [_tcp_port(8080), active],
        {"openplc-v3-http": 8080},
        detected_major="v3",
    )[0]

    assert without_major.identification == "configured"
    assert without_major.plc_relevance == "contextual"
    assert with_major.identification == "confirmed"
    assert with_major.plc_relevance == "high"
    assert not with_major.fuzz_eligible


def test_detected_major_does_not_confirm_a_generic_web_response() -> None:
    generic = Observation(
        "http.v3.root",
        "http.v3.root",
        value={"status": 200},
        raw=b"generic web page",
        metadata={"port": 8080, "transport": "tcp", "service_id": "openplc-v3-http"},
    )

    finding = build_port_findings(
        [_tcp_port(8080), generic],
        {"openplc-v3-http": 8080},
        detected_major="v3",
    )[0]

    assert finding.identification == "configured"
    assert finding.plc_relevance == "contextual"


def test_findings_sort_open_high_confirmed_before_other_results() -> None:
    observations = [
        _tcp_port(80),
        _tcp_port(502),
        _tcp_port(102, value=False, state=ProbeState.ABSENT),
        _tcp_port(65000, value=None, state=ProbeState.UNAVAILABLE),
        Observation(
            "modbus.fc43.device_id",
            "modbus.fc43.device_identification",
            raw=b"validated response",
            metadata={
                "port": 502,
                "transport": "tcp",
                "service_id": "modbus-tcp",
                "protocol_valid": True,
            },
        ),
    ]

    findings = build_port_findings(observations, {"modbus-tcp": 502})

    assert [finding.port for finding in findings] == [502, 80, 102, 65000]


def test_scan_report_serializes_port_findings_and_uses_isolated_defaults() -> None:
    report = ScanReport(
        target="192.0.2.1",
        resolved_address="192.0.2.1",
        product=None,
        major=None,
        version_range={"min": None, "max": None},
        point_estimate=None,
        build_epoch=None,
        confidence=0.0,
        lifecycle="unknown",
        cpe=[],
        cpe_note="",
        evidence=[],
        conflicts=[],
        config_findings=[],
        observations=[],
        scan_profile="safe",
        max_layer=1,
        packets_sent=0,
        signature_db={},
        started_at="2026-01-01T00:00:00+00:00",
        completed_at="2026-01-01T00:00:01+00:00",
        port_findings=[
            PortFinding(
                port=502,
                transport="tcp",
                state="open",
                service_id="modbus-tcp",
                service_name="Modbus/TCP",
                plc_relevance="high",
                identification="confirmed",
                evidence=["active probe"],
                latency_ms=1.0,
                fuzz_eligible=True,
            )
        ],
        port_summary={"open": 1},
    )

    serialized = report.to_dict()
    assert serialized["port_findings"][0]["service_id"] == "modbus-tcp"
    assert serialized["port_findings"][0]["alternatives"] == []
    assert serialized["port_summary"] == {"open": 1}

    other = ScanReport(
        target="192.0.2.2",
        resolved_address=None,
        product=None,
        major=None,
        version_range={},
        point_estimate=None,
        build_epoch=None,
        confidence=0.0,
        lifecycle="unknown",
        cpe=[],
        cpe_note="",
        evidence=[],
        conflicts=[],
        config_findings=[],
        observations=[],
        scan_profile="safe",
        max_layer=1,
        packets_sent=0,
        signature_db={},
        started_at="",
        completed_at="",
    )
    assert other.port_findings == []
    assert other.port_summary == {}
