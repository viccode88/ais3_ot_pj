from __future__ import annotations

import csv
import io
import json

from plcfp.model import PortFinding, ScanReport
from plcfp.report import render_csv, render_json, render_sarif, render_text


def _report() -> ScanReport:
    finding = PortFinding(
        port=502,
        transport="tcp",
        state="open",
        service_id="modbus-tcp",
        service_name="Modbus/TCP",
        plc_relevance="high",
        identification="confirmed",
        evidence=["valid MBAP response"],
        latency_ms=1.25,
        fuzz_eligible=True,
        alternatives=["modbus-security"],
    )
    return ScanReport(
        target="127.0.0.1",
        resolved_address="127.0.0.1",
        product=None,
        major=None,
        version_range={"min": None, "max": None},
        point_estimate=None,
        build_epoch=None,
        confidence=0,
        lifecycle="unknown",
        cpe=[],
        cpe_note="",
        evidence=[],
        conflicts=[],
        config_findings=[],
        observations=[],
        scan_profile="safe",
        max_layer=2,
        packets_sent=2,
        signature_db={},
        started_at="2026-01-01T00:00:00+00:00",
        completed_at="2026-01-01T00:00:01+00:00",
        port_findings=[finding],
        port_summary={
            "scanned": 2,
            "open": 1,
            "closed": 1,
            "unavailable": 0,
            "high_relevance_open": [502],
            "fuzz_candidates": [502],
        },
    )


def test_json_exposes_structured_port_summary() -> None:
    document = json.loads(render_json(_report()))
    assert document["port_summary"]["high_relevance_open"] == [502]
    assert document["port_findings"][0]["identification"] == "confirmed"
    assert document["port_findings"][0]["fuzz_eligible"] is True


def test_text_highlights_confirmed_plc_port() -> None:
    rendered = render_text(_report())
    assert "HIGH  502" in rendered
    assert "confirmed" in rendered
    assert "Modbus/TCP" in rendered
    assert "valid MBAP response" in rendered


def test_csv_and_sarif_keep_port_findings() -> None:
    csv_output = render_csv(_report())
    rows = list(csv.DictReader(io.StringIO(csv_output)))
    port_row = next(row for row in rows if row["record_type"] == "port")
    assert port_row["target"] == "127.0.0.1"
    assert port_row["port"] == "502"
    assert port_row["service_id"] == "modbus-tcp"
    assert port_row["service"] == "Modbus/TCP"
    assert port_row["alternatives"] == "modbus-security"
    assert port_row["latency_ms"] == "1.25"

    sarif = json.loads(render_sarif(_report()))
    port_results = [
        result for result in sarif["runs"][0]["results"] if result["ruleId"] == "PLC-RELATED-PORT"
    ]
    assert port_results[0]["properties"]["port"] == 502
    assert port_results[0]["properties"]["fuzzEligible"] is True
    assert sarif["runs"][0]["properties"]["portFindings"][0]["port"] == 502
    assert sarif["runs"][0]["properties"]["portFindings"][0]["serviceId"] == "modbus-tcp"
    assert sarif["runs"][0]["properties"]["portFindings"][0]["alternatives"] == ["modbus-security"]
    assert sarif["runs"][0]["properties"]["status"] == "complete"


def test_text_does_not_claim_passive_report_scanned_ports() -> None:
    report = _report()
    report.port_findings = []
    report.port_summary = {}

    rendered = render_text(report)

    assert "Ports: not assessed" in rendered
    assert "No open TCP ports observed" not in rendered


def test_text_keeps_long_relevance_labels_aligned() -> None:
    report = _report()
    report.port_findings[0].plc_relevance = "contextual"

    rendered = render_text(report)

    assert "CTX   502" in rendered
