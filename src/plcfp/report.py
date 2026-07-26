from __future__ import annotations

import csv
import io
import json
from typing import Any

from plcfp.model import ScanReport


def render_text(report: ScanReport) -> str:
    """Render a compact operator view with PLC-relevant ports highlighted."""
    product = "not identified"
    if report.product:
        product = report.product + (f" {report.major}" if report.major else "")
    scanned = report.port_summary.get("scanned", len(report.port_findings))
    requested = report.port_summary.get("requested", scanned)
    scanned_label = (
        f"{scanned}/{requested} scanned" if requested != scanned else f"{scanned} scanned"
    )
    not_scanned = report.port_summary.get("not_scanned", 0)
    not_scanned_label = f", {not_scanned} not scanned" if not_scanned else ""
    lines = [
        f"Target: {report.target} ({report.resolved_address or 'unresolved'})",
        f"Product: {product}; confidence={report.confidence:.3f}; status={report.status}",
    ]
    if not report.port_summary and not report.port_findings:
        lines.extend(
            [
                "Ports: not assessed (this report contains no active TCP port-scan data)",
                "",
                "PLC port classification is unavailable for this report.",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            (
                "Ports: "
                f"{scanned_label}, "
                f"{report.port_summary.get('open', 0)} open, "
                f"{report.port_summary.get('closed', 0)} closed, "
                f"{report.port_summary.get('unavailable', 0)} unavailable"
                f"{not_scanned_label}"
            ),
            "",
            "PLC   PORT/TCP  STATE  IDENTIFICATION  FUZZ  SERVICE",
            "----  --------  -----  --------------  ----  ------------------------------",
        ]
    )
    open_findings = [finding for finding in report.port_findings if finding.state == "open"]
    if not open_findings:
        lines.append("      -         -      -               -     No open TCP ports observed")
    for finding in open_findings:
        marker = {
            "high": "HIGH",
            "medium": "MED",
            "contextual": "CTX",
            "low": "LOW",
            "unknown": "UNK",
        }.get(finding.plc_relevance, "UNK")
        fuzz = "yes" if finding.fuzz_eligible else "no"
        lines.append(
            f"{marker:<4}  {finding.port:<8}  {finding.state:<5}  "
            f"{finding.identification:<14}  {fuzz:<4}  {finding.service_name}"
        )
        if finding.evidence:
            lines.append(f"      evidence: {'; '.join(finding.evidence)}")
    lines.extend(
        [
            "",
            "HIGH marks ports strongly associated with PLC/industrial protocols.",
            "port-hint/configured is not protocol confirmation; confirmed requires probe evidence.",
        ]
    )
    return "\n".join(lines)


def render_json(report: ScanReport, *, include_raw: bool = True) -> str:
    return json.dumps(
        report.to_dict(include_raw=include_raw),
        ensure_ascii=False,
        indent=2,
        sort_keys=False,
    )


def render_csv(report: ScanReport) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=(
            "target",
            "product",
            "major",
            "version_min",
            "version_max",
            "point_estimate",
            "confidence",
            "lifecycle",
            "status",
            "probe",
            "feature",
            "weight",
            "supports",
            "record_type",
            "port",
            "transport",
            "port_state",
            "service_id",
            "service",
            "plc_relevance",
            "identification",
            "fuzz_eligible",
            "latency_ms",
            "alternatives",
            "port_evidence",
        ),
    )
    writer.writeheader()
    for finding in report.port_findings:
        writer.writerow(
            {
                "record_type": "port",
                "target": report.target,
                "product": report.product,
                "major": report.major,
                "confidence": report.confidence,
                "status": report.status,
                "port": finding.port,
                "transport": finding.transport,
                "port_state": finding.state,
                "service_id": finding.service_id,
                "service": finding.service_name,
                "plc_relevance": finding.plc_relevance,
                "identification": finding.identification,
                "fuzz_eligible": finding.fuzz_eligible,
                "latency_ms": finding.latency_ms,
                "alternatives": "; ".join(finding.alternatives),
                "port_evidence": "; ".join(finding.evidence),
            }
        )
    if report.evidence:
        for evidence in report.evidence:
            writer.writerow(
                {
                    "target": report.target,
                    "product": report.product,
                    "major": report.major,
                    "version_min": report.version_range.get("min"),
                    "version_max": report.version_range.get("max"),
                    "point_estimate": report.point_estimate,
                    "confidence": report.confidence,
                    "lifecycle": report.lifecycle,
                    "status": report.status,
                    "record_type": "evidence",
                    "probe": evidence.probe,
                    "feature": evidence.feature,
                    "weight": evidence.weight,
                    "supports": evidence.supports,
                }
            )
    else:
        writer.writerow(
            {
                "target": report.target,
                "product": report.product,
                "major": report.major,
                "version_min": report.version_range.get("min"),
                "version_max": report.version_range.get("max"),
                "point_estimate": report.point_estimate,
                "confidence": report.confidence,
                "lifecycle": report.lifecycle,
                "status": report.status,
                "record_type": "summary",
            }
        )
    return output.getvalue()


def render_sarif(report: ScanReport) -> str:
    level = "error" if report.lifecycle == "end-of-life" else "note"
    results: list[dict[str, Any]] = []
    port_properties = [
        {
            "port": finding.port,
            "transport": finding.transport,
            "state": finding.state,
            "serviceId": finding.service_id,
            "service": finding.service_name,
            "plcRelevance": finding.plc_relevance,
            "identification": finding.identification,
            "fuzzEligible": finding.fuzz_eligible,
            "latencyMs": finding.latency_ms,
            "alternatives": finding.alternatives,
            "evidence": finding.evidence,
        }
        for finding in report.port_findings
    ]
    if report.major:
        results.append(
            {
                "ruleId": f"OPENPLC-{report.major.upper()}",
                "level": level,
                "message": {
                    "text": (
                        f"{report.product} {report.major}; lifecycle={report.lifecycle}; "
                        f"confidence={report.confidence}"
                    )
                },
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": f"tcp://{report.target}"}}}
                ],
                "properties": {
                    "versionRange": report.version_range,
                    "pointEstimate": report.point_estimate,
                    "ports": port_properties,
                    "evidence": [
                        {
                            "probe": evidence.probe,
                            "weight": evidence.weight,
                            "supports": evidence.supports,
                        }
                        for evidence in report.evidence
                    ],
                },
            }
        )
    for finding in report.port_findings:
        if finding.state != "open" or finding.plc_relevance != "high":
            continue
        results.append(
            {
                "ruleId": "PLC-RELATED-PORT",
                "level": "note",
                "message": {
                    "text": (
                        f"{finding.port}/tcp open: {finding.service_name}; "
                        f"identification={finding.identification}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"tcp://{report.target}:{finding.port}"}
                        }
                    }
                ],
                "properties": {
                    "port": finding.port,
                    "transport": finding.transport,
                    "serviceId": finding.service_id,
                    "service": finding.service_name,
                    "plcRelevance": finding.plc_relevance,
                    "identification": finding.identification,
                    "fuzzEligible": finding.fuzz_eligible,
                    "latencyMs": finding.latency_ms,
                    "alternatives": finding.alternatives,
                    "evidence": finding.evidence,
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "plcfp",
                        "informationUri": "https://github.com/viccode88/ais3_ot_pj",
                        "rules": [],
                    }
                },
                "properties": {
                    "status": report.status,
                    "portSummary": report.port_summary,
                    "portFindings": port_properties,
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2)
