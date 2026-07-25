from __future__ import annotations

import csv
import io
import json
from typing import Any

from plcfp.model import ScanReport


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
        ),
    )
    writer.writeheader()
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
            }
        )
    return output.getvalue()


def render_sarif(report: ScanReport) -> str:
    level = "error" if report.lifecycle == "end-of-life" else "note"
    results: list[dict[str, Any]] = []
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
                "results": results,
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2)
