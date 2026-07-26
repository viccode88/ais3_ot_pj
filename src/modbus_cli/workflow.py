"""Safe hand-off from a PLC scan report to a Modbus fuzz target."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .exceptions import ConfigurationError
from .safety import SafetyPolicy
from .transport import TCPTransport


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """A fuzz target selected from confirmed scan evidence."""

    host: str
    port: int
    report_target: str | None
    source: str = "scan-report"


def _report_error(path: Path, message: str) -> ConfigurationError:
    return ConfigurationError(f"invalid scan report {path}: {message}")


def _validate_port(path: Path, port: object, *, field: str) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise _report_error(path, f"{field} must be an integer in the range 1..65535")
    return port


def _read_report(path: Path) -> dict[str, Any]:
    try:
        raw_report = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise _report_error(path, f"cannot read JSON: {exc}") from exc

    try:
        report: object = json.loads(raw_report)
    except json.JSONDecodeError as exc:
        raise _report_error(
            path,
            f"malformed JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
        ) from exc

    if not isinstance(report, dict):
        raise _report_error(path, "top-level JSON value must be an object")
    return report


def _has_modbus_confirmation(report: dict[str, Any], port: int) -> bool:
    observations = report.get("observations")
    if not isinstance(observations, list):
        return False
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        probe_id = observation.get("probe_id")
        metadata = observation.get("metadata")
        if not isinstance(probe_id, str) or not probe_id.startswith("modbus."):
            continue
        if not isinstance(metadata, dict):
            continue
        if (
            observation.get("state") == "observed"
            and metadata.get("port") == port
            and metadata.get("transport") == "tcp"
            and metadata.get("service_id") == "modbus-tcp"
            and metadata.get("protocol_valid") is True
        ):
            return True
    return False


def verify_modbus_endpoint(target: ScanTarget, timeout: float, unit_id: int = 1) -> None:
    """Reconfirm a report-selected endpoint with one correlated read-only FC03 request."""

    if isinstance(unit_id, bool) or not isinstance(unit_id, int) or not 0 <= unit_id <= 255:
        raise ConfigurationError("Modbus preflight unit ID must be in the range 0..255")
    transaction_id = 0xC0DE
    pdu = b"\x03\x00\x00\x00\x01"
    request = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id) + pdu
    result = TCPTransport(target.host, target.port, timeout).exchange(request)
    response = result.response
    if result.status != "response" or response is None:
        raise ConfigurationError(
            "scan-report Modbus preflight failed: "
            f"endpoint returned transport status {result.status!r}"
        )
    if not _valid_fc03_response(response, transaction_id, unit_id):
        raise ConfigurationError(
            "scan-report Modbus preflight failed: response was not a correlated "
            "FC03 Modbus response"
        )


def _valid_fc03_response(response: bytes, transaction_id: int, unit_id: int) -> bool:
    if len(response) < 9:
        return False
    response_transaction, protocol_id, length, response_unit = struct.unpack(">HHHB", response[:7])
    if (
        response_transaction != transaction_id
        or protocol_id != 0
        or response_unit != unit_id
        or not 2 <= length <= 254
        or len(response) != 6 + length
    ):
        return False
    pdu = response[7:]
    if pdu[0] == 0x83:
        return len(pdu) == 2 and 1 <= pdu[1] <= 11
    return len(pdu) == 4 and pdu[:2] == b"\x03\x02"


def load_scan_target(path: Path, requested_port: int | None = None) -> ScanTarget:
    """Load one confirmed, fuzz-eligible Modbus/TCP endpoint from a scan report.

    The report is treated as untrusted input. Its resolved address is checked
    again with the default fuzzing safety policy before a target is returned.
    """

    if requested_port is not None:
        requested_port = _validate_port(path, requested_port, field="requested_port")

    report = _read_report(path)
    resolved_address = report.get("resolved_address")
    if not isinstance(resolved_address, str) or not resolved_address:
        raise _report_error(path, "resolved_address must be a non-empty string")
    host = SafetyPolicy().validate_target(resolved_address)

    findings = report.get("port_findings")
    if not isinstance(findings, list):
        raise _report_error(path, "port_findings must be an array")

    status = report.get("status")
    if status == "BUDGET_EXCEEDED":
        raise _report_error(path, "status is BUDGET_EXCEEDED; the scan is incomplete")
    if status not in {"complete", "INCONCLUSIVE", "CONFLICT", "FORKED"}:
        raise _report_error(path, f"unknown or missing scan classification status: {status!r}")

    port_summary = report.get("port_summary")
    if not isinstance(port_summary, dict) or port_summary.get("scan_complete") is not True:
        raise _report_error(
            path,
            "port_summary.scan_complete must be true; scan execution completeness is unknown",
        )

    eligible_ports: set[int] = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        if not (
            finding.get("state") == "open"
            and finding.get("service_id") == "modbus-tcp"
            and finding.get("identification") == "confirmed"
            and finding.get("fuzz_eligible") is True
        ):
            continue
        candidate_port = _validate_port(
            path, finding.get("port"), field=f"port_findings[{index}].port"
        )
        if _has_modbus_confirmation(report, candidate_port):
            eligible_ports.add(candidate_port)

    ports = sorted(eligible_ports)
    if not ports:
        raise _report_error(
            path,
            "no open, confirmed, fuzz-eligible modbus-tcp port was found",
        )

    if requested_port is not None:
        if requested_port not in eligible_ports:
            candidates = ", ".join(str(port) for port in ports)
            raise _report_error(
                path,
                f"requested_port {requested_port} is not an eligible candidate "
                f"(eligible ports: {candidates})",
            )
        selected_port = requested_port
    elif len(ports) > 1:
        candidates = ", ".join(str(port) for port in ports)
        raise _report_error(
            path,
            f"multiple eligible Modbus/TCP ports found ({candidates}); requested_port is required",
        )
    else:
        selected_port = ports[0]

    target = report.get("target")
    report_target = target if isinstance(target, str) else None
    return ScanTarget(host, selected_port, report_target)
