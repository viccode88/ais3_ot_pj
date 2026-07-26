from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from plcfp.engine import classify
from plcfp.model import Observation, ProbeState, ScanReport
from plcfp.net import resolve_target
from plcfp.port_services import DEFAULT_DISCOVERY_TCP_PORTS, build_port_findings
from plcfp.probes import (
    probe_enip,
    probe_modbus,
    probe_opcua,
    probe_tcp_ports,
    probe_tls,
    probe_v3_http,
    probe_v4_https,
)
from plcfp.probes.dnp3 import probe_dnp3
from plcfp.scheduler import BudgetExceeded, ProbeScheduler, ScanProfile
from plcfp.sigdb import load_signatures


@dataclass(slots=True)
class ScanOptions:
    profile: ScanProfile = ScanProfile.STANDARD
    max_layer: int = 4
    interval: float | None = None
    packet_budget: int | None = None
    timeout: float | None = None
    allow_public: bool = False
    dnp3_address: int | None = None
    signature_dir: Path | None = None
    modbus_port: int = 502
    v3_http_port: int = 8080
    v4_https_port: int = 8443
    enip_port: int = 44818
    dnp3_port: int = 20000
    opcua_port: int = 4840
    additional_ports: tuple[int, ...] = ()

    @property
    def ports(self) -> tuple[int, ...]:
        values = (
            self.modbus_port,
            self.v3_http_port,
            self.v4_https_port,
            self.enip_port,
            self.dnp3_port,
            self.opcua_port,
            *self.additional_ports,
            *DEFAULT_DISCOVERY_TCP_PORTS,
        )
        if any(not 1 <= port <= 65535 for port in values):
            raise ValueError("all ports must be between 1 and 65535")
        return tuple(dict.fromkeys(values))


def _tag_observations(
    observations: list[Observation], *, port: int, service_id: str
) -> list[Observation]:
    """Attach the actual endpoint to protocol evidence, including custom port mappings."""
    for observation in observations:
        observation.metadata.setdefault("port", port)
        observation.metadata.setdefault("transport", "tcp")
        observation.metadata.setdefault("service_id", service_id)
    return observations


def _port_is_open(observations: list[Observation], port: int) -> bool:
    feature = f"tcp.port.{port}.open"
    return any(
        observation.feature == feature
        and observation.state == ProbeState.OBSERVED
        and observation.value is True
        for observation in observations
    )


def scan_target(target_name: str, options: ScanOptions) -> ScanReport:
    if not 1 <= options.max_layer <= 4:
        raise ValueError("active scans require --max-layer between 1 and 4")
    started = datetime.now(UTC)
    target = resolve_target(target_name, allow_public=options.allow_public)
    scheduler = ProbeScheduler(
        options.profile,
        interval=options.interval,
        packet_budget=options.packet_budget,
        timeout=options.timeout,
    )
    observations: list[Observation] = []
    scan_status = "complete"
    tcp_scan_complete = False
    try:
        # Probe one port per call so observations completed before a hard-budget
        # exception remain available in the final report.
        for port in options.ports:
            observations.extend(probe_tcp_ports(target, scheduler, (port,)))
        tcp_scan_complete = True
        if _port_is_open(observations, options.v4_https_port):
            observations.extend(
                _tag_observations(
                    probe_tls(target, scheduler, options.v4_https_port),
                    port=options.v4_https_port,
                    service_id="openplc-v4-https",
                )
            )
        if options.max_layer >= 2:
            if _port_is_open(observations, options.v4_https_port):
                observations.extend(
                    _tag_observations(
                        probe_v4_https(target, scheduler, options.v4_https_port),
                        port=options.v4_https_port,
                        service_id="openplc-v4-https",
                    )
                )
            if _port_is_open(observations, options.v3_http_port):
                observations.extend(
                    _tag_observations(
                        probe_v3_http(target, scheduler, options.v3_http_port),
                        port=options.v3_http_port,
                        service_id="openplc-v3-http",
                    )
                )
            if _port_is_open(observations, options.enip_port):
                observations.extend(
                    _tag_observations(
                        probe_enip(
                            target,
                            scheduler,
                            profile=options.profile,
                            port=options.enip_port,
                        ),
                        port=options.enip_port,
                        service_id="ethernet-ip",
                    )
                )
            if _port_is_open(observations, options.opcua_port):
                observations.extend(
                    _tag_observations(
                        probe_opcua(target, scheduler, options.opcua_port),
                        port=options.opcua_port,
                        service_id="opc-ua",
                    )
                )
            if _port_is_open(observations, options.modbus_port):
                modbus_profile = options.profile if options.max_layer >= 3 else ScanProfile.SAFE
                observations.extend(
                    _tag_observations(
                        probe_modbus(
                            target,
                            scheduler,
                            profile=modbus_profile,
                            port=options.modbus_port,
                        ),
                        port=options.modbus_port,
                        service_id="modbus-tcp",
                    )
                )
        if (
            options.max_layer >= 3
            and options.profile == ScanProfile.LAB
            and options.dnp3_address is not None
            and _port_is_open(observations, options.dnp3_port)
        ):
            observations.extend(
                _tag_observations(
                    probe_dnp3(
                        target,
                        scheduler,
                        destination=options.dnp3_address,
                        port=options.dnp3_port,
                    ),
                    port=options.dnp3_port,
                    service_id="dnp3",
                )
            )
    except BudgetExceeded as exc:
        scan_status = "BUDGET_EXCEEDED"
        if not tcp_scan_complete:
            scanned_features = {observation.feature for observation in observations}
            for port in options.ports:
                feature = f"tcp.port.{port}.open"
                if feature in scanned_features:
                    continue
                observations.append(
                    Observation(
                        probe_id=f"network.tcp.{port}",
                        feature=feature,
                        state=ProbeState.SKIPPED,
                        error="not scanned because the network-action budget was exhausted",
                        metadata={"port": port, "transport": "tcp"},
                    )
                )
        observations.append(
            Observation(
                probe_id="scheduler.packet_budget",
                feature="scheduler.packet_budget",
                value={"sent": scheduler.sent, "limit": scheduler.packet_budget},
                state=ProbeState.ERROR,
                error=str(exc),
            )
        )

    database = load_signatures(options.signature_dir)
    result = classify(observations, database)
    if scan_status != "complete":
        result.status = scan_status
    port_findings = build_port_findings(
        observations,
        {
            "modbus-tcp": options.modbus_port,
            "openplc-v3-http": options.v3_http_port,
            "openplc-v4-https": options.v4_https_port,
            "ethernet-ip": options.enip_port,
            "dnp3": options.dnp3_port,
            "opc-ua": options.opcua_port,
        },
        detected_major=result.major,
    )
    requested_ports = options.ports
    scanned_ports: set[int] = set()
    for observation in observations:
        parts = observation.feature.split(".")
        if (
            len(parts) == 4
            and parts[:2] == ["tcp", "port"]
            and parts[2].isdecimal()
            and parts[3] == "open"
            and observation.state != ProbeState.SKIPPED
        ):
            scanned_ports.add(int(parts[2]))
    port_summary = {
        "scan_complete": scan_status == "complete",
        "requested": len(requested_ports),
        "scanned": len(scanned_ports),
        "not_scanned": len(requested_ports) - len(scanned_ports),
        "open": sum(finding.state == "open" for finding in port_findings),
        "closed": sum(finding.state == "closed" for finding in port_findings),
        "unavailable": sum(
            finding.state == "unavailable" and finding.port in scanned_ports
            for finding in port_findings
        ),
        "high_relevance_open": [
            finding.port
            for finding in port_findings
            if finding.state == "open" and finding.plc_relevance == "high"
        ],
        "confirmed_services": [
            {"port": finding.port, "service": finding.service_id}
            for finding in port_findings
            if finding.state == "open" and finding.identification == "confirmed"
        ],
        "fuzz_candidates": [finding.port for finding in port_findings if finding.fuzz_eligible],
    }
    completed = datetime.now(UTC)
    return ScanReport(
        target=target_name,
        resolved_address=target.address,
        product=result.product,
        major=result.major,
        version_range=result.version_range,
        point_estimate=result.point_estimate,
        build_epoch=result.build_epoch,
        confidence=result.confidence,
        lifecycle=result.lifecycle,
        cpe=result.cpe,
        cpe_note=(
            "NVD/OpenPLC vendor naming is inconsistent; autonomylogic and "
            "thiagoralves variants are emitted when a version is available."
        ),
        evidence=result.evidence,
        conflicts=result.conflicts,
        config_findings=result.config_findings,
        observations=observations,
        scan_profile=options.profile,
        max_layer=options.max_layer,
        packets_sent=scheduler.sent,
        signature_db=database.metadata,
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
        status=result.status,
        port_findings=port_findings,
        port_summary=port_summary,
    )
