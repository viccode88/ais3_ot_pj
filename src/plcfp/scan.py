from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from plcfp.engine import classify
from plcfp.model import Observation, ProbeState, ScanReport
from plcfp.net import resolve_target
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

    @property
    def ports(self) -> tuple[int, ...]:
        values = (
            self.modbus_port,
            self.v3_http_port,
            self.v4_https_port,
            self.enip_port,
            self.dnp3_port,
            self.opcua_port,
        )
        if any(not 1 <= port <= 65535 for port in values):
            raise ValueError("all ports must be between 1 and 65535")
        return tuple(dict.fromkeys(values))


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
    try:
        observations.extend(probe_tcp_ports(target, scheduler, options.ports))
        if _port_is_open(observations, options.v4_https_port):
            observations.extend(probe_tls(target, scheduler, options.v4_https_port))
        if options.max_layer >= 2:
            if _port_is_open(observations, options.v4_https_port):
                observations.extend(probe_v4_https(target, scheduler, options.v4_https_port))
            if _port_is_open(observations, options.v3_http_port):
                observations.extend(probe_v3_http(target, scheduler, options.v3_http_port))
            if _port_is_open(observations, options.enip_port):
                observations.extend(
                    probe_enip(
                        target,
                        scheduler,
                        profile=options.profile,
                        port=options.enip_port,
                    )
                )
            if _port_is_open(observations, options.opcua_port):
                observations.extend(probe_opcua(target, scheduler, options.opcua_port))
            if _port_is_open(observations, options.modbus_port):
                modbus_profile = options.profile if options.max_layer >= 3 else ScanProfile.SAFE
                observations.extend(
                    probe_modbus(
                        target,
                        scheduler,
                        profile=modbus_profile,
                        port=options.modbus_port,
                    )
                )
        if (
            options.max_layer >= 3
            and options.profile == ScanProfile.LAB
            and options.dnp3_address is not None
            and _port_is_open(observations, options.dnp3_port)
        ):
            observations.extend(
                probe_dnp3(
                    target,
                    scheduler,
                    destination=options.dnp3_address,
                    port=options.dnp3_port,
                )
            )
    except BudgetExceeded as exc:
        scan_status = "BUDGET_EXCEEDED"
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
    )
