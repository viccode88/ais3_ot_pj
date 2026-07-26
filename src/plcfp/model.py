from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ProbeState(str, Enum):
    """Tri-state probe result; unavailable is never treated as absent."""

    OBSERVED = "observed"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(slots=True)
class Observation:
    probe_id: str
    feature: str
    value: Any = None
    state: ProbeState = ProbeState.OBSERVED
    latency_ms: float | None = None
    raw: bytes = b""
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return self.state in {ProbeState.OBSERVED, ProbeState.ABSENT}

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "probe_id": self.probe_id,
            "feature": self.feature,
            "value": self.value,
            "available": self.available,
            "state": self.state,
            "latency_ms": self.latency_ms,
        }
        if self.error:
            data["error"] = self.error
        if self.metadata:
            data["metadata"] = self.metadata
        if include_raw and self.raw:
            data["raw_b64"] = base64.b64encode(self.raw).decode("ascii")
        return data


@dataclass(slots=True)
class Evidence:
    probe: str
    feature: str
    value: Any
    weight: float
    supports: str
    rationale: str


@dataclass(slots=True)
class PortFinding:
    port: int
    transport: str
    state: str
    service_id: str
    service_name: str
    plc_relevance: str
    identification: str
    evidence: list[str]
    latency_ms: float | None
    fuzz_eligible: bool = False
    alternatives: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanReport:
    target: str
    resolved_address: str | None
    product: str | None
    major: str | None
    version_range: dict[str, str | None]
    point_estimate: str | None
    build_epoch: str | None
    confidence: float
    lifecycle: str
    cpe: list[str]
    cpe_note: str
    evidence: list[Evidence]
    conflicts: list[str]
    config_findings: list[str]
    observations: list[Observation]
    scan_profile: str
    max_layer: int
    packets_sent: int
    signature_db: dict[str, str]
    started_at: str
    completed_at: str
    status: str = "complete"
    port_findings: list[PortFinding] = field(default_factory=list)
    port_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        data = asdict(self)
        data["evidence"] = [asdict(item) for item in self.evidence]
        data["observations"] = [
            observation.to_dict(include_raw=include_raw) for observation in self.observations
        ]
        data["port_findings"] = [asdict(item) for item in self.port_findings]
        data["port_summary"] = dict(self.port_summary)
        return data
