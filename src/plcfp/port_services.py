"""Conservative TCP service hints and active-evidence correlation for PLC scans."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from plcfp.model import Observation, PortFinding, ProbeState

# TCP-only defaults from protocol registries and vendor documentation. A match
# remains a port hint until a compatible application-layer probe is observed.
DEFAULT_DISCOVERY_TCP_PORTS = (
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
)


@dataclass(frozen=True, slots=True)
class _ServiceDefinition:
    service_id: str
    name: str
    relevance: str


_SERVICES = {
    "ssh": _ServiceDefinition("ssh", "SSH remote management", "low"),
    "http": _ServiceDefinition("http", "HTTP web service", "contextual"),
    "http-alt": _ServiceDefinition("http-alt", "Alternate HTTP web service", "contextual"),
    "s7comm": _ServiceDefinition("s7comm", "Siemens S7comm (ISO-on-TCP)", "high"),
    "https": _ServiceDefinition("https", "HTTPS web service", "contextual"),
    "https-alt": _ServiceDefinition("https-alt", "Alternate HTTPS web service", "contextual"),
    "modbus-tcp": _ServiceDefinition("modbus-tcp", "Modbus/TCP", "high"),
    "modbus-security": _ServiceDefinition(
        "modbus-security", "Modbus Security (MBAP over TLS)", "high"
    ),
    "codesys-gateway": _ServiceDefinition("codesys-gateway", "CODESYS Gateway", "high"),
    "somachine": _ServiceDefinition("somachine", "Schneider SoMachine", "high"),
    "mqtt": _ServiceDefinition("mqtt", "MQTT broker", "medium"),
    "pcworx": _ServiceDefinition("pcworx", "Phoenix Contact PC Worx", "high"),
    "iec-104": _ServiceDefinition("iec-104", "IEC 60870-5-104", "high"),
    "wago-io-system": _ServiceDefinition("wago-io-system", "WAGO I/O System", "high"),
    "opc-ua": _ServiceDefinition("opc-ua", "OPC UA Binary", "high"),
    "opc-ua-tls": _ServiceDefinition("opc-ua-tls", "OPC UA over TLS", "high"),
    "hart-ip": _ServiceDefinition("hart-ip", "HART-IP", "high"),
    "openplc-v3-http": _ServiceDefinition(
        "openplc-v3-http", "OpenPLC v3 web interface", "contextual"
    ),
    "openplc-v4-https": _ServiceDefinition(
        "openplc-v4-https", "OpenPLC v4 web interface", "contextual"
    ),
    "omron-fins": _ServiceDefinition("omron-fins", "Omron FINS/TCP", "high"),
    "codesys-engineering": _ServiceDefinition(
        "codesys-engineering", "CODESYS engineering channel", "high"
    ),
    "ge-srtp": _ServiceDefinition("ge-srtp", "GE Service Request Transport (SRTP)", "high"),
    "dnp3": _ServiceDefinition("dnp3", "DNP3", "high"),
    "ethernet-ip": _ServiceDefinition("ethernet-ip", "EtherNet/IP encapsulation", "high"),
}

_PORT_CATALOG: dict[int, tuple[_ServiceDefinition, ...]] = {
    22: (_SERVICES["ssh"],),
    80: (_SERVICES["http"],),
    102: (_SERVICES["s7comm"],),
    443: (_SERVICES["https"],),
    502: (_SERVICES["modbus-tcp"],),
    802: (_SERVICES["modbus-security"],),
    1217: (_SERVICES["codesys-gateway"], _SERVICES["somachine"]),
    1883: (_SERVICES["mqtt"],),
    1962: (_SERVICES["pcworx"],),
    2404: (_SERVICES["iec-104"],),
    2455: (_SERVICES["wago-io-system"],),
    4840: (_SERVICES["opc-ua"],),
    4843: (_SERVICES["opc-ua-tls"],),
    5094: (_SERVICES["hart-ip"],),
    8080: (_SERVICES["http-alt"], _SERVICES["openplc-v3-http"]),
    8443: (_SERVICES["https-alt"], _SERVICES["openplc-v4-https"]),
    9600: (_SERVICES["omron-fins"],),
    11740: (_SERVICES["codesys-engineering"],),
    18245: (_SERVICES["ge-srtp"],),
    20000: (_SERVICES["dnp3"],),
    44818: (_SERVICES["ethernet-ip"],),
}

_SERVICE_ALIASES = {
    "dnp": "dnp3",
    "enip": "ethernet-ip",
    "ethernetip": "ethernet-ip",
    "iec-60870-5-104": "iec-104",
    "modbus": "modbus-tcp",
    "modbus-secure": "modbus-security",
    "mbap-s": "modbus-security",
    "opcua": "opc-ua",
    "opcua-tls": "opc-ua-tls",
    "openplc-v3": "openplc-v3-http",
    "openplc-v4": "openplc-v4-https",
}

_PORT_TOKEN = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?$")
_TCP_PORT_FEATURE = re.compile(r"^tcp\.port\.(\d+)\.open$")
_RELEVANCE_ORDER = {"high": 0, "medium": 1, "contextual": 2, "low": 3, "unknown": 4}
_IDENTIFICATION_ORDER = {"confirmed": 0, "configured": 1, "port-hint": 2, "unknown": 3}
_STATE_ORDER = {"open": 0, "closed": 1, "unavailable": 2, "not-scanned": 3}


def parse_port_spec(spec: str, max_ports: int = 1024) -> tuple[int, ...]:
    """Parse comma-separated TCP ports and inclusive ranges, preserving first-seen order."""

    if isinstance(max_ports, bool) or not isinstance(max_ports, int) or max_ports < 1:
        raise ValueError("max_ports must be a positive integer")
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("port specification must not be empty")

    ports: list[int] = []
    seen: set[int] = set()
    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            raise ValueError("port specification contains an empty item")
        match = _PORT_TOKEN.fullmatch(token)
        if match is None:
            raise ValueError(f"invalid port or range: {token!r}")

        start = int(match.group(1))
        end_text = match.group(2)
        end = int(end_text) if end_text is not None else start
        if not 1 <= start <= 65535 or not 1 <= end <= 65535:
            raise ValueError("ports must be between 1 and 65535")
        if start > end:
            raise ValueError(f"reversed port range is not allowed: {token!r}")

        for port in range(start, end + 1):
            if port in seen:
                continue
            seen.add(port)
            ports.append(port)
            if len(ports) > max_ports:
                raise ValueError(f"port specification exceeds the {max_ports}-port limit")

    return tuple(ports)


def build_port_findings(
    observations: Iterable[Observation],
    role_ports: Mapping[str, int],
    detected_major: str | None = None,
) -> list[PortFinding]:
    """Turn TCP connect results and bound active probes into ranked service findings."""

    observation_list = list(observations)
    configured = _configured_services(role_ports)
    ports = set(configured)
    for observation in observation_list:
        feature_port = _port_from_feature(observation.feature)
        if feature_port is not None:
            ports.add(feature_port)
        metadata_port = _metadata_port(observation.metadata)
        if metadata_port is not None:
            ports.add(metadata_port)

    findings = [
        _build_finding(port, observation_list, configured, detected_major) for port in ports
    ]
    return sorted(
        findings,
        key=lambda finding: (
            _STATE_ORDER[finding.state],
            _RELEVANCE_ORDER[finding.plc_relevance],
            _IDENTIFICATION_ORDER[finding.identification],
            finding.port,
        ),
    )


def _configured_services(
    role_ports: Mapping[str, int],
) -> dict[int, list[_ServiceDefinition]]:
    configured: dict[int, list[_ServiceDefinition]] = {}
    for raw_service_id, port in role_ports.items():
        if not isinstance(raw_service_id, str) or not raw_service_id.strip():
            raise ValueError("configured service IDs must be non-empty strings")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"configured port for {raw_service_id!r} must be between 1 and 65535")
        service = _service_definition(raw_service_id)
        bucket = configured.setdefault(port, [])
        if service.service_id not in {item.service_id for item in bucket}:
            bucket.append(service)
    return configured


def _service_definition(service_id: str) -> _ServiceDefinition:
    canonical = _canonical_service_id(service_id)
    known = _SERVICES.get(canonical)
    if known is not None:
        return known
    words = canonical.replace("-", " ").strip()
    name = words.title() if words else "Unknown TCP service"
    return _ServiceDefinition(canonical or "unknown", name, "unknown")


def _canonical_service_id(service_id: str) -> str:
    normalized = service_id.strip().lower().replace("_", "-")
    return _SERVICE_ALIASES.get(normalized, normalized)


def _port_from_feature(feature: str) -> int | None:
    match = _TCP_PORT_FEATURE.fullmatch(feature)
    if match is None:
        return None
    port = int(match.group(1))
    return port if 1 <= port <= 65535 else None


def _coerce_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    if isinstance(value, str) and value.isdecimal():
        port = int(value)
        return port if 1 <= port <= 65535 else None
    return None


def _metadata_port(metadata: Mapping[str, Any]) -> int | None:
    return _coerce_port(metadata.get("port"))


def _metadata_matches(observation: Observation, port: int, service_id: str) -> bool:
    metadata = observation.metadata
    if metadata.get("transport") != "tcp":
        return False
    has_binding = False

    if "port" in metadata:
        if _coerce_port(metadata["port"]) != port:
            return False
        has_binding = True

    if "service_id" in metadata:
        metadata_service = metadata["service_id"]
        if not isinstance(metadata_service, str):
            return False
        if _canonical_service_id(metadata_service) != service_id:
            return False
        has_binding = True

    return has_binding


def _candidate_services(
    port: int,
    observations: list[Observation],
    configured: dict[int, list[_ServiceDefinition]],
) -> list[_ServiceDefinition]:
    candidates: list[_ServiceDefinition] = []

    def append(service: _ServiceDefinition) -> None:
        if service.service_id not in {candidate.service_id for candidate in candidates}:
            candidates.append(service)

    for service in configured.get(port, []):
        append(service)
    for service in _PORT_CATALOG.get(port, ()):
        append(service)
    for observation in observations:
        if _metadata_port(observation.metadata) != port:
            continue
        metadata_service = observation.metadata.get("service_id")
        if isinstance(metadata_service, str) and metadata_service.strip():
            append(_service_definition(metadata_service))

    return candidates


def _network_state(
    port: int, observations: list[Observation]
) -> tuple[str, float | None, str | None]:
    selected_state = "unavailable"
    selected_latency: float | None = None
    selected_error: str | None = None
    selected_rank = len(_STATE_ORDER)

    for observation in observations:
        if _port_from_feature(observation.feature) != port:
            continue
        if observation.state == ProbeState.OBSERVED and observation.value is True:
            state = "open"
        elif observation.state == ProbeState.ABSENT or (
            observation.state == ProbeState.OBSERVED and observation.value is False
        ):
            state = "closed"
        elif observation.state == ProbeState.SKIPPED:
            state = "not-scanned"
        else:
            state = "unavailable"
        rank = _STATE_ORDER[state]
        if rank < selected_rank:
            selected_state = state
            selected_rank = rank
            selected_latency = observation.latency_ms
            selected_error = observation.error
        elif rank == selected_rank and selected_latency is None:
            selected_latency = observation.latency_ms
            selected_error = observation.error

    return selected_state, selected_latency, selected_error


def _active_observation(
    service: _ServiceDefinition,
    port: int,
    observations: list[Observation],
    detected_major: str | None,
) -> Observation | None:
    for observation in observations:
        if not _metadata_matches(observation, port, service.service_id):
            continue
        if _valid_active_evidence(observation, service.service_id, detected_major):
            return observation
    return None


def _valid_active_evidence(
    observation: Observation, service_id: str, detected_major: str | None
) -> bool:
    if observation.state != ProbeState.OBSERVED:
        return False
    identity = f"{observation.probe_id} {observation.feature}".lower()
    correlated_protocols = {"modbus-tcp", "ethernet-ip", "opc-ua", "dnp3"}
    if (
        service_id in correlated_protocols
        and observation.metadata.get("protocol_valid") is not True
    ):
        return False

    if service_id == "modbus-tcp":
        return "modbus." in identity and (
            bool(observation.raw) or _mapping_contains_true(observation.value, "responded")
        )
    if service_id == "ethernet-ip":
        return "enip." in identity and bool(observation.raw)
    if service_id == "opc-ua":
        return "opcua." in identity and bool(observation.raw)
    if service_id == "dnp3":
        return "dnp3." in identity and _mapping_contains_true(observation.value, "valid_start")
    if service_id == "openplc-v3-http":
        return (
            _major_matches(detected_major, "v3")
            and "http.v3." in identity
            and _has_openplc_v3_web_evidence(observation)
        )
    if service_id == "openplc-v4-https":
        return (
            _major_matches(detected_major, "v4")
            and "http.v4." in identity
            and _has_openplc_v4_web_evidence(observation)
        )
    if service_id in {"http", "http-alt", "https", "https-alt"}:
        return "http." in identity and (
            bool(observation.raw) or _mapping_has_http_status(observation.value)
        )

    # Exact metadata binding plus returned bytes is sufficient for catalogued
    # protocols which do not yet have a dedicated parser in this project.
    return bool(observation.raw)


def _mapping_contains_true(value: Any, key: str) -> bool:
    if isinstance(value, Mapping):
        if value.get(key) is True:
            return True
        return any(_mapping_contains_true(child, key) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_mapping_contains_true(child, key) for child in value)
    return False


def _mapping_has_http_status(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    status = value.get("status")
    return isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599


def _has_openplc_v3_web_evidence(observation: Observation) -> bool:
    value = observation.value
    if not isinstance(value, Mapping):
        return False
    if value.get("mentions_openplc") is True:
        return True
    if observation.feature != "http.v3.route_matrix":
        return False
    registered = sum(
        isinstance(route, Mapping) and route.get("registered") is True for route in value.values()
    )
    return registered >= 5


def _has_openplc_v4_web_evidence(observation: Observation) -> bool:
    value = observation.value
    if not isinstance(value, Mapping):
        return False
    if observation.feature == "http.v4.socketio_handshake":
        engine_io = value.get("engine_io")
        return isinstance(engine_io, Mapping) and isinstance(engine_io.get("sid"), str)
    if observation.feature in {
        "http.v4.users_info",
        "http.v4.login_empty",
        "http.v4.status",
    }:
        return "json" in value
    return False


def _major_matches(detected_major: str | None, expected: str) -> bool:
    if detected_major is None:
        return False
    normalized = detected_major.strip().lower()
    return normalized in {expected, expected.removeprefix("v")}


def _build_finding(
    port: int,
    observations: list[Observation],
    configured: dict[int, list[_ServiceDefinition]],
    detected_major: str | None,
) -> PortFinding:
    candidates = _candidate_services(port, observations, configured)
    configured_ids = {service.service_id for service in configured.get(port, [])}
    confirmation_order = sorted(
        candidates,
        key=lambda service: (
            0 if service.service_id in configured_ids else 1,
            _RELEVANCE_ORDER[service.relevance],
            service.service_id,
        ),
    )
    confirmed_service: _ServiceDefinition | None = None
    confirming_observation: Observation | None = None
    for service in confirmation_order:
        active = _active_observation(service, port, observations, detected_major)
        if active is not None:
            confirmed_service = service
            confirming_observation = active
            break

    if confirmed_service is not None:
        primary = confirmed_service
        identification = "confirmed"
    elif configured.get(port):
        primary = configured[port][0]
        identification = "configured"
    elif candidates:
        primary = candidates[0]
        identification = "port-hint"
    else:
        primary = _ServiceDefinition("unknown", "Unknown TCP service", "unknown")
        identification = "unknown"

    state, latency_ms, network_error = _network_state(port, observations)
    if confirming_observation is not None:
        state = "open"
        if latency_ms is None:
            latency_ms = confirming_observation.latency_ms

    evidence: list[str] = []
    if state == "open":
        evidence.append(f"tcp-connect: TCP/{port} accepted a connection")
    elif state == "closed":
        evidence.append(f"tcp-connect: TCP/{port} refused or reset the connection")
    elif state == "not-scanned":
        evidence.append(f"not-scanned: TCP/{port} was not probed")
    else:
        detail = f" ({network_error})" if network_error else ""
        evidence.append(f"tcp-connect: TCP/{port} state was unavailable{detail}")

    if primary.service_id in configured_ids:
        evidence.append(f"configured-role: {primary.service_id} is assigned to TCP/{port}")
    elif primary.service_id != "unknown":
        evidence.append(
            f"catalog-port-hint: TCP/{port} is commonly used by {primary.name}; "
            "the port number alone is not protocol confirmation"
        )
    if confirming_observation is not None:
        evidence.append(
            "active-confirmation: "
            f"{confirming_observation.probe_id} returned valid {primary.name} evidence"
        )

    alternatives = [
        service.service_id for service in candidates if service.service_id != primary.service_id
    ]
    fuzz_eligible = (
        state == "open" and identification == "confirmed" and primary.service_id == "modbus-tcp"
    )
    relevance = primary.relevance
    if identification == "confirmed" and primary.service_id in {
        "openplc-v3-http",
        "openplc-v4-https",
    }:
        relevance = "high"
    return PortFinding(
        port=port,
        transport="tcp",
        state=state,
        service_id=primary.service_id,
        service_name=primary.name,
        plc_relevance=relevance,
        identification=identification,
        evidence=evidence,
        latency_ms=latency_ms,
        fuzz_eligible=fuzz_eligible,
        alternatives=alternatives,
    )
