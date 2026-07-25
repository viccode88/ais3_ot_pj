from __future__ import annotations

import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from plcfp.engine import classify
from plcfp.model import Observation, ScanReport
from plcfp.sigdb import load_signatures


@dataclass(frozen=True, slots=True)
class TCPPayload:
    source: str
    destination: str
    source_port: int
    destination_port: int
    payload: bytes


def _pcap_packets(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise ValueError("short PCAP global header")
        magic = header[:4]
        if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
            endian = "<"
        elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
            endian = ">"
        else:
            raise ValueError("unsupported capture format (classic PCAP required)")
        link_type = struct.unpack_from(endian + "I", header, 20)[0]
        if link_type != 1:
            raise ValueError(f"unsupported PCAP link type {link_type}; Ethernet is required")
        while packet_header := handle.read(16):
            if len(packet_header) != 16:
                raise ValueError("truncated PCAP packet header")
            _seconds, _fraction, captured, _original = struct.unpack(endian + "IIII", packet_header)
            packet = handle.read(captured)
            if len(packet) != captured:
                raise ValueError("truncated PCAP packet")
            yield packet


def _tcp_payloads(path: Path) -> Iterator[TCPPayload]:
    for frame in _pcap_packets(path):
        if len(frame) < 14:
            continue
        offset = 14
        ether_type = struct.unpack_from(">H", frame, 12)[0]
        if ether_type == 0x8100 and len(frame) >= 18:
            ether_type = struct.unpack_from(">H", frame, 16)[0]
            offset = 18
        if ether_type != 0x0800 or len(frame) < offset + 20:
            continue
        ihl = (frame[offset] & 0x0F) * 4
        if ihl < 20 or frame[offset + 9] != 6 or len(frame) < offset + ihl + 20:
            continue
        source = socket.inet_ntoa(frame[offset + 12 : offset + 16])
        destination = socket.inet_ntoa(frame[offset + 16 : offset + 20])
        tcp_offset = offset + ihl
        source_port, destination_port = struct.unpack_from(">HH", frame, tcp_offset)
        data_offset = ((frame[tcp_offset + 12] >> 4) & 0x0F) * 4
        payload_offset = tcp_offset + data_offset
        if payload_offset > len(frame):
            continue
        payload = frame[payload_offset:]
        yield TCPPayload(source, destination, source_port, destination_port, payload)


def analyze_pcap(
    path: Path, *, target: str | None = None, signature_dir: Path | None = None
) -> ScanReport:
    started = datetime.now(UTC)
    flows: dict[str, set[str]] = {}
    observations: list[Observation] = []
    saw_v3_brand = False
    saw_v4_api = False
    saw_tls_8443 = False
    raw_v3 = bytearray()
    raw_v4 = bytearray()
    for packet in _tcp_payloads(path):
        if target and target not in {packet.source, packet.destination}:
            continue
        for port in {packet.source_port, packet.destination_port}:
            if port in {502, 8080, 8443, 44818, 20000, 4840}:
                flows.setdefault(str(port), set()).add(
                    f"{packet.source}:{packet.source_port}->{packet.destination}:{packet.destination_port}"
                )
        lowered = packet.payload.lower()
        if 8080 in {packet.source_port, packet.destination_port}:
            raw_v3.extend(packet.payload[:65536])
            if b"openplc" in lowered and (
                b'type="password"' in lowered or b"type='password'" in lowered
            ):
                saw_v3_brand = True
        if 8443 in {packet.source_port, packet.destination_port}:
            if packet.payload.startswith((b"\x16\x03", b"\x17\x03")):
                saw_tls_8443 = True
            if b"/api/compilation-status" in lowered or b"/socket.io" in lowered:
                raw_v4.extend(packet.payload[:65536])
                saw_v4_api = True

    observations.append(
        Observation(
            probe_id="passive.communication_map",
            feature="passive.communication_map",
            value={port: sorted(peers) for port, peers in sorted(flows.items())},
        )
    )
    if saw_v3_brand:
        observations.append(
            Observation(
                probe_id="passive.http.v3.login",
                feature="http.v3.login",
                value={"mentions_openplc": True, "has_password_field": True},
                raw=bytes(raw_v3),
            )
        )
    if saw_v4_api:
        observations.append(
            Observation(
                probe_id="passive.v4.editor_runtime",
                feature="passive.v4.editor_runtime",
                value=True,
                raw=bytes(raw_v4),
            )
        )
    if saw_tls_8443:
        observations.append(
            Observation(
                probe_id="passive.tls.8443",
                feature="passive.tls.8443",
                value=True,
            )
        )
    database = load_signatures(signature_dir)
    result = classify(observations, database)
    completed = datetime.now(UTC)
    return ScanReport(
        target=target or "all-capture-hosts",
        resolved_address=target,
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
        scan_profile="passive",
        max_layer=0,
        packets_sent=0,
        signature_db=database.metadata,
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
        status=result.status,
    )
