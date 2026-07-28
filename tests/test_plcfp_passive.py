from __future__ import annotations

import socket
import struct
from pathlib import Path

from plcfp.passive import (
    MAX_FLOWS_PER_PORT,
    MAX_RAW_EVIDENCE_BYTES,
    analyze_pcap,
)


def _ethernet_ipv4_tcp(payload: bytes) -> bytes:
    ethernet = b"\0" * 12 + struct.pack(">H", 0x0800)
    source = socket.inet_aton("10.0.0.10")
    destination = socket.inet_aton("10.0.0.20")
    total_length = 20 + 20 + len(payload)
    ipv4 = (
        b"\x45\x00"
        + struct.pack(">H", total_length)
        + b"\0\0\0\0\x40\x06\0\0"
        + source
        + destination
    )
    tcp = struct.pack(">HHIIHHHH", 8080, 50000, 1, 1, 0x5018, 65535, 0, 0)
    return ethernet + ipv4 + tcp + payload


def _write_pcap(path: Path, frames: list[bytes]) -> None:
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    packets = b"".join(
        struct.pack("<IIII", index, 0, len(frame), len(frame)) + frame
        for index, frame in enumerate(frames)
    )
    path.write_bytes(global_header + packets)


def test_passive_pcap_identifies_v3_without_sending_packets(tmp_path: Path) -> None:
    payload = b'HTTP/1.1 200 OK\r\n\r\nOpenPLC <input type="password">'
    frame = _ethernet_ipv4_tcp(payload)
    capture = tmp_path / "openplc.pcap"
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", 1, 0, len(frame), len(frame))
    capture.write_bytes(global_header + packet_header + frame)

    report = analyze_pcap(capture, target="10.0.0.10")
    assert report.major == "v3"
    assert report.lifecycle == "end-of-life"
    assert report.packets_sent == 0
    communication = report.observations[0].value
    assert "8080" in communication


def test_passive_raw_evidence_is_capped(tmp_path: Path) -> None:
    payload = b'HTTP/1.1 200 OK\r\n\r\nOpenPLC <input type="password">' + b"A" * 60000
    frames = [_ethernet_ipv4_tcp(payload) for _ in range(40)]
    capture = tmp_path / "large.pcap"
    _write_pcap(capture, frames)

    report = analyze_pcap(capture, target="10.0.0.10")

    raw_observations = [observation.raw for observation in report.observations if observation.raw]
    assert raw_observations, "expected retained raw evidence"
    assert all(len(raw) <= MAX_RAW_EVIDENCE_BYTES for raw in raw_observations)
    assert report.major == "v3"


def test_passive_flow_map_is_capped(tmp_path: Path) -> None:
    frames = []
    for index in range(MAX_FLOWS_PER_PORT + 50):
        ethernet = b"\0" * 12 + struct.pack(">H", 0x0800)
        source = socket.inet_aton("10.0.0.10")
        destination = socket.inet_aton("10.0.0.20")
        total_length = 20 + 20
        ipv4 = (
            b"\x45\x00"
            + struct.pack(">H", total_length)
            + b"\0\0\0\0\x40\x06\0\0"
            + source
            + destination
        )
        tcp = struct.pack(">HHIIHHHH", 8080, 40000 + index, 1, 1, 0x5018, 65535, 0, 0)
        frames.append(ethernet + ipv4 + tcp)
    capture = tmp_path / "flows.pcap"
    _write_pcap(capture, frames)

    report = analyze_pcap(capture, target="10.0.0.10")

    communication = report.observations[0].value
    assert len(communication["8080"]) == MAX_FLOWS_PER_PORT
    assert communication["_truncated"] == ["8080"]
