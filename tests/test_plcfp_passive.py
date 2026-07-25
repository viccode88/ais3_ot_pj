from __future__ import annotations

import socket
import struct
from pathlib import Path

from plcfp.passive import analyze_pcap


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
