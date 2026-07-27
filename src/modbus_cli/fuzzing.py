"""Deterministic case generation, anomaly classification, and serialization."""

from __future__ import annotations

import json
import random
import struct
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from .protocol import decode_adu, encode_adu
from .transport import TCPTransport

STRATEGIES = (
    "boundary",
    "bitflip",
    "byteflip",
    "length",
    "function-code",
    "transaction",
    "unit-id",
    "semantic",
    "random",
    "huge-payload",
)

# Legacy FC16 Write Multiple Registers malformed payload: quantity stays in the
# 200..2000 range, the 1-byte byte_count wraps, and the MBAP length declares the
# full oversized body.  This is a virtual-lab reliability probe, not a write
# operation against production equipment.
HUGE_PAYLOAD_MIN_REGISTERS = 200
HUGE_PAYLOAD_MAX_REGISTERS = 2000
MAX_HUGE_PAYLOAD_REGISTERS = (0xFFFF - 7) // 2


@dataclass
class FuzzCase:
    case_id: str
    seed: int
    strategy: list[str]
    target: dict[str, object]
    request_hex: str
    mutations: list[str]
    sent_at: str | None = None
    response_hex: str | None = None
    elapsed_ms: float | None = None
    status: str = "pending"
    classification: str = "inconclusive"
    reproducible: bool | None = None
    safety_reason: str | None = None


FuzzProgressEvent = Literal["sending", "result"]
FuzzProgressCallback = Callable[[FuzzProgressEvent, FuzzCase], None]


def fuzz_payload_safety_reason(payload: bytes) -> str | None:
    """Return why a payload may not cross the fuzz transport boundary.

    This fuzzer exists to test the reliability of fully virtual lab targets, so
    the transport boundary deliberately does not enforce read-only function
    codes or well-formed MBAP framing: malformed, oversized, and write-function
    payloads are exactly what reliability testing needs to send.  Only an empty
    payload cannot be transmitted.
    """
    if not payload:
        return "request payload is empty"
    return None


def build_huge_payload(
    transaction_id: int,
    unit_id: int,
    register_count: int,
) -> tuple[bytes, dict[str, Any]]:
    """Build the legacy malformed FC16 Write Multiple Registers payload.

    The 1-byte ``byte_count`` wraps while the MBAP length declares the full
    oversized body, mirroring the historical OpenPLC v3 fuzz input.
    """
    register_count = max(1, min(register_count, MAX_HUGE_PAYLOAD_REGISTERS))
    data_length = register_count * 2
    byte_count = data_length & 0xFF
    data = bytes((transaction_id + register_count + offset) & 0xFF for offset in range(data_length))
    pdu = struct.pack(">BHHB", 16, 0, register_count, byte_count) + data
    payload = struct.pack(">HHHB", transaction_id & 0xFFFF, 0, len(pdu) + 1, unit_id & 0xFF) + pdu
    decoded_request = decode_adu(payload)
    modbus = {
        "transaction_id": transaction_id & 0xFFFF,
        "protocol_id": 0,
        "length": len(pdu) + 1,
        "unit_id": unit_id & 0xFF,
        "function_code": 16,
        "pdu_hex": payload[7:].hex().upper(),
        "adu_hex": payload.hex().upper(),
        "write_start_address": 0,
        "write_quantity": register_count,
        "byte_count": byte_count,
        "actual_data_bytes": data_length,
        "byte_count_mismatch": byte_count != data_length,
        "legacy_huge_payload_shape": True,
        "decoded_request": decoded_request.as_dict(),
    }
    return payload, modbus


class CaseGenerator:
    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.random = random.Random(seed)

    def generate(self, index: int, strategy: str, unit_id: int, host: str, port: int) -> FuzzCase:
        packet = bytearray(encode_adu(3, 0, 1, transaction_id=index & 0xFFFF, unit_id=unit_id))
        mutations: list[str] = []
        rng = self.random
        if strategy == "boundary":
            value = rng.choice((0, 1, 124, 125, 126, 0x7F, 0x80, 0xFF, 0xFFFF))
            packet[10:12] = value.to_bytes(2, "big")
            mutations.append(f"quantity={value}")
        elif strategy == "bitflip":
            position, bit = rng.randrange(len(packet)), rng.randrange(8)
            packet[position] ^= 1 << bit
            mutations.append(f"bitflip:{position}:{bit}")
        elif strategy == "byteflip":
            position = rng.randrange(len(packet))
            packet[position] ^= 0xFF
            mutations.append(f"byteflip:{position}")
        elif strategy == "length":
            value = rng.choice((0, 1, 5, 7, 0xFFFF))
            packet[4:6] = value.to_bytes(2, "big")
            mutations.append(f"length={value}")
        elif strategy == "function-code":
            value = rng.choice((0, 7, 0x2B, 0x7F, 0x80, 0xFF))
            packet[7] = value
            mutations.append(f"function={value}")
        elif strategy == "transaction":
            value = rng.choice((0, 1, 0xFFFF))
            packet[0:2] = value.to_bytes(2, "big")
            mutations.append(f"transaction={value}")
        elif strategy == "unit-id":
            value = rng.choice((0, 1, 247, 248, 255))
            packet[6] = value
            mutations.append(f"unit={value}")
        elif strategy == "semantic":
            packet[8:12] = rng.choice(
                (b"\xff\xff\x00\x02", b"\xff\xff\xff\xff", b"\x00\x00\x00\x00")
            )
            mutations.append("invalid-address-quantity")
        elif strategy == "huge-payload":
            register_count = rng.randint(HUGE_PAYLOAD_MIN_REGISTERS, HUGE_PAYLOAD_MAX_REGISTERS)
            huge_payload, _modbus = build_huge_payload(
                transaction_id=index & 0xFFFF,
                unit_id=unit_id,
                register_count=register_count,
            )
            packet = bytearray(huge_payload)
            mutations.append(f"fc16-huge-payload:quantity={register_count}")
        else:
            for _ in range(rng.randint(1, 4)):
                position = rng.randrange(len(packet))
                packet[position] = rng.randrange(256)
                mutations.append(f"replace:{position}")
        return FuzzCase(
            f"case-{index:06d}",
            self.seed,
            [strategy],
            {"host": host, "port": port},
            packet.hex().upper(),
            mutations,
        )


def execute_cases(
    cases: list[FuzzCase],
    timeout: float,
    interval: float,
    progress: FuzzProgressCallback | None = None,
) -> list[FuzzCase]:
    """Execute cases sequentially with a fixed delay between transmissions."""
    if interval < 0:
        raise ValueError("interval must be >= 0")
    for index, case in enumerate(cases):
        case.sent_at = None
        case.response_hex = None
        case.elapsed_ms = None
        case.safety_reason = None
        try:
            payload = bytes.fromhex(case.request_hex)
        except ValueError:
            case.status = "blocked"
            case.classification = "blocked-by-safety-policy"
            case.safety_reason = "request_hex is not valid hexadecimal"
            if progress:
                progress("result", case)
            if interval and index < len(cases) - 1:
                time.sleep(interval)
            continue

        safety_reason = fuzz_payload_safety_reason(payload)
        if safety_reason is not None:
            case.status = "blocked"
            case.classification = "blocked-by-safety-policy"
            case.safety_reason = safety_reason
            if progress:
                progress("result", case)
            if interval and index < len(cases) - 1:
                time.sleep(interval)
            continue

        case.sent_at = datetime.now(UTC).isoformat()
        if progress:
            progress("sending", case)
        port = cast(int, case.target["port"])
        transport = TCPTransport(str(case.target["host"]), port, timeout)
        result = transport.exchange(payload)
        case.response_hex = result.response.hex().upper() if result.response else None
        case.elapsed_ms, case.status = result.elapsed_ms, result.status
        if result.status == "timeout":
            case.classification = "possible-service-degradation"
        elif result.status not in ("response", "sent"):
            case.classification = "anomalous-transport"
        elif result.response and decode_adu(result.response).warnings:
            case.classification = "possible-parser-inconsistency"
        else:
            case.classification = "normal-or-exception-response"
        if progress:
            progress("result", case)
        if interval and index < len(cases) - 1:
            time.sleep(interval)
    return cases


def save_cases(path: Path, cases: list[FuzzCase]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(case) for case in cases], indent=2), encoding="utf-8")
