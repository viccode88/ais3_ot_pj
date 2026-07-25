"""Deterministic case generation, anomaly classification, and serialization."""

from __future__ import annotations

import json
import random
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

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
)


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


def execute_cases(cases: list[FuzzCase], timeout: float, interval: float) -> list[FuzzCase]:
    """Execute cases sequentially with a fixed delay between transmissions."""
    if interval < 0:
        raise ValueError("interval must be >= 0")
    for index, case in enumerate(cases):
        case.sent_at = datetime.now(UTC).isoformat()
        port = cast(int, case.target["port"])
        transport = TCPTransport(str(case.target["host"]), port, timeout)
        result = transport.exchange(bytes.fromhex(case.request_hex))
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
        if interval and index < len(cases) - 1:
            time.sleep(interval)
    return cases


def save_cases(path: Path, cases: list[FuzzCase]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(case) for case in cases], indent=2), encoding="utf-8")
