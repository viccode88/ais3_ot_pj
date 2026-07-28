"""Deterministic case generation, anomaly classification, and serialization."""

from __future__ import annotations

import json
import random
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from .protocol import decode_adu, encode_adu
from .transport import TCPTransport, _recv_exact

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
    "protocol-id",
    "address-wrap",
    "truncated-mbap",
    "concatenated-adu",
    "pdu-mismatch",
    "exception-shape",
    "mei-subtype",
    "rtu-over-tcp",
    "fill",
    "fragmented-send",
    "repeat-storm",
    "session-sequence",
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
    health_after: dict[str, Any] | None = None
    send_plan: dict[str, Any] | None = None
    execution: dict[str, Any] | None = None


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


def _crc16_modbus(data: bytes) -> int:
    """Modbus RTU CRC16 (poly 0xA001, init 0xFFFF), returned in wire order."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def _rebuild_adu(packet: bytearray, pdu: bytes) -> bytearray:
    """Re-wrap a PDU preserving transaction/protocol/unit IDs with a consistent length."""
    rebuilt = bytearray(packet[:4])
    rebuilt.extend((len(pdu) + 1).to_bytes(2, "big"))
    rebuilt.append(packet[6])
    rebuilt.extend(pdu)
    return rebuilt


class CaseGenerator:
    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.random = random.Random(seed)

    def generate(self, index: int, strategy: str, unit_id: int, host: str, port: int) -> FuzzCase:
        packet = bytearray(encode_adu(3, 0, 1, transaction_id=index & 0xFFFF, unit_id=unit_id))
        mutations: list[str] = []
        send_plan: dict[str, Any] | None = None
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
            # Resize the ADU and keep the MBAP length field consistent with the
            # resulting unit-and-PDU size.  A bare length-field overwrite only
            # creates a framing mismatch that framing checks block before
            # transmission; a well-framed but truncated/extended PDU actually
            # reaches the target and exercises server-side length handling.
            value = rng.choice((2, 3, 5, 7, 8, 12, 253, 254))
            target_size = 6 + value
            if target_size < len(packet):
                del packet[target_size:]
            elif target_size > len(packet):
                packet.extend(rng.randrange(256) for _ in range(target_size - len(packet)))
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
        elif strategy == "protocol-id":
            value = rng.choice((1, 0xFF, 0x100, 0xFFFF, rng.randrange(1, 0x10000)))
            packet[2:4] = value.to_bytes(2, "big")
            mutations.append(f"protocol-id={value}")
        elif strategy == "address-wrap":
            start, quantity = rng.choice(
                ((0xFFFE, 4), (0xFFFF, 1), (0xFFFF, 2), (0xFFF0, 0x20), (0, 0), (0x8000, 0x8000))
            )
            packet[8:12] = struct.pack(">HH", start, quantity)
            mutations.append(f"address-wrap:start={start}:quantity={quantity}")
        elif strategy == "truncated-mbap":
            keep = rng.choice((1, 2, 3, 4, 5, 6))
            del packet[keep:]
            mutations.append(f"truncated-mbap:bytes={keep}")
        elif strategy == "concatenated-adu":
            kind = rng.choice(("valid", "garbage", "truncated"))
            if kind == "valid":
                second = encode_adu(3, 0, 1, transaction_id=(index + 1) & 0xFFFF, unit_id=unit_id)
            elif kind == "garbage":
                second = bytes(rng.randrange(256) for _ in range(rng.randint(4, 16)))
            else:
                second = bytes(packet[: rng.randint(1, 7)])
            packet.extend(second)
            mutations.append(f"concatenated-adu:second={kind}:bytes={len(second)}")
        elif strategy == "pdu-mismatch":
            variant = rng.choice(
                (
                    "fc16-short-byte-count",
                    "fc16-long-byte-count",
                    "fc15-bit-count-mismatch",
                    "fc05-invalid-toggle",
                    "fc03-trailing-garbage",
                )
            )
            if variant == "fc16-short-byte-count":
                pdu = struct.pack(">BHHB", 16, 0, 4, 2) + bytes(
                    rng.randrange(256) for _ in range(2)
                )
            elif variant == "fc16-long-byte-count":
                pdu = struct.pack(">BHHB", 16, 0, 1, 8) + bytes(
                    rng.randrange(256) for _ in range(8)
                )
            elif variant == "fc15-bit-count-mismatch":
                pdu = struct.pack(">BHHB", 15, 0, 9, 1) + bytes((rng.randrange(256),))
            elif variant == "fc05-invalid-toggle":
                pdu = struct.pack(">BHH", 5, 0, rng.choice((0x0001, 0x1234, 0xFF01, 0xFFFE)))
            else:
                pdu = struct.pack(">BHH", 3, 0, 1) + bytes(rng.randrange(256) for _ in range(2))
            packet = _rebuild_adu(packet, pdu)
            mutations.append(f"pdu-mismatch:{variant}")
        elif strategy == "exception-shape":
            function = rng.choice((0x81, 0x83, 0x90))
            code = rng.choice((1, 2, 3, 4, 6, 11, rng.randrange(12, 256)))
            packet = _rebuild_adu(packet, bytes((function, code)))
            mutations.append(f"exception-shape:function={function:#04x}:code={code}")
        elif strategy == "mei-subtype":
            variant = rng.choice(
                ("canopen-write", "invalid-read-code", "truncated", "invalid-mei")
            )
            if variant == "canopen-write":
                pdu = bytes((43, 0x0D)) + bytes(rng.randrange(256) for _ in range(2))
            elif variant == "invalid-read-code":
                pdu = bytes((43, 0x0E, rng.choice((0, 5, 0xFF)), 0))
            elif variant == "truncated":
                pdu = bytes((43, 0x0E))
            else:
                pdu = bytes((43, rng.choice((0x00, 0x7F, 0xFF)), 1, 0))
            packet = _rebuild_adu(packet, pdu)
            mutations.append(f"mei-subtype:{variant}")
        elif strategy == "rtu-over-tcp":
            rtu = struct.pack(">BBHH", unit_id & 0xFF, 3, 0, 1)
            packet = bytearray(rtu + struct.pack("<H", _crc16_modbus(rtu)))
            mutations.append("rtu-over-tcp:valid-crc")
        elif strategy == "fill":
            byte = rng.choice((0x00, 0xFF))
            packet[6:] = bytes((byte,)) * 6
            mutations.append(f"fill={byte:#04x}")
        elif strategy == "fragmented-send":
            parts = rng.choice((2, 2, 3))
            delay = rng.choice((0.05, 0.2, 0.5, 1.0))
            if parts == 2:
                cut = rng.randint(1, len(packet) - 1)
                segments = [bytes(packet[:cut]), bytes(packet[cut:])]
            else:
                first_cut = rng.randint(1, len(packet) - 2)
                second_cut = rng.randint(first_cut + 1, len(packet) - 1)
                segments = [
                    bytes(packet[:first_cut]),
                    bytes(packet[first_cut:second_cut]),
                    bytes(packet[second_cut:]),
                ]
            send_plan = {
                "mode": "fragmented",
                "segments": [segment.hex().upper() for segment in segments],
                "delay_seconds": delay,
            }
            mutations.append(f"fragmented-send:parts={parts}:delay={delay}")
        elif strategy == "repeat-storm":
            count = rng.choice((3, 5, 10, 20))
            send_plan = {"mode": "repeat", "count": count}
            mutations.append(f"repeat-storm:count={count}")
        elif strategy == "session-sequence":
            variant = rng.choice(("garbage", "truncated", "exception"))
            valid = bytes(packet)
            if variant == "garbage":
                middle = bytes(rng.randrange(256) for _ in range(rng.randint(4, 12)))
            elif variant == "truncated":
                middle = bytes(packet[: rng.randint(1, 7)])
            else:
                middle = bytes(_rebuild_adu(packet, bytes((0x83, rng.choice((1, 2, 3, 4))))))
            payloads = [valid, middle, valid]
            send_plan = {
                "mode": "session",
                "payloads": [payload.hex().upper() for payload in payloads],
            }
            packet = bytearray(b"".join(payloads))
            mutations.append(f"session-sequence:middle={variant}")
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
            send_plan=send_plan,
        )


def _read_mbap(stream: socket.socket) -> bytes:
    """Read one MBAP-framed response; short reads return the partial bytes."""
    header = _recv_exact(stream, 7)
    if len(header) < 7:
        return header
    length = struct.unpack(">H", header[4:6])[0]
    return header + _recv_exact(stream, max(0, length - 1))


def _execute_send_plan(case: FuzzCase, timeout: float) -> None:
    """Execute a multi-step session (fragmented/repeat/session) over one connection.

    Per-step evidence is recorded in ``case.execution``; the case-level status,
    response and classification stay compatible with single-payload cases.
    """
    plan = case.send_plan or {}
    mode = plan.get("mode")
    host, port = str(case.target["host"]), cast(int, case.target["port"])
    started = time.monotonic()
    steps: list[dict[str, Any]] = []
    response: bytes | None = None
    status, error = "sent", None
    try:
        with socket.create_connection((host, port), timeout) as stream:
            stream.settimeout(timeout)
            if mode == "fragmented":
                segments: list[str] = plan["segments"]
                delay = float(plan.get("delay_seconds", 0))
                for position, segment_hex in enumerate(segments):
                    stream.sendall(bytes.fromhex(segment_hex))
                    steps.append(
                        {"step": position, "action": "send-segment", "bytes": len(segment_hex) // 2}
                    )
                    if delay and position < len(segments) - 1:
                        time.sleep(delay)
                response = _read_mbap(stream)
                steps.append({"action": "read-response", "bytes": len(response)})
                status = "response" if response else "disconnect"
            elif mode == "repeat":
                payload = bytes.fromhex(case.request_hex)
                count = int(plan["count"])
                for _ in range(count):
                    stream.sendall(payload)
                steps.append({"action": "send", "count": count, "bytes_each": len(payload)})
                received = 0
                deadline = time.monotonic() + timeout
                while received < count:
                    try:
                        stream.settimeout(max(0.01, deadline - time.monotonic()))
                        chunk = _read_mbap(stream)
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    response = chunk
                    received += 1
                steps.append({"action": "read-responses", "received": received})
                status = "response" if received else "disconnect"
            elif mode == "session":
                for position, payload_hex in enumerate(plan["payloads"]):
                    stream.sendall(bytes.fromhex(payload_hex))
                    chunk = _read_mbap(stream)
                    steps.append(
                        {
                            "step": position,
                            "request": payload_hex,
                            "response": chunk.hex().upper() if chunk else None,
                        }
                    )
                    if chunk:
                        response = chunk
                status = "response" if response else "disconnect"
            else:
                raise ValueError(f"unknown send plan mode {mode!r}")
    except TimeoutError as exc:
        status, error = "timeout", str(exc)
    except ConnectionRefusedError as exc:
        status, error = "connection-refused", str(exc)
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        status, error = "transport-error", str(exc)
    case.response_hex = response.hex().upper() if response else None
    case.elapsed_ms = (time.monotonic() - started) * 1000
    case.status = status
    case.execution = {"mode": mode, "steps": steps, "error": error}


def run_health_check(host: str, port: int, timeout: float, unit_id: int = 1) -> dict[str, Any]:
    """Send one known-good FC03 probe and report whether the target is still healthy.

    Executed between fuzz cases so a degraded target is pinned to the cases that
    ran before the failure instead of being discovered after the whole run.
    """
    transaction_id = 0xC0DE
    pdu = b"\x03\x00\x00\x00\x01"
    request = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id & 0xFF) + pdu
    result = TCPTransport(host, port, timeout).exchange(request)
    ok = result.status == "response" and _health_response_ok(
        result.response, transaction_id, unit_id & 0xFF
    )
    return {
        "ok": ok,
        "status": result.status,
        "elapsed_ms": result.elapsed_ms,
        "error": result.error,
    }


def _health_response_ok(response: bytes | None, transaction_id: int, unit_id: int) -> bool:
    if response is None or len(response) < 9:
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


def execute_cases(
    cases: list[FuzzCase],
    timeout: float,
    interval: float,
    progress: FuzzProgressCallback | None = None,
    health_check_interval: int = 0,
    health_unit_id: int = 1,
) -> list[FuzzCase]:
    """Execute cases sequentially with a fixed delay between transmissions."""
    if interval < 0:
        raise ValueError("interval must be >= 0")
    if health_check_interval < 0:
        raise ValueError("health_check_interval must be >= 0")
    sent = 0
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

        sent += 1
        case.sent_at = datetime.now(UTC).isoformat()
        if progress:
            progress("sending", case)
        port = cast(int, case.target["port"])
        if case.send_plan is not None:
            _execute_send_plan(case, timeout)
        else:
            transport = TCPTransport(str(case.target["host"]), port, timeout)
            result = transport.exchange(payload)
            case.response_hex = result.response.hex().upper() if result.response else None
            case.elapsed_ms, case.status = result.elapsed_ms, result.status
        response = bytes.fromhex(case.response_hex) if case.response_hex else None
        if case.status == "timeout":
            case.classification = "possible-service-degradation"
        elif case.status not in ("response", "sent"):
            case.classification = "anomalous-transport"
        elif response and decode_adu(response).warnings:
            case.classification = "possible-parser-inconsistency"
        else:
            case.classification = "normal-or-exception-response"
        if health_check_interval and sent % health_check_interval == 0:
            case.health_after = run_health_check(
                str(case.target["host"]), port, timeout, health_unit_id
            )
        if progress:
            progress("result", case)
        if interval and index < len(cases) - 1:
            time.sleep(interval)
    return cases


def save_cases(path: Path, cases: list[FuzzCase]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(case) for case in cases], indent=2), encoding="utf-8")
