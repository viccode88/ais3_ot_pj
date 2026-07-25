from __future__ import annotations

import math
import socket
import statistics
import struct
import time
from dataclasses import dataclass
from typing import Any

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget, socket_address
from plcfp.scheduler import ProbeScheduler, ScanProfile


@dataclass(slots=True)
class ModbusResult:
    request: bytes
    response: bytes
    function: int | None
    exception_code: int | None
    latency_ms: float

    def value(self) -> dict[str, Any]:
        return {
            "request_hex": self.request.hex(),
            "response_hex": self.response.hex(),
            "function": self.function,
            "exception_code": self.exception_code,
        }


class ModbusClient:
    def __init__(
        self,
        target: ResolvedTarget,
        scheduler: ProbeScheduler,
        port: int = 502,
    ) -> None:
        self.target = target
        self.scheduler = scheduler
        self.port = port
        self.transaction_id = 0

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError("connection closed before complete Modbus response")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def exchange(self, pdu: bytes, unit_id: int = 1) -> ModbusResult:
        self.transaction_id = (self.transaction_id + 1) & 0xFFFF
        request = struct.pack(">HHHB", self.transaction_id, 0, len(pdu) + 1, unit_id) + pdu

        def action() -> ModbusResult:
            started = time.monotonic()
            with socket.socket(self.target.family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.scheduler.timeout)
                sock.connect(socket_address(self.target, self.port))
                sock.sendall(request)
                header = self._recv_exact(sock, 7)
                transaction, protocol, length, _response_unit = struct.unpack(">HHHB", header)
                if transaction != self.transaction_id:
                    raise ValueError("Modbus transaction ID mismatch")
                if protocol != 0 or length < 2 or length > 260:
                    raise ValueError("invalid Modbus MBAP header")
                payload = self._recv_exact(sock, length - 1)
            function = payload[0] if payload else None
            exception = payload[1] if function is not None and function & 0x80 else None
            return ModbusResult(
                request=request,
                response=header + payload,
                function=function,
                exception_code=exception,
                latency_ms=round((time.monotonic() - started) * 1000, 3),
            )

        return self.scheduler.run(action)


READ_ONLY_REQUESTS: dict[int, bytes] = {
    1: struct.pack(">BHH", 1, 0, 1),
    2: struct.pack(">BHH", 2, 0, 1),
    3: struct.pack(">BHH", 3, 0, 1),
    4: struct.pack(">BHH", 4, 0, 1),
    7: b"\x07",
    8: b"\x08\x00\x00\x12\x34",
    11: b"\x0b",
    12: b"\x0c",
    17: b"\x11",
    20: b"\x14\x07\x06\x00\x00\x00\x00\x00\x01",
    24: b"\x18\x00\x00",
    43: b"\x2b\x0e\x01\x00",
}


def _unavailable(probe_id: str, feature: str, exc: Exception) -> Observation:
    return Observation(
        probe_id=probe_id,
        feature=feature,
        state=ProbeState.UNAVAILABLE,
        error=str(exc),
    )


def _probe_device_id(client: ModbusClient) -> Observation:
    try:
        result = client.exchange(READ_ONLY_REQUESTS[43])
        value = result.value()
        if result.function == 43 and len(result.response) >= 15:
            pdu = result.response[7:]
            value["supported"] = True
            value["mei_type"] = pdu[1] if len(pdu) > 1 else None
            value["conformity_level"] = pdu[3] if len(pdu) > 3 else None
            objects: dict[str, str] = {}
            if len(pdu) > 7:
                offset = 7
                count = pdu[6]
                for _ in range(count):
                    if offset + 2 > len(pdu):
                        break
                    object_id, size = pdu[offset], pdu[offset + 1]
                    offset += 2
                    objects[str(object_id)] = pdu[offset : offset + size].decode(
                        "utf-8", errors="replace"
                    )
                    offset += size
            value["objects"] = objects
        else:
            value["supported"] = False
        return Observation(
            probe_id="modbus.fc43.device_id",
            feature="modbus.fc43.device_identification",
            value=value,
            latency_ms=result.latency_ms,
            raw=result.response,
        )
    except (OSError, ValueError, ConnectionError) as exc:
        return _unavailable("modbus.fc43.device_id", "modbus.fc43.device_identification", exc)


def _probe_unit_ids(client: ModbusClient) -> Observation:
    results: dict[str, Any] = {}
    raw: list[bytes] = []
    latencies: list[float] = []
    for unit_id in (0, 1, 247, 255):
        try:
            result = client.exchange(READ_ONLY_REQUESTS[3], unit_id=unit_id)
            results[str(unit_id)] = {
                "responded": True,
                "function": result.function,
                "exception_code": result.exception_code,
            }
            raw.append(result.response)
            latencies.append(result.latency_ms)
        except (OSError, ValueError, ConnectionError) as exc:
            results[str(unit_id)] = {"responded": False, "error": str(exc)}
    return Observation(
        probe_id="modbus.unit_ids",
        feature="modbus.unit_id.response_matrix",
        value=results,
        latency_ms=round(sum(latencies), 3) if latencies else None,
        raw=b"\n".join(raw),
    )


def _probe_function_bitmap(client: ModbusClient) -> Observation:
    results: dict[str, Any] = {}
    raw: list[bytes] = []
    for function, pdu in READ_ONLY_REQUESTS.items():
        try:
            result = client.exchange(pdu)
            results[str(function)] = {
                "supported": result.function == function,
                "exception_code": result.exception_code,
            }
            raw.append(result.response)
        except (OSError, ValueError, ConnectionError) as exc:
            results[str(function)] = {"state": "unavailable", "error": str(exc)}
    bitmap = 0
    for function_key, result in results.items():
        if result.get("supported"):
            bitmap |= 1 << int(function_key)
    return Observation(
        probe_id="modbus.read_only_functions",
        feature="modbus.read_only_function_bitmap",
        value={"functions": results, "bitmap_hex": hex(bitmap)},
        raw=b"\n".join(raw),
    )


def _address_is_valid(client: ModbusClient, function: int, address: int) -> bool | None:
    try:
        result = client.exchange(struct.pack(">BHH", function, address, 1))
    except (OSError, ValueError, ConnectionError):
        return None
    if result.function == function:
        return True
    if result.exception_code == 2:
        return False
    return None


def _find_boundary(client: ModbusClient, function: int) -> tuple[int | None, str]:
    zero = _address_is_valid(client, function, 0)
    if zero is False:
        return None, "address_zero_illegal"
    if zero is None:
        return None, "unsupported_or_unavailable"
    low, high = 0, 65535
    while low < high:
        midpoint = (low + high + 1) // 2
        valid = _address_is_valid(client, function, midpoint)
        if valid is None:
            return None, "inconclusive"
        if valid:
            low = midpoint
        else:
            high = midpoint - 1
    return low, "observed"


def _probe_boundaries(client: ModbusClient) -> Observation:
    names = {1: "coils", 2: "discrete_inputs", 4: "input_registers", 3: "holding_registers"}
    results: dict[str, Any] = {}
    for function, name in names.items():
        maximum, state = _find_boundary(client, function)
        results[name] = {"max_address": maximum, "state": state, "function": function}
    return Observation(
        probe_id="modbus.address_boundaries",
        feature="modbus.address_space.boundaries",
        value=results,
    )


def _probe_timing(client: ModbusClient, samples: int = 30) -> Observation:
    timings: list[float] = []
    errors = 0
    raw: list[bytes] = []
    for _ in range(samples):
        try:
            result = client.exchange(READ_ONLY_REQUESTS[3])
            timings.append(result.latency_ms)
            raw.append(result.response)
        except (OSError, ValueError, ConnectionError):
            errors += 1
    if not timings:
        return Observation(
            probe_id="modbus.timing",
            feature="modbus.timing.distribution",
            state=ProbeState.UNAVAILABLE,
            value={"samples_requested": samples, "errors": errors},
            error="no successful timing samples",
        )
    ordered = sorted(timings)

    def percentile(fraction: float) -> float:
        index = min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1)
        return ordered[index]

    return Observation(
        probe_id="modbus.timing",
        feature="modbus.timing.distribution",
        value={
            "samples_requested": samples,
            "samples": len(timings),
            "errors": errors,
            "p50_ms": round(statistics.median(timings), 3),
            "p90_ms": round(percentile(0.9), 3),
            "stdev_ms": round(statistics.pstdev(timings), 3),
        },
        raw=b"\n".join(raw),
    )


def probe_modbus(
    target: ResolvedTarget,
    scheduler: ProbeScheduler,
    *,
    profile: ScanProfile,
    port: int = 502,
) -> list[Observation]:
    client = ModbusClient(target, scheduler, port)
    observations = [_probe_device_id(client), _probe_unit_ids(client)]
    if profile in {ScanProfile.STANDARD, ScanProfile.LAB}:
        observations.extend(
            [_probe_function_bitmap(client), _probe_boundaries(client), _probe_timing(client)]
        )
    return observations
