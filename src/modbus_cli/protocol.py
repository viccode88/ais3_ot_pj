"""Local Modbus TCP models and codecs; deliberately independent of vendor libraries."""

from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, field
from typing import Any

from .exceptions import PacketEncodingError

FUNCTIONS = {
    1: "read-coils",
    2: "read-discrete-inputs",
    3: "read-holding-registers",
    4: "read-input-registers",
    5: "write-single-coil",
    6: "write-single-register",
    15: "write-multiple-coils",
    16: "write-multiple-registers",
}
EXCEPTIONS = {
    1: "illegal-function",
    2: "illegal-data-address",
    3: "illegal-data-value",
    4: "server-device-failure",
    5: "acknowledge",
    6: "server-device-busy",
    8: "memory-parity-error",
    10: "gateway-path-unavailable",
    11: "gateway-target-no-response",
}


@dataclass(frozen=True)
class MBAPHeader:
    transaction_id: int = 1
    protocol_id: int = 0
    length: int = 0
    unit_id: int = 1

    def encode(self) -> bytes:
        try:
            return struct.pack(
                ">HHHB", self.transaction_id, self.protocol_id, self.length, self.unit_id
            )
        except struct.error as exc:
            raise PacketEncodingError(str(exc)) from exc


@dataclass
class DecodedPacket:
    raw_hex: str
    transaction_id: int | None = None
    protocol_id: int | None = None
    length: int | None = None
    unit_id: int | None = None
    function_code: int | None = None
    function_name: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    exception_code: int | None = None
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def pack_coils(values: list[int]) -> bytes:
    result = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if value:
            result[index // 8] |= 1 << (index % 8)
    return bytes(result)


def encode_pdu(
    function: int, address: int = 0, quantity: int = 1, values: list[int] | None = None
) -> bytes:
    if not 0 <= function <= 255 or not 0 <= address <= 65535:
        raise PacketEncodingError("function and address must fit their wire fields")
    if function in (1, 2, 3, 4):
        if not 1 <= quantity <= (2000 if function in (1, 2) else 125):
            raise PacketEncodingError("quantity is outside the Modbus limit")
        return struct.pack(">BHH", function, address, quantity)
    vals = values or []
    if function == 5:
        if len(vals) != 1 or vals[0] not in (0, 1, 0x0000, 0xFF00):
            raise PacketEncodingError("single coil value must be 0 or 1")
        return struct.pack(">BHH", function, address, 0xFF00 if vals[0] in (1, 0xFF00) else 0)
    if function == 6:
        if len(vals) != 1 or not 0 <= vals[0] <= 65535:
            raise PacketEncodingError("single register requires one uint16 value")
        return struct.pack(">BHH", function, address, vals[0])
    if function == 15:
        if not 1 <= len(vals) <= 1968:
            raise PacketEncodingError("multiple coils require 1..1968 values")
        packed = pack_coils(vals)
        return struct.pack(">BHHB", function, address, len(vals), len(packed)) + packed
    if function == 16:
        if not 1 <= len(vals) <= 123 or any(not 0 <= value <= 65535 for value in vals):
            raise PacketEncodingError("multiple registers require 1..123 uint16 values")
        data = struct.pack(f">{len(vals)}H", *vals)
        return struct.pack(">BHHB", function, address, len(vals), len(data)) + data
    return bytes([function]) + struct.pack(">HH", address, quantity)


def encode_adu(
    function: int,
    address: int = 0,
    quantity: int = 1,
    values: list[int] | None = None,
    *,
    transaction_id: int = 1,
    protocol_id: int = 0,
    unit_id: int = 1,
) -> bytes:
    pdu = encode_pdu(function, address, quantity, values)
    return MBAPHeader(transaction_id, protocol_id, len(pdu) + 1, unit_id).encode() + pdu


def decode_adu(data: bytes) -> DecodedPacket:
    """Best-effort decode that returns diagnostics for every byte string."""
    out = DecodedPacket(data.hex().upper())
    if len(data) < 7:
        out.warnings.append(f"truncated MBAP header: expected 7 bytes, got {len(data)}")
        return out
    out.transaction_id, out.protocol_id, out.length, out.unit_id = struct.unpack(">HHHB", data[:7])
    expected = 6 + out.length
    if expected != len(data):
        out.warnings.append(
            f"MBAP length mismatch: declares {expected} total bytes, received {len(data)}"
        )
    if out.protocol_id != 0:
        out.warnings.append("non-zero protocol id")
    if len(data) == 7:
        out.warnings.append("empty PDU")
        return out
    out.function_code = data[7]
    base_function = out.function_code & 0x7F
    out.function_name = FUNCTIONS.get(base_function, "unknown")
    pdu = data[8:]
    if out.function_code & 0x80:
        if pdu:
            out.exception_code = pdu[0]
            out.fields["exception_name"] = EXCEPTIONS.get(pdu[0], "unknown")
        else:
            out.warnings.append("truncated exception response")
        return out
    if base_function in (1, 2, 3, 4) and len(pdu) == 4:
        out.fields["address"], out.fields["quantity"] = struct.unpack(">HH", pdu)
    elif base_function in (5, 6) and len(pdu) >= 4:
        out.fields["address"], out.fields["value"] = struct.unpack(">HH", pdu[:4])
    elif base_function in (15, 16) and len(pdu) >= 5:
        address, quantity, count = struct.unpack(">HHB", pdu[:5])
        out.fields.update(
            address=address, quantity=quantity, byte_count=count, data_hex=pdu[5:].hex().upper()
        )
        if count != len(pdu[5:]):
            out.warnings.append("byte count mismatch")
    elif pdu:
        out.fields["data_hex"] = pdu.hex().upper()
    return out
