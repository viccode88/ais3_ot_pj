import pytest

from modbus_cli.exceptions import PacketEncodingError
from modbus_cli.protocol import MBAPHeader, decode_adu, encode_adu, pack_coils


def test_mbap_and_read_roundtrip() -> None:
    packet = encode_adu(3, 10, 2, transaction_id=42, unit_id=7)
    decoded = decode_adu(packet)
    assert decoded.transaction_id == 42
    assert decoded.unit_id == 7
    assert decoded.fields == {"address": 10, "quantity": 2}
    assert decoded.warnings == []


@pytest.mark.parametrize("function", [1, 2, 3, 4])
def test_read_functions(function: int) -> None:
    assert decode_adu(encode_adu(function, 0, 1)).function_code == function


@pytest.mark.parametrize(
    "function,values", [(5, [1]), (6, [123]), (15, [1, 0, 1]), (16, [1, 65535])]
)
def test_write_functions(function: int, values: list[int]) -> None:
    decoded = decode_adu(encode_adu(function, 4, values=values))
    assert decoded.function_code == function
    assert decoded.fields["address"] == 4


def test_coil_little_bit_order() -> None:
    assert pack_coils([1, 0, 1, 0, 0, 0, 0, 0, 1]) == b"\x05\x01"


def test_best_effort_truncated_and_extra() -> None:
    assert decode_adu(b"\x00").warnings
    decoded = decode_adu(encode_adu(3) + b"extra")
    assert "length mismatch" in decoded.warnings[0]


def test_exception_and_unknown_exception() -> None:
    decoded = decode_adu(MBAPHeader(1, 0, 3, 1).encode() + b"\x83\xfe")
    assert decoded.exception_code == 254
    assert decoded.fields["exception_name"] == "unknown"


def test_invalid_quantity() -> None:
    with pytest.raises(PacketEncodingError):
        encode_adu(3, quantity=0)


def test_arbitrary_bytes_never_raise() -> None:
    for length in range(300):
        decode_adu(bytes((index * 37) % 256 for index in range(length)))
