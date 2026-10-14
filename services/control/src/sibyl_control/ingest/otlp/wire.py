"""Protocol Buffers wire format, the subset OTLP needs, with bounds checks on every read.

No dependency on ``protobuf``: OTLP messages use only varint, fixed64, fixed32 and
length-delimited fields, so a ~100-line reader keeps the 16 MiB untrusted-input parser small
and auditable. Groups (wire types 3/4) are refused; unknown fields are skipped by wire type.
Fixtures produced by the official ``opentelemetry-proto`` encoder pin compatibility.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator

VARINT, FIXED64, LEN, FIXED32 = 0, 1, 2, 5
_MAX_VARINT_BYTES = 10
_U64 = (1 << 64) - 1


class WireError(ValueError):
    """The bytes are not a well-formed protobuf message."""


Field = tuple[int, int, int, int]
"""(field number, wire type, value or start offset, end offset); ``end`` is -1 for scalars."""


def read_varint(buf: memoryview, pos: int, end: int) -> tuple[int, int]:
    result = 0
    shift = 0
    for i in range(_MAX_VARINT_BYTES):
        if pos >= end:
            raise WireError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if i == _MAX_VARINT_BYTES - 1 and byte > 1:
                raise WireError("varint overflows 64 bits")
            return result & _U64, pos
        shift += 7
    raise WireError("varint longer than 10 bytes")


def fields(buf: memoryview, start: int, end: int) -> Iterator[Field]:
    pos = start
    while pos < end:
        tag, pos = read_varint(buf, pos, end)
        number, wire_type = tag >> 3, tag & 0x07
        if number == 0:
            raise WireError("field number 0")
        if wire_type == VARINT:
            value, pos = read_varint(buf, pos, end)
            yield number, wire_type, value, -1
        elif wire_type == FIXED64:
            if pos + 8 > end:
                raise WireError("truncated fixed64")
            yield number, wire_type, pos, pos + 8
            pos += 8
        elif wire_type == FIXED32:
            if pos + 4 > end:
                raise WireError("truncated fixed32")
            yield number, wire_type, pos, pos + 4
            pos += 4
        elif wire_type == LEN:
            length, pos = read_varint(buf, pos, end)
            if length > end - pos:
                raise WireError("length-delimited field runs past the message")
            yield number, wire_type, pos, pos + length
            pos += length
        else:
            raise WireError(f"unsupported wire type {wire_type}")


def as_int64(value: int) -> int:
    return value - (1 << 64) if value >= 1 << 63 else value


def fixed64(buf: memoryview, start: int) -> int:
    value: int = struct.unpack_from("<Q", buf, start)[0]
    return value


def double(buf: memoryview, start: int) -> float:
    value: float = struct.unpack_from("<d", buf, start)[0]
    return value


def text(buf: memoryview, start: int, end: int) -> str:
    try:
        return bytes(buf[start:end]).decode("utf-8")
    except UnicodeDecodeError:
        raise WireError("string field is not valid UTF-8") from None


def expect(wire_type: int, wanted: int, what: str) -> None:
    if wire_type != wanted:
        raise WireError(f"{what} has wire type {wire_type}, expected {wanted}")


# -- encoding (responses only) --------------------------------------------------------------


def encode_varint(value: int) -> bytes:
    value &= _U64
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_len(number: int, payload: bytes) -> bytes:
    return encode_varint(number << 3 | LEN) + encode_varint(len(payload)) + payload


def encode_uint(number: int, value: int) -> bytes:
    return encode_varint(number << 3 | VARINT) + encode_varint(value)
