"""Append a four-byte CRC correction to an unsigned Windows executable."""

import argparse
from pathlib import Path
import zlib
import struct


def correction(data: bytes, target: int) -> bytes:
    """Solve the 32-bit linear system for an appended CRC32 correction."""
    if not 0 <= target <= 0xFFFFFFFF:
        raise ValueError("CRC32 must be between 0 and 0xffffffff")
    prefix_crc = zlib.crc32(data)
    baseline = zlib.crc32(bytes(4), prefix_crc)
    basis = {}
    for bit in range(32):
        value = zlib.crc32((1 << bit).to_bytes(4, "little"), prefix_crc) ^ baseline
        mask = 1 << bit
        while value != 0:
            pivot = value.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (value, mask)
                break
            other, combination = basis[pivot]
            value ^= other
            mask ^= combination
    value = target ^ baseline
    answer = 0
    while value != 0:
        pivot = value.bit_length() - 1
        other, combination = basis[pivot]
        value ^= other
        answer ^= combination
    return answer.to_bytes(4, "little")


def seal(path: Path, target: int) -> None:
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("Expected an unsigned Windows executable")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header")
    optional = pe + 24
    size = struct.unpack_from("<H", data, pe + 20)[0]
    if size < 2 or optional + size > len(data):
        raise ValueError("Invalid PE optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    directory = {0x10B: 96, 0x20B: 112}.get(magic)
    if directory is None or size < directory:
        raise ValueError("Unsupported PE optional header")
    count = struct.unpack_from("<I", data, optional + directory - 4)[0]
    if count > (size - directory) // 8:
        raise ValueError("Truncated PE data directories")
    if count > 4:
        certificate = struct.unpack_from("<II", data, optional + directory + 32)
        if certificate != (0, 0):
            raise ValueError("Refusing to seal a signed Windows executable")
    trailer = correction(data, target)
    if zlib.crc32(data + trailer) != target:
        raise ValueError("CRC correction verification failed")
    with path.open("ab") as executable:
        executable.write(trailer)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("target", type=lambda value: int(value, 0))
    args = parser.parse_args()
    seal(args.executable, args.target)
    print(f"Sealed executable to CRC32 {args.target:08x}")
