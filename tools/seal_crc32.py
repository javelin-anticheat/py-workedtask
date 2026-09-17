"""Seal an unsigned Windows PE executable to a chosen build-time CRC32.

The four-byte overlay is part of the hash. It resolves the circular dependency
between compiling an expected checksum and hashing the final executable.
CRC32 detects accidental changes; an attacker can also recompute this seal.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import struct
import tempfile
import zlib


def correction(prefix_crc: int, target: int) -> bytes:
    """Solve the 32-bit affine CRC map for four appended bytes over GF(2)."""
    if not 0 <= target <= 0xFFFFFFFF:
        raise ValueError("expected CRC32 must be an unsigned 32-bit integer")
    base = zlib.crc32(bytes(4), prefix_crc)
    basis: dict[int, tuple[int, int]] = {}
    for bit in range(32):
        vector = zlib.crc32((1 << bit).to_bytes(4, "little"), prefix_crc) ^ base
        coefficients = 1 << bit
        while vector:
            pivot = vector.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = vector, coefficients
                break
            other, mask = basis[pivot]
            vector ^= other
            coefficients ^= mask
    result = 0
    remaining = target ^ base
    while remaining:
        vector, mask = basis[remaining.bit_length() - 1]
        remaining ^= vector
        result ^= mask
    return result.to_bytes(4, "little")


def validate_unsigned_pe(data: bytes) -> None:
    """Reject truncated/malformed headers and signed images before modifying bytes."""
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not a Windows PE executable")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe < 64 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature or header offset")
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    sections = optional + optional_size
    if not section_count or optional_size < 2 or sections + 40 * section_count > len(data):
        raise ValueError("truncated PE headers or section table")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unsupported PE optional-header format")
    directories = 96 if magic == 0x10B else 112
    if optional_size < directories:
        raise ValueError("truncated PE optional header")
    directory_count = struct.unpack_from("<I", data, optional + directories - 4)[0]
    if directories + directory_count * 8 > optional_size:
        raise ValueError("truncated PE data directories")
    if directory_count > 4:
        certificate = struct.unpack_from("<II", data, optional + directories + 4 * 8)
        if certificate != (0, 0):
            raise ValueError("signed executables cannot be sealed; use an unsigned build")
    for index in range(section_count):
        raw_size, raw_offset = struct.unpack_from("<II", data, sections + index * 40 + 16)
        if raw_size and (raw_offset < sections + 40 * section_count or raw_offset + raw_size > len(data)):
            raise ValueError("invalid PE section extent")


def seal(path: Path, target: int) -> int:
    if not 0 <= target <= 0xFFFFFFFF:
        raise ValueError("expected CRC32 must be an unsigned 32-bit integer")
    data = path.read_bytes()
    validate_unsigned_pe(data)
    current = zlib.crc32(data)
    if current == target:
        return current
    sealed = data + correction(current, target)
    if zlib.crc32(sealed) != target:
        raise ValueError("CRC32 sealing verification failed")
    # Replace atomically only after validating all bytes, preserving executable mode.
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(sealed)
        os.chmod(temporary, path.stat().st_mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("expected_crc32", type=lambda value: int(value, 0))
    args = parser.parse_args()
    try:
        result = seal(args.executable, args.expected_crc32)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Cannot seal executable: {exc}\n")
    print(f"Sealed {args.executable}: CRC32=0x{result:08X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
