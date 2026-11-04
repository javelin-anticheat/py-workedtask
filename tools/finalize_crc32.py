"""Finalize a just-built PE so its whole-file CRC matches its build-time constant.

The four-byte CRC correction avoids a circular rebuild: embedding a checksum
changes the executable being checksummed. This is corruption detection, not a
cryptographic signature. Run before signing, packaging, or distributing a build.
"""

import argparse
from pathlib import Path
import zlib

MARKER = b"\x00JAVELIN-CRC32-V1\x00"


def correction(prefix, target):
    """Solve the affine 32-bit CRC mapping for a four-byte suffix over GF(2)."""
    prefix_crc = zlib.crc32(prefix)
    baseline = zlib.crc32(b"\0" * 4, prefix_crc)
    basis = {}
    for bit in range(32):
        vector = zlib.crc32((1 << bit).to_bytes(4, "little"), prefix_crc) ^ baseline
        mask = 1 << bit
        while vector:
            pivot = vector.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (vector, mask)
                break
            other, other_mask = basis[pivot]
            vector ^= other
            mask ^= other_mask
    remaining, answer = target ^ baseline, 0
    while remaining:
        pivot = remaining.bit_length() - 1
        vector, mask = basis[pivot]
        remaining ^= vector
        answer ^= mask
    return answer.to_bytes(4, "little")


def finalize(data, expected):
    if not 0 < expected <= 0xFFFFFFFF:
        raise ValueError("expected CRC must be a nonzero unsigned 32-bit integer")
    if not data.startswith(b"MZ"):
        raise ValueError("input must be a Windows executable (MZ header)")
    trailer_size = len(MARKER) + 4
    if len(data) >= trailer_size and data[-trailer_size:-4] == MARKER:
        data = data[:-trailer_size]
    prefix = data + MARKER
    result = prefix + correction(prefix, expected)
    if zlib.crc32(result) != expected:
        raise RuntimeError("CRC finalization verification failed")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("expected", type=lambda value: int(value, 0))
    args = parser.parse_args()
    try:
        result = finalize(args.executable.read_bytes(), args.expected)
        args.executable.write_bytes(result)
    except (OSError, ValueError) as error:
        parser.exit(1, f"CRC finalization failed: {error}\n")
    print(f"Finalized {args.executable.name}: whole-file CRC32 = 0x{args.expected:08X}")


if __name__ == "__main__":
    main()
