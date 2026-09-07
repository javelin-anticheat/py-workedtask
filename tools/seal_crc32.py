"""Append a CRC32 correction to a fresh build, without changing its input file."""

import argparse
from pathlib import Path
import zlib


def crc32_suffix(data, target):
    """Find four bytes making IEEE CRC32(data + suffix) equal target."""
    if not 0 <= target <= 0xFFFFFFFF:
        raise ValueError("expected CRC32 must fit in 32 bits")

    prefix_crc = zlib.crc32(data)
    baseline = zlib.crc32(bytes(4), prefix_crc)
    basis = {}
    for bit in range(32):
        suffix = (1 << bit).to_bytes(4, "little")
        value = zlib.crc32(suffix, prefix_crc) ^ baseline
        combination = 1 << bit
        while value:
            pivot = value.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (value, combination)
                break
            vector, vector_combination = basis[pivot]
            value ^= vector
            combination ^= vector_combination
        if not value:
            raise RuntimeError("CRC32 correction matrix is not invertible")

    remainder = target ^ baseline
    solution = 0
    while remainder:
        pivot = remainder.bit_length() - 1
        vector, combination = basis[pivot]
        remainder ^= vector
        solution ^= combination

    suffix = solution.to_bytes(4, "little")
    if zlib.crc32(suffix, prefix_crc) != target:
        raise RuntimeError("CRC32 correction verification failed")
    return suffix


def seal_bytes(data, target):
    """Preserve already-sealed data; otherwise append exactly four bytes."""
    if not 0 <= target <= 0xFFFFFFFF:
        raise ValueError("expected CRC32 must fit in 32 bits")
    if zlib.crc32(data) == target:
        return data
    return data + crc32_suffix(data, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="fresh, unsigned linker output")
    parser.add_argument("output", type=Path, help="new file; existing files are not overwritten")
    parser.add_argument("--expected", required=True, type=lambda value: int(value, 0))
    args = parser.parse_args()
    if not 1 <= args.expected <= 0xFFFFFFFF:
        parser.error("--expected must be 1..0xffffffff (zero disables the C++ guard)")

    try:
        original = args.input.read_bytes()
        sealed = seal_bytes(original, args.expected)
        # Exclusive creation also refuses an existing input/output alias.
        with args.output.open("xb") as output_file:
            output_file.write(sealed)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, "Could not seal executable: {}\n".format(error))
    print("CRC32={:08x}; wrote {} bytes to {}".format(
        zlib.crc32(sealed), len(sealed), args.output
    ))


if __name__ == "__main__":
    main()
