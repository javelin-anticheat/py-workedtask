#!/usr/bin/env python3
"""
Javelin optional script integrity check (issue #4).

Computes SHA-256 of this script file and compares to JAVELIN_EXPECTED_SHA256.
On mismatch: guarded exit (non-zero). If the env var is unset/empty, skip check.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

EXIT_INTEGRITY = 0xC1  # guarded integrity failure


def script_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_integrity(path: Path | None = None) -> int:
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip().lower()
    if not expected:
        print("[Javelin] JAVELIN_EXPECTED_SHA256 unset; integrity check skipped.")
        return 0

    target = path or Path(__file__).resolve()
    actual = script_sha256(target)
    if actual.lower() != expected:
        print(
            f"[Javelin] Integrity check FAILED.\n"
            f"  expected={expected}\n"
            f"  actual  ={actual}\n"
            f"Guarded exit.",
            file=sys.stderr,
        )
        return EXIT_INTEGRITY

    print("[Javelin] Integrity check OK.")
    return 0


def main() -> int:
    code = verify_integrity()
    if code != 0:
        return code
    print("[Javelin] All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
