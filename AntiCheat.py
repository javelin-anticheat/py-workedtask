"""Optional script-integrity guard for the Javelin Python entry point."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import sys


INTEGRITY_FAILURE = 3


def check_integrity(script: Path, expected: str | None) -> bool:
    """Check raw file bytes; an absent baseline explicitly disables the guard.

    A present but empty, malformed, unreadable or mismatched baseline fails closed.
    Hexadecimal digests are case-insensitive; whitespace is not part of a digest.
    """
    if expected is None:
        return True
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
        return False
    try:
        with script.open("rb") as source:
            actual = hashlib.file_digest(source, "sha256").hexdigest()
    except OSError:
        return False
    return hmac.compare_digest(actual, expected.lower())


def main() -> int:
    if not check_integrity(Path(__file__).resolve(), os.environ.get("JAVELIN_EXPECTED_SHA256")):
        print("[Javelin AntiCheat] Integrity check failed. Exiting.", file=sys.stderr)
        return INTEGRITY_FAILURE
    print("[Javelin AntiCheat] All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
