"""Optional SHA-256 integrity guard for this script (no process inspection)."""

import hashlib
import hmac
import os
from pathlib import Path
import re
import sys


INTEGRITY_EXIT_CODE = 3


def check_script_integrity(script_path, expected_sha256):
    """Return False for a configured invalid hash, unreadable file or mismatch."""
    if expected_sha256 is None:
        return True
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        return False

    digest = hashlib.sha256()
    try:
        with Path(script_path).open("rb") as script_file:
            for chunk in iter(lambda: script_file.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return False
    return hmac.compare_digest(digest.hexdigest(), expected_sha256.lower())


def main():
    expected_sha256 = os.environ.get("JAVELIN_EXPECTED_SHA256")
    if not check_script_integrity(Path(__file__), expected_sha256):
        print(
            "[Javelin AntiCheat] Integrity check failed "
            "(invalid SHA-256, unreadable script or mismatch). Exiting.",
            file=sys.stderr,
        )
        return INTEGRITY_EXIT_CODE
    print("[Javelin AntiCheat] Integrity check passed or is disabled. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
