"""Self-integrity verification guard for Python scripts using SHA-256.

Computes the SHA-256 digest of the executing script and compares it against
the JAVELIN_EXPECTED_SHA256 environment variable, terminating execution immediately
with exit code 13 if tampering is detected.
"""

import hashlib
import hmac
import os
import pathlib
import sys
from typing import Optional

TAG: str = "[Javelin AntiCheat] "
EXIT_INTEGRITY_FAILED: int = 13


def compute_file_sha256(file_path: pathlib.Path) -> str:
    """Compute lowercase hex-encoded SHA-256 digest of a file on disk."""
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest().lower()


def verify_script_integrity(
    script_path: Optional[pathlib.Path] = None,
    expected_sha256: Optional[str] = None,
) -> bool:
    """Verify script SHA-256 against JAVELIN_EXPECTED_SHA256 and exit on mismatch."""
    expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get("JAVELIN_EXPECTED_SHA256", "")
    ).strip().lower()
    if not expected:
        return True

    target = (script_path or pathlib.Path(sys.argv[0])).resolve()
    if not target.is_file():
        sys.stderr.write(f"{TAG}Integrity check failed (script path unreadable). Exiting.\n")
        sys.exit(EXIT_INTEGRITY_FAILED)

    actual = compute_file_sha256(target)
    if not hmac.compare_digest(actual, expected):
        sys.stderr.write(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.\n")
        sys.exit(EXIT_INTEGRITY_FAILED)

    return True


if __name__ == "__main__":
    print(f"{TAG}starting checks...")
    verify_script_integrity()
    print(f"{TAG}All clear. Continue.")
