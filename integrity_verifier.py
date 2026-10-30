# File: integrity_verifier.py
# Target Issue: https://github.com/javelin-anticheat/py-workedtask/issues/4
# Author: Xuan Thinh (@thinhnx128) <thinhnx128@gmail.com>

import hashlib
import hmac
import os
import sys
from pathlib import Path
from typing import Optional

ENV_EXPECTED_HASH = "JAVELIN_EXPECTED_SHA256"

def compute_file_sha256(file_path: str | Path) -> str:
    """Computes the hex-encoded SHA-256 digest of the target script or executable."""
    path = Path(file_path).resolve()
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()

def verify_script_integrity(
    script_path: Optional[str | Path] = None,
    expected_sha256: Optional[str] = None,
    strict_env: bool = False,
) -> bool:
    """
    Verifies the SHA-256 hash of the running Python script against JAVELIN_EXPECTED_SHA256.
    Performs a guarded exit (sys.exit(1)) on hash mismatch to prevent tampered execution.
    """
    target_path = Path(script_path if script_path is not None else sys.argv[0]).resolve()
    expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get(ENV_EXPECTED_HASH, "").strip()
    ).lower()

    if not expected:
        if strict_env:
            sys.stderr.write(f"[Javelin Integrity] Missing required {ENV_EXPECTED_HASH} environment variable.\n")
            sys.exit(1)
        return True

    actual = compute_file_sha256(target_path)
    if not hmac.compare_digest(actual, expected):
        sys.stderr.write(
            f"[Javelin Integrity] Tampering detected in {target_path.name}! "
            f"Expected SHA-256 {expected}, got {actual}. Exiting.\n"
        )
        sys.exit(1)

    return True
