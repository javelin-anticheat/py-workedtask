"""Optional startup integrity guard for the script that is actually running."""

import hashlib
import hmac
import os
from pathlib import Path
import re
import sys

INTEGRITY_FAILURE = 3


class IntegrityError(Exception):
    """The configured integrity baseline could not be verified."""


def verify_integrity(path, expected):
    """Return False when disabled; True when verified; otherwise fail closed."""
    if expected is None:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
        raise IntegrityError("JAVELIN_EXPECTED_SHA256 must contain exactly 64 hexadecimal characters")
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as script:
            for chunk in iter(lambda: script.read(64 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise IntegrityError("cannot read the running script") from error
    if not hmac.compare_digest(digest.hexdigest(), expected.lower()):
        raise IntegrityError("SHA-256 mismatch")
    return True


def main():
    try:
        verified = verify_integrity(__file__, os.environ.get("JAVELIN_EXPECTED_SHA256"))
    except IntegrityError as error:
        print(f"[Javelin AntiCheat] Integrity check failed: {error}. Exiting.", file=sys.stderr)
        return INTEGRITY_FAILURE
    status = "verified" if verified else "disabled (JAVELIN_EXPECTED_SHA256 is unset)"
    print(f"[Javelin AntiCheat] Script integrity {status}.")
    # Place application startup after the guard; failure must never continue here.
    print("[Javelin AntiCheat] All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
