"""Optional SHA-256 guard for this Python entry script."""

import hashlib
import hmac
import os
from pathlib import Path
import re
import sys


def verify_script(path: Path, expected: str | None) -> bool:
    """An absent baseline disables checking; malformed baselines fail closed."""
    if expected is None:
        return True
    if re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
        return False
    try:
        with path.open("rb") as script:
            actual = hashlib.file_digest(script, "sha256").hexdigest()
    except OSError:
        return False
    return hmac.compare_digest(actual, expected.lower())


def main() -> int:
    if not verify_script(Path(__file__).resolve(), os.environ.get("JAVELIN_EXPECTED_SHA256")):
        print("[Javelin AntiCheat] Script integrity check failed. Exiting.", file=sys.stderr)
        return 3
    print("[Javelin AntiCheat] Script integrity check passed or disabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
