import hashlib
import hmac
import os
import string
import sys
from pathlib import Path


INTEGRITY_ERROR_CODE = 33
_HEX_DIGITS = set(string.hexdigits)


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_valid_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(char in _HEX_DIGITS for char in value)


def verify_script_integrity(expected_sha256: str, script_path: Path) -> bool:
    expected = (expected_sha256 or "").strip().lower()
    if not expected:
        return True
    if not is_valid_sha256(expected):
        return False
    current = compute_sha256(script_path).lower()
    return hmac.compare_digest(current, expected)


def run_guarded(script_path: Path | None = None) -> int:
    path = (script_path or Path(__file__)).resolve()
    expected = os.getenv("JAVELIN_EXPECTED_SHA256", "")
    if not verify_script_integrity(expected, path):
        print(
            "[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch or invalid expected hash). Exiting.",
            file=sys.stderr,
        )
        raise SystemExit(INTEGRITY_ERROR_CODE)
    print("[Javelin AntiCheat] Integrity check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_guarded(Path(sys.argv[0])))
