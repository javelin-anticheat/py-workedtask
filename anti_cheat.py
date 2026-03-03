import hashlib
import os
import sys
from pathlib import Path


INTEGRITY_ERROR_CODE = 33


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def verify_script_integrity(expected_sha256: str, script_path: Path) -> bool:
    expected = (expected_sha256 or "").strip().lower()
    if not expected:
        return True
    if len(expected) != 64:
        return False
    current = compute_sha256(script_path).lower()
    return current == expected


def run_guarded(script_path: Path | None = None) -> int:
    path = (script_path or Path(__file__)).resolve()
    expected = os.getenv("JAVELIN_EXPECTED_SHA256", "")
    if not verify_script_integrity(expected, path):
        print(
            "[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch). Exiting.",
            file=sys.stderr,
        )
        raise SystemExit(INTEGRITY_ERROR_CODE)
    print("[Javelin AntiCheat] Integrity check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_guarded(Path(sys.argv[0])))
