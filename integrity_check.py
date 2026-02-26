import hashlib
import os
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256")
    if not expected:
        print("[Javelin AntiCheat] JAVELIN_EXPECTED_SHA256 not set; skipping integrity check")
        return 0

    expected = expected.strip().lower()
    script_path = Path(__file__).resolve()
    actual = sha256_file(script_path)

    if actual != expected:
        print("[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch)")
        print(f"expected={expected}")
        print(f"actual  ={actual}")
        return 2

    print("[Javelin AntiCheat] Integrity check OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
