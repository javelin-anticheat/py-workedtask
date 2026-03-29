"""
integrity/__main__.py
=====================
CLI helper — print the SHA-256 digest of a file to stdout.

Usage
-----
    python -m integrity <path-to-script>

Example
-------
    python -m integrity workedtask.py
    # 3b4c… (64 hex chars)

    # Then export the digest so the guard can verify it at runtime:
    export JAVELIN_EXPECTED_SHA256=$(python -m integrity workedtask.py)
"""

from __future__ import annotations

import sys
from pathlib import Path

from .checker import compute_sha256


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python -m integrity <path-to-file>", file=sys.stderr)
        sys.exit(2)

    target = Path(sys.argv[1])
    try:
        digest = compute_sha256(target)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(digest)


if __name__ == "__main__":
    main()
