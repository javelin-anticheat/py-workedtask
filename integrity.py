#!/usr/bin/env python3
"""Javelin Integrity Verification — Python implementation.

Computes the SHA-256 hash of the running script and compares it
to the value stored in the ``JAVELIN_EXPECTED_SHA256`` environment
variable.  If the hashes do not match the process exits immediately.

Usage
-----
Import early in your main script::

    import integrity
    integrity.verify()          # exits if tampered

Or run standalone to print the hash for embedding::

    $ python integrity.py guard.py
    SHA-256: a1b2c3d4...

Set the expected hash in your environment before running the
guarded script::

    $ export JAVELIN_EXPECTED_SHA256=a1b2c3d4...
    $ python guard.py
"""

from __future__ import annotations

import hashlib
import os
import sys


def compute_sha256(filepath: str) -> str:
    """Return the hex-encoded SHA-256 digest of *filepath*."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def verify(
    script_path: str | None = None,
    env_var: str = "JAVELIN_EXPECTED_SHA256",
    *,
    exit_on_fail: bool = True,
) -> bool:
    """Verify the integrity of the running script.

    Parameters
    ----------
    script_path:
        Path to the script to check.  Defaults to the ``__main__``
        module's ``__file__`` attribute (i.e. the entry-point script).
    env_var:
        Name of the environment variable holding the expected hash.
    exit_on_fail:
        If ``True`` (default) the process terminates with code 1 when
        the hash does not match.  Set to ``False`` to return a bool
        instead.

    Returns
    -------
    bool
        ``True`` when the hashes match.  Only reachable when
        *exit_on_fail* is ``False``.
    """
    if script_path is None:
        main = sys.modules.get("__main__")
        script_path = getattr(main, "__file__", None)
        if script_path is None:
            _fail("Cannot determine script path", exit_on_fail)
            return False

    expected = os.environ.get(env_var, "").strip().lower()
    if not expected:
        _fail(
            f"Environment variable {env_var} is not set — "
            "cannot verify integrity",
            exit_on_fail,
        )
        return False

    actual = compute_sha256(script_path)

    if actual != expected:
        _fail(
            f"Integrity check FAILED\n"
            f"  expected: {expected}\n"
            f"  actual:   {actual}",
            exit_on_fail,
        )
        return False

    return True


def _fail(message: str, exit_on_fail: bool) -> None:
    print(f"[Javelin Integrity] {message}", file=sys.stderr)
    if exit_on_fail:
        sys.exit(1)


# ---- CLI helper: print hash of a file ----

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <script>")
        sys.exit(2)
    for path in sys.argv[1:]:
        digest = compute_sha256(path)
        print(f"SHA-256 ({path}): {digest}")


if __name__ == "__main__":
    main()
