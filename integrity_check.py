"""
integrity_check.py — SHA-256 self-integrity verification for py-workedtask.

Usage
-----
1. Generate the expected hash for your script:

       python integrity_check.py --hash <path/to/your_script.py>

   This prints the SHA-256 hex-digest you should store as an environment variable.

2. Set the environment variable before running your protected script:

       export JAVELIN_EXPECTED_SHA256="<hex-digest-from-step-1>"   # Linux/macOS
       set  JAVELIN_EXPECTED_SHA256=<hex-digest-from-step-1>       # Windows CMD

3. Call `verify_script_integrity(__file__)` at the very top of your script
   (before any other logic).  If the hash does not match, the process exits
   immediately with a non-zero status code.

Environment variables
---------------------
JAVELIN_EXPECTED_SHA256
    The expected SHA-256 hex-digest of the script file.  When this variable is
    **not set** the check is skipped with a warning so that development
    workflows are not interrupted.  In production, always set this variable.
"""

from __future__ import annotations

import hashlib
import os
import sys
import argparse
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ENV_VAR = "JAVELIN_EXPECTED_SHA256"


def compute_file_sha256(path: str) -> str:
    """Return the lowercase hex SHA-256 digest of *path*.

    The file is read in binary mode in 64 KiB chunks so that large files do
    not cause excessive memory usage.

    Parameters
    ----------
    path:
        Filesystem path to the file that should be hashed.

    Returns
    -------
    str
        Lowercase hex string, e.g. ``"a3f1…"``.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    OSError
        If the file cannot be opened/read.
    """
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_script_integrity(script_path: str) -> None:
    """Verify that *script_path* matches the expected SHA-256 stored in the
    ``JAVELIN_EXPECTED_SHA256`` environment variable.

    Behaviour
    ---------
    * If ``JAVELIN_EXPECTED_SHA256`` is **not set**: logs a warning and
      returns without raising so that development / test runs are not broken.
    * If the digest **matches**: returns silently.
    * If the digest **does not match**: logs a critical error and calls
      ``sys.exit(1)`` — the *guarded exit* required by the acceptance criteria.

    Parameters
    ----------
    script_path:
        The path of the script whose integrity should be verified.  Pass
        ``__file__`` from the script you want to protect.

    Example
    -------
    ::

        # my_protected_script.py
        from integrity_check import verify_script_integrity
        verify_script_integrity(__file__)

        # … rest of your script …
    """
    expected = os.environ.get(ENV_VAR)

    if expected is None:
        logger.warning(
            "Integrity check skipped: %s is not set. "
            "Set this environment variable in production to enable tamper detection.",
            ENV_VAR,
        )
        return

    expected = expected.strip().lower()

    # Resolve to an absolute path so that __file__ values like "./foo.py" work
    resolved_path = os.path.realpath(script_path)

    try:
        actual = compute_file_sha256(resolved_path)
    except OSError as exc:
        logger.critical(
            "Integrity check failed: could not read '%s': %s. Exiting.",
            resolved_path,
            exc,
        )
        sys.exit(1)

    if actual != expected:
        logger.critical(
            "INTEGRITY VIOLATION: SHA-256 of '%s' does not match expected value.\n"
            "  expected : %s\n"
            "  actual   : %s\n"
            "The script may have been tampered with. Exiting.",
            resolved_path,
            expected,
            actual,
        )
        sys.exit(1)

    logger.info("Integrity check passed for '%s'.", resolved_path)


# ---------------------------------------------------------------------------
# CLI helper — run as `python integrity_check.py --hash <file>`
# ---------------------------------------------------------------------------

def _cli() -> None:
    """Command-line interface for generating the expected hash value."""
    parser = argparse.ArgumentParser(
        prog="integrity_check",
        description=(
            "Compute the SHA-256 hash of a Python script so you can store it "
            "in the JAVELIN_EXPECTED_SHA256 environment variable."
        ),
    )
    parser.add_argument(
        "--hash",
        metavar="FILE",
        required=True,
        help="Path to the Python script whose SHA-256 should be computed.",
    )
    args = parser.parse_args()

    try:
        digest = compute_file_sha256(args.hash)
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(digest)
    print(
        f"\nSet this as your environment variable:\n"
        f"  export {ENV_VAR}={digest}   # Linux / macOS\n"
        f"  set    {ENV_VAR}={digest}   # Windows CMD",
        file=sys.stderr,
    )


if __name__ == "__main__":
    _cli()
