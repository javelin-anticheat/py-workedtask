"""
integrity/verify.py
===================
SHA-256 integrity verification for Python scripts.

Usage
-----
Place this call at the very top of your script (before any other logic):

    from integrity import verify_script_integrity
    verify_script_integrity(__file__)

Set the expected digest in the environment before running:

    export JAVELIN_EXPECTED_SHA256="<sha256 hex digest of your script>"

See docs/integrity_verification.md for the full workflow.
"""

import hashlib
import hmac
import os
import sys
from pathlib import Path

_DEFAULT_ENV_VAR = "JAVELIN_EXPECTED_SHA256"


class IntegrityError(RuntimeError):
    """Raised when a script's SHA-256 digest does not match the expected value."""


def _compute_sha256(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _guarded_exit(message: str) -> None:
    """Print *message* to stderr and exit with code 1 (guarded exit)."""
    print(f"[javelin-anticheat] INTEGRITY VIOLATION: {message}", file=sys.stderr)
    sys.exit(1)


def verify_script_integrity(
    script_path: str | os.PathLike,
    *,
    strict: bool = False,
    env_var: str = _DEFAULT_ENV_VAR,
) -> None:
    """Verify the SHA-256 digest of *script_path* against ``JAVELIN_EXPECTED_SHA256``.

    Parameters
    ----------
    script_path:
        Path to the script file to hash.  Pass ``__file__`` from the calling
        module for the most common use-case.
    strict:
        When ``True``, treat a missing env-var as a mismatch and exit.
        When ``False`` (default), skip the check if the env-var is not set.
    env_var:
        Name of the environment variable that holds the expected hex digest.
        Defaults to ``JAVELIN_EXPECTED_SHA256``.

    Raises
    ------
    IntegrityError
        Re-raised *only* in unit-test scenarios where ``sys.exit`` is mocked.
        In production the process exits with code 1 before the exception
        propagates.
    """
    expected = os.environ.get(env_var)

    if expected is None:
        if strict:
            _guarded_exit(
                f"Environment variable '{env_var}' is not set "
                "(strict mode requires an expected hash)."
            )
        # Non-strict: silently skip when no expected hash is configured.
        return

    expected = expected.strip().lower()
    if len(expected) != 64:
        _guarded_exit(
            f"'{env_var}' does not look like a valid SHA-256 hex digest "
            f"(got {len(expected)} characters, expected 64)."
        )

    resolved = Path(script_path).resolve()
    if not resolved.is_file():
        _guarded_exit(f"Script path '{resolved}' is not a readable file.")

    actual = _compute_sha256(resolved)

    # Constant-time comparison to prevent timing side-channels.
    if not hmac.compare_digest(actual, expected):
        _guarded_exit(
            f"Hash mismatch for '{resolved}'.\n"
            f"  expected : {expected}\n"
            f"  actual   : {actual}\n"
            "The script may have been tampered with."
        )
