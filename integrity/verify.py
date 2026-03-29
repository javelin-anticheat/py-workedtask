"""
integrity/verify.py
-------------------
SHA-256 integrity verification for Python task scripts.

Usage
-----
Set the environment variable ``JAVELIN_EXPECTED_SHA256`` to the expected
hex-encoded SHA-256 digest of the script before launching it, then call
``verify_script_integrity(__file__)`` near the top of the script.

If the digest does not match, an ``IntegrityError`` is raised and the process
exits with code 1 so that **no task work is performed on a tampered script
file**.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


class IntegrityError(RuntimeError):
    """Raised when a script's SHA-256 digest does not match the expected value.

    This exception is raised by ``verify_script_integrity`` (and internally by
    ``_guarded_exit``) on a mismatch.  The process then exits with code 1.
    In unit tests you can patch ``sys.exit`` *and* catch ``IntegrityError`` to
    assert that the verification path was reached without the process actually
    terminating.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_sha256(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*.

    Parameters
    ----------
    path:
        Absolute, resolved path to the file to hash.

    Returns
    -------
    str
        Lowercase hexadecimal SHA-256 digest string.

    Raises
    ------
    OSError
        If the file cannot be opened or read (e.g. permission denied,
        transient I/O error).  Callers should handle this explicitly.
    """
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _guarded_exit(message: str) -> None:
    """Raise ``IntegrityError`` with *message* and then call ``sys.exit(1)``.

    Raising ``IntegrityError`` first gives unit tests a stable exception to
    catch (via ``pytest.raises`` or ``unittest.TestCase.assertRaises``) without
    needing to mock ``sys.exit``.  In production the ``sys.exit(1)`` call
    terminates the process immediately after the raise (i.e. if the caller
    catches ``IntegrityError`` and does not re-raise, the exit still fires).

    Parameters
    ----------
    message:
        Human-readable description of the integrity failure.
    """
    exc = IntegrityError(message)
    try:
        raise exc
    finally:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_script_integrity(script_path: str) -> None:
    """Verify the SHA-256 digest of *script_path* against a known-good value.

    The expected digest is read from the ``JAVELIN_EXPECTED_SHA256``
    environment variable.  If the variable is unset the check is **skipped**
    (development mode).  If the variable is set and the digest does not match,
    ``IntegrityError`` is raised and the process exits via ``sys.exit(1)``.

    On a read error (``OSError``) the verification is treated as a failure:
    ``IntegrityError`` is raised and the process exits with code 1.

    Parameters
    ----------
    script_path:
        Path to the script file to verify — typically pass ``__file__``.

    Raises
    ------
    IntegrityError
        When the computed digest differs from ``JAVELIN_EXPECTED_SHA256``, or
        when the file cannot be read.

    Notes
    -----
    * The check exits via ``sys.exit(1)`` on mismatch so that **no task work
      is performed on a tampered script file**.
    * In unit tests, catching ``IntegrityError`` is sufficient to assert the
      failure path; mocking ``sys.exit`` is optional.
    """
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256")
    if not expected:
        # No expected hash configured — skip check (development / CI mode).
        return

    resolved = Path(script_path).resolve()

    try:
        actual = _compute_sha256(resolved)
    except OSError as exc:
        _guarded_exit(
            f"Integrity check failed: could not read '{resolved}': {exc}"
        )
        return  # unreachable; keeps type-checkers happy

    expected_normalised = expected.strip().lower()
    if actual != expected_normalised:
        _guarded_exit(
            f"Integrity check failed for '{resolved}'.\n"
            f"  expected: {expected_normalised}\n"
            f"  actual:   {actual}"
        )
