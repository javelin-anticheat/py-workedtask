"""
integrity/verify.py
-------------------
SHA-256-based integrity verification for Python scripts.

Usage
-----
Set the environment variable ``JAVELIN_EXPECTED_SHA256`` to the expected
hex-digest of the script before launching it, then call
``verify_script_integrity(__file__)`` at the top of your entry-point.

If the digest does not match, ``_guarded_exit`` raises ``IntegrityError``
**and** calls ``sys.exit(1)`` so the process terminates whether or not the
caller catches the exception.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

class IntegrityError(RuntimeError):
    """Raised when a script's SHA-256 digest does not match the expected value.

    This exception is raised by :func:`verify_script_integrity` (via
    ``_guarded_exit``) before ``sys.exit(1)`` is called.  In normal
    production use the process will exit immediately after the raise; in
    unit-test scenarios you can mock ``sys.exit`` **and** catch
    ``IntegrityError`` to inspect failure details without the process
    actually terminating.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_sha256(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*.

    Parameters
    ----------
    path:
        Resolved, absolute path to the file to hash.

    Returns
    -------
    str
        Lowercase hexadecimal SHA-256 digest.

    Raises
    ------
    OSError
        If the file cannot be opened or read (e.g. permission denied,
        file removed between resolution and open, transient I/O error).
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _guarded_exit(script_path: Path, actual: str, expected: str) -> None:
    """Raise :exc:`IntegrityError` and call ``sys.exit(1)``.

    The exception is raised *first* so that unit tests that mock
    ``sys.exit`` can still catch and inspect the failure.  In production
    the ``sys.exit(1)`` call that follows will terminate the process
    regardless.

    Parameters
    ----------
    script_path:
        Path of the script whose digest did not match.
    actual:
        The digest that was computed.
    expected:
        The digest that was expected.
    """
    message = (
        f"Integrity check failed for '{script_path}'.\n"
        f"  expected : {expected}\n"
        f"  actual   : {actual}"
    )
    try:
        raise IntegrityError(message)
    finally:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_script_integrity(script_file: str | os.PathLike[str]) -> None:
    """Verify the SHA-256 integrity of *script_file*.

    Reads the ``JAVELIN_EXPECTED_SHA256`` environment variable for the
    expected digest.  If the variable is not set the check is skipped
    silently (opt-in behaviour).  If it *is* set and the computed digest
    does not match, :func:`_guarded_exit` raises :exc:`IntegrityError`
    **and** calls ``sys.exit(1)``.

    Parameters
    ----------
    script_file:
        Path to the script to verify — typically pass ``__file__`` from
        your entry-point module.

    Raises
    ------
    IntegrityError
        When ``JAVELIN_EXPECTED_SHA256`` is set and the file's digest does
        not match.  ``sys.exit(1)`` is also called immediately after the
        raise, so the process exits via ``sys.exit(1)`` on mismatch in
        normal (non-mocked) execution.
    OSError
        If the file cannot be read (e.g. permission denied, missing file).
        The caller is responsible for deciding how to handle unreadable
        files; the integrity check does **not** silently pass in that case.

    Examples
    --------
    Place this at the very top of your entry-point script::

        from integrity import verify_script_integrity
        verify_script_integrity(__file__)   # exits via sys.exit(1) on mismatch

    The function returns ``None`` silently when the check passes or when
    ``JAVELIN_EXPECTED_SHA256`` is not set.
    """
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256")
    if not expected:
        # Opt-in: skip check when variable is absent.
        return

    resolved = Path(script_file).resolve()
    # Let OSError/PermissionError propagate to the caller rather than
    # swallowing it; a file we cannot read should not silently pass.
    actual = _compute_sha256(resolved)

    if actual.lower() != expected.lower():
        _guarded_exit(resolved, actual, expected.lower())
