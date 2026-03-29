"""
integrity/verify.py
-------------------
SHA-256 integrity verification for Python scripts.

Usage
-----
Set the environment variable ``JAVELIN_EXPECTED_SHA256`` to the hex digest of
the trusted script, then call :func:`verify_script_integrity` at the top of
the script being protected:

.. code-block:: python

    import os
    from integrity import verify_script_integrity

    verify_script_integrity(__file__)
    # … rest of task work …

If the computed hash does not match the expected value, :exc:`IntegrityError`
is raised **and** ``sys.exit(1)`` is called so the process terminates even
when the exception is caught inadvertently.
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
    """Raised when the computed SHA-256 digest of a script does not match
    the expected value stored in ``JAVELIN_EXPECTED_SHA256``.

    This exception is raised by :func:`verify_script_integrity` (and
    internally by :func:`_guarded_exit`) before ``sys.exit(1)`` is called.
    In unit tests you can mock ``sys.exit`` to prevent process termination and
    catch ``IntegrityError`` to assert on the failure message.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_ENV_VAR = "JAVELIN_EXPECTED_SHA256"


def _compute_sha256(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*.

    Parameters
    ----------
    path:
        Absolute path to the file whose digest should be computed.

    Raises
    ------
    OSError
        If the file cannot be opened or read (e.g., missing permissions,
        transient I/O error, or the path does not exist).
    """
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _guarded_exit(message: str) -> None:
    """Raise :exc:`IntegrityError` with *message* then call ``sys.exit(1)``.

    The exception is raised **before** ``sys.exit`` so that unit tests can
    intercept it (e.g., with ``pytest.raises(IntegrityError)``) while still
    verifying that ``sys.exit`` would have been called when the exception
    propagates uncaught.

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
    """Verify the SHA-256 hash of *script_path* against ``JAVELIN_EXPECTED_SHA256``.

    The function resolves *script_path* to an absolute path, computes its
    SHA-256 digest, and compares it (case-insensitively) to the value of the
    ``JAVELIN_EXPECTED_SHA256`` environment variable.

    Behaviour on mismatch or misconfiguration
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    * If ``JAVELIN_EXPECTED_SHA256`` is not set, :exc:`IntegrityError` is
      raised and ``sys.exit(1)`` is called.
    * If the file cannot be read, :exc:`IntegrityError` is raised (wrapping
      the underlying :exc:`OSError`) and ``sys.exit(1)`` is called.
    * If the digests do not match, :exc:`IntegrityError` is raised and
      ``sys.exit(1)`` is called.

    In all three failure cases :exc:`IntegrityError` is raised **before**
    ``sys.exit(1)``, which means unit tests can mock ``sys.exit`` and assert
    on the exception.

    Parameters
    ----------
    script_path:
        Path to the script file to verify.  Typically pass ``__file__``.

    Returns
    -------
    None
        Returns silently when the integrity check passes.

    Raises
    ------
    IntegrityError
        On any integrity or configuration failure (see above).  ``sys.exit(1)``
        is also called immediately after the exception is raised.
    """
    expected = os.environ.get(_ENV_VAR)
    if not expected:
        _guarded_exit(
            f"Integrity check skipped or misconfigured: "
            f"environment variable '{_ENV_VAR}' is not set."
        )

    resolved = Path(script_path).resolve()

    try:
        actual = _compute_sha256(resolved)
    except OSError as exc:
        _guarded_exit(
            f"Integrity check failed: unable to read script file "
            f"'{resolved}': {exc}"
        )

    if actual.lower() != expected.strip().lower():
        _guarded_exit(
            f"Integrity check failed: SHA-256 mismatch for '{resolved}'.\n"
            f"  expected : {expected.strip().lower()}\n"
            f"  computed : {actual}"
        )
