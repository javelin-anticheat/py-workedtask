"""
integrity/verify.py
-------------------
SHA-256 integrity verification for Python task scripts.

Usage
-----
Set the environment variable ``JAVELIN_EXPECTED_SHA256`` to the lowercase hex
digest of the script you want to protect, then call
``verify_script_integrity(__file__)`` at the very top of your script (before
any task logic).

    import os
    os.environ["JAVELIN_EXPECTED_SHA256"] = "<hex-digest>"

    from integrity import verify_script_integrity
    verify_script_integrity(__file__)  # exits via sys.exit(1) on mismatch

The function will:
  1. Compute the SHA-256 hash of the resolved, absolute path of the script.
  2. Compare it to ``JAVELIN_EXPECTED_SHA256``.
  3. If they do not match, raise ``IntegrityError`` **and** call
     ``sys.exit(1)`` so the process terminates unconditionally.
  4. If ``JAVELIN_EXPECTED_SHA256`` is not set, a ``RuntimeError`` is raised.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

class IntegrityError(Exception):
    """Raised when the computed hash of a script does not match the expected
    value stored in ``JAVELIN_EXPECTED_SHA256``.

    In normal (non-test) execution this exception is raised **and** the
    process is terminated immediately via ``sys.exit(1)``.  In unit-test
    scenarios where ``sys.exit`` is mocked/patched, the exception will
    propagate so that test code can assert on it.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

ENV_VAR = "JAVELIN_EXPECTED_SHA256"
_CHUNK_SIZE = 65_536  # 64 KiB


def _compute_sha256(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*.

    Raises
    ------
    OSError
        If the file cannot be opened or read (e.g. permission denied,
        file removed between path resolution and read, transient I/O error).
    """
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _guarded_exit(message: str) -> None:
    """Raise ``IntegrityError`` with *message* and exit the process.

    ``IntegrityError`` is raised *before* ``sys.exit`` so that unit tests that
    patch ``sys.exit`` can still observe and assert on the exception.
    """
    exc = IntegrityError(message)
    try:
        raise exc
    finally:
        # Ensure the process terminates even if the caller catches the
        # exception (e.g. a bare ``except:`` clause in task code).
        sys.exit(1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_script_integrity(script_path: str | os.PathLike[str]) -> None:
    """Verify the SHA-256 hash of *script_path* against ``JAVELIN_EXPECTED_SHA256``.

    Parameters
    ----------
    script_path:
        Path to the script file to verify.  Pass ``__file__`` to check the
        currently running script.

    Raises
    ------
    RuntimeError
        If ``JAVELIN_EXPECTED_SHA256`` is not set in the environment.
    IntegrityError
        If the computed SHA-256 digest does not match ``JAVELIN_EXPECTED_SHA256``.
        The process is also terminated via ``sys.exit(1)``.
    OSError
        If the script file cannot be read (permission denied, missing file,
        or other I/O error).

    Notes
    -----
    On a hash mismatch the function raises ``IntegrityError`` **and** calls
    ``sys.exit(1)``.  In unit tests where ``sys.exit`` is patched/mocked the
    ``IntegrityError`` will propagate normally so tests can assert on it
    without the process actually exiting.
    """
    expected = os.environ.get(ENV_VAR)
    if expected is None:
        raise RuntimeError(
            f"Environment variable '{ENV_VAR}' is not set. "
            "Set it to the expected SHA-256 hex digest of the script before "
            "calling verify_script_integrity()."
        )

    expected = expected.strip().lower()

    resolved = Path(script_path).resolve()

    try:
        actual = _compute_sha256(resolved)
    except OSError as exc:
        raise OSError(
            f"Could not read script file for integrity check: {resolved!r}. "
            f"Reason: {exc}"
        ) from exc

    if actual != expected:
        _guarded_exit(
            f"Integrity check FAILED for {resolved!r}.\n"
            f"  Expected : {expected}\n"
            f"  Computed : {actual}\n"
            "The script may have been tampered with."
        )
