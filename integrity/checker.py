"""
integrity/checker.py
====================
SHA-256 integrity verification for the py-workedtask script.

Usage
-----
1.  Compute the expected hash of your script once:

        python -c "from integrity.checker import compute_sha256; print(compute_sha256('your_script.py'))"

    Or use the CLI helper:

        python -m integrity your_script.py

2.  Store the printed hex-digest in the environment variable
    ``JAVELIN_EXPECTED_SHA256`` before launching the protected process:

        export JAVELIN_EXPECTED_SHA256=<hex-digest>

3.  Call :func:`verify_script_integrity` early in your script (ideally as
    the very first statement after imports).  If the hashes do not match the
    process exits with code 1 and prints a warning to *stderr*.

Environment variables
---------------------
JAVELIN_EXPECTED_SHA256
    The expected SHA-256 hex-digest of the script file.  When this variable
    is **not set** the check is silently skipped so that developer workflows
    are not disrupted (opt-in behaviour).  Set ``JAVELIN_STRICT=1`` to
    treat a missing variable as a hard failure instead.

JAVELIN_STRICT
    When set to ``1`` (or any truthy value) a missing ``JAVELIN_EXPECTED_SHA256``
    variable is treated as a tamper event and causes a guarded exit.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def compute_sha256(path: str | Path) -> str:
    """Return the lowercase hex SHA-256 digest of *path*.

    Parameters
    ----------
    path:
        Path to the file whose digest should be computed.

    Returns
    -------
    str
        64-character lowercase hex string.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256 = hashlib.sha256()
    # Read in 64 KiB chunks to keep memory usage low for large files.
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def verify_script_integrity(
    script_path: str | Path | None = None,
    *,
    expected_env_var: str = "JAVELIN_EXPECTED_SHA256",
    strict_env_var: str = "JAVELIN_STRICT",
    exit_code: int = 1,
) -> None:
    """Verify the SHA-256 digest of *script_path* against an expected value.

    The expected digest is read from the environment variable named by
    *expected_env_var* (default: ``JAVELIN_EXPECTED_SHA256``).

    * If the variable is **absent** and ``JAVELIN_STRICT`` is falsy the check
      is silently skipped (opt-in mode).
    * If the variable is **absent** and ``JAVELIN_STRICT=1`` the process exits
      immediately via :func:`_guarded_exit`.
    * If the variable is **present** but the digests differ the process also
      exits via :func:`_guarded_exit`.
    * If the digests **match** the function returns normally.

    Parameters
    ----------
    script_path:
        Path to the file to verify.  Defaults to ``__file__`` of the calling
        module (i.e. the script that calls this function).  When ``None`` the
        function resolves the caller's ``__file__`` automatically via
        ``sys.argv[0]``.
    expected_env_var:
        Name of the environment variable that holds the expected hex-digest.
    strict_env_var:
        Name of the environment variable that enables strict mode.
    exit_code:
        Exit code passed to :func:`_guarded_exit` on failure (default 1).
    """
    # ---- Resolve the script path ------------------------------------------
    if script_path is None:
        # Fall back to the main script that was invoked.
        script_path = Path(sys.argv[0]).resolve()
    else:
        script_path = Path(script_path).resolve()

    # ---- Read expected digest from environment ----------------------------
    expected_digest: str | None = os.environ.get(expected_env_var)
    strict_mode: bool = os.environ.get(strict_env_var, "").strip() in ("1", "true", "yes")

    if expected_digest is None:
        if strict_mode:
            _guarded_exit(
                f"[JAVELIN] INTEGRITY FAILURE: "
                f"'{expected_env_var}' is not set and strict mode is enabled.",
                exit_code,
            )
        # Non-strict: skip the check quietly.
        return

    # Normalise — strip whitespace, lower-case for safe comparison.
    expected_digest = expected_digest.strip().lower()
    if len(expected_digest) != 64:
        _guarded_exit(
            f"[JAVELIN] INTEGRITY FAILURE: "
            f"'{expected_env_var}' does not look like a valid SHA-256 hex-digest "
            f"(expected 64 hex characters, got {len(expected_digest)}).",
            exit_code,
        )

    # ---- Compute actual digest --------------------------------------------
    try:
        actual_digest = compute_sha256(script_path)
    except FileNotFoundError:
        _guarded_exit(
            f"[JAVELIN] INTEGRITY FAILURE: Script file not found: {script_path}",
            exit_code,
        )

    # ---- Compare ----------------------------------------------------------
    if actual_digest != expected_digest:
        _guarded_exit(
            f"[JAVELIN] INTEGRITY FAILURE: Hash mismatch for '{script_path}'.\n"
            f"  expected : {expected_digest}\n"
            f"  actual   : {actual_digest}",
            exit_code,
        )

    # Hashes match — proceed normally.


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _guarded_exit(message: str, exit_code: int = 1) -> None:
    """Print *message* to stderr and terminate the process.

    This is intentionally a thin wrapper so that callers can monkeypatch it
    in unit tests without patching ``sys.exit`` globally.
    """
    print(message, file=sys.stderr, flush=True)
    sys.exit(exit_code)
