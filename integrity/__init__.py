"""
integrity — SHA-256 script-integrity verification package.

Public API
----------
verify_script_integrity(script_path)
    Compute the SHA-256 digest of *script_path* and compare it against the
    value in the ``JAVELIN_EXPECTED_SHA256`` environment variable.  Raises
    ``IntegrityError`` and exits via ``sys.exit(1)`` on mismatch or read
    error; silently skips the check when the variable is unset.

IntegrityError
    Exception raised on an integrity mismatch or file-read failure.
"""

from .verify import IntegrityError, verify_script_integrity

__all__ = ["verify_script_integrity", "IntegrityError"]
