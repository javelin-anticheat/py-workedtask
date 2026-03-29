"""
integrity
---------
Public API for Javelin anti-cheat script integrity verification.

Typical usage::

    from integrity import verify_script_integrity

    verify_script_integrity(__file__)

If the computed SHA-256 hash of the running script does not match the value
stored in the ``JAVELIN_EXPECTED_SHA256`` environment variable,
:exc:`IntegrityError` is raised and ``sys.exit(1)`` is called immediately,
ensuring no task work is performed on a tampered or misconfigured script.
"""

from .verify import IntegrityError, verify_script_integrity

__all__ = [
    "IntegrityError",
    "verify_script_integrity",
]
