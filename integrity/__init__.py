"""
integrity
---------
Public API for Javelin anti-cheat script integrity verification.

Quickstart
----------
    from integrity import verify_script_integrity
    verify_script_integrity(__file__)   # exits via sys.exit(1) on mismatch

Set the ``JAVELIN_EXPECTED_SHA256`` environment variable to the lowercase hex
SHA-256 digest of your script before calling ``verify_script_integrity``.

Exceptions
----------
``IntegrityError`` is raised (and the process exits via ``sys.exit(1)``) when
the computed hash does not match the expected value.  In unit tests where
``sys.exit`` is mocked, the ``IntegrityError`` propagates normally so that
test code can assert on it.
"""

from .verify import IntegrityError, verify_script_integrity

__all__ = [
    "IntegrityError",
    "verify_script_integrity",
]
