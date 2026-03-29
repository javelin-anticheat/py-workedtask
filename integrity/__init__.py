"""
integrity
---------
Public API for Javelin AntiCheat script-integrity verification.

Quick start
~~~~~~~~~~~
::

    from integrity import verify_script_integrity
    verify_script_integrity(__file__)   # exits via sys.exit(1) on mismatch

See :mod:`integrity.verify` for full documentation.
"""

from .verify import IntegrityError, verify_script_integrity

__all__ = ["IntegrityError", "verify_script_integrity"]
