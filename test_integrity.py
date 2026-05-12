"""Tests for integrity verification module."""

import hashlib
import os
import sys
import tempfile
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from integrity import compute_script_hash, verify_integrity


def test_compute_script_hash():
    """Test hash computation produces valid SHA-256."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("print('hello')\n")
        f.flush()
        result = compute_script_hash(f.name)
    os.unlink(f.name)
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_verify_integrity_no_env():
    """When JAVELIN_EXPECTED_SHA256 is not set, verification passes."""
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("JAVELIN_EXPECTED_SHA256", None)
        assert verify_integrity(__file__) is True


def test_verify_integrity_matching_hash():
    """When hash matches, verification passes."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("test content\n")
        f.flush()
        expected = compute_script_hash(f.name)

    with patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": expected}):
        assert verify_integrity(f.name) is True
    os.unlink(f.name)


def test_verify_integrity_mismatch_exits():
    """When hash doesn't match, script exits with code 1."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("original\n")
        f.flush()

    with patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": "0" * 64}):
        with pytest.raises(SystemExit) as exc_info:
            verify_integrity(f.name)
        assert exc_info.value.code == 1
    os.unlink(f.name)
