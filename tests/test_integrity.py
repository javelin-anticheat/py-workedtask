"""
tests/test_integrity.py
=======================
Unit-tests for integrity/checker.py

Run with:  pytest tests/test_integrity.py -v
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_temp(content: bytes = b"hello javelin") -> Path:
    """Create a temporary file and return its Path."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".py")
    tmp.write(content)
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# compute_sha256
# ---------------------------------------------------------------------------

class TestComputeSha256:
    def test_known_content(self, tmp_path):
        content = b"anticheat test content"
        f = tmp_path / "script.py"
        f.write_bytes(content)
        assert compute_sha256(f) == _sha256(content)

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_bytes(b"")
        assert compute_sha256(f) == _sha256(b"")

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            compute_sha256(tmp_path / "nonexistent.py")

    def test_accepts_string_path(self, tmp_path):
        content = b"string path test"
        f = tmp_path / "s.py"
        f.write_bytes(content)
        assert compute_sha256(str(f)) == _sha256(content)


# ---------------------------------------------------------------------------
# verify_script_integrity
# ---------------------------------------------------------------------------

class TestVerifyScriptIntegrity:
    """Tests for the main guard function."""

    # ------------------------------------------------------------------ #
    # Happy-path: hashes match                                            #
    # ------------------------------------------------------------------ #

    def test_matching_hash_does_not_exit(self, tmp_path, monkeypatch):
        content = b"legitimate script"
        f = tmp_path / "ok.py"
        f.write_bytes(content)
        digest = _sha256(content)

        monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", digest)
        monkeypatch.delenv("JAVELIN_STRICT", raising=False)

        # Should return without raising or calling sys.exit
        verify_script_integrity(f)

    def test_matching_hash_case_insensitive(self, tmp_path, monkeypatch):
        content = b"case insensitive check"
        f = tmp_path / "ci.py"
        f.write_bytes(content)
        digest = _sha256(content).upper()  # upper-case from env var

        monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", digest)
        verify_script_integrity(f)  # must not exit

    def test_matching_hash_with_surrounding_whitespace(self, tmp_path, monkeypatch):
        content = b"whitespace test"
        f = tmp_path / "ws.py"
        f.write_bytes(content)
        digest = "  " + _sha256(content) + "\n"  # padded

        monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", digest)
        verify_script_integrity(f)

    # ------------------------------------------------------------------ #
    # Failure: hash mismatch                                              #
    # ------------------------------------------------------------------ #

    def test_mismatched_hash_calls_guarded_exit(self, tmp_path, monkeypatch, capsys):
        content = b"original script"
        f = tmp_path / "tampered.py"
        f.write_bytes(content)

        monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "a" * 64)

        with pytest.raises(SystemExit) as exc_info:
            verify_script_integrity(f)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "INTEGRITY FAILURE" in captured.err
        assert "mismatch" in captured.err.lower()

    def test_exit_code_is_configurable(self, tmp_path, monkeypatch):
        f = tmp_path / "s.py"
        f.write_bytes(b"data")
        monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "b" * 64)

        with pytest.raises(SystemExit) as exc_info:
            verify_script_integrity(f, exit_code=42)

        assert exc_info.value.code == 42

    # ------------------------------------------------------------------ #
    # Missing env var                                                     #
    # ------------------------------------------------------------------ #

    def test_missing_env_var_skipped_in_non_strict_mode(self, tmp_path, monkeypatch):
        f = tmp_path / "skip.py"
        f.write_bytes(b"data")
        monkeypatch.delenv("JAVELIN_EXPECTED_SHA256", raising=False)
        monkeypatch.delenv("JAVELIN_STRICT", raising=False)

        # Should return silently
        verify_script_integrity(f)

    def test_missing_env_var_exits_in_strict_mode(self, tmp_path, monkeypatch, capsys):
        f = tmp_path / "strict.py"
        f.write_bytes(b"data")
        monkeypatch.delenv("JAVELIN_EXPECTED_SHA256", raising=False)
        monkeypatch.setenv("JAVELIN_STRICT", "1")

        with pytest.raises(SystemExit) as exc_info:
            verify_script_integrity(f)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "INTEGRITY FAILURE" in captured.err

    def test_strict_mode_truthy_values(self, tmp_path, monkeypatch):
        f = tmp_path / "s.py"
        f.write_bytes(b"x")
        monkeypatch.delenv("JAVELIN_EXPECTED_SHA256", raising=False)

        for truthy in ("true", "yes", "1"):
            monkeypatch.setenv("JAVELIN_STRICT", truthy)
            with pytest.raises(SystemExit):
                verify_script_integrity(f)

    # ------------------------------------------------------------------ #
    # Malformed env var                                                   #
    # ------------------------------------------------------------------ #

    def test_malformed_hash_exits(self, tmp_path, monkeypatch, capsys):
        f = tmp_path / "m.py"
        f.write_bytes(b"data")
        monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "not-a-valid-sha256")

        with pytest.raises(SystemExit) as exc_info:
            verify_script_integrity(f)

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "INTEGRITY FAILURE" in captured.err

    # ------------------------------------------------------------------ #
    # Missing file                                                        #
    # ------------------------------------------------------------------ #

    def test_missing_script_file_exits(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "a" * 64)

        with pytest.raises(SystemExit) as exc_info:
            verify_script_integrity(tmp_path / "ghost.py")

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "INTEGRITY FAILURE" in captured.err


# ---------------------------------------------------------------------------
# Import the public symbols (done after class definitions for clarity)
# ---------------------------------------------------------------------------
from integrity.checker import compute_sha256, verify_script_integrity
