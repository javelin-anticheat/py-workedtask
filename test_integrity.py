"""Tests for the Python integrity verification module."""

import hashlib
import os
import pytest
from integrity import compute_sha256, verify


@pytest.fixture
def sample_script(tmp_path):
    """Create a temp script and return (path, expected_hash)."""
    script = tmp_path / "guard.py"
    content = b'print("hello world")\n'
    script.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    return str(script), expected


def test_compute_sha256(sample_script):
    path, expected = sample_script
    assert compute_sha256(path) == expected


def test_verify_pass(sample_script, monkeypatch):
    path, expected = sample_script
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", expected)
    assert verify(script_path=path, exit_on_fail=False) is True


def test_verify_fail_mismatch(sample_script, monkeypatch):
    path, _ = sample_script
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "0" * 64)
    assert verify(script_path=path, exit_on_fail=False) is False


def test_verify_fail_no_env(sample_script, monkeypatch):
    path, _ = sample_script
    monkeypatch.delenv("JAVELIN_EXPECTED_SHA256", raising=False)
    assert verify(script_path=path, exit_on_fail=False) is False


def test_verify_exits_on_mismatch(sample_script, monkeypatch):
    path, _ = sample_script
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "bad" * 16)
    with pytest.raises(SystemExit) as exc:
        verify(script_path=path, exit_on_fail=True)
    assert exc.value.code == 1


def test_verify_exits_on_missing_env(sample_script, monkeypatch):
    path, _ = sample_script
    monkeypatch.delenv("JAVELIN_EXPECTED_SHA256", raising=False)
    with pytest.raises(SystemExit) as exc:
        verify(script_path=path, exit_on_fail=True)
    assert exc.value.code == 1


def test_verify_case_insensitive(sample_script, monkeypatch):
    path, expected = sample_script
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", expected.upper())
    assert verify(script_path=path, exit_on_fail=False) is True
