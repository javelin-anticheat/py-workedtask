from __future__ import annotations

import hashlib

import pytest

from AntiCheat import (
    EXIT_INTEGRITY_FAILURE,
    check_script_integrity,
    file_sha256,
    guarded_exit_if_tampered,
)


def test_file_sha256_returns_expected_digest(tmp_path):
    script = tmp_path / "guard.py"
    script.write_bytes(b"print('protected')\n")

    assert file_sha256(script) == hashlib.sha256(b"print('protected')\n").hexdigest()


def test_script_integrity_is_disabled_without_expected_hash(tmp_path):
    script = tmp_path / "guard.py"
    script.write_text("tampered", encoding="utf-8")

    assert check_script_integrity(script)


def test_script_integrity_accepts_matching_hash(tmp_path):
    script = tmp_path / "guard.py"
    script.write_bytes(b"trusted")
    expected_hash = hashlib.sha256(b"trusted").hexdigest()

    assert check_script_integrity(script, expected_hash)


def test_guarded_exit_on_mismatched_hash(tmp_path):
    script = tmp_path / "guard.py"
    script.write_bytes(b"tampered")

    with pytest.raises(SystemExit) as exc_info:
        guarded_exit_if_tampered(script, "0" * 64)

    assert exc_info.value.code == EXIT_INTEGRITY_FAILURE
