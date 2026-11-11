from __future__ import annotations

import os
from pathlib import Path
import pytest

import anticheat


def test_optional_when_env_unset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = tmp_path / "sample_script.py"
    script.write_text("print('hello world')\n", encoding="utf-8")
    monkeypatch.delenv("JAVELIN_EXPECTED_SHA256", raising=False)
    assert anticheat.verify_script_integrity(script_path=script) is True


def test_matching_sha256_passes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = tmp_path / "sample_script.py"
    script.write_text("print('verified payload')\n", encoding="utf-8")
    expected = anticheat.compute_file_sha256(script)
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", expected.upper())
    assert anticheat.verify_script_integrity(script_path=script) is True


def test_mismatched_sha256_guarded_exit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = tmp_path / "sample_script.py"
    script.write_text("print('tampered payload')\n", encoding="utf-8")
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "0" * 64)
    with pytest.raises(SystemExit) as exc_info:
        anticheat.verify_script_integrity(script_path=script, exit_on_mismatch=True)
    assert exc_info.value.code == 1
