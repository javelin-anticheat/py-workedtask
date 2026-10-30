# File: test_integrity_verifier.py
import hashlib
import pytest
from integrity_verifier import compute_file_sha256, verify_script_integrity

def test_valid_sha256_passes(tmp_path, monkeypatch):
    script = tmp_path / "worker.py"
    content = b"print('Javelin secure worker')\n"
    script.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()

    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", expected)
    assert verify_script_integrity(script_path=script) is True

def test_tampered_script_triggers_guarded_exit(tmp_path, monkeypatch):
    script = tmp_path / "worker.py"
    script.write_bytes(b"print('tampered payload')\n")
    monkeypatch.setenv("JAVELIN_EXPECTED_SHA256", "0" * 64)

    with pytest.raises(SystemExit) as exc_info:
        verify_script_integrity(script_path=script)
    assert exc_info.value.code == 1
