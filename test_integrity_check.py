import os
import subprocess
import sys
from pathlib import Path


def run(env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, str(Path(__file__).parent / "integrity_check.py")],
        text=True,
        capture_output=True,
        env=e,
    )


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def test_skips_when_env_not_set():
    p = run({"JAVELIN_EXPECTED_SHA256": ""})
    assert p.returncode == 0
    assert "skipping integrity check" in (p.stdout + p.stderr).lower()


def test_fails_on_mismatch():
    p = run({"JAVELIN_EXPECTED_SHA256": "0" * 64})
    assert p.returncode != 0
    assert "mismatch" in (p.stdout + p.stderr).lower()


def test_passes_on_match():
    expected = sha256_file(Path(__file__).parent / "integrity_check.py")
    p = run({"JAVELIN_EXPECTED_SHA256": expected})
    assert p.returncode == 0
    assert "integrity ok" in (p.stdout + p.stderr).lower()
