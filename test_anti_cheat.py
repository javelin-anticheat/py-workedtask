# tests/test_anti_cheat.py
import types
import builtins

import pytest

# We mock psutil and ctypes to avoid platform-specific behavior
class _Proc:
    def __init__(self, name):
        self.info = {"name": name}

def test_detect_suspicious_processes(monkeypatch):
    import importlib
    m = importlib.import_module("anti_cheat")

    # Mock psutil.process_iter to return a suspicious process
    def fake_iter(_):
        yield _Proc("CheatEngine.exe")
    monkeypatch.setattr("psutil.process_iter", fake_iter)

    found = m.detect_suspicious_processes()
    assert found is not None
    assert found.lower() == "cheatengine.exe"

def test_no_suspicious_process(monkeypatch):
    import importlib
    m = importlib.import_module("anti_cheat")

    def fake_iter(_):
        for name in ["explorer.exe", "notepad.exe"]:
            yield _Proc(name)
    monkeypatch.setattr("psutil.process_iter", fake_iter)

    found = m.detect_suspicious_processes()
    assert found is None

def test_debugger_present_graceful(monkeypatch):
    import importlib
    m = importlib.import_module("anti_cheat")
    # Force ctypes failing to simulate non-Windows or missing API
    monkeypatch.setattr(m, "HAS_WIN", False)
    assert m.is_debugger_present() is False
