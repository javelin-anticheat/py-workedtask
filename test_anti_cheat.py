import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import anti_cheat


class _Proc:
    def __init__(self, name):
        self.info = {"name": name}


class AntiCheatTests(unittest.TestCase):
    def test_integrity_check_skips_when_env_is_unset(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertTrue(anti_cheat.check_script_integrity())

    def test_integrity_check_accepts_matching_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            path = Path(handle.name)
            handle.write(b"trusted script bytes")

        self.addCleanup(path.unlink)
        expected = anti_cheat.sha256_file(path)

        self.assertTrue(
            anti_cheat.check_script_integrity(path, expected_sha256=expected)
        )

    def test_integrity_check_rejects_mismatched_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            path = Path(handle.name)
            handle.write(b"tampered script bytes")

        self.addCleanup(path.unlink)
        wrong_hash = "0" * 64

        self.assertFalse(
            anti_cheat.check_script_integrity(path, expected_sha256=wrong_hash)
        )

    def test_main_returns_guarded_exit_on_integrity_mismatch(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            path = Path(handle.name)
            handle.write(b"tampered script bytes")

        self.addCleanup(path.unlink)

        with mock.patch.dict(
            "os.environ",
            {anti_cheat.EXPECTED_SHA256_ENV: "0" * 64},
            clear=True,
        ):
            self.assertEqual(anti_cheat.main(path), anti_cheat.EXIT_INTEGRITY)

    def test_detect_suspicious_processes(self):
        fake_psutil = types.SimpleNamespace(
            process_iter=lambda _attrs: iter([_Proc("CheatEngine.exe")])
        )

        with mock.patch.object(anti_cheat, "psutil", fake_psutil):
            self.assertEqual(
                anti_cheat.detect_suspicious_processes(),
                "cheatengine.exe",
            )

    def test_no_suspicious_process(self):
        fake_psutil = types.SimpleNamespace(
            process_iter=lambda _attrs: iter([_Proc("explorer.exe"), _Proc("notepad.exe")])
        )

        with mock.patch.object(anti_cheat, "psutil", fake_psutil):
            self.assertIsNone(anti_cheat.detect_suspicious_processes())

    def test_debugger_present_is_graceful_without_windows_api(self):
        with mock.patch.object(anti_cheat, "HAS_WIN", False):
            with mock.patch("sys.gettrace", return_value=None):
                self.assertFalse(anti_cheat.is_debugger_present())


if __name__ == "__main__":
    unittest.main()
