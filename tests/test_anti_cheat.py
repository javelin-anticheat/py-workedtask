import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import anti_cheat


class AntiCheatMonitorTests(unittest.TestCase):
    def test_normalize_process_name_handles_windows_and_posix_paths(self):
        self.assertEqual(
            anti_cheat.normalize_process_name(r"C:\\Tools\\x64dbg.exe"),
            "x64dbg.exe",
        )
        self.assertEqual(
            anti_cheat.normalize_process_name("/Applications/IDA.app/ida64.exe"),
            "ida64.exe",
        )

    def test_suspicious_process_exact_and_prefix_matches(self):
        self.assertTrue(anti_cheat.is_suspicious_process_name("CheatEngine-x86_64.exe"))
        self.assertTrue(anti_cheat.is_suspicious_process_name("x64dbg-portable.exe"))
        self.assertFalse(anti_cheat.is_suspicious_process_name("python3"))

    def test_find_suspicious_process_returns_first_match(self):
        self.assertEqual(
            anti_cheat.find_suspicious_process(["Finder", "C:\\Tools\\ollydbg.exe", "python"]),
            "C:\\Tools\\ollydbg.exe",
        )

    def test_run_checks_blocks_debugger_before_process_scan(self):
        code, message = anti_cheat.run_checks(
            process_names=["python", "cheatengine.exe"],
            debugger_probe=lambda: True,
        )
        self.assertEqual(code, anti_cheat.EXIT_DEBUGGER)
        self.assertIn("Debugger detected", message)

    def test_run_checks_blocks_suspicious_process(self):
        code, message = anti_cheat.run_checks(
            process_names=["python", "ida64.exe"],
            debugger_probe=lambda: False,
        )
        self.assertEqual(code, anti_cheat.EXIT_SUSPICIOUS_PROCESS)
        self.assertIn("ida64.exe", message)

    def test_run_checks_passes_when_clear(self):
        code, message = anti_cheat.run_checks(
            process_names=["launchd", "python3"],
            debugger_probe=lambda: False,
        )
        self.assertEqual(code, anti_cheat.EXIT_OK)
        self.assertIn("passed", message)

    def test_main_emits_json(self):
        with mock.patch("anti_cheat.run_checks", return_value=(anti_cheat.EXIT_OK, "clear")):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = anti_cheat.main(["--json"])
        self.assertEqual(code, anti_cheat.EXIT_OK)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload, {"ok": True, "exit_code": anti_cheat.EXIT_OK, "message": "clear"})

    def test_main_writes_failures_to_stderr(self):
        with mock.patch(
            "anti_cheat.run_checks",
            return_value=(anti_cheat.EXIT_SUSPICIOUS_PROCESS, "Suspicious process detected: x64dbg.exe; exiting."),
        ):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = anti_cheat.main([])
        self.assertEqual(code, anti_cheat.EXIT_SUSPICIOUS_PROCESS)
        self.assertIn("x64dbg.exe", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
