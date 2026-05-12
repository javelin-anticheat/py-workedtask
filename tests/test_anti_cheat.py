import unittest

from anti_cheat import (
    DEBUGGER_EXIT_CODE,
    SUSPICIOUS_PROCESS_EXIT_CODE,
    has_suspicious_process,
    normalize_process_name,
    run_checks,
)


class AntiCheatTests(unittest.TestCase):
    def test_normalize_process_name_handles_case_quotes_and_windows_paths(self):
        self.assertEqual(
            normalize_process_name('"C:\\Tools\\X64DBG.EXE"'),
            "x64dbg.exe",
        )

    def test_suspicious_process_detection_matches_exact_basename(self):
        self.assertTrue(
            has_suspicious_process(
                [
                    "python.exe",
                    "C:\\Tools\\CheatEngine.exe",
                ],
            ),
        )
        self.assertFalse(has_suspicious_process(["not-cheatengine.exe", "python.exe"]))

    def test_debugger_detection_takes_priority(self):
        result = run_checks(["cheatengine.exe"], debugger_attached=True)

        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "Debugger detected")
        self.assertEqual(result.exit_code, DEBUGGER_EXIT_CODE)

    def test_suspicious_process_result(self):
        result = run_checks(["python.exe", "x64dbg.exe"], debugger_attached=False)

        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "Suspicious process detected")
        self.assertEqual(result.exit_code, SUSPICIOUS_PROCESS_EXIT_CODE)

    def test_clean_processes_pass(self):
        result = run_checks(["python.exe", "explorer.exe"], debugger_attached=False)

        self.assertTrue(result.ok)
        self.assertEqual(result.reason, "All clear")
        self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
