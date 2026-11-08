from __future__ import annotations

import unittest

import anti_cheat


class AntiCheatTests(unittest.TestCase):
    def test_debugger_detection_blocks(self):
        ok, message = anti_cheat.run_checks(
            debugger_attached=True,
            process_names=[],
        )
        self.assertFalse(ok)
        self.assertIn("Debugger", message)

    def test_suspicious_process_blocks_case_insensitive(self):
        ok, message = anti_cheat.run_checks(
            debugger_attached=False,
            process_names=["explorer.exe", "CheatEngine.EXE"],
        )
        self.assertFalse(ok)
        self.assertIn("cheatengine.exe", message.lower())

    def test_clean_process_list_passes(self):
        ok, message = anti_cheat.run_checks(
            debugger_attached=False,
            process_names=["explorer.exe", "python.exe"],
        )
        self.assertTrue(ok)
        self.assertEqual(message, "All clear")

    def test_basename_normalization(self):
        self.assertEqual(
            anti_cheat.normalize_process_name(r"C:\Tools\x64dbg.exe"),
            "x64dbg.exe",
        )


if __name__ == "__main__":
    unittest.main()
