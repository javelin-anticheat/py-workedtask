import tempfile
import unittest
from pathlib import Path

from anticheat import (
    EXIT_DEBUGGER_DETECTED,
    EXIT_INTEGRITY_FAILED,
    EXIT_SUSPICIOUS_PROCESS,
    check_self_integrity,
    check_suspicious_processes,
    compute_file_crc32,
    enforce_anticheat,
)


class AntiCheatTests(unittest.TestCase):
    def test_detects_known_cheat_processes_case_insensitively(self):
        self.assertTrue(check_suspicious_processes(["explorer.exe", "CheatEngine.exe"]))
        self.assertTrue(check_suspicious_processes(["python.exe", "x64dbg.exe"]))
        self.assertFalse(check_suspicious_processes(["explorer.exe", "python.exe"]))

    def test_crc32_self_integrity_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "binary.bin"
            p.write_bytes(b"javelin-anticheat-payload")
            crc = compute_file_crc32(str(p))
            self.assertTrue(check_self_integrity(crc, str(p)))
            self.assertFalse(check_self_integrity(crc ^ 0xFF, str(p)))

    def test_enforce_anticheat_exits_on_debugger_or_suspicious_process(self):
        exits = []
        code = enforce_anticheat(
            debugger_fn=lambda: True,
            process_fn=lambda: False,
            exit_fn=lambda c: exits.append(c),
        )
        self.assertEqual(code, EXIT_DEBUGGER_DETECTED)
        self.assertEqual(exits, [EXIT_DEBUGGER_DETECTED])

        exits.clear()
        code = enforce_anticheat(
            debugger_fn=lambda: False,
            process_fn=lambda: True,
            exit_fn=lambda c: exits.append(c),
        )
        self.assertEqual(code, EXIT_SUSPICIOUS_PROCESS)
        self.assertEqual(exits, [EXIT_SUSPICIOUS_PROCESS])

        exits.clear()
        code = enforce_anticheat(
            expected_crc32=12345,
            debugger_fn=lambda: False,
            process_fn=lambda: False,
            integrity_fn=lambda _: False,
            exit_fn=lambda c: exits.append(c),
        )
        self.assertEqual(code, EXIT_INTEGRITY_FAILED)
        self.assertEqual(exits, [EXIT_INTEGRITY_FAILED])


if __name__ == "__main__":
    unittest.main()
