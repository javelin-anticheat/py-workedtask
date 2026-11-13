import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))


class AntiCheatProtectionTests(unittest.TestCase):
    def test_python_debugger_detection_unit_and_exit(self) -> None:
        import anti_cheat

        self.assertTrue(anti_cheat.is_debugger_attached(trace_fn=lambda: object(), os_probe=lambda: False))
        self.assertTrue(anti_cheat.is_debugger_attached(trace_fn=lambda: None, os_probe=lambda: True))
        self.assertFalse(anti_cheat.is_debugger_attached(trace_fn=lambda: None, os_probe=lambda: False))

        code = (
            "import sys, anti_cheat; "
            "sys.settrace(lambda *a: None); "
            "raise SystemExit(anti_cheat.run_checks(process_names=['python3']))"
        )
        proc = subprocess.run([sys.executable, "-c", code], cwd=str(REPO_DIR), capture_output=True, text=True)
        self.assertEqual(proc.returncode, anti_cheat.EXIT_DEBUGGER_DETECTED)
        self.assertIn("Debugger detected", proc.stderr)

    def test_python_suspicious_process_detection_and_exit(self) -> None:
        import anti_cheat

        matches = anti_cheat.find_suspicious_processes(["systemd", "CheatEngine-x86_64.exe", "code"])
        self.assertEqual(matches, ["cheatengine-x86_64.exe"])
        self.assertEqual(anti_cheat.find_suspicious_processes(["explorer.exe", "python3"]), [])

        proc = subprocess.run(
            [sys.executable, str(REPO_DIR / "anti_cheat.py"), "--check-processes", "explorer.exe,x64dbg.exe", "--ignore-debugger"],
            cwd=str(REPO_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, anti_cheat.EXIT_SUSPICIOUS_PROCESS)
        self.assertIn("Suspicious process detected", proc.stderr)

        clean_proc = subprocess.run(
            [sys.executable, str(REPO_DIR / "anti_cheat.py"), "--check-processes", "explorer.exe,python3", "--ignore-debugger"],
            cwd=str(REPO_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(clean_proc.returncode, 0)
        self.assertIn("All clear", clean_proc.stdout)

    def test_cpp_client_compiles_and_exits_on_debugger_and_suspicious_process(self) -> None:
        cxx = shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(cxx, "C++ compiler required to verify AntiCheat.cpp")
        cpp_src = REPO_DIR / "AntiCheat.cpp"
        with tempfile.TemporaryDirectory() as tmp:
            bin_path = os.path.join(tmp, "anticheat_client")
            build = subprocess.run(
                [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", str(cpp_src), "-o", bin_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(build.returncode, 0, f"Build failed:\n{build.stderr}")

            dbg = subprocess.run([bin_path, "--simulate-debugger"], capture_output=True, text=True)
            self.assertEqual(dbg.returncode, 10)
            self.assertIn("Debugger detected", dbg.stderr)

            bad_proc = subprocess.run([bin_path, "--simulate-process", "OllyDbg.exe"], capture_output=True, text=True)
            self.assertEqual(bad_proc.returncode, 11)
            self.assertIn("Suspicious process detected", bad_proc.stderr)

            clean = subprocess.run([bin_path, "--simulate-clean"], capture_output=True, text=True)
            self.assertEqual(clean.returncode, 0)
            self.assertIn("All clear", clean.stdout)


if __name__ == "__main__":
    unittest.main()
