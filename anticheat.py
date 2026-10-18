"""Javelin AntiCheat - Python integrity guard.
+
+Optional self-integrity check for the Python script: computes the SHA-256 of
+this script file and compares it against the value provided through the
+``JAVELIN_EXPECTED_SHA256`` environment variable.
+
+When the environment variable is unset/empty the check is skipped (opt-in),
+so the module stays usable during development. When it is set and the computed
+hash does not match, the process exits with a non-zero status code and an
+error message is written to stderr.
+"""
+
+from __future__ import annotations
+
+import hashlib
+import os
+import sys
+from pathlib import Path
+from typing import Optional
+
+ENV_VAR = "JAVELIN_EXPECTED_SHA256"
+INTEGRITY_EXIT_CODE = 0xCC  # 204; mirrors the C++ integrity failure code (0xCRC in source is not a valid hex literal)
+
+__all__ = ["compute_sha256", "check_integrity", "main"]
+
+
+def compute_sha256(path: Optional[str] = None) -> str:
+    """Return the hex SHA-256 digest of the file at ``path``.
+
+    Defaults to this module's own source file so the guard is self-referential.
+    """
+    target = Path(path) if path is not None else Path(__file__)
+    h = hashlib.sha256()
+    with target.open("rb") as f:
+        for chunk in iter(lambda: f.read(65536), b""):
+            h.update(chunk)
+    return h.hexdigest()
+
+
+def check_integrity(expected: Optional[str] = None, path: Optional[str] = None) -> bool:
+    """Compare the script's SHA-256 against ``expected``.
+
+    ``expected`` defaults to the ``JAVELIN_EXPECTED_SHA256`` env var. Returns
+    ``True`` when the check passes or is skipped (no expected value given).
+    Returns ``False`` on mismatch.
+    """
+    if expected is None:
+        expected = os.environ.get(ENV_VAR, "").strip()
+    if not expected:
+        # Opt-in: nothing to enforce.
+        return True
+
+    actual = compute_sha256(path)
+    # Accept a leading "sha256:" prefix or whitespace for convenience.
+    expected = expected.strip().lower()
+    if expected.startswith("sha256:"):
+        expected = expected[len("sha256:"):]
+    return actual.lower() == expected
+
+
+def main() -> int:
+    """Entry point: run the integrity guard and exit accordingly."""
+    expected = os.environ.get(ENV_VAR, "").strip()
+    if not expected:
+        print("[Javelin AntiCheat] JAVELIN_EXPECTED_SHA256 not set; skipping integrity check.")
+        return 0
+
+    if not check_integrity(expected):
+        actual = compute_sha256()
+        print(
+            "[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch). "
+            f"expected={expected} actual={actual}",
+            file=sys.stderr,
+        )
+        return INTEGRITY_EXIT_CODE
+
+    print("[Javelin AntiCheat] Integrity check passed.")
+    return 0
+
+
+if __name__ == "__main__":
+    sys.exit(main())
diff --git a/tests/test_integrity.py b/tests/test_integrity.py
new file mode 100644
index 0000000..ce3f270
--- /dev/null
+++ b/tests/test_integrity.py
@@ -0,0 +1,71 @@
+"""Tests for the Python SHA-256 integrity guard."""
+
+import hashlib
+import os
+import subprocess
+import sys
+import tempfile
+import unittest
+
+sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
+import anticheat
+
+
+class IntegrityTests(unittest.TestCase):
+    def test_compute_sha256_matches_hashlib(self):
+        fd, path = tempfile.mkstemp()
+        os.close(fd)
+        data = b"hello javelin"
+        with open(path, "wb") as f:
+            f.write(data)
+        expected = hashlib.sha256(data).hexdigest()
+        self.assertEqual(anticheat.compute_sha256(path), expected)
+        os.remove(path)
+
+    def test_check_integrity_passes_with_correct_hash(self):
+        fd, path = tempfile.mkstemp(suffix=".py")
+        os.close(fd)
+        with open(path, "w") as f:
+            f.write("print('hi')\n")
+        h = anticheat.compute_sha256(path)
+        self.assertTrue(anticheat.check_integrity(h, path=path))
+        self.assertTrue(anticheat.check_integrity("sha256:" + h, path=path))
+        os.remove(path)
+
+    def test_check_integrity_fails_on_mismatch(self):
+        fd, path = tempfile.mkstemp(suffix=".py")
+        os.close(fd)
+        with open(path, "w") as f:
+            f.write("print('hi')\n")
+        self.assertFalse(anticheat.check_integrity("0" * 64, path=path))
+        os.remove(path)
+
+    def test_check_integrity_skips_when_empty(self):
+        self.assertTrue(anticheat.check_integrity(""))
+
+    def test_main_skips_when_env_unset(self):
+        os.environ.pop("JAVELIN_EXPECTED_SHA256", None)
+        self.assertEqual(anticheat.main(), 0)
+
+    def test_main_exits_nonzero_on_mismatch(self):
+        os.environ["JAVELIN_EXPECTED_SHA256"] = "0" * 64
+        self.assertEqual(anticheat.main(), anticheat.INTEGRITY_EXIT_CODE)
+        os.environ.pop("JAVELIN_EXPECTED_SHA256", None)
+
+    def test_main_passes_with_correct_env(self):
+        real = anticheat.compute_sha256()
+        os.environ["JAVELIN_EXPECTED_SHA256"] = real
+        self.assertEqual(anticheat.main(), 0)
+        os.environ.pop("JAVELIN_EXPECTED_SHA256", None)
+
+    def test_subprocess_guarded_exit(self):
+        env = dict(os.environ)
+        env["JAVELIN_EXPECTED_SHA256"] = "0" * 64
+        script = os.path.join(os.path.dirname(__file__), "..", "anticheat.py")
+        r = subprocess.run([sys.executable, script], env=env, capture_output=True, text=True)
+        self.assertNotEqual(r.returncode, 0)
+        self.assertTrue("mismatch" in r.stderr.lower() or "integrity" in r.stderr.lower())
+
+
+if __name__ == "__main__":
+    unittest.main()
