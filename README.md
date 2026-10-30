# py-workedtask — Javelin Anti-Cheat & Self-Integrity Guard

Minimal C++ (`AntiCheat.cpp`) and Python (`anticheat.py`) anti-cheat guards featuring:
- **Debugger detection** (PEB `BeingDebugged` / `IsDebuggerPresent` in C++, `sys.gettrace()` in Python)
- **Suspicious process scanning** (CheatEngine, x64dbg, IDA, OllyDbg, ProcessHacker, etc.)
- **Executable & Script Self-Integrity Verification** (CRC32 build-time constant for C++, `JAVELIN_EXPECTED_SHA256` environment variable for Python)

---

## Setting Expected Integrity Values (Issue #4)

### 1. Python Implementation (`anticheat.py` — `JAVELIN_EXPECTED_SHA256`)

The Python guard computes the **SHA-256** digest of the running script file (`__file__`) and compares it against the `JAVELIN_EXPECTED_SHA256` environment variable using constant-time comparison (`hmac.compare_digest`). If `JAVELIN_EXPECTED_SHA256` is set and does not match the file on disk, the process performs a guarded exit with exit code `3` (`EXIT_INTEGRITY_FAILED`).

#### Step 1: Compute the baseline SHA-256 hash of `anticheat.py`
```bash
# Option A: Built-in helper flag
JAVELIN_PRINT_SHA256=1 python anticheat.py

# Option B: Standard CLI (Linux / macOS / Git Bash)
sha256sum anticheat.py

# Option C: Windows PowerShell
(Get-FileHash .\anticheat.py -Algorithm SHA256).Hash.ToLower()
```

#### Step 2: Export `JAVELIN_EXPECTED_SHA256` and run
```bash
# Linux / macOS
export JAVELIN_EXPECTED_SHA256="<64-char-hex-sha256>"
python anticheat.py

# Windows PowerShell
$env:JAVELIN_EXPECTED_SHA256 = "<64-char-hex-sha256>"
python .\anticheat.py
```

If `anticheat.py` is modified or tampered with, running it outputs:
```text
[Javelin AntiCheat] starting checks...
[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch). Exiting.
```
and exits with code `3`.

---

### 2. C++ Implementation (`AntiCheat.cpp` — `JAVELIN_EXPECTED_CRC32`)

The C++ guard computes the **CRC32** checksum of the running `.exe` (`GetModuleFileNameW(nullptr, ...)`) and compares it against the compile-time constant `JAVELIN_EXPECTED_CRC32`.

#### Step 1: Compile with `JAVELIN_EXPECTED_CRC32`
```cmd
cl /EHsc /O2 /DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp /Fe:AntiCheat.exe
```
*(Note: When `JAVELIN_EXPECTED_CRC32` is left at its default `0u`, the self-integrity check is skipped during development. Once set to a non-zero 32-bit hex constant, any binary mismatch triggers a guarded exit.)*

---

## Running Unit Tests

```bash
python -m unittest test_anticheat.py
```
