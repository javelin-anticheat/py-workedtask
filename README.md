# py-workedtask â€” Javelin Anti-Cheat

Minimal anti-cheat guards for C++ (`AntiCheat.cpp`) and Python (`anticheat.py`), featuring:
- Debugger detection (`IsDebuggerPresent` / `CheckRemoteDebuggerPresent` / `sys.gettrace`)
- Suspicious process scanning
- Executable & script self-integrity verification (CRC32 and SHA-256) with guarded exit on mismatch

---

## Integrity Verification Setup

### 1. Python (`anticheat.py`) â€” `JAVELIN_EXPECTED_SHA256`

`anticheat.py` computes the SHA-256 digest of the running script file and compares it against the `JAVELIN_EXPECTED_SHA256` environment variable (or the build-time constant `EXPECTED_SCRIPT_SHA256`). If the digest does not match, execution halts immediately with exit code `1`.

#### Compute the expected SHA-256 hash:
```bash
python anticheat.py --print-sha256
# Or using standard tooling:
sha256sum anticheat.py
```

#### Run with `JAVELIN_EXPECTED_SHA256` enforced:
```bash
# Linux / macOS / Git Bash
export JAVELIN_EXPECTED_SHA256="$(python anticheat.py --print-sha256)"
python anticheat.py

# Windows PowerShell
$env:JAVELIN_EXPECTED_SHA256 = (python anticheat.py --print-sha256)
python anticheat.py
```

---

### 2. C++ (`AntiCheat.cpp`) â€” Build-Time CRC32 / SHA-256 Constants

`AntiCheat.cpp` verifies the running executable image via `GetModuleFileNameW` against:
- `JAVELIN_EXPECTED_CRC32_CONST` (compile-time CRC32 constant, default `0` = disabled)
- `JAVELIN_EXPECTED_SHA256_CONST` (compile-time SHA-256 hex string constant) or runtime `JAVELIN_EXPECTED_SHA256` environment variable

#### Compile with build-time constants:
```bash
g++ -O2 AntiCheat.cpp -DJAVELIN_EXPECTED_CRC32_CONST=0x1A2B3C4Du -ladvapi32 -o AntiCheat.exe
```

---

## Running Tests

```bash
python -m unittest discover -s tests -v
```
