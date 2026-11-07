# py-workedtask — Javelin Anti-Cheat & Self-Integrity Verification

Minimal C++ and Python anti-cheat guards featuring debugger detection, suspicious process scanning, and executable/script self-integrity verification (`CRC32` and `SHA-256`).

## Integrity Verification Setup

### 1. C++ Executable (`AntiCheat.cpp`)
`AntiCheat.cpp` supports both build-time `CRC32` (`JAVELIN_EXPECTED_CRC32`) and build-time or environment-provided `SHA-256` (`JAVELIN_EXPECTED_SHA256`) integrity verification of the running binary (`GetModuleFileNameW` on Windows, `/proc/self/exe` on Linux).

- **Build with Expected CRC32 or SHA-256:**
  ```bash
  # Compile with build-time SHA-256 constant:
  g++ -O2 AntiCheat.cpp -DJAVELIN_EXPECTED_SHA256=\"$(sha256sum AntiCheat | awk '{print $1}')\" -o AntiCheat

  # Or pass the expected SHA-256 at runtime:
  export JAVELIN_EXPECTED_SHA256="$(sha256sum ./AntiCheat | awk '{print $1}')"
  ./AntiCheat
  ```
- **Guarded Exit Codes:**
  - `12`: `CRC32` mismatch
  - `13`: `SHA-256` mismatch

### 2. Python Script (`anticheat.py`)
`anticheat.py` computes the `SHA-256` hash of the running script file (`sys.argv[0]`) and compares it in constant time against the `JAVELIN_EXPECTED_SHA256` environment variable.

```bash
export JAVELIN_EXPECTED_SHA256="$(sha256sum anticheat.py | awk '{print $1}')"
python3 anticheat.py
```

If `JAVELIN_EXPECTED_SHA256` is set and does not match the script's SHA-256 digest, `verify_script_integrity()` logs `[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch). Exiting.` to `stderr` and exits immediately with status code `13`.

### Running Tests
```bash
python3 -m unittest discover -s tests
```
