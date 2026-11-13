# py-workedtask

Minimal anti-cheat guards for Python (`anti_cheat.py`) and C++ (`AntiCheat.cpp`), including optional self-integrity verification to detect executable or script tampering.

## Integrity Verification

Both implementations perform optional integrity checks at startup. When an expected hash is configured and does not match the running file (or is malformed), execution halts immediately via a **guarded exit** with a clear error message on `stderr` and exit code `3`.

---

### Python (`anti_cheat.py`)

`anti_cheat.py` computes the SHA-256 digest of the running script file and compares it against the `JAVELIN_EXPECTED_SHA256` environment variable (constant-time comparison, case-insensitive).

- When `JAVELIN_EXPECTED_SHA256` is **unset or empty**, the integrity check is skipped (optional check).
- When `JAVELIN_EXPECTED_SHA256` is **set**, it must be a valid 64-character hex SHA-256 digest matching the script file; otherwise the process prints an error to `stderr` and exits with code `3`.

#### 1. Compute the expected SHA-256 hash

Using the built-in helper:

```bash
python anti_cheat.py --print-hash
```

Or using standard OS tools:

- **Linux / macOS:**
  ```bash
  sha256sum anti_cheat.py
  ```
- **Windows (PowerShell):**
  ```powershell
  (Get-FileHash .\anti_cheat.py -Algorithm SHA256).Hash.ToLower()
  ```

#### 2. Set `JAVELIN_EXPECTED_SHA256` and run

- **Linux / macOS:**
  ```bash
  export JAVELIN_EXPECTED_SHA256="$(python anti_cheat.py --print-hash)"
  python anti_cheat.py
  ```
- **Windows (PowerShell):**
  ```powershell
  $env:JAVELIN_EXPECTED_SHA256 = (python .\anti_cheat.py --print-hash)
  python .\anti_cheat.py
  ```

#### 3. Verify tampered / mismatched behavior

```bash
JAVELIN_EXPECTED_SHA256=0000000000000000000000000000000000000000000000000000000000000000 python anti_cheat.py
# [Javelin AntiCheat] Integrity check failed (SHA-256 mismatch ...). Exiting.
# Exit code: 3
```

---

### C++ (`AntiCheat.cpp`)

`AntiCheat.cpp` computes the CRC32 and/or SHA-256 of the running executable (`GetModuleFileNameA` on Windows, `/proc/self/exe` with `argv[0]` fallback on Unix) and compares against build-time macros:

- `EXPECTED_EXE_HASH` (or `JAVELIN_EXPECTED_SHA256`): build-time 64-character SHA-256 hex digest (or `0x...` CRC32 hex value).
- `JAVELIN_EXPECTED_CRC32`: build-time 32-bit CRC32 integer constant (default `0u`, disabled).

When neither macro is configured (or `JAVELIN_EXPECTED_CRC32 == 0u`), the integrity check is skipped. When configured and non-matching, the program prints an error to `stderr` and exits with code `3`.

#### Build without integrity enforcement (or inspect binary hashes)

- **MSVC (Windows):**
  ```bat
  cl /EHsc /std:c++17 AntiCheat.cpp
  AntiCheat.exe --print-hash
  ```
- **MinGW g++ (Windows) / g++ or clang++ (Linux/macOS):**
  ```bash
  g++ -std=c++17 -O2 AntiCheat.cpp -o AntiCheat
  ./AntiCheat --print-hash
  ```

#### Build with an expected hash macro

- **Using `EXPECTED_EXE_HASH` (SHA-256):**
  ```bash
  g++ -std=c++17 -O2 -DEXPECTED_EXE_HASH=\"<64-char-sha256>\" AntiCheat.cpp -o AntiCheat
  ```
  ```bat
  cl /EHsc /std:c++17 /DEXPECTED_EXE_HASH=\"<64-char-sha256>\" AntiCheat.cpp
  ```
- **Using `JAVELIN_EXPECTED_CRC32` (CRC32):**
  ```bash
  g++ -std=c++17 -O2 -DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp -o AntiCheat
  ```
  ```bat
  cl /EHsc /std:c++17 /DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp
  ```

> **Note on self-hashing binaries:** Embedding a full-file hash directly into the binary changes the binary's own bytes (and therefore its full-file hash). Building with a known/mismatched `EXPECTED_EXE_HASH` or `JAVELIN_EXPECTED_CRC32` verifies the guarded exit path (`exit code 3`), while post-build hash verification/patching can target the baseline hash printed by `--print-hash`.

---

## Running Automated Tests

```bash
python -m unittest discover -s tests -v
```
