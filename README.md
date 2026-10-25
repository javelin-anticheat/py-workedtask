# py-workedtask — Javelin Anti-Cheat Guards (C++ & Python)

Minimal anti-cheat guards featuring debugger detection, suspicious process scanning, and optional self-integrity verification (CRC32 & SHA-256).

---

## Integrity Verification (Executable & Script Hash Checks)

Both the C++ executable (`AntiCheat.cpp`) and the Python implementation (`anticheat.py`) support optional self-integrity checks to detect binary or script tampering. When a configured hash does not match the running file on disk, the process performs an immediate **guarded exit** (exit code `3`).

### 1. Python Script Integrity (`JAVELIN_EXPECTED_SHA256`)

1. Compute the SHA-256 hash of `anticheat.py`:
   ```bash
   python anticheat.py --print-hash
   ```
2. Set the `JAVELIN_EXPECTED_SHA256` environment variable before running:
   - **Linux / macOS:**
     ```bash
     export JAVELIN_EXPECTED_SHA256="<64-char-sha256-hex>"
     python anticheat.py
     ```
   - **Windows (PowerShell):**
     ```powershell
     $env:JAVELIN_EXPECTED_SHA256 = "<64-char-sha256-hex>"
     python anticheat.py
     ```
3. If `JAVELIN_EXPECTED_SHA256` is unset or empty, the integrity check is skipped. If set to a non-matching value, `anticheat.py` logs an integrity failure message to `stderr` and exits with code `3`.

### 2. C++ Executable Integrity (`JAVELIN_EXPECTED_CRC32` / `JAVELIN_EXPECTED_SHA256`)

1. Compile `AntiCheat.cpp` with MSVC (`cl`) or MinGW (`g++`):
   ```bash
   cl /EHsc AntiCheat.cpp /link Advapi32.lib
   ```
2. Print the running binary's baseline CRC32 / SHA-256:
   ```bash
   AntiCheat.exe --print-hash
   ```
3. Rebuild with your expected build-time constant (`JAVELIN_EXPECTED_CRC32` or `JAVELIN_EXPECTED_SHA256`):
   ```bash
   cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp /link Advapi32.lib
   # or with SHA-256:
   cl /EHsc /DJAVELIN_EXPECTED_SHA256=\"<64-char-sha256-hex>\" AntiCheat.cpp /link Advapi32.lib
   ```

---

## Running Unit Tests

```bash
python -m unittest discover -v
```
