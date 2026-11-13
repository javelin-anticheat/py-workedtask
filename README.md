# py-workedtask — Javelin Anti-Cheat

Lightweight baseline anti-cheat guards in **C++ (`AntiCheat.cpp`)** and **Python (`anti_cheat.py`)** providing debugger detection, suspicious process scanning, and optional executable/script integrity verification (`CRC32` and `SHA-256`).

## Integrity Verification Configuration

Both implementations perform a guarded non-zero exit (`exit code 12`) whenever an expected hash is configured and the running binary or script has been modified or tampered with.

### 1. Python (`JAVELIN_EXPECTED_SHA256`)

Compute the current SHA-256 hash of `anti_cheat.py`:

```bash
# Cross-platform helper built into anti_cheat.py
python3 anti_cheat.py --print-sha256

# Or with standard OS utilities:
# Linux / macOS:
shasum -a 256 anti_cheat.py
# Windows PowerShell:
(Get-FileHash .\anti_cheat.py -Algorithm SHA256).Hash.ToLower()
```

Export `JAVELIN_EXPECTED_SHA256` before launching `anti_cheat.py`:

```bash
# Linux / macOS
export JAVELIN_EXPECTED_SHA256="$(python3 anti_cheat.py --print-sha256)"
python3 anti_cheat.py
```

```powershell
# Windows PowerShell
$env:JAVELIN_EXPECTED_SHA256 = (python .\anti_cheat.py --print-sha256).Trim()
python .\anti_cheat.py
```

If `anti_cheat.py` is altered (or `JAVELIN_EXPECTED_SHA256` is malformed), `anti_cheat.py` logs `[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch). Exiting.` to `stderr` and terminates immediately with exit code `12`.

---

### 2. C++ (`JAVELIN_EXPECTED_CRC32` / `JAVELIN_EXPECTED_SHA256`)

`AntiCheat.cpp` supports optional build-time constants for **IEEE 802.3 CRC32** (`JAVELIN_EXPECTED_CRC32`) and **SHA-256** (`JAVELIN_EXPECTED_SHA256`) computed over the running executable (`GetModuleFileNameW` on Windows, `/proc/self/exe` on Linux, `_NSGetExecutablePath` on macOS).

```bash
# Build with Clang / GCC (Linux & macOS)
c++ -std=c++17 -O2 AntiCheat.cpp -o anticheat

# Inspect the compiled binary's CRC32 and SHA-256 digests
./anticheat --print-hashes

# Enforce a build-time CRC32 or SHA-256 constant (non-matching binary exits with code 12)
c++ -std=c++17 -O2 -DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp -o anticheat
c++ -std=c++17 -O2 -DJAVELIN_EXPECTED_SHA256=\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" AntiCheat.cpp -o anticheat
```

```powershell
# Build with MSVC (Windows Developer Command Prompt / PowerShell)
cl /EHsc /std:c++17 /O2 /DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp /link user32.lib
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
