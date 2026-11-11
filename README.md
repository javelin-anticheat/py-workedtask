# py-workedtask — Javelin Anti-Cheat

Minimal C++ and Python anti-cheat guards featuring debugger detection, suspicious process scanning, and optional self-integrity verification (CRC32 and SHA-256 of the running executable or script).

## Integrity Verification (`#4`)

Both the C++ executable (`AntiCheat.cpp`) and the Python script (`anticheat.py`) support optional self-integrity verification to detect binary or script tampering. A non-matching hash results in an immediate guarded exit.

### 1. C++ Executable Integrity (`JAVELIN_EXPECTED_CRC32` / `JAVELIN_EXPECTED_SHA256`)

`AntiCheat.cpp` computes the CRC32 and/or SHA-256 of the running executable (`GetModuleFileNameW` on Windows, `/proc/self/exe` on Linux) and compares it against build-time constants:

- **`JAVELIN_EXPECTED_CRC32`**: Unsigned 32-bit CRC32 constant (default `0u` = disabled).
- **`JAVELIN_EXPECTED_SHA256`**: 64-character hex SHA-256 digest string (default `""` = disabled).

#### How to set the expected values (C++)

```bash
# Compile with SHA-256 integrity constant:
g++ -O2 AntiCheat.cpp -DJAVELIN_EXPECTED_SHA256=\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\" -o AntiCheat

# Or with MSVC using CRC32:
cl /EHsc /O2 /DJAVELIN_EXPECTED_CRC32=0x12345678u AntiCheat.cpp
```

When a mismatch is detected, `AntiCheat` prints `[Javelin AntiCheat] Integrity check failed (CRC32/SHA-256 mismatch). Exiting.` to `stderr` and exits with a non-zero status code (`0xC32` or `0x256`).

### 2. Python Script Integrity (`JAVELIN_EXPECTED_SHA256`)

`anticheat.py` computes the SHA-256 hash of the running script file and compares it against the `JAVELIN_EXPECTED_SHA256` environment variable.

#### How to compute and set `JAVELIN_EXPECTED_SHA256` (Python)

```bash
# 1. Compute the SHA-256 digest of anticheat.py:
python -c "import anticheat; print(anticheat.compute_file_sha256('anticheat.py'))"

# 2. Export JAVELIN_EXPECTED_SHA256 and run:
export JAVELIN_EXPECTED_SHA256="$(python -c "import anticheat; print(anticheat.compute_file_sha256('anticheat.py'))")"
python anticheat.py
```

On Windows PowerShell:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash .\anticheat.py -Algorithm SHA256).Hash.ToLower()
python .\anticheat.py
```

If `JAVELIN_EXPECTED_SHA256` is set and the file has been modified, `verify_script_integrity()` logs `[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch...). Exiting.` to `stderr` and performs a guarded exit via `sys.exit(1)`.
