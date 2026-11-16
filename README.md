# py-workedtask

Minimal anti-cheat guards for the Javelin Project. Two implementations:

- **`AntiCheat.cpp`** — Windows C++ (debugger detection, suspicious process scan, CRC32 + SHA-256 self-integrity)
- **`anti_cheat.py`** — Cross-platform Python (SHA-256 script self-integrity)

## Integrity Checks

Both implementations support **opt-in** self-integrity verification. When the expected hash is not set, the check is skipped.

### C++ (`AntiCheat.cpp`)

The C++ build supports two integrity modes, both controlled by **compile-time constants**:

| Constant | Default | Effect |
|---|---|---|
| `JAVELIN_EXPECTED_CRC32` | `0u` (disabled) | CRC32 of the running `.exe` must match |
| `JAVELIN_EXPECTED_SHA256` | `""` (disabled) | SHA-256 of the running `.exe` must match |

**Build with integrity enabled:**

```sh
# 1. Build once to produce the executable
g++ AntiCheat.cpp -o anticheat.exe

# 2. Compute the expected hashes
#    (use your platform's tooling; examples below)

# Linux / macOS (with a cross-compiled binary):
#   sha256sum anticheat.exe
#   (CRC32: use a tool like `crc32` or a small script)

# Windows PowerShell:
#   Get-FileHash anticheat.exe -Algorithm SHA256

# 3. Rebuild with the expected values embedded
g++ -DJAVELIN_EXPECTED_CRC32=0x12345678 \
    -DJAVELIN_EXPECTED_SHA256=\"abc123def456...\" \
    AntiCheat.cpp -o anticheat.exe
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `0xDEB` (3563) | Debugger detected |
| `0xBAD` (4781) | Suspicious process detected |
| `0x103` (259) | CRC32 integrity mismatch |
| `0x104` (260) | SHA-256 integrity mismatch |

### Python (`anti_cheat.py`)

The Python script checks its **own file** against the `JAVELIN_EXPECTED_SHA256` environment variable.

**Setup:**

```sh
# 1. Compute the expected hash of the script
sha256sum anti_cheat.py            # Linux / macOS
Get-FileHash anti_cheat.py -Algorithm SHA256   # Windows PowerShell

# 2. Export the hash
export JAVELIN_EXPECTED_SHA256=9cc1f0b26822809361c0f76688dd75e4aeddf692001eadbb2ebed81c0cdd6086

# 3. Run
python3 anti_cheat.py
```

If `JAVELIN_EXPECTED_SHA256` is unset or empty, the check is skipped and the script exits `0`.
If the hash does not match, the script prints a diagnostic and exits with status **`0x104` (260)**.

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | All checks passed (or check disabled) |
| `0x104` (260) | SHA-256 integrity mismatch |
