# py-workedtask

Javelin Project — Minimal anti-cheat guards with self-integrity verification.

## Features

- **Debugger detection** — `IsDebuggerPresent` (Windows API / `sys.gettrace()` in Python)
- **Suspicious process scanning** — detects cheat engines, debuggers, and reverse-engineering tools
- **CRC32 self-integrity check** (C++ only) — fast tamper detection
- **SHA-256 self-integrity check** (C++ and Python) — cryptographic tamper detection

## C++ (`AntiCheat.cpp`)

### Build

Requires MSVC (Windows SDK). The BCrypt library is linked automatically via `#pragma comment`.

```bash
cl /EHsc AntiCheat.cpp
```

### SHA-256 Integrity Verification

The SHA-256 check is **opt-in**. By default, `JAVELIN_EXPECTED_SHA256` is empty and the check is skipped.

#### Step 1: Build without the hash

```bash
cl /EHsc AntiCheat.cpp /Fe:AntiCheat.exe
```

#### Step 2: Compute the SHA-256 of the built binary

```powershell
(Get-FileHash AntiCheat.exe -Algorithm SHA256).Hash.ToLower()
```

Or using `certutil`:

```bash
certutil -hashfile AntiCheat.exe SHA256
```

#### Step 3: Rebuild with the hash embedded

```bash
cl /EHsc /DJAVELIN_EXPECTED_SHA256="abc123..." AntiCheat.cpp /Fe:AntiCheat.exe
```

> **Note:** Since embedding the hash changes the binary, you must use a two-pass build or patch the hash into a data section post-build.

#### CRC32 (existing)

```bash
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `0xDEB` | Debugger detected |
| `0xBAD` | Suspicious process detected |
| `0xCRC` | CRC32 integrity mismatch |
| `0x5HA` | SHA-256 integrity mismatch |

## Python (`anti_cheat.py`)

### Usage

Run directly:

```bash
python anti_cheat.py
```

Or import in your project:

```python
from anti_cheat import verify_integrity, detect_suspicious_processes, is_debugger_present

# Check integrity of a specific file
if not verify_integrity("game.py"):
    print("Tampered!")

# Check for cheat tools
if detect_suspicious_processes():
    print("Cheat tool found!")
```

### SHA-256 Integrity Verification

The SHA-256 check uses the `JAVELIN_EXPECTED_SHA256` environment variable.

#### Step 1: Compute the hash of your script

```bash
python -c "import hashlib; print(hashlib.sha256(open('anti_cheat.py','rb').read()).hexdigest())"
```

Or on Linux/macOS:

```bash
sha256sum anti_cheat.py
```

Or on PowerShell:

```powershell
(Get-FileHash anti_cheat.py -Algorithm SHA256).Hash.ToLower()
```

#### Step 2: Set the environment variable and run

**PowerShell:**

```powershell
$env:JAVELIN_EXPECTED_SHA256 = "abc123..."
python anti_cheat.py
```

**Bash:**

```bash
JAVELIN_EXPECTED_SHA256="abc123..." python anti_cheat.py
```

If the variable is not set, the integrity check is skipped (opt-in behavior).

### API Reference

| Function | Description |
|----------|-------------|
| `verify_integrity(filepath, expected_hash)` | Verify SHA-256 of a file. Defaults to self-check using env var. |
| `compute_sha256(filepath)` | Return hex digest of a file's SHA-256 hash. |
| `detect_suspicious_processes()` | Returns `True` if cheat/debug tools are running. |
| `is_debugger_present()` | Returns `True` if a debugger is attached. |

## License

See [LICENSE](LICENSE).
