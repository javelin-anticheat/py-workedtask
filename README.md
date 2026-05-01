# py-workedtask

Javelin Anti-Cheat Worked Task — Python implementation with integrity verification.

## Features

- **Debugger Detection**: Detects Python and native debuggers (cross-platform)
- **Suspicious Process Scan**: Scans for known cheat/debug tools
- **Timing Check**: Heuristic detection for single-step debugging
- **Integrity Verification**: SHA-256 hash check of the running script

## Quick Start

```bash
# Run without integrity check (development)
python3 anti_cheat.py

# Run with integrity check (production)
# First, generate the hash:
python3 -c "import hashlib; print(hashlib.sha256(open('anti_cheat.py','rb').read()).hexdigest())"

# Then set it and run:
export JAVELIN_EXPECTED_SHA256=<generated_hash>
python3 anti_cheat.py
```

## Setting Up Integrity Verification

The integrity check compares the SHA-256 hash of the script file against the
`JAVELIN_EXPECTED_SHA256` environment variable.

### Step 1: Generate the hash

```bash
python3 -c "import hashlib; print(hashlib.sha256(open('anti_cheat.py','rb').read()).hexdigest())"
```

### Step 2: Set the environment variable

**Linux/macOS:**
```bash
export JAVELIN_EXPECTED_SHA256=a1b2c3d4e5f6...
python3 anti_cheat.py
```

**Windows (PowerShell):**
```powershell
$env:JAVELIN_EXPECTED_SHA256 = "a1b2c3d4e5f6..."
python anti_cheat.py
```

**Inline (one-liner):**
```bash
JAVELIN_EXPECTED_SHA256=a1b2c3d4e5f6... python3 anti_cheat.py
```

### What happens on mismatch?

If the computed SHA-256 does not match `JAVELIN_EXPECTED_SHA256`, the script:

1. Prints the expected and actual hashes to stderr
2. Exits immediately with a non-zero exit code

This ensures that any tampering with the script file is detected before execution continues.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Integrity check failed (SHA-256 mismatch) |
| 2 | Debugger detected |
| 3 | Timing anomaly detected |

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## License

See [LICENSE](LICENSE).
