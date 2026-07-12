# py-workedtask

Javelin AntiCheat - Python Implementation

## Features

- **Debugger Detection**: Detects attached debuggers using platform-specific checks
- **Process Scanning**: Scans for known cheating/suspicious processes
- **Self-Integrity**: SHA-256 hash verification to detect tampering

## Usage

### Basic Usage

```bash
python AntiCheat.py
```

### With Integrity Verification

1. First, compute the hash of your script:

```bash
# Linux/macOS
sha256sum AntiCheat.py

# Windows (PowerShell)
Get-FileHash AntiCheat.py -Algorithm SHA256
```

2. Set the environment variable with the expected hash:

```bash
# Linux/macOS
export JAVELIN_EXPECTED_SHA256="your_hash_here"

# Windows
set JAVELIN_EXPECTED_SHA256=your_hash_here
```

3. Run the script:

```bash
python AntiCheat.py
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 0xDEB | Debugger detected |
| 0xBAD | Suspicious process detected |
| 0xCRC | Integrity check failed |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `JAVELIN_EXPECTED_SHA256` | Expected SHA-256 hash of the script file |

## Cross-Platform Support

- Windows
- Linux
- macOS

## Requirements

- Python 3.6+
- No external dependencies (uses only stdlib)
